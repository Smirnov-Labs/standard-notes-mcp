package writeengine

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jonhadfield/gosn-v2/items"
	"github.com/smirnov-labs/standard-notes-mcp/internal/snclient"
)

var (
	ErrKilled       = errors.New("engine killed")
	ErrCapReached   = errors.New("max writes per run reached")
	ErrDuplicated   = errors.New("sync produced a duplicate; halting")
	ErrVerifyFailed = errors.New("read-after-write verification failed")
)

// Engine serializes every write through one path: bounded by a max-writes cap
// and a kill switch, recorded in the op-ledger (intended -> acked -> verified),
// and halted if a write makes an item it did not mean to make.
//
// Two facts about gosn-v2 (pin 041e51be565f) shape the design. Both were
// reproduced against the Docker server.
//
//   - Pushing a uuid the server already holds is a sync_conflict, not an upsert.
//     gosn-v2 answers it by re-pushing the item under a new uuid. So a retry
//     never pushes blind. See Change.reconcile.
//   - That copy has duplicate_of null, on the wire and on the server, and Sync
//     drops it from SavedItems. A DuplicateOf scan cannot see it, and
//     SyncOutput.Items holds the whole account, so the scan also fires on every
//     old conflict copy. So pushAndVerify compares live snapshots taken before
//     and after the push.
//
// A third fact decides how a change reaches the server. gosn-v2 parses a note
// into a fixed struct, and it encrypts that struct again on a push. A field that
// the struct lacks is gone after that write: starred, archived, a third-party
// appData domain, a key that a later app version adds. A tag loses fields the same
// way. So a change to an existing note or tag never goes through Push. It goes
// through the surgical path in snclient (FetchRawOne or FetchRawTag, EncryptMutated,
// PushEncrypted), and pushRawAndVerify pushes it. pushAndVerify is for an item that
// the change creates.
//
// Concurrency: Commit calls queue on mu, and Kill is safe from any goroutine.
// Reads through Client() are NOT serialized with Commit. gosn-v2 mutates its
// shared session on every sync, so a read that overlaps a Commit is a data race.
// Call Client() only from the goroutine that calls Commit (one writer, used
// sequentially). Serializing them needs a mutex inside snclient (Plan 2).
type Engine struct {
	cl        *snclient.Client
	led       *Ledger
	mu        sync.Mutex // serializes Commit and guards written
	maxWrites int
	written   int         // write attempts, not successes
	killed    atomic.Bool // lock-free: Kill must not wait behind a hung write
}

func NewEngine(cl *snclient.Client, led *Ledger, maxWrites int) *Engine {
	return &Engine{cl: cl, led: led, maxWrites: maxWrites}
}

func (e *Engine) Client() *snclient.Client { return e.cl }

// Kill stops the engine: later Commits return ErrKilled, and a write that has
// not reached its push yet stops there. A push already on the wire is not recalled.
func (e *Engine) Kill() { e.killed.Store(true) }

// PlanCreateNote pre-assigns the uuid (so a retry reuses it -> idempotent) and
// binds the apply and the reconcile. Building the Change does NOT write
// (dry-run); Commit writes.
//
// The pre-assigned uuid is the note's identity. It is ch.NoteUUID and part of
// the OpID, and the closures capture it, so a retry of the same Change finds
// the note by uuid. A second PlanCreateNote call mints a new uuid, so it is a
// new change and not a retry.
func (e *Engine) PlanCreateNote(title, text string, refs items.ItemReferences) (*Change, error) {
	id := uuid.NewString()
	ch := &Change{OpID: "create:" + id, Kind: "create", NoteUUID: id,
		After: map[string]any{"title": title, "text": text}}
	ch.reconcile = func() (bool, error) {
		cur, err := e.cl.FetchOne(id)
		switch {
		case err != nil:
			return false, err
		case cur == nil:
			return false, nil // never landed: safe to push
		case cur.Title == title && cur.Text == text:
			return true, nil // landed: nothing to push
		default:
			return false, ErrVerifyFailed // exists but differs: a push would conflict and mint a copy
		}
	}
	ch.apply = func() error {
		n, err := items.NewNote(title, text, refs)
		if err != nil {
			return err
		}
		n.SetUUID(id)
		n.Content.SetUpdateTime(time.Now().UTC())
		return e.pushAndVerify(ch, items.Items{&n}, func(got *snclient.NoteView) bool {
			return got != nil && got.Title == title && got.Text == text
		})
	}
	return ch, nil
}

// PlanTrashNote moves a note to the trash. It sets the reversible trashed flag
// inside the note content. The note stays on the server, and an official app can
// restore it. It never sets the permanent deleted flag on the item envelope.
// guard_test.go fails if any non-test source does.
//
// It goes through the surgical path, so it changes the trashed key and
// client_updated_at, and no other part of the note. Every other field of the
// note keeps its exact bytes, whether or not gosn-v2 models it. The nonce, the
// reconcile and the fresh read are in planNoteChange.
func (e *Engine) PlanTrashNote(noteUUID string) (*Change, error) {
	return e.planNoteChange(noteUUID, "trash", "trashed", true,
		func(n *snclient.NoteView) any { return n.Trashed })
}

// Commit runs a planned change through the single serialized, bounded, verified
// path. In order:
//
// A killed engine returns ErrKilled. A change the ledger already marks verified
// is a no-op (idempotent replay).
//
// A retry (the ledger holds intended or acked) calls ch.reconcile first. If the
// change already landed, Commit records verified and returns nil: that is a read,
// so it uses no write budget. If reconcile errs, Commit returns the error. A
// retry with no reconcile is refused.
//
// Then the cap check. A first attempt records intended before it touches the
// server. A retry keeps the state it has, so acked never falls back to intended.
//
// Then ch.apply runs. The attempt counts against the cap even if apply fails,
// because a write can land and still fail a check. ErrDuplicated also halts the
// engine for good: every later Commit returns ErrKilled.
func (e *Engine) Commit(ch *Change) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.killed.Load() {
		return ErrKilled
	}
	prev := e.led.LastState(ch.OpID)
	if prev == StateVerified {
		return nil // idempotent replay
	}
	if prev != "" { // retry: the earlier attempt may have reached the server
		if ch.reconcile == nil {
			return fmt.Errorf("retry of %s refused, cannot tell whether the earlier attempt landed: %w", ch.OpID, ErrVerifyFailed)
		}
		landed, err := ch.reconcile() // a read, so it needs no write budget
		if err != nil {
			return err
		}
		if landed {
			return e.led.Record(ch.OpID, ch.Kind, ch.NoteUUID, StateVerified)
		}
	}
	if e.written >= e.maxWrites {
		return ErrCapReached
	}
	if prev == "" {
		if err := e.led.Record(ch.OpID, ch.Kind, ch.NoteUUID, StateIntended); err != nil {
			return err
		}
	}
	e.written++ // count the attempt, not the success: a write can land and still fail a check
	if err := ch.apply(); err != nil {
		if errors.Is(err, ErrDuplicated) {
			e.killed.Store(true) // halt for real: no further writes this run
		}
		return err
	}
	return e.led.Record(ch.OpID, ch.Kind, ch.NoteUUID, StateVerified)
}

// pushAndVerify pushes, records the ack, detects a duplicate gosn-v2 minted on a
// sync_conflict, then read-after-write verifies. It pushes typed items, so use it
// only for an item that the change creates. A change to an existing note or tag
// must use pushRawAndVerify, which keeps every field of the item.
//
// Duplicate detection is by state, not by flag (see Engine). It reads the notes
// and tags live before the push and again after it. A note or tag that is in
// the second read, was not in the first, and is not ch.NoteUUID or ch.TagUUID
// is a duplicate, and the error names it. The same signal also fires for an
// item that someone else created in the same few seconds. Halting is the safe
// answer for both.
func (e *Engine) pushAndVerify(ch *Change, toPush items.Items, ok func(*snclient.NoteView) bool) error {
	if e.killed.Load() {
		return ErrKilled
	}
	notesBefore, tagsBefore, err := e.cl.Fetch()
	if err != nil {
		return err
	}
	seen := make(map[string]bool, len(notesBefore)+len(tagsBefore))
	for _, n := range notesBefore {
		seen[n.UUID] = true
	}
	for _, t := range tagsBefore {
		seen[t.UUID] = true
	}
	if e.killed.Load() { // a Kill that landed during the read above stops the write here
		return ErrKilled
	}
	out, err := e.cl.Push(toPush)
	if err != nil {
		return err
	}
	if err := e.led.Record(ch.OpID, ch.Kind, ch.NoteUUID, StateAcked); err != nil {
		return err
	}
	for _, it := range out.SavedItems { // defense in depth: gosn-v2 does not set DuplicateOf on the copies it mints
		if it.DuplicateOf != nil {
			return fmt.Errorf("%w: pushed item %s carries duplicate_of %s", ErrDuplicated, it.UUID, *it.DuplicateOf)
		}
	}
	notesAfter, tagsAfter, err := e.cl.Fetch() // always-live read-after-write
	if err != nil {
		return err
	}
	var got *snclient.NoteView
	var stray []string
	for _, n := range notesAfter {
		switch {
		case n.UUID == ch.NoteUUID:
			got = n
		case !seen[n.UUID]:
			stray = append(stray, n.UUID)
		}
	}
	for _, t := range tagsAfter {
		if t.UUID != ch.TagUUID && !seen[t.UUID] {
			stray = append(stray, t.UUID)
		}
	}
	if len(stray) > 0 {
		return fmt.Errorf("%w: item(s) %v appeared that this change did not create", ErrDuplicated, stray)
	}
	if !ok(got) {
		return ErrVerifyFailed
	}
	return nil
}
