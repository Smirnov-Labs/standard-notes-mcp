package writeengine

// An edit of an existing note goes through the surgical path in snclient. The
// path has four steps: read the raw content of the note, change one key, encrypt
// that exact JSON, and push it. The typed path (Push of an items.Note) rebuilds
// the note from a fixed struct. It drops every field that the struct lacks. So no
// edit of an existing note can use it.

import (
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jonhadfield/gosn-v2/items"
	"github.com/smirnov-labs/standard-notes-mcp/internal/snclient"
)

// PlanEditNote sets the text of a note. It changes the text key and
// client_updated_at, and no other part of the note. See planNoteChange.
func (e *Engine) PlanEditNote(noteUUID, newText string) (*Change, error) {
	return e.planNoteChange(noteUUID, "edit", "text", newText,
		func(n *snclient.NoteView) any { return n.Text })
}

// PlanRenameNote sets the title of a note. It changes the title key and
// client_updated_at, and no other part of the note. See planNoteChange.
func (e *Engine) PlanRenameNote(noteUUID, newTitle string) (*Change, error) {
	return e.planNoteChange(noteUUID, "rename", "title", newTitle,
		func(n *snclient.NoteView) any { return n.Title })
}

// PlanUntrashNote takes a note out of the trash. It sets the reversible trashed
// flag, inside the note content, back to false. It is the opposite of
// PlanTrashNote. It changes the trashed key and client_updated_at, and no other
// part of the note. See planNoteChange.
func (e *Engine) PlanUntrashNote(noteUUID string) (*Change, error) {
	return e.planNoteChange(noteUUID, "untrash", "trashed", false,
		func(n *snclient.NoteView) any { return n.Trashed })
}

// planNoteChange builds the Change for an edit of one existing note. The edit
// sets one top-level key of the note content. The edits are: edit (text), rename
// (title), trash (trashed) and untrash (trashed). kind names the change in the
// ledger. value is what the change sets key to. It must be a string or a bool.
// read gives the same field from the typed view, so that the change can tell
// whether it has landed.
//
// The write goes through the surgical path, so it changes key and
// client_updated_at and no other part of the note. A field that gosn-v2 does not
// model keeps its exact bytes.
//
// Each call is one intent, so each call puts a fresh nonce in the OpID. A verified
// OpID is a no-op for good. Without the nonce, a second change to a note after
// someone undid the first returns nil and does nothing. Every step reports
// success, but the note is not changed.
//
// Both closures read the note live.
//
//   - reconcile answers a retry. If the note already holds value in key, the
//     change landed, so Commit does not push. If it does not, Commit pushes. If
//     the note is gone, reconcile refuses.
//   - apply reads the note again right before the push, so the push carries the
//     server's current timestamp. A stale timestamp is a sync_conflict, and
//     gosn-v2 answers it by minting a copy. The change lands on top of any save
//     that another writer made since the plan, and keeps that save. The one
//     exception is key itself: apply sets it to value whatever the note holds
//     there now.
//
// The read-after-write check needs two facts. The typed view holds value in key.
// And the typed view counts the same references as the raw content that apply
// read. That count catches a write that loses a reference.
func (e *Engine) planNoteChange(noteUUID, kind, key string, value any, read func(*snclient.NoteView) any) (*Change, error) {
	cur, err := e.cl.FetchOne(noteUUID)
	if err != nil {
		return nil, err
	}
	if cur == nil {
		return nil, fmt.Errorf("%w: %s", snclient.ErrNoteNotFound, noteUUID)
	}
	nonce := uuid.NewString() // one intent per invocation, so a repeat after an undo is not a no-op
	ch := &Change{
		OpID: kind + ":" + noteUUID + ":" + nonce, Kind: kind, NoteUUID: noteUUID,
		Before: map[string]any{key: read(cur)}, After: map[string]any{key: value},
	}
	ch.reconcile = func() (bool, error) { // retry: live read, no write
		live, err := e.cl.FetchOne(noteUUID)
		if err != nil {
			return false, err
		}
		if live == nil {
			return false, ErrVerifyFailed // note is gone: refuse
		}
		return read(live) == value, nil // true = already holds (landed); false = safe to push
	}
	ch.apply = func() error {
		r, err := e.cl.FetchRawOne(noteUUID) // fresh server timestamp right before the push
		if err != nil {
			return err
		}
		refs, err := refCount(r)
		if err != nil {
			return err
		}
		enc, err := e.cl.EncryptMutated(r, snclient.SetKey(key, value))
		if err != nil {
			return err
		}
		return e.pushRawAndVerify(ch, items.EncryptedItems{enc}, func(g *snclient.NoteView) bool {
			return g != nil && read(g) == value && g.RefCount() == refs
		})
	}
	return ch, nil
}

// refCount returns how many references the raw content of a note holds.
func refCount(r *snclient.RawNote) (int, error) {
	var content struct {
		References []json.RawMessage `json:"references"`
	}
	if err := json.Unmarshal([]byte(r.Content()), &content); err != nil {
		return 0, fmt.Errorf("note %s: read references: %w", r.UUID, err)
	}
	return len(content.References), nil
}

// pushRawAndVerify is pushAndVerify for items that are already encrypted. It
// pushes with PushEncrypted, so the bytes that EncryptMutated made are the bytes
// that land. Every change to an existing note or tag uses it. See the note on edits
// at the top of this file. A tag change has no note for the ok hook to check. It
// passes a hook that accepts every state, and it reads the tag back itself. See
// applyTagEdit.
//
// It does what pushAndVerify does, in the same order, with one more check. The
// order matters. Keep the snapshot and stray-item logic in step with
// pushAndVerify.
//
//  1. Read the notes and tags live, before the push.
//  2. Push, and record the ack. The ack shows that the push call returned. It
//     does not show that the server saved the item: step 4 checks that.
//  3. Read them live again. A note or tag that is new, and that is not
//     ch.NoteUUID or ch.TagUUID, is a duplicate. Return ErrDuplicated. Commit
//     halts the engine for good on that error.
//  4. Require that the server saved every pushed item. A push that returns no
//     error can still save nothing. A stale push is the case that matters. The
//     server rejects it. gosn-v2 returns no error. It saves our item as a copy
//     under a new uuid, built through the lossy typed path. Step 3 finds that
//     copy. Step 4 finds that our write did not land. When the server rejects a
//     push and gosn-v2 makes no copy, only step 4 finds it.
//  5. Run ok on the note.
//
// Step 3 must come before step 4. A stale push leaves a copy in the account. An
// early return at step 4 leaves that copy there without a halt.
func (e *Engine) pushRawAndVerify(ch *Change, toPush items.EncryptedItems, ok func(*snclient.NoteView) bool) error {
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
	out, err := e.cl.PushEncrypted(toPush)
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
	var notSaved error // reported after the stray scan: see step 3 and step 4 above
	for _, it := range toPush {
		if err := snclient.RequireSaved(out, it.UUID); err != nil {
			notSaved = err
			break
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
		if notSaved != nil {
			return fmt.Errorf("%w: item(s) %v appeared that this change did not create, and the push was not saved: %w",
				ErrDuplicated, stray, notSaved)
		}
		return fmt.Errorf("%w: item(s) %v appeared that this change did not create", ErrDuplicated, stray)
	}
	if notSaved != nil {
		return notSaved
	}
	if !ok(got) {
		return ErrVerifyFailed
	}
	return nil
}
