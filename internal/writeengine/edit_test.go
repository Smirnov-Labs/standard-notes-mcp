package writeengine_test

// The engine's note edits are edit, rename, trash and untrash. Each one goes
// through the surgical write path: decrypt the note, change one key in the raw
// JSON, encrypt, push. So each one changes its own key and client_updated_at,
// and nothing else. A field that gosn-v2 does not model keeps its exact bytes.
// These tests need the Docker SN server (see ops/docker).

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/jonhadfield/gosn-v2/common"
	"github.com/jonhadfield/gosn-v2/items"
	"github.com/smirnov-labs/standard-notes-mcp/internal/snclient"
	we "github.com/smirnov-labs/standard-notes-mcp/internal/writeengine"
)

// refUUID is the target of a reference. Nothing checks that the item exists.
const refUUID = "11111111-1111-4111-8111-111111111111"

// A rich note carries every kind of field that gosn-v2's typed note model drops.
// It has top-level flags (protected, starred), flags inside the SN appData domain
// (archived, locked), a third-party appData domain, and an unknown key. It has a
// reference and a spellcheck flag too. richTrashedContent is the same note, in
// the trash.
const (
	richHead = `{"title":"rich","text":"old body","references":[{"uuid":"` + refUUID + `","content_type":"Note"}],` +
		`"protected":true,"starred":true,`
	richTail = `"appData":{"org.standardnotes.sn":{"client_updated_at":"2020-01-01T00:00:00.000Z","archived":true,"locked":true},` +
		`"dev.example.editor":{"theme":"dark","fontSize":17}},` +
		`"spellcheck":false,"future_unknown_key":"must survive"}`

	richContent        = richHead + richTail
	richTrashedContent = richHead + `"trashed":true,` + richTail
)

// seedRaw creates a note whose content is exactly raw, and returns its uuid.
func seedRaw(t *testing.T, e *we.Engine, raw string) string {
	t.Helper()
	id, err := e.Client().SeedRawNote(t, raw)
	if err != nil {
		t.Fatalf("seed note: %v", err)
	}
	return id
}

// rawContent returns the decrypted content that the server holds for a note.
func rawContent(t *testing.T, e *we.Engine, id string) string {
	t.Helper()
	r, err := e.Client().FetchRawOne(id)
	if err != nil {
		t.Fatalf("FetchRawOne(%s): %v", id, err)
	}
	return r.Content()
}

// viewOf returns the typed view of a note. It fails the test if the note is not there.
func viewOf(t *testing.T, e *we.Engine, id string) *snclient.NoteView {
	t.Helper()
	n, err := e.Client().FetchOne(id)
	if err != nil {
		t.Fatal(err)
	}
	if n == nil {
		t.Fatalf("note %s is not on the server", id)
	}
	return n
}

// objectOf decodes a JSON object into its top-level raw values.
func objectOf(t *testing.T, raw string) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &m); err != nil || m == nil {
		t.Fatalf("not a JSON object (%v): %s", err, raw)
	}
	return m
}

// diffKeys compares two objects key by key on the raw bytes. changed holds keys
// whose bytes differ; added and removed hold keys that exist on one side only.
func diffKeys(before, after map[string]json.RawMessage) (changed, added, removed []string) {
	for k, b := range before {
		a, ok := after[k]
		switch {
		case !ok:
			removed = append(removed, k)
		case !bytes.Equal(a, b):
			changed = append(changed, k)
		}
	}
	for k := range after {
		if _, ok := before[k]; !ok {
			added = append(added, k)
		}
	}
	sort.Strings(changed)
	sort.Strings(added)
	sort.Strings(removed)
	return changed, added, removed
}

// requireKeys fails unless got equals want. level names the object for the message.
func requireKeys(t *testing.T, level, what string, got, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("%s: %s keys = %v, want %v", level, what, got, want)
	}
}

// show renders m[k] for a failure message. Go prints a missing RawMessage as
// null, which reads as a value, so say <missing> instead.
func show(m map[string]json.RawMessage, k string) string {
	v, ok := m[k]
	if !ok {
		return "<missing>"
	}
	return string(v)
}

// writeKey saves a note with one top-level key set to value, as another writer
// does. It uses the same raw primitives as the engine, so the other keys keep their bytes.
func writeKey(t *testing.T, e *we.Engine, id, key string, value any) {
	t.Helper()
	c := e.Client()
	r, err := c.FetchRawOne(id)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := c.EncryptMutated(r, snclient.SetKey(key, value))
	if err != nil {
		t.Fatal(err)
	}
	out, err := c.PushEncrypted(items.EncryptedItems{enc})
	if err != nil {
		t.Fatal(err)
	}
	if err := snclient.RequireSaved(out, id); err != nil {
		t.Fatal(err)
	}
}

// fieldOf reads a top-level key from the typed view. The view models these three.
func fieldOf(n *snclient.NoteView, key string) any {
	switch key {
	case "title":
		return n.Title
	case "text":
		return n.Text
	case "trashed":
		return n.Trashed
	}
	panic("the typed view does not model " + key)
}

// editCase is one kind of note edit, with the note it starts from and what it must do.
type editCase struct {
	name     string
	seed     string                                       // the raw content that the note starts with
	plan     func(*we.Engine, string) (*we.Change, error) // builds the change for a note uuid
	key      string                                       // the one top-level key that the change sets
	val      any                                          // what the change sets it to
	orig     any                                          // what the note held before
	otherKey string                                       // a different key, which another writer changes
	otherVal any
}

var editCases = []editCase{
	{"edit", richContent,
		func(e *we.Engine, id string) (*we.Change, error) { return e.PlanEditNote(id, "new body") },
		"text", "new body", "old body", "title", "other title"},
	{"rename", richContent,
		func(e *we.Engine, id string) (*we.Change, error) { return e.PlanRenameNote(id, "renamed") },
		"title", "renamed", "rich", "text", "other text"},
	{"trash", richContent,
		func(e *we.Engine, id string) (*we.Change, error) { return e.PlanTrashNote(id) },
		"trashed", true, false, "text", "other text"},
	{"untrash", richTrashedContent,
		func(e *we.Engine, id string) (*we.Change, error) { return e.PlanUntrashNote(id) },
		"trashed", false, true, "text", "other text"},
}

func TestEditNoteChangesOnlyTheText(t *testing.T) {
	e, path := newEngineAt(t, 100)
	id := seedRaw(t, e, richContent)

	ch, err := e.PlanEditNote(id, "new body")
	if err != nil {
		t.Fatal(err)
	}
	if ch.Kind != "edit" || ch.NoteUUID != id {
		t.Fatalf("change: kind %q, note %q, want edit and %q", ch.Kind, ch.NoteUUID, id)
	}
	if got := viewOf(t, e, id); got.Text != "old body" {
		t.Fatalf("planning wrote to the note: text = %q", got.Text)
	}
	if err := e.Commit(ch); err != nil {
		t.Fatal(err)
	}

	got := viewOf(t, e, id)
	if got.Text != "new body" || got.Title != "rich" || got.RefCount() != 1 || got.Trashed {
		t.Fatalf("after the edit: text=%q title=%q refs=%d trashed=%v, want the new text and all else as before",
			got.Text, got.Title, got.RefCount(), got.Trashed)
	}
	if n := noteCount(t, e); n != 1 {
		t.Fatalf("want 1 note, got %d", n)
	}
	want := []string{we.StateIntended, we.StateAcked, we.StateVerified}
	if states := ledgerStates(t, path, ch.OpID); !slices.Equal(states, want) {
		t.Fatalf("ledger states = %v, want %v", states, want)
	}
}

func TestRenameNoteChangesOnlyTheTitle(t *testing.T) {
	e, path := newEngineAt(t, 100)
	id := seedRaw(t, e, richContent)

	ch, err := e.PlanRenameNote(id, "renamed")
	if err != nil {
		t.Fatal(err)
	}
	if ch.Kind != "rename" || ch.NoteUUID != id {
		t.Fatalf("change: kind %q, note %q, want rename and %q", ch.Kind, ch.NoteUUID, id)
	}
	if got := viewOf(t, e, id); got.Title != "rich" {
		t.Fatalf("planning wrote to the note: title = %q", got.Title)
	}
	if err := e.Commit(ch); err != nil {
		t.Fatal(err)
	}

	got := viewOf(t, e, id)
	if got.Title != "renamed" || got.Text != "old body" || got.RefCount() != 1 || got.Trashed {
		t.Fatalf("after the rename: title=%q text=%q refs=%d trashed=%v, want the new title and all else as before",
			got.Title, got.Text, got.RefCount(), got.Trashed)
	}
	if n := noteCount(t, e); n != 1 {
		t.Fatalf("want 1 note, got %d", n)
	}
	want := []string{we.StateIntended, we.StateAcked, we.StateVerified}
	if states := ledgerStates(t, path, ch.OpID); !slices.Equal(states, want) {
		t.Fatalf("ledger states = %v, want %v", states, want)
	}
}

// Untrash undoes trash. The note leaves the trash, and nothing else about it changes.
func TestUntrashLeavesTheTrash(t *testing.T) {
	e := newEngine(t)
	id := createNote(t, e, "Round trip", "body")

	trash, err := e.PlanTrashNote(id)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Commit(trash); err != nil {
		t.Fatal(err)
	}
	if !viewOf(t, e, id).Trashed {
		t.Fatal("premise: the trash did not land")
	}

	untrash, err := e.PlanUntrashNote(id)
	if err != nil {
		t.Fatal(err)
	}
	if untrash.Kind != "untrash" || untrash.NoteUUID != id {
		t.Fatalf("change: kind %q, note %q, want untrash and %q", untrash.Kind, untrash.NoteUUID, id)
	}
	if err := e.Commit(untrash); err != nil {
		t.Fatal(err)
	}
	got := viewOf(t, e, id)
	if got.Trashed || got.Title != "Round trip" || got.Text != "body" {
		t.Fatalf("after the untrash: %+v, want an untrashed note with its title and text", got)
	}
	if c := copiesOf(t, e.Client(), "Round trip"); c != 1 {
		t.Fatalf("want 1 note titled %q, got %d", "Round trip", c)
	}
}

// A plan for a note that is not on the server must fail at once, name the
// problem, and hand back no Change.
func TestPlansRefuseAMissingNote(t *testing.T) {
	e := newEngine(t)
	const missing = "00000000-0000-4000-8000-000000000000"
	for _, tc := range editCases {
		ch, err := tc.plan(e, missing)
		if ch != nil || !errors.Is(err, snclient.ErrNoteNotFound) {
			t.Errorf("%s: plan for a missing note gave change=%v err=%v, want nil and ErrNoteNotFound", tc.name, ch, err)
		}
	}
}

// The preservation test at the engine level. Task 1 proved the primitive. This
// proves the plans use it. Each plan, committed through the engine, changes its
// key and client_updated_at. Every other field, modeled or not, known or not,
// keeps its exact bytes.
func TestEnginePlansPreserveEveryUnmodeledField(t *testing.T) {
	e := newEngine(t)
	for _, tc := range editCases {
		t.Run(tc.name, func(t *testing.T) {
			id := seedRaw(t, e, tc.seed)
			// Premise: the server holds the seed byte for byte. Without this, a later
			// match proves nothing: the seed can already be damaged.
			if got := rawContent(t, e, id); got != tc.seed {
				t.Fatalf("premise broken: seeded content did not round-trip\n got: %s\nwant: %s", got, tc.seed)
			}
			ch, err := tc.plan(e, id)
			if err != nil {
				t.Fatal(err)
			}
			if got := rawContent(t, e, id); got != tc.seed {
				t.Fatalf("planning wrote to the note:\n%s", got)
			}
			if err := e.Commit(ch); err != nil {
				t.Fatal(err)
			}

			before := objectOf(t, tc.seed)
			after := objectOf(t, rawContent(t, e, id))
			beforeApp, afterApp := objectOf(t, string(before["appData"])), objectOf(t, string(after["appData"]))
			beforeSN := objectOf(t, string(beforeApp["org.standardnotes.sn"]))
			afterSN := objectOf(t, string(afterApp["org.standardnotes.sn"]))

			// The change landed, as the official apps write the value.
			want, err := json.Marshal(tc.val)
			if err != nil {
				t.Fatal(err)
			}
			if got := show(after, tc.key); got != string(want) {
				t.Errorf("%s = %s, want %s", tc.key, got, want)
			}

			// client_updated_at changed, and it is the current time.
			var stamp string
			if err := json.Unmarshal(afterSN["client_updated_at"], &stamp); err != nil {
				t.Fatalf("client_updated_at is not a JSON string: %s", afterSN["client_updated_at"])
			}
			at, err := time.Parse(common.TimeLayout, stamp)
			if err != nil {
				t.Fatalf("client_updated_at %q is not in layout %q: %v", stamp, common.TimeLayout, err)
			}
			if d := time.Since(at); d < -time.Minute || d > time.Minute {
				t.Errorf("client_updated_at %q is %v from now", stamp, d)
			}

			// Each field that the brief names is byte-identical.
			for _, k := range []string{"references", "protected", "starred", "spellcheck", "future_unknown_key"} {
				if !bytes.Equal(before[k], after[k]) {
					t.Errorf("top-level %q changed: %s -> %s", k, show(before, k), show(after, k))
				}
			}
			for _, k := range []string{"archived", "locked"} {
				if !bytes.Equal(beforeSN[k], afterSN[k]) {
					t.Errorf("appData[org.standardnotes.sn].%s changed: %s -> %s", k, show(beforeSN, k), show(afterSN, k))
				}
			}
			if !bytes.Equal(beforeApp["dev.example.editor"], afterApp["dev.example.editor"]) {
				t.Errorf("third-party appData changed: %s -> %s",
					show(beforeApp, "dev.example.editor"), show(afterApp, "dev.example.editor"))
			}

			// Whole-object check. At each of the three levels, exactly the intended
			// key changed, and nothing was removed. A trash flag that the note did
			// not have counts as added.
			changed, added, removed := diffKeys(before, after)
			touched := append(slices.Clone(changed), added...)
			sort.Strings(touched)
			wantTouched := []string{"appData", tc.key}
			sort.Strings(wantTouched)
			requireKeys(t, "content", "touched", touched, wantTouched)
			requireKeys(t, "content", "removed", removed, nil)
			changed, added, removed = diffKeys(beforeApp, afterApp)
			requireKeys(t, "appData", "changed", changed, []string{"org.standardnotes.sn"})
			requireKeys(t, "appData", "added", added, nil)
			requireKeys(t, "appData", "removed", removed, nil)
			changed, added, removed = diffKeys(beforeSN, afterSN)
			requireKeys(t, "appData[org.standardnotes.sn]", "changed", changed, []string{"client_updated_at"})
			requireKeys(t, "appData[org.standardnotes.sn]", "added", added, nil)
			requireKeys(t, "appData[org.standardnotes.sn]", "removed", removed, nil)

			// The typed view agrees with the raw content.
			got := viewOf(t, e, id)
			if fieldOf(got, tc.key) != tc.val || got.RefCount() != 1 {
				t.Errorf("typed view: %s=%v refs=%d, want %v and 1 reference", tc.key, fieldOf(got, tc.key), got.RefCount(), tc.val)
			}
		})
	}
}

// Each plan is one intent, so each plan puts its own nonce in the OpID. A
// verified OpID is a no-op for good. Suppose two plans share an OpID. Another
// writer puts the field back, and the user asks for the same change again. The
// second Commit finds the first one's verified entry, returns nil, and pushes
// nothing. Every step reports success, but the change is not there.
func TestEachPlanIsItsOwnIntent(t *testing.T) {
	e := newEngine(t) // one account for all cases: each case seeds its own note
	for _, tc := range editCases {
		t.Run(tc.name, func(t *testing.T) {
			id := seedRaw(t, e, tc.seed)

			first, err := tc.plan(e, id)
			if err != nil {
				t.Fatal(err)
			}
			if err := e.Commit(first); err != nil {
				t.Fatal(err)
			}
			if got := fieldOf(viewOf(t, e, id), tc.key); got != tc.val {
				t.Fatalf("premise: the first %s did not land: %s = %v", tc.name, tc.key, got)
			}

			writeKey(t, e, id, tc.key, tc.orig) // another writer puts the field back
			if got := fieldOf(viewOf(t, e, id), tc.key); got != tc.orig {
				t.Fatalf("premise: the other writer did not put %s back: %v", tc.key, got)
			}

			second, err := tc.plan(e, id)
			if err != nil {
				t.Fatal(err)
			}
			if second.OpID == first.OpID {
				t.Fatalf("two plans share the OpID %s", first.OpID)
			}
			if err := e.Commit(second); err != nil {
				t.Fatal(err)
			}
			if got := fieldOf(viewOf(t, e, id), tc.key); got != tc.val {
				t.Fatalf("the second %s did not land: %s = %v", tc.name, tc.key, got)
			}
		})
	}
}

// apply must read the note again right before it pushes. A plan can wait, and
// the server timestamp can move in that time (another device saves the note). A
// push with a stale timestamp is a sync_conflict. gosn-v2 answers it by minting
// a copy of the note under a new uuid. With a fresh read, the change lands on top
// of the other writer's save, and keeps it.
func TestPlansReadTheNoteFreshBeforePushing(t *testing.T) {
	e := newEngine(t) // one account for all cases: each case seeds its own note
	for _, tc := range editCases {
		t.Run(tc.name, func(t *testing.T) {
			id := seedRaw(t, e, tc.seed)
			notes := noteCount(t, e)
			ch, err := tc.plan(e, id) // reads the note at its current timestamp
			if err != nil {
				t.Fatal(err)
			}

			// Before Commit, another writer saves the note, so its server timestamp moves on.
			writeKey(t, e, id, tc.otherKey, tc.otherVal)

			if err := e.Commit(ch); err != nil {
				t.Fatalf("%s after the server timestamp moved: %v", tc.name, err)
			}
			got := viewOf(t, e, id)
			if fieldOf(got, tc.key) != tc.val {
				t.Errorf("the change did not land: %s = %v, want %v", tc.key, fieldOf(got, tc.key), tc.val)
			}
			if fieldOf(got, tc.otherKey) != tc.otherVal {
				t.Errorf("the change lost the other writer's save: %s = %v, want %v",
					tc.otherKey, fieldOf(got, tc.otherKey), tc.otherVal)
			}
			if n := noteCount(t, e); n != notes {
				t.Errorf("want %d notes, got %d: a stale push leaves a copy", notes, n)
			}
		})
	}
}

// Commit treats a change as a retry when the ledger holds intended or acked for
// its OpID. reconcile reads the note live and decides the retry. If the end
// state already holds, the earlier push landed, so the retry must not push. If
// it does not, the earlier push did not land, so the retry pushes once.
func TestEditRetryIsDecidedByLiveRead(t *testing.T) {
	e, path := newEngineAt(t, 100) // one account and one ledger for all cases: each OpID is its own
	for _, tc := range editCases {
		t.Run(tc.name+" landed", func(t *testing.T) {
			id := seedRaw(t, e, tc.seed)
			notes := noteCount(t, e)
			ch, err := tc.plan(e, id)
			if err != nil {
				t.Fatal(err)
			}
			if err := e.Commit(ch); err != nil { // the server takes the write
				t.Fatal(err)
			}

			for _, lastState := range []string{we.StateIntended, we.StateAcked} {
				// Cap 0: only a read can succeed, so a nil error proves the retry did not push.
				e2 := restartAt(t, e.Client(), path, ch, lastState, 0)
				if err := e2.Commit(ch); err != nil {
					t.Fatalf("retry of a change that already landed, ledger says %s: %v", lastState, err)
				}
				states := ledgerStates(t, path, ch.OpID)
				if last := states[len(states)-1]; last != we.StateVerified {
					t.Fatalf("a landed retry must end verified, ledger says %v", states)
				}
			}
			if got := fieldOf(viewOf(t, e, id), tc.key); got != tc.val {
				t.Fatalf("%s = %v, want %v", tc.key, got, tc.val)
			}
			if n := noteCount(t, e); n != notes {
				t.Fatalf("want %d notes, got %d", notes, n)
			}
		})

		t.Run(tc.name+" never landed", func(t *testing.T) {
			id := seedRaw(t, e, tc.seed)
			notes := noteCount(t, e)
			ch, err := tc.plan(e, id) // planned, then the process died before the push
			if err != nil {
				t.Fatal(err)
			}

			e2 := restartAt(t, e.Client(), path, ch, we.StateIntended, 100)
			if err := e2.Commit(ch); err != nil {
				t.Fatalf("retry of a change that never landed: %v", err)
			}
			if got := fieldOf(viewOf(t, e, id), tc.key); got != tc.val {
				t.Fatalf("%s = %v, want %v", tc.key, got, tc.val)
			}
			if n := noteCount(t, e); n != notes {
				t.Fatalf("want %d notes, got %d", notes, n)
			}
			want := []string{we.StateIntended, we.StateAcked, we.StateVerified}
			if got := ledgerStates(t, path, ch.OpID); !slices.Equal(got, want) {
				t.Fatalf("ledger states = %v, want %v", got, want)
			}
		})
	}
}
