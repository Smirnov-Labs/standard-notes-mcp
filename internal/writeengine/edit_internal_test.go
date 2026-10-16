package writeengine

// Tests for pushRawAndVerify, the sibling of pushAndVerify that pushes items
// which are already encrypted. They live in the package so they can call it and
// bind their own apply funcs. Tests that name a server need the Docker SN server
// (see ops/docker). The kill test runs offline.

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jonhadfield/gosn-v2/common"
	"github.com/jonhadfield/gosn-v2/items"
	"github.com/smirnov-labs/standard-notes-mcp/internal/snclient"
)

// staleSeed is a note with fields that gosn-v2's typed model drops. A copy built
// through the typed path lacks them, so a test can tell the copy from the original.
const staleSeed = `{"title":"stale","text":"version 1","references":[],` +
	`"protected":true,"starred":true,"future_unknown_key":"must survive"}`

// anything is an ok hook that accepts every state. The tests below use it to show
// that the checks around the hook stop the fault, and not the hook.
func anything(*snclient.NoteView) bool { return true }

// rawObject returns the content that the server holds for a note, as top-level raw values.
func rawObject(t *testing.T, c *snclient.Client, id string) map[string]json.RawMessage {
	t.Helper()
	r, err := c.FetchRawOne(id)
	if err != nil {
		t.Fatalf("FetchRawOne(%s): %v", id, err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(r.Content()), &m); err != nil {
		t.Fatalf("content of %s is not a JSON object: %v", id, err)
	}
	return m
}

// pushRawAndVerify must honor Kill before it touches the client. The engine has a
// nil client here, so a Kill check placed after the first read panics.
func TestPushRawAndVerifyHonorsKill(t *testing.T) {
	e := offlineEngine(t, 10)
	e.Kill()
	err := e.pushRawAndVerify(&Change{OpID: "k", Kind: "edit", NoteUUID: "k"}, nil, anything)
	if !errors.Is(err, ErrKilled) {
		t.Fatalf("want ErrKilled, got %v", err)
	}
}

// A stale write must halt the engine. The note changes after the writer read it.
// The server answers sync_conflict. gosn-v2 returns no error. It keeps the
// server's version, and it saves the stale write as a copy under a new uuid,
// built through the lossy typed path. The note's own uuid is not in SavedItems.
// Only the snapshot diff sees the copy. The hook accepts every state, so the
// checks around it are what stop the write.
func TestStaleRawWriteHaltsTheEngine(t *testing.T) {
	e, c := liveEngine(t)
	id, err := c.SeedRawNote(t, staleSeed)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	ch := &Change{OpID: "edit:stale", Kind: "edit", NoteUUID: id}
	ch.apply = func() error {
		stale, err := c.FetchRawOne(id) // this writer reads version 1
		if err != nil {
			return err
		}
		if err := c.EditNoteText(id, "version 2"); err != nil { // another writer saves version 2
			return err
		}
		enc, err := c.EncryptMutated(stale, snclient.SetKey("text", "stale write"))
		if err != nil {
			return err
		}
		return e.pushRawAndVerify(ch, items.EncryptedItems{enc}, anything)
	}
	err = e.Commit(ch)

	notes, _, ferr := c.Fetch()
	if ferr != nil {
		t.Fatal(ferr)
	}
	copyID := ""
	for _, n := range notes {
		if n.UUID != id {
			copyID = n.UUID
		}
	}
	if len(notes) != 2 || copyID == "" {
		t.Fatalf("premise failed: a stale push no longer mints a copy (%d notes). "+
			"gosn-v2 or the server changed. Re-check the stale-write detection in pushRawAndVerify.", len(notes))
	}
	if !errors.Is(err, ErrDuplicated) {
		t.Fatalf("a stale write minted copy %s but Commit returned %v, want ErrDuplicated", copyID, err)
	}
	t.Logf("a stale write is reported as: %v", err)
	if !strings.Contains(err.Error(), copyID) {
		t.Errorf("the error must name the copy %s, got: %v", copyID, err)
	}
	if !errors.Is(err, snclient.ErrPushNotSaved) {
		t.Errorf("the error must also say that the write was not saved, got: %v", err)
	}

	// The engine halted, and the change does not read as done.
	pushed := false
	next := &Change{OpID: "edit:next", Kind: "edit", NoteUUID: id, apply: func() error { pushed = true; return nil }}
	if err := e.Commit(next); pushed || !errors.Is(err, ErrKilled) {
		t.Errorf("the engine kept writing after a stale write (pushed=%v, err=%v)", pushed, err)
	}
	if got := e.led.LastState(ch.OpID); got != StateAcked {
		t.Errorf("ledger state = %q, want %q: a stale write must not read as verified", got, StateAcked)
	}

	// The newer version is still the live note. The stale write did not touch it.
	live := rawObject(t, c, id)
	if got := string(live["text"]); got != `"version 2"` {
		t.Errorf("text = %s, want \"version 2\": the stale write overwrote it", got)
	}
	if got := string(live["future_unknown_key"]); got != `"must survive"` {
		t.Errorf("future_unknown_key = %s, want it kept", got)
	}
}

// A push that the server did not save is not a success, even when the hook accepts
// the state and no stray item appeared. gosn-v2 refuses to modify an existing
// SN|ItemsKey item. It drops such an item before the request and returns no error.
// So that push saves nothing and mints no copy. It stands for any outcome that
// gosn-v2 settles by keeping the server's version, such as a content error or a
// read-only error.
func TestRawPushThatIsNotSavedIsNotSuccess(t *testing.T) {
	e, c := liveEngine(t)
	id, err := c.SeedRawNote(t, staleSeed)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	r, err := c.FetchRawOne(id)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := c.EncryptMutated(r, snclient.SetKey("text", "never lands"))
	if err != nil {
		t.Fatal(err)
	}
	enc.ContentType = common.SNItemTypeItemsKey
	enc.UpdatedAt = "2026-01-01T00:00:00.000000Z"

	ch := &Change{OpID: "edit:unsaved", Kind: "edit", NoteUUID: id}
	err = e.pushRawAndVerify(ch, items.EncryptedItems{enc}, anything)
	if !errors.Is(err, snclient.ErrPushNotSaved) {
		t.Fatalf("a push that saved nothing returned %v, want ErrPushNotSaved. If it returned nil, "+
			"check that gosn-v2 still drops an SN|ItemsKey item that has an updated_at.", err)
	}
	if errors.Is(err, ErrDuplicated) {
		t.Errorf("no copy was made, but the error says duplicate: %v", err)
	}
	if got := string(rawObject(t, c, id)["text"]); got != `"version 1"` {
		t.Errorf("text = %s, want \"version 1\"", got)
	}
}

// pushRawAndVerify ends with the ok hook. The hook sees the note as the server
// holds it after the push, and its verdict decides the result. A saved push with
// no stray item still fails when the hook says that the end state is wrong.
func TestPushRawAndVerifyRunsTheVerifyHook(t *testing.T) {
	e, c := liveEngine(t)
	id, err := c.SeedRawNote(t, staleSeed)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	r, err := c.FetchRawOne(id)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := c.EncryptMutated(r, snclient.SetKey("text", "version 2"))
	if err != nil {
		t.Fatal(err)
	}

	var seen *snclient.NoteView
	ch := &Change{OpID: "edit:hook", Kind: "edit", NoteUUID: id}
	err = e.pushRawAndVerify(ch, items.EncryptedItems{enc}, func(g *snclient.NoteView) bool {
		seen = g
		return false
	})
	if !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("a hook that says no returned %v, want ErrVerifyFailed", err)
	}
	if seen == nil || seen.UUID != id || seen.Text != "version 2" {
		t.Errorf("the hook must see the pushed note as the server holds it after the push, got %+v", seen)
	}
	if got := e.led.LastState(ch.OpID); got != StateAcked {
		t.Errorf("ledger state = %q, want %q", got, StateAcked)
	}
}
