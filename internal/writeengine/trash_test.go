package writeengine_test

import (
	"slices"
	"testing"

	we "github.com/smirnov-labs/standard-notes-mcp/internal/writeengine"
)

func TestTrashSetsReversibleFlag(t *testing.T) {
	e := newEngine(t)
	ch, _ := e.PlanCreateNote("ToTrash", "x", nil)
	if err := e.Commit(ch); err != nil {
		t.Fatal(err)
	}

	tr, err := e.PlanTrashNote(ch.NoteUUID)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Commit(tr); err != nil {
		t.Fatal(err)
	}

	n, _ := e.Client().FetchOne(ch.NoteUUID)
	if n == nil {
		t.Fatal("trashed note must still exist (reversible)")
	}
	if !n.Trashed {
		t.Fatal("note not marked trashed")
	}
}

// requireTrashedOnce checks three facts: the note exists, it is trashed, and no
// other note has its title. The title count catches a copy, because a push from
// a stale view mints one.
func requireTrashedOnce(t *testing.T, e *we.Engine, uuid, title string) {
	t.Helper()
	n, err := e.Client().FetchOne(uuid)
	if err != nil {
		t.Fatal(err)
	}
	if n == nil || !n.Trashed {
		t.Fatalf("note %s should exist and be trashed, got %+v", uuid, n)
	}
	if c := copiesOf(t, e.Client(), title); c != 1 {
		t.Fatalf("want 1 note titled %q, got %d", title, c)
	}
}

// Each PlanTrashNote is its own intent, so each puts its own nonce in the OpID. A
// verified OpID is a no-op for good. Suppose two trash plans for one note share
// an OpID. The second Commit finds the first one's verified entry, returns nil,
// and pushes nothing. The user trashes a note, restores it in the official app,
// and trashes it again. Every step reports success, but the note stays live.
func TestRetrashAfterRestoreTrashesAgain(t *testing.T) {
	e := newEngine(t)
	note, _ := e.PlanCreateNote("Restored", "x", nil)
	if err := e.Commit(note); err != nil {
		t.Fatal(err)
	}

	first, err := e.PlanTrashNote(note.NoteUUID)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Commit(first); err != nil {
		t.Fatal(err)
	}
	requireTrashedOnce(t, e, note.NoteUUID, "Restored") // premise: the first trash landed

	// An official app restores the note: the trashed flag goes back to false.
	c := e.Client()
	nv, err := c.FetchOne(note.NoteUUID)
	if err != nil || nv == nil {
		t.Fatalf("fetch before the restore: note=%v err=%v", nv, err)
	}
	if err := c.SetTrashed(nv, false); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Push(c.Raw(nv)); err != nil {
		t.Fatal(err)
	}
	if back, err := c.FetchOne(note.NoteUUID); err != nil || back == nil || back.Trashed {
		t.Fatalf("premise: the simulated restore did not untrash the note: %+v (err=%v)", back, err)
	}

	// A fresh plan for the same note is a new intent. It must trash the note again.
	second, err := e.PlanTrashNote(note.NoteUUID)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Commit(second); err != nil {
		t.Fatal(err)
	}
	requireTrashedOnce(t, e, note.NoteUUID, "Restored")
}

// apply must read the note again right before it pushes. A plan can wait, and the
// server timestamp can move in that time (another device saves the note). A push
// with the stale plan-time timestamp is a sync_conflict. gosn-v2 answers it by
// minting a copy of the note under a new uuid.
func TestTrashReadsTheNoteFreshBeforePushing(t *testing.T) {
	e := newEngine(t)
	note, _ := e.PlanCreateNote("Bumped", "v1", nil)
	if err := e.Commit(note); err != nil {
		t.Fatal(err)
	}
	ch, err := e.PlanTrashNote(note.NoteUUID) // reads the note at its current timestamp
	if err != nil {
		t.Fatal(err)
	}

	// Before Commit, another writer saves the note, so its server timestamp moves on.
	c := e.Client()
	nv, err := c.FetchOne(note.NoteUUID)
	if err != nil || nv == nil {
		t.Fatalf("fetch before the bump: note=%v err=%v", nv, err)
	}
	if err := c.ApplyTextEdit(nv, "bumped"); err != nil {
		t.Fatal(err)
	}

	if err := e.Commit(ch); err != nil {
		t.Fatalf("trash after the server timestamp moved: %v", err)
	}
	requireTrashedOnce(t, e, note.NoteUUID, "Bumped") // trashed, and no conflict copy
	got, err := c.FetchOne(note.NoteUUID)
	if err != nil || got == nil || got.Text != "bumped" {
		t.Fatalf("the trash lost the other writer's edit: %+v (err=%v)", got, err)
	}
}

// Commit treats a trash as a retry when the ledger holds intended or acked for
// its OpID. reconcile reads the note live and decides the retry.
// If the note is already trashed, the earlier push landed, so the retry must not
// push. If the note is not trashed, the earlier push did not land, so the retry
// pushes once.
//
// A second PlanTrashNote is not a retry. It has a new nonce, so Commit sees a
// first try and never calls reconcile.
func TestTrashRetryIsDecidedByLiveRead(t *testing.T) {
	for _, lastState := range []string{we.StateIntended, we.StateAcked} {
		t.Run("landed, ledger says "+lastState, func(t *testing.T) {
			e, path := newEngineAt(t, 100)
			note, _ := e.PlanCreateNote("ToTrash", "x", nil)
			if err := e.Commit(note); err != nil {
				t.Fatal(err)
			}
			tr, err := e.PlanTrashNote(note.NoteUUID)
			if err != nil {
				t.Fatal(err)
			}
			if err := e.Commit(tr); err != nil { // the server takes the write
				t.Fatal(err)
			}

			// Cap 0: only a read can succeed, so a nil error proves the retry did not push.
			e2 := restartAt(t, e.Client(), path, tr, lastState, 0)
			if err := e2.Commit(tr); err != nil {
				t.Fatalf("retry of a trash that already landed: %v", err)
			}
			requireTrashedOnce(t, e, note.NoteUUID, "ToTrash")
			states := ledgerStates(t, path, tr.OpID)
			if last := states[len(states)-1]; last != we.StateVerified {
				t.Fatalf("a landed retry must end verified, ledger says %v", states)
			}
		})
	}

	t.Run("never landed", func(t *testing.T) {
		e, path := newEngineAt(t, 100)
		note, _ := e.PlanCreateNote("ToTrash", "x", nil)
		if err := e.Commit(note); err != nil {
			t.Fatal(err)
		}
		tr, err := e.PlanTrashNote(note.NoteUUID) // planned, then the process died before the push
		if err != nil {
			t.Fatal(err)
		}

		e2 := restartAt(t, e.Client(), path, tr, we.StateIntended, 100)
		if err := e2.Commit(tr); err != nil {
			t.Fatalf("retry of a trash that never landed: %v", err)
		}
		requireTrashedOnce(t, e, note.NoteUUID, "ToTrash")
		want := []string{we.StateIntended, we.StateAcked, we.StateVerified}
		if got := ledgerStates(t, path, tr.OpID); !slices.Equal(got, want) {
			t.Fatalf("ledger states = %v, want %v", got, want)
		}
	})
}
