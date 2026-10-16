package writeengine

// Regression tests for the write-safety bugs found while building the engine.
// They live in the package so they can bind their own apply and reconcile funcs.
// Tests that name a server need the Docker SN server (see ops/docker). The rest
// run offline.

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jonhadfield/gosn-v2/items"
	"github.com/smirnov-labs/standard-notes-mcp/internal/snclient"
	"github.com/smirnov-labs/standard-notes-mcp/internal/testsupport"
)

func offlineEngine(t *testing.T, maxWrites int) *Engine {
	t.Helper()
	l, err := OpenLedger(filepath.Join(t.TempDir(), "l.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return NewEngine(nil, l, maxWrites) // nil client: these applies never touch the network
}

func liveEngine(t *testing.T) (*Engine, *snclient.Client) {
	t.Helper()
	email, pw := testsupport.NewAccount(t)
	c, err := snclient.SignIn(snclient.Config{Server: testsupport.TestServer}, email, pw, func(string) (string, error) { return "", nil })
	if err != nil {
		t.Fatal(err)
	}
	l, err := OpenLedger(filepath.Join(t.TempDir(), "l.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return NewEngine(c, l, 100), c
}

// A write that LANDS but then fails a post-push check must still use up the
// cap. Otherwise a systematic verify failure writes without bound.
func TestCapCountsWritesThatLandButFailVerification(t *testing.T) {
	e := offlineEngine(t, 2)
	landed := 0
	for i := 0; i < 5; i++ {
		id := fmt.Sprintf("op%d", i)
		_ = e.Commit(&Change{OpID: id, Kind: "create", NoteUUID: id, apply: func() error {
			landed++               // the push reached the server...
			return ErrVerifyFailed // ...then the read-after-write check failed
		}})
	}
	if landed > 2 {
		t.Fatalf("cap=2 but %d writes reached the server", landed)
	}
}

// ErrDuplicated says "halting". The engine must really stop writing.
func TestDuplicateHaltsTheEngine(t *testing.T) {
	e := offlineEngine(t, 10)
	if err := e.Commit(&Change{OpID: "a", Kind: "create", NoteUUID: "a", apply: func() error { return ErrDuplicated }}); !errors.Is(err, ErrDuplicated) {
		t.Fatalf("want ErrDuplicated, got %v", err)
	}
	pushed := false
	err := e.Commit(&Change{OpID: "b", Kind: "create", NoteUUID: "b", apply: func() error { pushed = true; return nil }})
	if pushed || !errors.Is(err, ErrKilled) {
		t.Fatalf("engine kept writing after a duplicate (pushed=%v, err=%v)", pushed, err)
	}
}

// Kill is the emergency stop. It must return at once even if a write is hung on
// the network, not wait for that write to finish.
func TestKillDoesNotBlockBehindInflightWrite(t *testing.T) {
	e := offlineEngine(t, 10)
	started, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- e.Commit(&Change{OpID: "x", Kind: "create", NoteUUID: "x", apply: func() error {
			close(started)
			<-release // a push stuck on the network
			return nil
		}})
	}()
	<-started
	killed := make(chan struct{})
	go func() { e.Kill(); close(killed) }()
	select {
	case <-killed:
	case <-time.After(500 * time.Millisecond):
		close(release)
		<-done
		t.Fatal("Kill() blocked behind an in-flight write")
	}
	close(release)
	<-done
}

// pushAndVerify must honor Kill before it touches the client. The engine has a
// nil client here, so a Kill check placed after the first read would panic.
func TestPushAndVerifyHonorsKill(t *testing.T) {
	e := offlineEngine(t, 10)
	e.Kill()
	err := e.pushAndVerify(&Change{OpID: "k", Kind: "create", NoteUUID: "k"}, nil, func(*snclient.NoteView) bool { return true })
	if !errors.Is(err, ErrKilled) {
		t.Fatalf("want ErrKilled, got %v", err)
	}
}

// Commit's side of the reconcile contract (see Change.reconcile). Each row is an
// op whose earlier attempt got an ack, so Commit treats it as a retry.
func TestCommitHonorsReconcileVerdicts(t *testing.T) {
	errNet := errors.New("network down")
	cases := []struct {
		name        string
		cap         int
		landed      bool
		recErr      error
		wantErr     error // matched with errors.Is; nil means Commit succeeds
		wantApply   bool
		wantState   string
		wantWritten int
	}{
		{"landed: verified with no push and no budget", 0, true, nil, nil, false, StateVerified, 0},
		{"absent: push and count the attempt", 1, false, nil, nil, true, StateVerified, 1},
		{"absent but the cap is spent: no push", 0, false, nil, ErrCapReached, false, StateAcked, 0},
		{"exists but differs: refuse, no push", 1, false, ErrVerifyFailed, ErrVerifyFailed, false, StateAcked, 0},
		{"reconcile read fails: return it, no push", 1, false, errNet, errNet, false, StateAcked, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := offlineEngine(t, tc.cap)
			applied := false
			ch := &Change{OpID: "op", Kind: "create", NoteUUID: "u",
				reconcile: func() (bool, error) { return tc.landed, tc.recErr },
				apply:     func() error { applied = true; return nil }}
			if err := e.led.Record(ch.OpID, ch.Kind, ch.NoteUUID, StateAcked); err != nil {
				t.Fatal(err)
			}
			err := e.Commit(ch)
			if (tc.wantErr == nil && err != nil) || (tc.wantErr != nil && !errors.Is(err, tc.wantErr)) {
				t.Fatalf("Commit err = %v, want %v", err, tc.wantErr)
			}
			if applied != tc.wantApply {
				t.Fatalf("apply ran = %v, want %v", applied, tc.wantApply)
			}
			if got := e.led.LastState(ch.OpID); got != tc.wantState {
				t.Fatalf("ledger state = %q, want %q", got, tc.wantState)
			}
			if e.written != tc.wantWritten {
				t.Fatalf("written = %d, want %d", e.written, tc.wantWritten)
			}
		})
	}
}

// A change with no reconcile cannot be retried, because Commit cannot tell
// whether the earlier attempt landed and a blind push can mint a copy. Its
// first attempt is not affected.
func TestRetryWithoutReconcileIsRefused(t *testing.T) {
	e := offlineEngine(t, 10)
	pushed := 0
	apply := func() error { pushed++; return nil }

	first := &Change{OpID: "first", Kind: "trash", NoteUUID: "n1", apply: apply}
	if err := e.Commit(first); err != nil || pushed != 1 {
		t.Fatalf("first attempt without a reconcile must work: err=%v pushed=%d", err, pushed)
	}

	retry := &Change{OpID: "retry", Kind: "trash", NoteUUID: "n2", apply: apply}
	if err := e.led.Record(retry.OpID, retry.Kind, retry.NoteUUID, StateIntended); err != nil {
		t.Fatal(err)
	}
	if err := e.Commit(retry); !errors.Is(err, ErrVerifyFailed) || pushed != 1 {
		t.Fatalf("retry without a reconcile must be refused: err=%v pushed=%d", err, pushed)
	}
}

// When gosn-v2 DOES mint a duplicate, pushAndVerify must notice and name it.
// gosn-v2 never sets DuplicateOf on the copy, and Sync drops the copy from
// SavedItems, so only a before/after snapshot sees it.
func TestPushAndVerifyDetectsADuplicateGosnMints(t *testing.T) {
	e, c := liveEngine(t)
	orig, _ := e.PlanCreateNote("Orig", "body", nil)
	if err := e.Commit(orig); err != nil {
		t.Fatal(err)
	}

	// Push the SAME uuid again with no server timestamp. The server answers
	// sync_conflict, and gosn-v2 re-pushes the note under a fresh uuid.
	n, _ := items.NewNote("Orig", "body", nil)
	n.SetUUID(orig.NoteUUID)
	n.Content.SetUpdateTime(time.Now().UTC())
	probe := &Change{OpID: "probe", Kind: "create", NoteUUID: orig.NoteUUID}
	err := e.pushAndVerify(probe, items.Items{&n}, func(g *snclient.NoteView) bool {
		return g != nil && g.Title == "Orig" && g.Text == "body"
	})

	notes, _, _ := c.Fetch()
	copies, copyID := 0, ""
	for _, x := range notes {
		if x.Title == "Orig" {
			copies++
			if x.UUID != orig.NoteUUID {
				copyID = x.UUID
			}
		}
	}
	if copies != 2 {
		t.Fatalf("premise failed: re-pushing an existing uuid no longer mints a copy (copies=%d). "+
			"gosn-v2 or the server changed. Re-check the duplicate detection described on Engine.", copies)
	}
	if !errors.Is(err, ErrDuplicated) {
		t.Fatalf("a duplicate was minted (2 copies of 'Orig') but pushAndVerify returned %v, want ErrDuplicated", err)
	}
	if !strings.Contains(err.Error(), copyID) {
		t.Fatalf("the error must name the stray copy %s, got: %v", copyID, err)
	}
}

// A duplicate TAG must halt too. The hot tag is the riskiest write, and a
// snapshot of notes alone would miss a copy of it.
func TestPushAndVerifyDetectsADuplicateTag(t *testing.T) {
	e, c := liveEngine(t)
	tag, err := items.NewTag("hot", nil)
	if err != nil {
		t.Fatal(err)
	}
	probe := &Change{OpID: "tag-probe", Kind: "tag", TagUUID: tag.GetUUID()}
	anything := func(*snclient.NoteView) bool { return true } // a tag change has no note to check

	// The first push creates the tag. The change names its uuid, so it is not a stray.
	if err := e.pushAndVerify(probe, items.Items{&tag}, anything); err != nil {
		t.Fatalf("creating the tag the change names: %v", err)
	}
	// The same tag again has no server timestamp: sync_conflict, and gosn-v2 mints a copy.
	err = e.pushAndVerify(probe, items.Items{&tag}, anything)

	_, tags, _ := c.Fetch()
	copies, copyID := 0, ""
	for _, x := range tags {
		if x.Title == "hot" {
			copies++
			if x.UUID != tag.GetUUID() {
				copyID = x.UUID
			}
		}
	}
	if copies != 2 {
		t.Fatalf("premise failed: re-pushing an existing tag no longer mints a copy (copies=%d)", copies)
	}
	if !errors.Is(err, ErrDuplicated) {
		t.Fatalf("a duplicate tag was minted but pushAndVerify returned %v, want ErrDuplicated", err)
	}
	if !strings.Contains(err.Error(), copyID) {
		t.Fatalf("the error must name the stray tag %s, got: %v", copyID, err)
	}
}
