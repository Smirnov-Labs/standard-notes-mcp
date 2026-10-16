package writeengine_test

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/smirnov-labs/standard-notes-mcp/internal/snclient"
	"github.com/smirnov-labs/standard-notes-mcp/internal/testsupport"
	we "github.com/smirnov-labs/standard-notes-mcp/internal/writeengine"
)

// newEngine is reused by Tasks 9-11 tests (trash, merge, tags). Keep it here.
func newEngine(t *testing.T) *we.Engine {
	email, pw := testsupport.NewAccount(t)
	c, err := snclient.SignIn(snclient.Config{Server: testsupport.TestServer}, email, pw, func(string) (string, error) { return "", nil })
	if err != nil {
		t.Fatal(err)
	}
	l, err := we.OpenLedger(filepath.Join(t.TempDir(), "l.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return we.NewEngine(c, l, 100)
}

func TestDryRunMutatesNothing(t *testing.T) {
	e := newEngine(t)
	ch, err := e.PlanCreateNote("Idea", "body", nil)
	if err != nil {
		t.Fatal(err)
	}
	if ch.NoteUUID == "" {
		t.Fatal("plan should pre-assign a uuid")
	}
	if got, _ := e.Client().FetchOne(ch.NoteUUID); got != nil {
		t.Fatal("dry-run leaked a write")
	}
}

func TestCreateIsIdempotent(t *testing.T) {
	e := newEngine(t)
	ch, _ := e.PlanCreateNote("Once", "body", nil)
	if err := e.Commit(ch); err != nil {
		t.Fatal(err)
	}
	if err := e.Commit(ch); err != nil {
		t.Fatalf("replay should be a no-op, got %v", err)
	}
	notes, _, _ := e.Client().Fetch()
	n := 0
	for _, x := range notes {
		if x.Title == "Once" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("idempotency broken: %d copies", n)
	}
}

// newEngineAt is newEngine with a chosen write cap. It also returns the ledger
// path so a test can read the ledger file.
func newEngineAt(t *testing.T, maxWrites int) (*we.Engine, string) {
	t.Helper()
	email, pw := testsupport.NewAccount(t)
	c, err := snclient.SignIn(snclient.Config{Server: testsupport.TestServer}, email, pw, func(string) (string, error) { return "", nil })
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "l.jsonl")
	l, err := we.OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	return we.NewEngine(c, l, maxWrites), path
}

// ledgerStates returns, in file order, every state recorded for opID.
func ledgerStates(t *testing.T, path, opID string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var states []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var rec struct{ OpID, Kind, UUID, State string }
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatalf("bad ledger line %q: %v", sc.Text(), err)
		}
		if rec.OpID == opID {
			states = append(states, rec.State)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return states
}

func TestKillStopsWrites(t *testing.T) {
	e := newEngine(t)
	ch, _ := e.PlanCreateNote("Never", "body", nil)
	e.Kill()
	if err := e.Commit(ch); !errors.Is(err, we.ErrKilled) {
		t.Fatalf("want ErrKilled after Kill, got %v", err)
	}
	if got, _ := e.Client().FetchOne(ch.NoteUUID); got != nil {
		t.Fatal("a killed engine still wrote")
	}
}

func TestMaxWritesCapStopsNewWrites(t *testing.T) {
	e, _ := newEngineAt(t, 2)
	var done []*we.Change
	for _, title := range []string{"One", "Two"} {
		ch, _ := e.PlanCreateNote(title, "b", nil)
		if err := e.Commit(ch); err != nil {
			t.Fatalf("%s: %v", title, err)
		}
		done = append(done, ch)
	}
	third, _ := e.PlanCreateNote("Three", "b", nil)
	if err := e.Commit(third); !errors.Is(err, we.ErrCapReached) {
		t.Fatalf("want ErrCapReached on the 3rd write, got %v", err)
	}
	if got, _ := e.Client().FetchOne(third.NoteUUID); got != nil {
		t.Fatal("the write past the cap still reached the server")
	}
	// A replay of a verified change is a no-op, so it needs no budget.
	if err := e.Commit(done[0]); err != nil {
		t.Fatalf("replay at the cap should be a no-op, got %v", err)
	}
}

// Plan records nothing. Commit records intended (before the push), then acked,
// then verified, in that order.
func TestCommitLedgersIntendedAckedVerified(t *testing.T) {
	e, path := newEngineAt(t, 100)
	ch, _ := e.PlanCreateNote("Ledgered", "body", nil)
	if got := ledgerStates(t, path, ch.OpID); len(got) != 0 {
		t.Fatalf("Plan must not touch the ledger, got %v", got)
	}
	if err := e.Commit(ch); err != nil {
		t.Fatal(err)
	}
	want := []string{we.StateIntended, we.StateAcked, we.StateVerified}
	if got := ledgerStates(t, path, ch.OpID); !slices.Equal(got, want) {
		t.Fatalf("ledger states = %v, want %v", got, want)
	}
}
