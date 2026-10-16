package writeengine_test

// Regression tests for the write-safety bugs found while building the engine.
// The first design scanned DuplicateOf and re-pushed a uuid on retry. Both
// failed against the real server. These tests need the Docker SN server
// (see ops/docker).

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/jonhadfield/gosn-v2/auth"
	"github.com/jonhadfield/gosn-v2/common"
	"github.com/jonhadfield/gosn-v2/items"
	"github.com/jonhadfield/gosn-v2/session"
	"github.com/smirnov-labs/standard-notes-mcp/internal/snclient"
	"github.com/smirnov-labs/standard-notes-mcp/internal/testsupport"
	we "github.com/smirnov-labs/standard-notes-mcp/internal/writeengine"
)

func copiesOf(t *testing.T, c *snclient.Client, title string) int {
	t.Helper()
	notes, _, err := c.Fetch()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, x := range notes {
		if x.Title == title {
			n++
		}
	}
	return n
}

// restartAt models a crash. The ledger's last word on ch is state, and the
// process comes back with a fresh engine over the same ledger file and the same
// server session.
func restartAt(t *testing.T, c *snclient.Client, path string, ch *we.Change, state string, maxWrites int) *we.Engine {
	t.Helper()
	l, err := we.OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Record(ch.OpID, ch.Kind, ch.NoteUUID, state); err != nil {
		t.Fatal(err)
	}
	l2, err := we.OpenLedger(path) // the restart
	if err != nil {
		t.Fatal(err)
	}
	return we.NewEngine(c, l2, maxWrites)
}

// A retry whose earlier attempt already reached the server must not mint a
// second note. Pushing a uuid the server holds is a sync_conflict, not an
// upsert: gosn-v2 answers it by re-pushing the note under a new uuid. The retry
// is a read, so it returns nil, ends in verified, and needs no write budget
// (the cap is 0 here).
func TestRetryAfterLostAckDoesNotDuplicate(t *testing.T) {
	for _, lastState := range []string{we.StateIntended, we.StateAcked} {
		t.Run(lastState, func(t *testing.T) {
			e, path := newEngineAt(t, 100)
			ch, _ := e.PlanCreateNote("Once", "body", nil)
			if err := e.Commit(ch); err != nil {
				t.Fatal(err)
			}
			// The server took the write, but the ledger's last word is lastState.
			e2 := restartAt(t, e.Client(), path, ch, lastState, 0)
			if err := e2.Commit(ch); err != nil {
				t.Fatalf("retry from ledger state %q: %v", lastState, err)
			}
			if n := copiesOf(t, e.Client(), "Once"); n != 1 {
				t.Fatalf("retry from ledger state %q minted a duplicate: %d copies of 'Once'", lastState, n)
			}
			states := ledgerStates(t, path, ch.OpID)
			if last := states[len(states)-1]; last != we.StateVerified {
				t.Fatalf("a landed retry must end verified, ledger says %v", states)
			}
		})
	}
}

// A retry whose earlier attempt never reached the server pushes, once. The
// retry keeps the ledger state it found: no second "intended".
func TestRetryOfNeverLandedChangePushes(t *testing.T) {
	e, path := newEngineAt(t, 100)
	ch, _ := e.PlanCreateNote("Late", "body", nil)
	e2 := restartAt(t, e.Client(), path, ch, we.StateIntended, 100) // died before the push
	if err := e2.Commit(ch); err != nil {
		t.Fatal(err)
	}
	if n := copiesOf(t, e.Client(), "Late"); n != 1 {
		t.Fatalf("want 1 copy of 'Late', got %d", n)
	}
	want := []string{we.StateIntended, we.StateAcked, we.StateVerified}
	if got := ledgerStates(t, path, ch.OpID); !slices.Equal(got, want) {
		t.Fatalf("ledger states = %v, want %v", got, want)
	}
}

// A retry that finds the note changed by someone else must not push over it.
// The push would be a sync_conflict, and the edit must survive.
func TestRetryRefusesWhenTargetDiverged(t *testing.T) {
	e, path := newEngineAt(t, 100)
	ch, _ := e.PlanCreateNote("Once", "body", nil)
	if err := e.Commit(ch); err != nil {
		t.Fatal(err)
	}
	nv, err := e.Client().FetchOne(ch.NoteUUID)
	if err != nil || nv == nil {
		t.Fatalf("fetch: %v", err)
	}
	if err := e.Client().ApplyTextEdit(nv, "edited elsewhere"); err != nil {
		t.Fatal(err)
	}

	e2 := restartAt(t, e.Client(), path, ch, we.StateAcked, 100)
	if err := e2.Commit(ch); !errors.Is(err, we.ErrVerifyFailed) {
		t.Fatalf("want ErrVerifyFailed, got %v", err)
	}
	if n := copiesOf(t, e.Client(), "Once"); n != 1 {
		t.Fatalf("the refused retry still left %d copies of 'Once'", n)
	}
	got, err := e.Client().FetchOne(ch.NoteUUID)
	if err != nil || got == nil || got.Text != "edited elsewhere" {
		t.Fatalf("the edit was lost or overwritten: %+v (err=%v)", got, err)
	}
}

func plantLegacyDuplicateOf(t *testing.T, email, pw, origUUID string) {
	t.Helper()
	hc := common.NewHTTPClient()
	so, err := auth.SignIn(auth.SignInInput{HTTPClient: hc, Email: email, Password: pw, APIServer: testsupport.TestServer})
	if err != nil {
		t.Fatal(err)
	}
	s := &session.Session{HTTPClient: hc, Server: testsupport.TestServer, FilesServerUrl: so.Session.FilesServerUrl,
		MasterKey: so.Session.MasterKey, KeyParams: so.KeyParams, AccessToken: so.Session.AccessToken,
		RefreshToken: so.Session.RefreshToken, AccessExpiration: so.Session.AccessExpiration,
		RefreshExpiration: so.Session.RefreshExpiration, AccessTokenCookie: so.Session.AccessTokenCookie,
		RefreshTokenCookie: so.Session.RefreshTokenCookie, PasswordNonce: so.Session.PasswordNonce}
	if _, err := items.Sync(items.SyncInput{Session: s}); err != nil { // adopt the items key
		t.Fatal(err)
	}
	legacy, _ := items.NewNote("Legacy conflicted copy", "old", nil)
	legacy.Content.SetUpdateTime(time.Now().UTC())
	its := items.Items{&legacy}
	enc, err := its.Encrypt(s, s.DefaultItemsKey)
	if err != nil {
		t.Fatal(err)
	}
	enc[0].DuplicateOf = &origUUID // what an official-app conflict copy looks like on the server
	if _, err := items.Sync(items.SyncInput{Session: s, Items: enc}); err != nil {
		t.Fatal(err)
	}
}

// An account that already holds an item with duplicate_of set (every official
// app conflict copy) must not make unrelated, healthy writes fail. Sync returns
// the whole account, so a DuplicateOf scan of its output fires on old copies.
func TestPreexistingDuplicateOfDoesNotFailHealthyWrites(t *testing.T) {
	email, pw := testsupport.NewAccount(t)
	c, err := snclient.SignIn(snclient.Config{Server: testsupport.TestServer}, email, pw, func(string) (string, error) { return "", nil })
	if err != nil {
		t.Fatal(err)
	}
	l, _ := we.OpenLedger(filepath.Join(t.TempDir(), "l.jsonl"))
	e := we.NewEngine(c, l, 100)

	first, _ := e.PlanCreateNote("First", "x", nil)
	if err := e.Commit(first); err != nil { // also bootstraps the items key
		t.Fatal(err)
	}
	plantLegacyDuplicateOf(t, email, pw, first.NoteUUID)

	ch, _ := e.PlanCreateNote("Healthy", "fine", nil)
	if err := e.Commit(ch); err != nil {
		t.Fatalf("healthy create failed only because the vault already holds a duplicate_of item: %v", err)
	}
}

// One writer, used sequentially: this is all Plan 1 and the chat-review loop
// need. Writes interleave with reads through Client(). Replays are no-ops, in
// the same process and after a restart, and they need no budget. The vault ends
// with exactly the notes that were planned. Run it with -race.
func TestSequentialSingleWriterSession(t *testing.T) {
	const n = 5
	e, path := newEngineAt(t, 100)
	var changes []*we.Change
	for i := 0; i < n; i++ {
		ch, err := e.PlanCreateNote(fmt.Sprintf("Seq-%d", i), fmt.Sprintf("body %d", i), nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := e.Commit(ch); err != nil {
			t.Fatalf("commit %d: %v", i, err)
		}
		changes = append(changes, ch)
		if _, _, err := e.Client().Fetch(); err != nil { // a read between writes
			t.Fatal(err)
		}
	}
	for i, ch := range changes {
		if err := e.Commit(ch); err != nil {
			t.Fatalf("replay %d: %v", i, err)
		}
	}
	l, err := we.OpenLedger(path) // restart: the ledger remembers
	if err != nil {
		t.Fatal(err)
	}
	e2 := we.NewEngine(e.Client(), l, 0) // cap 0: a replay must not need budget
	for i, ch := range changes {
		if err := e2.Commit(ch); err != nil {
			t.Fatalf("replay after restart %d: %v", i, err)
		}
	}

	notes, _, err := e.Client().Fetch()
	if err != nil {
		t.Fatal(err)
	}
	titles := map[string]int{}
	for _, x := range notes {
		titles[x.Title]++
	}
	if len(notes) != n {
		t.Fatalf("want %d notes, got %d: %v", n, len(notes), titles)
	}
	for i := 0; i < n; i++ {
		if c := titles[fmt.Sprintf("Seq-%d", i)]; c != 1 {
			t.Fatalf("Seq-%d appears %d times, want 1", i, c)
		}
	}
}

// KNOWN OPEN, deferred to Plan 2. Engine.Client() is public, but only Commit is
// serialized. A read that overlaps a Commit races on gosn-v2's *session.Session,
// which every items.Sync call mutates. The fix is a mutex inside snclient.
// Remove the Skip when that lands and run with -race. Sequential use is
// race-clean: see TestSequentialSingleWriterSession.
func TestClientReadDuringCommitIsRaceFree(t *testing.T) {
	t.Skip("known open: Client() reads race with Commit on gosn-v2's session; needs a mutex inside snclient (Plan 2)")
	e := newEngine(t)
	seed, _ := e.PlanCreateNote("seed", "s", nil)
	if err := e.Commit(seed); err != nil {
		t.Fatal(err)
	}
	ch, _ := e.PlanCreateNote("racy", "r", nil)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 3; i++ {
			_, _, _ = e.Client().Fetch() // what a read-only MCP tool would do
		}
	}()
	if err := e.Commit(ch); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
}
