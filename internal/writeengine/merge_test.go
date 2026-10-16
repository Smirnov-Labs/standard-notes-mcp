package writeengine_test

// A merge is additive. It creates one consolidated note and never touches a
// source. The coverage gate runs before anything is written, so a lossy
// synthesis is rejected with the account unchanged. These tests need the Docker
// SN server (see ops/docker).

import (
	"errors"
	"slices"
	"sort"
	"strings"
	"testing"

	we "github.com/smirnov-labs/standard-notes-mcp/internal/writeengine"
)

// createNote plans and commits a note and returns its uuid. It fails the test on
// any error, so a broken fixture cannot pass for a merge failure.
func createNote(t *testing.T, e *we.Engine, title, text string) string {
	t.Helper()
	ch, err := e.PlanCreateNote(title, text, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Commit(ch); err != nil {
		t.Fatal(err)
	}
	return ch.NoteUUID
}

// noteCount reads the account live and returns how many notes it holds.
func noteCount(t *testing.T, e *we.Engine) int {
	t.Helper()
	notes, _, err := e.Client().Fetch()
	if err != nil {
		t.Fatal(err)
	}
	return len(notes)
}

// requireIntact fails unless the note is on the server, not trashed, and still
// has exactly its original text.
func requireIntact(t *testing.T, e *we.Engine, id, text string) {
	t.Helper()
	n, err := e.Client().FetchOne(id)
	if err != nil {
		t.Fatal(err)
	}
	if n == nil || n.Trashed || n.Text != text {
		t.Fatalf("source %s was touched: want an untrashed note with text %q, got %+v", id, text, n)
	}
}

func TestMergeRejectsLossySynthesis(t *testing.T) {
	e := newEngine(t)
	a := createNote(t, e, "A", "alpha unique-token-A")
	b := createNote(t, e, "B", "beta unique-token-B")
	before := noteCount(t, e)

	// The synthesis drops token-B, so it must be rejected before anything is written.
	ch, err := e.PlanMerge([]string{a, b}, "AB", "only alpha unique-token-A")
	if !errors.Is(err, we.ErrCoverage) {
		t.Fatalf("want ErrCoverage, got %v", err)
	}
	if ch != nil {
		t.Fatalf("a rejected merge must not hand back a Change to commit, got %+v", ch)
	}

	// Nothing reached the server: no new note, both sources as they were.
	if after := noteCount(t, e); after != before {
		t.Fatalf("a rejected merge changed the note count: %d -> %d", before, after)
	}
	requireIntact(t, e, a, "alpha unique-token-A")
	requireIntact(t, e, b, "beta unique-token-B")
}

func TestMergeAppendixPreservesSources(t *testing.T) {
	e, ledgerPath := newEngineAt(t, 100)
	a := createNote(t, e, "A", "alpha unique-token-A")
	b := createNote(t, e, "B", "beta unique-token-B")

	ch, err := e.PlanMerge([]string{a, b}, "AB",
		"Summary.\n\n---\nalpha unique-token-A\n\n---\nbeta unique-token-B") // appendix carries both verbatim
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Commit(ch); err != nil {
		t.Fatal(err)
	}

	// Neither source was deleted, trashed, or edited.
	requireIntact(t, e, a, "alpha unique-token-A")
	requireIntact(t, e, b, "beta unique-token-B")

	// The consolidated note exists and carries both source bodies verbatim.
	cn, err := e.Client().FetchOne(ch.NoteUUID)
	if err != nil {
		t.Fatal(err)
	}
	if cn == nil {
		t.Fatal("consolidated note missing")
	}
	if cn.Title != "AB" {
		t.Fatalf("consolidated title = %q, want %q", cn.Title, "AB")
	}
	for _, body := range []string{"alpha unique-token-A", "beta unique-token-B"} {
		if !strings.Contains(cn.Text, body) {
			t.Fatalf("consolidated note lost source body %q: %q", body, cn.Text)
		}
	}

	// The merge is its own ledger intent. PlanMerge relabels the Change after
	// PlanCreateNote built it, so the ledger must hold merge:<uuid> and nothing
	// under create:<uuid>.
	if ch.Kind != "merge" || !strings.HasPrefix(ch.OpID, "merge:") {
		t.Fatalf("want Kind merge and an OpID that starts with merge:, got %q / %q", ch.Kind, ch.OpID)
	}
	want := []string{we.StateIntended, we.StateAcked, we.StateVerified}
	if got := ledgerStates(t, ledgerPath, ch.OpID); !slices.Equal(got, want) {
		t.Fatalf("ledger states for %s = %v, want %v", ch.OpID, got, want)
	}
	if got := ledgerStates(t, ledgerPath, "create:"+ch.NoteUUID); len(got) != 0 {
		t.Fatalf("the merge also left create: ledger entries: %v", got)
	}

	// The merge inherits create's idempotency: a replay is a no-op, not a second note.
	if err := e.Commit(ch); err != nil {
		t.Fatalf("replay should be a no-op, got %v", err)
	}
	if n := copiesOf(t, e.Client(), "AB"); n != 1 {
		t.Fatalf("replay left %d consolidated notes, want 1", n)
	}
}

// The gate must check every source, wherever it sits in the list. Dropping the
// first, the middle, or the last of three is rejected. Carrying all three
// verbatim is accepted, and all three sources survive the commit.
func TestMergeChecksEverySource(t *testing.T) {
	e := newEngine(t)
	titles := []string{"A", "B", "C"}
	bodies := []string{"alpha unique-token-A", "beta unique-token-B", "gamma unique-token-C"}
	ids := make([]string, len(bodies))
	for i := range bodies {
		ids[i] = createNote(t, e, titles[i], bodies[i])
	}
	before := noteCount(t, e)

	for drop := range bodies {
		kept := slices.Delete(slices.Clone(bodies), drop, drop+1)
		ch, err := e.PlanMerge(ids, "ABC", "Summary.\n\n---\n"+strings.Join(kept, "\n\n---\n"))
		if !errors.Is(err, we.ErrCoverage) || ch != nil {
			t.Fatalf("dropping source %d (%q): want ErrCoverage and no Change, got %v / %+v", drop, bodies[drop], err, ch)
		}
	}
	if after := noteCount(t, e); after != before {
		t.Fatalf("rejected merges changed the note count: %d -> %d", before, after)
	}

	ch, err := e.PlanMerge(ids, "ABC", "Summary.\n\n---\n"+strings.Join(bodies, "\n\n---\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Commit(ch); err != nil {
		t.Fatal(err)
	}
	cn, err := e.Client().FetchOne(ch.NoteUUID)
	if err != nil || cn == nil {
		t.Fatalf("consolidated note missing: %v", err)
	}
	for i, body := range bodies {
		if !strings.Contains(cn.Text, body) {
			t.Fatalf("consolidated note lost source %d body %q", i, body)
		}
		requireIntact(t, e, ids[i], body)
	}
	if after := noteCount(t, e); after != before+1 {
		t.Fatalf("a merge should add exactly the consolidated note: %d -> %d", before, after)
	}
}

// A merge only creates the consolidated note, and the caller trashes the sources
// afterwards with PlanTrashNote. That trash goes through the surgical path, so a
// source keeps every field it has. Only its trash flag and client_updated_at change.
func TestTrashingMergeSourcesKeepsTheirMetadata(t *testing.T) {
	e := newEngine(t)
	rich := seedRaw(t, e, richContent) // its text is "old body"
	plain := createNote(t, e, "B", "beta unique-token-B")

	merge, err := e.PlanMerge([]string{rich, plain}, "Merged",
		"Summary.\n\n---\nold body\n\n---\nbeta unique-token-B")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Commit(merge); err != nil {
		t.Fatal(err)
	}
	if got := rawContent(t, e, rich); got != richContent {
		t.Fatalf("the merge touched a source:\n%s", got)
	}

	for _, id := range []string{rich, plain} {
		tr, err := e.PlanTrashNote(id)
		if err != nil {
			t.Fatal(err)
		}
		if err := e.Commit(tr); err != nil {
			t.Fatal(err)
		}
	}

	// Both sources are in the trash, not deleted. The consolidated note is live.
	requireTrashedOnce(t, e, rich, "rich")
	requireTrashedOnce(t, e, plain, "B")
	cn := viewOf(t, e, merge.NoteUUID)
	if cn.Trashed || cn.Title != "Merged" {
		t.Fatalf("consolidated note: %+v, want a live note titled Merged", cn)
	}
	if n := noteCount(t, e); n != 3 {
		t.Fatalf("want 3 notes (two sources and the merge), got %d", n)
	}

	// The rich source kept every field. The trash flag and client_updated_at are the only changes.
	before, after := objectOf(t, richContent), objectOf(t, rawContent(t, e, rich))
	changed, added, removed := diffKeys(before, after)
	touched := append(slices.Clone(changed), added...)
	sort.Strings(touched)
	requireKeys(t, "content", "touched", touched, []string{"appData", "trashed"})
	requireKeys(t, "content", "removed", removed, nil)
	if got := show(after, "trashed"); got != "true" {
		t.Errorf("trashed = %s, want true", got)
	}
}
