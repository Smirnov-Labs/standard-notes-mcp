package mcptools_test

// Live tests for the gated write tools. They need the Docker SN server and skip
// cleanly without it (testsupport.NewAccount probes the server and honors
// SN_TEST_SERVER=off). The checks that need no server are in write_internal_test.go.
//
// The rule under test is the one of the read tools: a sensitive note's title, body or
// snippet never appears in a result, and a preview is a result. Every leak check runs
// over the JSON of the WHOLE result, which is what the MCP SDK sends to the
// orchestrator. A write tool also has a second duty: a dry run writes nothing, and a
// write changes only what it names. Those checks read the vault back through a
// client that the tool did not use to write.

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/smirnov-labs/standard-notes-mcp/internal/gate"
	"github.com/smirnov-labs/standard-notes-mcp/internal/mcptools"
	"github.com/smirnov-labs/standard-notes-mcp/internal/snclient"
	"github.com/smirnov-labs/standard-notes-mcp/internal/writeengine"
)

// The note that the gate must stub, and what it holds. The prober says "not
// sensitive" for everything, so the scanner alone stubs it (an AWS key).
const (
	secretTitle = "prod keys"
	secretText  = "AKIAIOSFODNN7EXAMPLE"
)

// fixture is the write side as the server wires it: one client, a guard around it,
// and an engine around the same client. The tools run through w. The tests read the
// vault back through c.
type fixture struct {
	c      *snclient.Client
	guard  *snclient.Guard
	eng    *writeengine.Engine
	w      *mcptools.Writer
	tools  *mcptools.Tools
	ledger string // path of the ledger file
}

func newFixture(t *testing.T, p interface {
	SensitiveProbability(string) (float64, error)
}, maxWrites int) *fixture {
	t.Helper()
	c := signIn(t) // skips cleanly if the Docker server is down
	ledger := filepath.Join(t.TempDir(), "ledger.jsonl")
	led, err := writeengine.OpenLedger(ledger)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{c: c, guard: snclient.NewGuard(c, ""), eng: writeengine.NewEngine(c, led, maxWrites), ledger: ledger}
	gt := gate.New(p, 0.5)
	f.w = mcptools.NewWriter(f.guard, f.eng, gt)
	f.tools = mcptools.New(f.guard, gt)
	return f
}

// ledgerOf returns the ledger records, one string per line.
func ledgerOf(t *testing.T, path string) []string {
	t.Helper()
	fh, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	var lines []string
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return lines
}

// ledgerStatesFor returns, in order, every state that the ledger holds for the ops of
// one kind.
func ledgerStatesFor(t *testing.T, path, kind string) []string {
	t.Helper()
	var states []string
	for _, line := range ledgerOf(t, path) {
		var rec struct{ OpID, Kind, UUID, State string }
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("bad ledger line %q: %v", line, err)
		}
		if rec.Kind == kind {
			states = append(states, rec.State)
		}
	}
	return states
}

// vaultOf is the whole vault as one string: every note and tag with the fields that a
// write tool can change. Two reads that give the same string saw the same vault.
func vaultOf(t *testing.T, c *snclient.Client) string {
	t.Helper()
	notes, tags, err := c.Fetch()
	if err != nil {
		t.Fatal(err)
	}
	var rows []string
	for _, n := range notes {
		b, _ := json.Marshal([]any{"note", n.UUID, n.Title, n.Text, n.Trashed, n.RefCount()})
		rows = append(rows, string(b))
	}
	for _, g := range tags {
		ids := slices.Clone(g.NoteUUIDs)
		slices.Sort(ids)
		b, _ := json.Marshal([]any{"tag", g.UUID, g.Title, ids})
		rows = append(rows, string(b))
	}
	slices.Sort(rows)
	return strings.Join(rows, "\n")
}

// liveNote reads one note live and fails the test when it is gone.
func liveNote(t *testing.T, c *snclient.Client, id string) *snclient.NoteView {
	t.Helper()
	n, err := c.FetchOne(id)
	if err != nil {
		t.Fatal(err)
	}
	if n == nil {
		t.Fatalf("note %s is gone: a write tool must never delete a note", id)
	}
	return n
}

// requireStubBefore fails unless the note's Before is the bare stub of uuid.
func requireStubBefore(t *testing.T, where string, res mcptools.NoteWriteResult, uuid string) {
	t.Helper()
	if res.Before.Note != nil || res.Before.Stub == nil || *res.Before.Stub != gate.Stub(uuid) {
		t.Fatalf("%s: the sensitive note %s is not a bare stub: %s", where, uuid, wire(t, res))
	}
}

// The plan's acceptance test for the privacy rule on previews. The two note tools that
// set no content, trash and untrash, still work on a sensitive note, and their preview
// must show only the stub: no title and no text. The two that set content, edit and
// rename, refuse a sensitive note: see TestEditAndRenameRefuseASensitiveNote. A normal
// note, as the control, shows its old title and text on all four tools. A dry run must
// also leave the vault as it was, and the ledger empty.
func TestNotePreviewsNeverShowASensitiveNote(t *testing.T) {
	f := newFixture(t, notSensitive{}, 100)
	normal := seed(t, f.c, "Shopping", "milk and eggs")
	secret := seed(t, f.c, secretTitle, secretText)
	telltales := []string{secretText, secretTitle, "AKIA", "prod"}
	before := vaultOf(t, f.c)

	calls := map[string]func(id string) (mcptools.NoteWriteResult, error){
		"note_edit":    func(id string) (mcptools.NoteWriteResult, error) { return f.w.NoteEdit(id, "replacement body", true) },
		"note_rename":  func(id string) (mcptools.NoteWriteResult, error) { return f.w.NoteRename(id, "New Title", true) },
		"note_trash":   func(id string) (mcptools.NoteWriteResult, error) { return f.w.NoteTrash(id, true) },
		"note_untrash": func(id string) (mcptools.NoteWriteResult, error) { return f.w.NoteUntrash(id, true) },
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			if name == "note_trash" || name == "note_untrash" { // the tools that stay allowed on a sensitive note
				res, err := call(secret)
				if err != nil {
					t.Fatal(err)
				}
				requireNoLeak(t, name+" preview of a sensitive note", res, telltales...)
				requireStubBefore(t, name, res, secret)
				if !res.DryRun || res.Action != name || res.OpID != "" {
					t.Fatalf("a dry run must say so, name its tool and have no ledger id: %s", wire(t, res))
				}
			}

			// The control: a normal note is not over-stubbed, and shows what it holds now.
			res, err := call(normal)
			if err != nil {
				t.Fatal(err)
			}
			if n := res.Before.Note; res.Before.Stub != nil || n == nil || n.UUID != normal || n.Title != "Shopping" || n.Text != "milk and eggs" {
				t.Fatalf("%s: a normal note must show its old title and text: %s", name, wire(t, res))
			}
		})
	}

	// The values the caller gave are echoed: the orchestrator supplied them, so they hold
	// nothing it does not have.
	res, err := f.w.NoteEdit(normal, "replacement body", true)
	if err != nil || res.NewText == nil || *res.NewText != "replacement body" || res.NewTitle != nil {
		t.Fatalf("note_edit must echo the new text and no title: %v %s", err, wire(t, res))
	}
	res, err = f.w.NoteRename(normal, "  New Title  ", true)
	if err != nil || res.NewTitle == nil || *res.NewTitle != "New Title" || res.NewText != nil {
		t.Fatalf("note_rename must echo the trimmed title and no text: %v %s", err, wire(t, res))
	}

	if after := vaultOf(t, f.c); after != before {
		t.Fatalf("a dry run changed the vault:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if lines := ledgerOf(t, f.ledger); len(lines) != 0 {
		t.Fatalf("a dry run reached Commit: the ledger holds %q", lines)
	}
}

// A trash and an untrash set no content and can be undone, so they stay allowed on a
// sensitive note. The write is the user's call, and the ask prompt guards it. The result
// must still have no content: only the stub. An edit and a rename do not appear here
// because they refuse a sensitive note: see TestEditAndRenameRefuseASensitiveNote.
func TestWritesToASensitiveNoteShowOnlyAStub(t *testing.T) {
	f := newFixture(t, notSensitive{}, 100)
	telltales := []string{secretText, secretTitle, "AKIA", "prod"}

	id := seed(t, f.c, secretTitle, secretText)
	res, err := f.w.NoteTrash(id, false)
	if err != nil {
		t.Fatal(err)
	}
	requireNoLeak(t, "note_trash", res, telltales...)
	requireStubBefore(t, "note_trash", res, id)
	if res.DryRun || res.OpID == "" {
		t.Fatalf("a write must say it is not a dry run and give its ledger id: %s", wire(t, res))
	}
	if n := liveNote(t, f.c, id); !n.Trashed || n.Text != secretText || n.Title != secretTitle {
		t.Fatalf("note_trash must trash the note and keep it whole: %+v", n)
	}
	res, err = f.w.NoteUntrash(id, false)
	if err != nil {
		t.Fatal(err)
	}
	requireNoLeak(t, "note_untrash", res, telltales...)
	requireStubBefore(t, "note_untrash", res, id)
	if n := liveNote(t, f.c, id); n.Trashed || n.Text != secretText || n.Title != secretTitle {
		t.Fatalf("note_untrash must take the note out of the trash and keep it whole: %+v", n)
	}
}

// An edit and a rename set content, the text or the title, for a note. On a sensitive
// note the caller cannot see what it overwrites, and the user approves the change
// without the old text, so both tools refuse it. The refusal is an error with fixed
// text and no result. It comes in a dry run and in a write, before the tool plans or
// commits anything: the vault stays as it was and the ledger stays empty. The same
// calls on a normal note still work. The prober says "not sensitive" for everything, so
// the scanner alone flags the AKIA note.
func TestEditAndRenameRefuseASensitiveNote(t *testing.T) {
	f := newFixture(t, notSensitive{}, 100)
	normal := seed(t, f.c, "Shopping", "milk and eggs")
	secret := seed(t, f.c, secretTitle, secretText)
	telltales := []string{secretText, secretTitle, "AKIA", "prod"}
	before := vaultOf(t, f.c)

	const refusal = "cannot edit a sensitive note; it is walled off from the assistant"
	calls := map[string]func(id string, dryRun bool) (mcptools.NoteWriteResult, error){
		"note_edit": func(id string, dry bool) (mcptools.NoteWriteResult, error) {
			return f.w.NoteEdit(id, "replacement body", dry)
		},
		"note_rename": func(id string, dry bool) (mcptools.NoteWriteResult, error) { return f.w.NoteRename(id, "Renamed", dry) },
	}
	for name, call := range calls {
		for _, dry := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s dry=%v", name, dry), func(t *testing.T) {
				res, err := call(secret, dry)
				if !errors.Is(err, mcptools.ErrSensitiveEdit) {
					t.Fatalf("got %v, want ErrSensitiveEdit", err)
				}
				if err.Error() != refusal {
					t.Fatalf("error text %q, want %q", err.Error(), refusal)
				}
				// Neither the error nor the result holds a trace of the note.
				requireNoLeak(t, name+" refusal", struct {
					Err string
					Res mcptools.NoteWriteResult
				}{err.Error(), res}, telltales...)
				if !reflect.DeepEqual(res, mcptools.NoteWriteResult{}) {
					t.Fatalf("a refused call must return no result: %s", wire(t, res))
				}
			})
		}
	}
	if after := vaultOf(t, f.c); after != before {
		t.Fatalf("a refused call changed the vault:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if n := liveNote(t, f.c, secret); n.Title != secretTitle || n.Text != secretText {
		t.Fatalf("a refused call changed the sensitive note: %q %q", n.Title, n.Text)
	}
	if lines := ledgerOf(t, f.ledger); len(lines) != 0 {
		t.Fatalf("a refused call reached Commit: the ledger holds %q", lines)
	}

	// The same calls on a normal note still work: a dry run shows what the note holds, and
	// a write lands.
	for name, call := range calls {
		res, err := call(normal, true)
		if err != nil {
			t.Fatalf("%s dry run on a normal note: %v", name, err)
		}
		if n := res.Before.Note; !res.DryRun || n == nil || n.Title != "Shopping" || n.Text != "milk and eggs" {
			t.Fatalf("%s dry run on a normal note: %s", name, wire(t, res))
		}
	}
	if _, err := f.w.NoteEdit(normal, "milk, eggs and butter", false); err != nil {
		t.Fatal(err)
	}
	if _, err := f.w.NoteRename(normal, "Groceries", false); err != nil {
		t.Fatal(err)
	}
	if n := liveNote(t, f.c, normal); n.Title != "Groceries" || n.Text != "milk, eggs and butter" {
		t.Fatalf("the edit and the rename of a normal note must land: %q %q", n.Title, n.Text)
	}

	// The refusal comes before Commit. After a kill, a write that reaches Commit fails
	// with ErrKilled. The sensitive note still gets the refusal, so the refusal came first.
	f.eng.Kill()
	if _, err := f.w.NoteEdit(normal, "x", false); !errors.Is(err, writeengine.ErrKilled) {
		t.Fatalf("control: an edit of a normal note after a kill must reach Commit: got %v", err)
	}
	if _, err := f.w.NoteEdit(secret, "x", false); !errors.Is(err, mcptools.ErrSensitiveEdit) {
		t.Fatalf("an edit of a sensitive note must be refused before Commit: got %v", err)
	}
	if _, err := f.w.NoteRename(secret, "x", false); !errors.Is(err, mcptools.ErrSensitiveEdit) {
		t.Fatalf("a rename of a sensitive note must be refused before Commit: got %v", err)
	}
}

// When jev is down the gate fails closed, so every note is a stub. A preview must
// follow: the normal note's title and text must not show. The tools that set content or
// copy it refuse, because a note that the gate cannot check counts as sensitive.
func TestPreviewsFailClosedWhenJevIsDown(t *testing.T) {
	f := newFixture(t, jevDown{}, 100)
	normal := seed(t, f.c, "Shopping", "milk and eggs")
	other := seed(t, f.c, "Errands", "buy stamps")

	res, err := f.w.NoteTrash(normal, true)
	if err != nil {
		t.Fatal(err)
	}
	requireStubBefore(t, "note_trash with jev down", res, normal)
	requireNoLeak(t, "note_trash with jev down", res, "Shopping", "milk and eggs")

	if _, err := f.w.NoteEdit(normal, "replacement body", true); !errors.Is(err, mcptools.ErrSensitiveEdit) {
		t.Fatalf("an edit with jev down must be refused, because every note is a stub: %v", err)
	}
	if _, err := f.w.NoteRename(normal, "Renamed", false); !errors.Is(err, mcptools.ErrSensitiveEdit) {
		t.Fatalf("a rename with jev down must be refused, because every note is a stub: %v", err)
	}
	if _, err := f.w.NoteMerge([]string{normal, other}, "Merged", true); !errors.Is(err, mcptools.ErrSensitiveMerge) {
		t.Fatalf("a merge with jev down must be refused, because every note is a stub: %v", err)
	}
}

// A merge copies each source into a new note, so it must refuse when any source is
// sensitive: the orchestrator is not allowed to see that text. The refusal comes
// before anything is built or written, in a dry run and in a write, whichever
// position the sensitive source has. The error text holds no content.
func TestNoteMergeRefusesASensitiveSource(t *testing.T) {
	f := newFixture(t, notSensitive{}, 100)
	a := seed(t, f.c, "Shopping", "milk and eggs")
	b := seed(t, f.c, "Errands", "buy stamps")
	secret := seed(t, f.c, secretTitle, secretText)
	before := vaultOf(t, f.c)

	for name, ids := range map[string][]string{
		"sensitive last":   {a, secret},
		"sensitive first":  {secret, a},
		"sensitive middle": {a, secret, b},
		"all three":        {a, b, secret},
	} {
		for _, dry := range []bool{true, false} {
			t.Run(name, func(t *testing.T) {
				res, err := f.w.NoteMerge(ids, "Merged", dry)
				if !errors.Is(err, mcptools.ErrSensitiveMerge) {
					t.Fatalf("got %v, want ErrSensitiveMerge", err)
				}
				if got, want := err.Error(), "cannot merge a sensitive note; it is walled off"; got != want {
					t.Fatalf("error text %q, want %q", got, want)
				}
				requireNoLeak(t, "the merge refusal", struct {
					Err string
					Res mcptools.MergeResult
				}{err.Error(), res}, secretText, secretTitle, "AKIA", "prod", "Shopping", "milk and eggs")
				if res.NoteUUID != "" || len(res.Sources) != 0 {
					t.Fatalf("a refused merge must return an empty result: %s", wire(t, res))
				}
			})
		}
	}
	if after := vaultOf(t, f.c); after != before {
		t.Fatalf("a refused merge changed the vault:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if lines := ledgerOf(t, f.ledger); len(lines) != 0 {
		t.Fatalf("a refused merge reached Commit: the ledger holds %q", lines)
	}
}

// A merge is additive. It makes one note that holds each source byte for byte, and
// it moves the sources to the trash, whole. The dry run shows the plan and writes
// nothing. The text uses a CRLF, a trailing space and Unicode: the engine's coverage
// check is byte-exact, and a retyped source would fail it.
func TestNoteMergeIsAdditiveAndVerbatim(t *testing.T) {
	f := newFixture(t, notSensitive{}, 100)
	textA := "book a cleaning\r\nfor next month  \n— the one on Oak St, café 日本語\n"
	textB := "book a cleaning"
	a := seed(t, f.c, "Call the dentist", textA)
	b := seed(t, f.c, "call dentist", textB)
	untouched := seed(t, f.c, "Shopping", "milk and eggs")
	before := vaultOf(t, f.c)

	want := "Call the dentist\n\n" + textA + "\n\n---\n\n" + "call dentist\n\n" + textB

	t.Run("dry run", func(t *testing.T) {
		res, err := f.w.NoteMerge([]string{a, b}, "  Dentist  ", true)
		if err != nil {
			t.Fatal(err)
		}
		if !res.DryRun || res.NoteUUID != "" || res.OpID != "" || res.Title != "Dentist" || res.Bytes != len(want) {
			t.Fatalf("dry run result: %s", wire(t, res))
		}
		wantSources := []mcptools.MergeSource{{UUID: a, Title: "Call the dentist", Trashed: true}, {UUID: b, Title: "call dentist", Trashed: true}}
		if !slices.Equal(res.Sources, wantSources) {
			t.Fatalf("sources %+v, want %+v", res.Sources, wantSources)
		}
		if after := vaultOf(t, f.c); after != before {
			t.Fatalf("a dry run changed the vault:\nbefore:\n%s\nafter:\n%s", before, after)
		}
		if lines := ledgerOf(t, f.ledger); len(lines) != 0 {
			t.Fatalf("a dry run reached Commit: the ledger holds %q", lines)
		}
	})

	t.Run("write", func(t *testing.T) {
		res, err := f.w.NoteMerge([]string{a, b, a}, "Dentist", false) // a repeat is dropped
		if err != nil {
			t.Fatal(err)
		}
		if res.DryRun || res.NoteUUID == "" || res.OpID == "" || res.Bytes != len(want) || res.Notice != "" || len(res.Sources) != 2 {
			t.Fatalf("write result: %s", wire(t, res))
		}
		merged := liveNote(t, f.c, res.NoteUUID)
		if merged.Title != "Dentist" || merged.Trashed {
			t.Fatalf("the merged note: title %q, trashed %v", merged.Title, merged.Trashed)
		}
		if merged.Text != want {
			t.Fatalf("the merged text is not the sources, byte for byte:\n got %q\nwant %q", merged.Text, want)
		}
		// The sources are in the trash and whole: a merge never deletes.
		for id, text := range map[string]string{a: textA, b: textB} {
			if n := liveNote(t, f.c, id); !n.Trashed || n.Text != text {
				t.Fatalf("source %s: trashed=%v text=%q, want it trashed and whole", id, n.Trashed, n.Text)
			}
		}
		for _, s := range res.Sources {
			if !s.Trashed {
				t.Fatalf("source %s must be reported as trashed", s.UUID)
			}
		}
		if n := liveNote(t, f.c, untouched); n.Trashed || n.Text != "milk and eggs" {
			t.Fatal("a merge must not touch a note that is not a source")
		}
		// One merge, two trashes: all verified.
		if got := ledgerStatesFor(t, f.ledger, "merge"); !slices.Equal(got, []string{"intended", "acked", "verified"}) {
			t.Fatalf("merge ledger states %v", got)
		}
		if got := ledgerStatesFor(t, f.ledger, "trash"); !slices.Equal(got, []string{"intended", "acked", "verified", "intended", "acked", "verified"}) {
			t.Fatalf("trash ledger states %v", got)
		}
	})
}

// A merge needs two different notes, a title, and notes that exist.
func TestNoteMergeRefusesBadInput(t *testing.T) {
	f := newFixture(t, notSensitive{}, 100)
	a := seed(t, f.c, "Shopping", "milk and eggs")
	b := seed(t, f.c, "Errands", "buy stamps")
	tag, err := f.w.TagCreate("project", false)
	if err != nil {
		t.Fatal(err)
	}
	before := vaultOf(t, f.c)

	for name, tc := range map[string]struct {
		ids   []string
		title string
		want  error
	}{
		"no sources":        {nil, "Merged", mcptools.ErrMergeNeedsTwo},
		"one source":        {[]string{a}, "Merged", mcptools.ErrMergeNeedsTwo},
		"one source twice":  {[]string{a, a, " " + a + " "}, "Merged", mcptools.ErrMergeNeedsTwo},
		"a blank uuid":      {[]string{a, " "}, "Merged", mcptools.ErrEmptyUUID},
		"a blank title":     {[]string{a, b}, "  ", mcptools.ErrEmptyTitle},
		"a source is gone":  {[]string{a, "00000000-0000-4000-8000-000000000000"}, "Merged", mcptools.ErrNotFound},
		"the uuid of a tag": {[]string{a, tag.Tag.UUID}, "Merged", mcptools.ErrNotFound},
	} {
		t.Run(name, func(t *testing.T) {
			for _, dry := range []bool{true, false} {
				if _, err := f.w.NoteMerge(tc.ids, tc.title, dry); !errors.Is(err, tc.want) {
					t.Fatalf("dry=%v: got %v, want %v", dry, err, tc.want)
				}
			}
		})
	}
	if after := vaultOf(t, f.c); after != before {
		t.Fatal("a refused merge changed the vault")
	}
}

// rich is a note whose raw content carries fields that gosn-v2 does not model: the
// kind of note that the typed write path ruins. A tool that went through a lossy
// helper would drop them.
const rich = `{"title":"rich","text":"old body","references":[],` +
	`"protected":true,"starred":true,` +
	`"appData":{"org.standardnotes.sn":{"client_updated_at":"2020-01-01T00:00:00.000Z","archived":true,"locked":true},` +
	`"dev.example.editor":{"theme":"dark","fontSize":17}},` +
	`"spellcheck":false,"future_unknown_key":"must survive"}`

// rawOf returns the top-level keys of a note's raw content.
func rawOf(t *testing.T, c *snclient.Client, id string) map[string]json.RawMessage {
	t.Helper()
	r, err := c.FetchRawOne(id)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(r.Content()), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// requireKept fails unless every key of before, except the ones in changed and
// appData, holds the same bytes in after, and the third-party and legacy parts of
// appData are the same too.
func requireKept(t *testing.T, where string, before, after map[string]json.RawMessage, changed ...string) {
	t.Helper()
	for k, v := range before {
		if k == "appData" || slices.Contains(changed, k) {
			continue
		}
		if got, ok := after[k]; !ok || string(got) != string(v) {
			t.Fatalf("%s: key %q changed or was dropped: %s -> %s", where, k, v, got)
		}
	}
	var bd, ad map[string]json.RawMessage
	if err := json.Unmarshal(before["appData"], &bd); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(after["appData"], &ad); err != nil {
		t.Fatalf("%s: appData is gone: %v", where, err)
	}
	if string(bd["dev.example.editor"]) != string(ad["dev.example.editor"]) {
		t.Fatalf("%s: a third-party appData domain changed: %s -> %s", where, bd["dev.example.editor"], ad["dev.example.editor"])
	}
	var bs, as map[string]json.RawMessage
	if err := json.Unmarshal(bd["org.standardnotes.sn"], &bs); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(ad["org.standardnotes.sn"], &as); err != nil {
		t.Fatal(err)
	}
	for k, v := range bs {
		if k != "client_updated_at" && string(as[k]) != string(v) {
			t.Fatalf("%s: appData[org.standardnotes.sn].%s changed or was dropped: %s -> %s", where, k, v, as[k])
		}
	}
}

// A real trash moves the note to the trash and nothing more. A read shows it trashed,
// with its text, and not deleted. An untrash reverses it. Every field that gosn-v2
// does not model is still there after each write tool: the tools go through the
// engine's surgical path.
func TestWriteToolsAreReversibleAndKeepEveryField(t *testing.T) {
	f := newFixture(t, notSensitive{}, 100)
	id, err := f.c.SeedRawNote(t, rich)
	if err != nil {
		t.Fatal(err)
	}
	orig := rawOf(t, f.c, id)

	// Trash.
	res, err := f.w.NoteTrash(id, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.DryRun || res.OpID == "" || res.Before.Note == nil || res.Before.Note.Trashed {
		t.Fatalf("trash result: %s", wire(t, res))
	}
	got, err := f.tools.Get(id) // the read tool: the note is trashed, and it is still there
	if err != nil || got.Note == nil || !got.Note.Trashed || got.Note.Text != "old body" || got.Note.Title != "rich" {
		t.Fatalf("after note_trash a read must show the note trashed, with its text: %v %s", err, wire(t, got))
	}
	rs, err := f.tools.List(0, 0)
	if err != nil || find(rs, id) != nil {
		t.Fatalf("a trashed note is not listed: %v %s", err, wire(t, rs))
	}
	now := rawOf(t, f.c, id)
	if string(now["trashed"]) != "true" {
		t.Fatalf("trashed = %s, want true", now["trashed"])
	}
	requireKept(t, "note_trash", orig, now, "trashed")

	// Untrash.
	if _, err := f.w.NoteUntrash(id, false); err != nil {
		t.Fatal(err)
	}
	now = rawOf(t, f.c, id)
	if string(now["trashed"]) != "false" {
		t.Fatalf("trashed = %s after note_untrash, want false", now["trashed"])
	}
	requireKept(t, "note_untrash", orig, now, "trashed")
	got, err = f.tools.Get(id)
	if err != nil || got.Note == nil || got.Note.Trashed {
		t.Fatalf("after note_untrash a read must show the note out of the trash: %v %s", err, wire(t, got))
	}

	// Edit and rename.
	if _, err := f.w.NoteEdit(id, "new body", false); err != nil {
		t.Fatal(err)
	}
	now = rawOf(t, f.c, id)
	if string(now["text"]) != `"new body"` || string(now["title"]) != `"rich"` {
		t.Fatalf("note_edit: text %s title %s", now["text"], now["title"])
	}
	requireKept(t, "note_edit", orig, now, "trashed", "text")
	if _, err := f.w.NoteRename(id, "renamed", false); err != nil {
		t.Fatal(err)
	}
	now = rawOf(t, f.c, id)
	if string(now["title"]) != `"renamed"` || string(now["text"]) != `"new body"` {
		t.Fatalf("note_rename: title %s text %s", now["title"], now["text"])
	}
	requireKept(t, "note_rename", orig, now, "trashed", "text", "title")

	// Every write is in the ledger, and verified.
	for _, kind := range []string{"trash", "untrash", "edit", "rename"} {
		if got := ledgerStatesFor(t, f.ledger, kind); !slices.Equal(got, []string{"intended", "acked", "verified"}) {
			t.Fatalf("%s ledger states %v", kind, got)
		}
	}
}

// A note that does not exist is an error with fixed text, and the other note tools
// refuse a blank uuid. Neither reaches the engine.
func TestNoteToolsRefuseUnknownAndBlankUUIDs(t *testing.T) {
	f := newFixture(t, notSensitive{}, 100)
	const missing = "00000000-0000-4000-8000-000000000000"
	for name, call := range map[string]func(id string) error{
		"note_edit":    func(id string) error { _, err := f.w.NoteEdit(id, "x", false); return err },
		"note_rename":  func(id string) error { _, err := f.w.NoteRename(id, "x", false); return err },
		"note_trash":   func(id string) error { _, err := f.w.NoteTrash(id, false); return err },
		"note_untrash": func(id string) error { _, err := f.w.NoteUntrash(id, false); return err },
	} {
		if err := call(missing); !errors.Is(err, mcptools.ErrNotFound) || err.Error() != "note not found" {
			t.Fatalf("%s on an unknown uuid: got %v, want a bare ErrNotFound", name, err)
		}
		if err := call("  "); !errors.Is(err, mcptools.ErrEmptyUUID) {
			t.Fatalf("%s on a blank uuid: got %v, want ErrEmptyUUID", name, err)
		}
	}
	if lines := ledgerOf(t, f.ledger); len(lines) != 0 {
		t.Fatalf("a refused call reached Commit: %q", lines)
	}
}

// An edit that blanks the text, and a rename that blanks the title, are refused: a
// model that sends an empty string by mistake must not wipe a note. note_trash is the
// way to remove one.
func TestEditAndRenameRefuseABlankValue(t *testing.T) {
	f := newFixture(t, notSensitive{}, 100)
	id := seed(t, f.c, "Shopping", "milk and eggs")
	if _, err := f.w.NoteEdit(id, " \n\t ", false); !errors.Is(err, mcptools.ErrEmptyText) {
		t.Fatalf("a blank text: got %v, want ErrEmptyText", err)
	}
	if _, err := f.w.NoteRename(id, "   ", false); !errors.Is(err, mcptools.ErrEmptyTitle) {
		t.Fatalf("a blank title: got %v, want ErrEmptyTitle", err)
	}
	if n := liveNote(t, f.c, id); n.Title != "Shopping" || n.Text != "milk and eggs" {
		t.Fatal("a refused call changed the note")
	}
}

// tagOf returns the tag with this uuid, read live, or fails the test.
func tagOf(t *testing.T, c *snclient.Client, id string) *snclient.TagView {
	t.Helper()
	_, tags, err := c.Fetch()
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range tags {
		if g.UUID == id {
			return g
		}
	}
	t.Fatalf("tag %s is gone: a write tool must never delete a tag", id)
	return nil
}

func sorted(s []string) []string { s = slices.Clone(s); slices.Sort(s); return s }

// The five tag tools, each as a dry run and as a write. No result shows a note's
// title: the notes here have titles that must not appear.
func TestTagTools(t *testing.T) {
	f := newFixture(t, notSensitive{}, 100)
	n1 := seed(t, f.c, "Shopping", "milk and eggs")
	n2 := seed(t, f.c, "Errands", "buy stamps")
	n3 := seed(t, f.c, secretTitle, secretText)
	noTitles := func(where string, v any) {
		t.Helper()
		requireNoLeak(t, where, v, "Shopping", "Errands", secretTitle, secretText, "milk", "stamps")
	}

	// tag_create: a dry run makes nothing. A write makes the tag. A repeat finds it.
	res, err := f.w.TagCreate(" project ", true)
	if err != nil || !res.DryRun || !res.Created || res.Tag.Title != "project" || res.Tag.UUID != "" || res.OpID != "" {
		t.Fatalf("tag_create dry run: %v %s", err, wire(t, res))
	}
	if tl, _ := f.tools.TagsList(); len(tl.Tags) != 0 {
		t.Fatalf("a dry run made a tag: %s", wire(t, tl))
	}
	res, err = f.w.TagCreate("project", false)
	if err != nil || res.DryRun || !res.Created || res.Tag.UUID == "" || res.OpID == "" {
		t.Fatalf("tag_create: %v %s", err, wire(t, res))
	}
	project := res.Tag.UUID
	if g := tagOf(t, f.c, project); g.Title != "project" || len(g.NoteUUIDs) != 0 {
		t.Fatalf("the new tag: %+v", g)
	}
	res, err = f.w.TagCreate("project", false)
	if err != nil || res.Created || res.Tag.UUID != project || res.OpID != "" {
		t.Fatalf("a repeat of tag_create must find the tag and write nothing: %v %s", err, wire(t, res))
	}
	if tl, _ := f.tools.TagsList(); len(tl.Tags) != 1 {
		t.Fatalf("a repeat made a second tag: %s", wire(t, tl))
	}

	// tag_apply: a note that does not exist is refused before anything is written.
	before := vaultOf(t, f.c)
	if _, err := f.w.TagApply("later", []string{n1, "00000000-0000-4000-8000-000000000000"}, false); !errors.Is(err, mcptools.ErrNotFound) {
		t.Fatalf("tag_apply with an unknown note: got %v, want ErrNotFound", err)
	}
	if vaultOf(t, f.c) != before {
		t.Fatal("a refused tag_apply changed the vault")
	}
	// A dry run on a new tag says it would make the tag, and writes nothing.
	res, err = f.w.TagApply("later", []string{n1, n2}, true)
	if err != nil || !res.DryRun || !res.Created || res.NotesChanged != 2 || res.NotesSkipped != 0 || res.Tag.UUID != "" {
		t.Fatalf("tag_apply dry run: %v %s", err, wire(t, res))
	}
	noTitles("tag_apply dry run", res)
	if vaultOf(t, f.c) != before {
		t.Fatal("a dry run changed the vault")
	}
	// Apply to the tag that exists: one note is new, one is already on it.
	if _, err := f.w.TagApply("project", []string{n1}, false); err != nil {
		t.Fatal(err)
	}
	res, err = f.w.TagApply("project", []string{n1, n2, n3, n2}, false)
	if err != nil || res.Created || res.Tag.UUID != project || res.NotesChanged != 2 || res.NotesSkipped != 1 || res.OpID == "" {
		t.Fatalf("tag_apply: %v %s", err, wire(t, res))
	}
	noTitles("tag_apply", res)
	if g := tagOf(t, f.c, project); !slices.Equal(sorted(g.NoteUUIDs), sorted([]string{n1, n2, n3})) {
		t.Fatalf("project holds %v, want all three notes", g.NoteUUIDs)
	}
	// Apply makes the tag when none has the title.
	res, err = f.w.TagApply("later", []string{n2}, false)
	if err != nil || !res.Created || res.Tag.UUID == "" || res.NotesChanged != 1 {
		t.Fatalf("tag_apply that makes a tag: %v %s", err, wire(t, res))
	}
	later := res.Tag.UUID

	// tag_detach: one note is on the tag, one is not.
	res, err = f.w.TagDetach(project, []string{n3, n2, "not-on-the-tag"}, true)
	if err != nil || !res.DryRun || res.NotesChanged != 2 || res.NotesSkipped != 1 || res.Tag != (mcptools.TagRef{UUID: project, Title: "project"}) {
		t.Fatalf("tag_detach dry run: %v %s", err, wire(t, res))
	}
	res, err = f.w.TagDetach(project, []string{n3, "not-on-the-tag"}, false)
	if err != nil || res.NotesChanged != 1 || res.NotesSkipped != 1 || res.OpID == "" {
		t.Fatalf("tag_detach: %v %s", err, wire(t, res))
	}
	noTitles("tag_detach", res)
	if g := tagOf(t, f.c, project); !slices.Equal(sorted(g.NoteUUIDs), sorted([]string{n1, n2})) {
		t.Fatalf("project holds %v, want n1 and n2", g.NoteUUIDs)
	}
	if _, err := f.w.TagDetach("00000000-0000-4000-8000-000000000000", []string{n1}, false); !errors.Is(err, mcptools.ErrTagNotFound) {
		t.Fatalf("tag_detach on an unknown tag: got %v, want ErrTagNotFound", err)
	}
	if _, err := f.w.TagDetach(n1, []string{n1}, false); !errors.Is(err, mcptools.ErrTagNotFound) {
		t.Fatalf("tag_detach given a NOTE uuid must be ErrTagNotFound: got %v", err)
	}

	// tag_rename.
	if _, err := f.w.TagRename(project, "later", false); !errors.Is(err, mcptools.ErrTagTitleTaken) {
		t.Fatalf("tag_rename to a title that another tag has: got %v, want ErrTagTitleTaken", err)
	}
	if _, err := f.w.TagRename("00000000-0000-4000-8000-000000000000", "x", false); !errors.Is(err, mcptools.ErrTagNotFound) {
		t.Fatalf("tag_rename on an unknown tag: got %v, want ErrTagNotFound", err)
	}
	res, err = f.w.TagRename(project, "projects/alpha", true)
	if err != nil || !res.DryRun || res.NewTitle == nil || *res.NewTitle != "projects/alpha" || res.Tag.Title != "project" {
		t.Fatalf("tag_rename dry run: %v %s", err, wire(t, res))
	}
	if g := tagOf(t, f.c, project); g.Title != "project" {
		t.Fatal("a dry run renamed the tag")
	}
	if _, err := f.w.TagRename(project, "projects/alpha", false); err != nil {
		t.Fatal(err)
	}
	if g := tagOf(t, f.c, project); g.Title != "projects/alpha" || !slices.Equal(sorted(g.NoteUUIDs), sorted([]string{n1, n2})) {
		t.Fatalf("after tag_rename: %+v, want the new title and the same notes", g)
	}

	// tag_trash marks the tag. It does not delete it, and the result says what that
	// means: the official app does not hide a trashed tag.
	res, err = f.w.TagTrash(later, true)
	if err != nil || !res.DryRun || res.Notice == "" {
		t.Fatalf("tag_trash dry run: %v %s", err, wire(t, res))
	}
	if raw, err := f.c.FetchRawTag(later); err != nil || strings.Contains(raw.Content(), `"trashed":true`) {
		t.Fatalf("a dry run trashed the tag: %v", err)
	}
	res, err = f.w.TagTrash(later, false)
	if err != nil || res.DryRun || res.OpID == "" || res.Tag.UUID != later || res.Tag.Title != "later" {
		t.Fatalf("tag_trash: %v %s", err, wire(t, res))
	}
	for _, must := range []string{"trashed", "reversible", "official", "does not hide", "never deletes"} {
		if !strings.Contains(res.Notice, must) {
			t.Fatalf("the tag_trash notice must say %q: %s", must, res.Notice)
		}
	}
	raw, err := f.c.FetchRawTag(later) // refuses a deleted tag, so success is the proof
	if err != nil || !strings.Contains(raw.Content(), `"trashed":true`) {
		t.Fatalf("tag_trash must set the trashed flag and keep the tag: %v", err)
	}
	if g := tagOf(t, f.c, later); g.Title != "later" || !slices.Equal(g.NoteUUIDs, []string{n2}) {
		t.Fatalf("a trashed tag keeps its title and notes: %+v", g)
	}
	if _, err := f.w.TagTrash("", false); !errors.Is(err, mcptools.ErrEmptyUUID) {
		t.Fatalf("tag_trash on a blank uuid: got %v", err)
	}
}

// Two tags with one title make tag_apply ambiguous, because the engine finds a tag by
// title and could pick either. The tool refuses, and writes nothing.
func TestTagApplyRefusesAnAmbiguousTitle(t *testing.T) {
	f := newFixture(t, notSensitive{}, 100)
	n1 := seed(t, f.c, "Shopping", "milk and eggs")
	for range 2 {
		tag, err := f.c.NewTag("twin")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.c.Push(f.c.RawTag(tag)); err != nil {
			t.Fatal(err)
		}
	}
	before := vaultOf(t, f.c)
	for _, dry := range []bool{true, false} {
		if _, err := f.w.TagApply("twin", []string{n1}, dry); !errors.Is(err, mcptools.ErrTagAmbiguous) {
			t.Fatalf("dry=%v: got %v, want ErrTagAmbiguous", dry, err)
		}
	}
	if vaultOf(t, f.c) != before {
		t.Fatal("a refused tag_apply changed the vault")
	}
}

// tag_merge combines tags BY UUID, so it dedups duplicate titles — the case tag_apply
// refuses. The keeper gains every note from the sources (a note it already holds is not
// added twice), the sources are trashed (not deleted), and the keeper is left alone.
func TestTagMerge(t *testing.T) {
	f := newFixture(t, notSensitive{}, 100)
	n1 := seed(t, f.c, "Shopping", "milk")
	n2 := seed(t, f.c, "Errands", "stamps")
	n3 := seed(t, f.c, "Ideas", "a cli")

	mkTag := func(title string, noteUUIDs ...string) string {
		t.Helper()
		tag, err := f.c.NewTag(title)
		if err != nil {
			t.Fatal(err)
		}
		if len(noteUUIDs) > 0 {
			f.c.SetTagRefs(tag, noteUUIDs)
		}
		if _, err := f.c.Push(f.c.RawTag(tag)); err != nil {
			t.Fatal(err)
		}
		return tag.UUID
	}

	keeper := mkTag("work", n1)
	dupWork := mkTag("work", n1, n2) // same title as the keeper, and shares n1
	archive := mkTag("archive", n3)

	// Bad input writes nothing.
	if _, err := f.w.TagMerge("", []string{dupWork}, false); !errors.Is(err, mcptools.ErrEmptyUUID) {
		t.Fatalf("blank keeper: got %v, want ErrEmptyUUID", err)
	}
	if _, err := f.w.TagMerge(keeper, []string{keeper}, false); !errors.Is(err, mcptools.ErrTagMergeNeedsSource) {
		t.Fatalf("only the keeper as source: got %v, want ErrTagMergeNeedsSource", err)
	}
	if _, err := f.w.TagMerge(keeper, []string{"00000000-0000-4000-8000-000000000000"}, false); !errors.Is(err, mcptools.ErrTagNotFound) {
		t.Fatalf("unknown source: got %v, want ErrTagNotFound", err)
	}

	// Dry run: reports the plan, writes nothing. n1 is already on the keeper, so only
	// n2 and n3 are added.
	before := vaultOf(t, f.c)
	res, err := f.w.TagMerge(keeper, []string{dupWork, archive}, true)
	if err != nil || !res.DryRun || res.Action != "tag_merge" || res.Keeper.UUID != keeper || len(res.Sources) != 2 || res.NotesAdded != 2 {
		t.Fatalf("tag_merge dry run: %v %s", err, wire(t, res))
	}
	if vaultOf(t, f.c) != before {
		t.Fatal("a dry run changed the vault")
	}

	// The write: the keeper gains n2 and n3 (n1 not added twice), both sources trashed.
	res, err = f.w.TagMerge(keeper, []string{dupWork, archive}, false)
	if err != nil || res.DryRun || res.NotesAdded != 2 || len(res.OpIDs) == 0 || res.Notice == "" {
		t.Fatalf("tag_merge: %v %s", err, wire(t, res))
	}
	if g := tagOf(t, f.c, keeper); !slices.Equal(sorted(g.NoteUUIDs), sorted([]string{n1, n2, n3})) {
		t.Fatalf("keeper holds %v, want all three notes once each", g.NoteUUIDs)
	}
	for _, src := range []string{dupWork, archive} {
		raw, err := f.c.FetchRawTag(src) // refuses a deleted tag, so success proves the tag is kept
		if err != nil || !strings.Contains(raw.Content(), `"trashed":true`) {
			t.Fatalf("source %s must be trashed and kept: %v", src, err)
		}
	}
	if raw, err := f.c.FetchRawTag(keeper); err != nil || strings.Contains(raw.Content(), `"trashed":true`) {
		t.Fatalf("the keeper must not be trashed: %v", err)
	}
}

// A dry run reaches no Commit and no write, for every one of the eleven tools.
func TestDryRunWritesNothingOnAnyTool(t *testing.T) {
	f := newFixture(t, notSensitive{}, 100)
	a := seed(t, f.c, "Shopping", "milk and eggs")
	b := seed(t, f.c, "Errands", "buy stamps")
	tag, err := f.w.TagApply("project", []string{a}, false)
	if err != nil {
		t.Fatal(err)
	}
	other, err := f.w.TagApply("other", []string{b}, false) // a second tag, to dry-run a merge
	if err != nil {
		t.Fatal(err)
	}
	// The setup wrote. Count the ledger from here.
	base := ledgerOf(t, f.ledger)
	before := vaultOf(t, f.c)

	for name, call := range map[string]func() error{
		"note_edit":    func() error { _, err := f.w.NoteEdit(a, "new", true); return err },
		"note_rename":  func() error { _, err := f.w.NoteRename(a, "new", true); return err },
		"note_trash":   func() error { _, err := f.w.NoteTrash(a, true); return err },
		"note_untrash": func() error { _, err := f.w.NoteUntrash(a, true); return err },
		"note_merge":   func() error { _, err := f.w.NoteMerge([]string{a, b}, "m", true); return err },
		"tag_apply":    func() error { _, err := f.w.TagApply("project", []string{b}, true); return err },
		"tag_apply new": func() error {
			_, err := f.w.TagApply("brand new", []string{b}, true)
			return err
		},
		"tag_detach": func() error { _, err := f.w.TagDetach(tag.Tag.UUID, []string{a}, true); return err },
		"tag_create": func() error { _, err := f.w.TagCreate("brand new", true); return err },
		"tag_rename": func() error { _, err := f.w.TagRename(tag.Tag.UUID, "new", true); return err },
		"tag_trash":  func() error { _, err := f.w.TagTrash(tag.Tag.UUID, true); return err },
		"tag_merge":  func() error { _, err := f.w.TagMerge(tag.Tag.UUID, []string{other.Tag.UUID}, true); return err },
	} {
		if err := call(); err != nil {
			t.Fatalf("%s dry run: %v", name, err)
		}
		if after := vaultOf(t, f.c); after != before {
			t.Fatalf("%s dry run changed the vault:\nbefore:\n%s\nafter:\n%s", name, before, after)
		}
	}
	if got := ledgerOf(t, f.ledger); !slices.Equal(got, base) {
		t.Fatalf("a dry run reached Commit: the ledger grew from %q to %q", base, got)
	}
}

// The write cap and the kill switch live in the engine. The tools must keep both: a
// write past the cap, and a write after a kill, are refused with fixed text and leave
// the vault alone. A dry run still works, because it never commits.
func TestWriteToolsKeepTheCapAndTheKillSwitch(t *testing.T) {
	t.Run("cap", func(t *testing.T) {
		f := newFixture(t, notSensitive{}, 0)
		id := seed(t, f.c, "Shopping", "milk and eggs")
		if _, err := f.w.NoteTrash(id, true); err != nil {
			t.Fatalf("a dry run must work at a cap of 0: %v", err)
		}
		_, err := f.w.NoteTrash(id, false)
		var we *mcptools.WriteError
		if !errors.Is(err, writeengine.ErrCapReached) || !errors.As(err, &we) || !strings.Contains(err.Error(), "cap") {
			t.Fatalf("got %v, want a WriteError over ErrCapReached that says cap", err)
		}
		if liveNote(t, f.c, id).Trashed {
			t.Fatal("a write past the cap changed the note")
		}
	})
	t.Run("kill", func(t *testing.T) {
		f := newFixture(t, notSensitive{}, 100)
		id := seed(t, f.c, "Shopping", "milk and eggs")
		f.eng.Kill()
		if _, err := f.w.NoteTrash(id, true); err != nil {
			t.Fatalf("a dry run must work after a kill: %v", err)
		}
		if _, err := f.w.NoteTrash(id, false); !errors.Is(err, writeengine.ErrKilled) {
			t.Fatalf("got %v, want ErrKilled", err)
		}
		if _, err := f.w.TagCreate("project", false); !errors.Is(err, writeengine.ErrKilled) {
			t.Fatalf("got %v, want ErrKilled", err)
		}
		if liveNote(t, f.c, id).Trashed {
			t.Fatal("a write after a kill changed the note")
		}
	})
}

// A merge that runs out of cap after it made the merged note must say so: which note
// exists, and which sources are still out of the trash. Nothing is lost, and the text
// holds no content.
func TestAMergeThatStopsHalfWayNamesWhatExists(t *testing.T) {
	f := newFixture(t, notSensitive{}, 2) // the merged note and one trash
	a := seed(t, f.c, "Shopping", "milk and eggs")
	b := seed(t, f.c, "Errands", "buy stamps")
	_, err := f.w.NoteMerge([]string{a, b}, "Merged", false)
	var we *mcptools.WriteError
	if !errors.Is(err, writeengine.ErrCapReached) || !errors.As(err, &we) {
		t.Fatalf("got %v, want a WriteError over ErrCapReached", err)
	}
	notes, _, ferr := f.c.Fetch()
	if ferr != nil {
		t.Fatal(ferr)
	}
	var merged string
	for _, n := range notes {
		if n.Title == "Merged" {
			merged = n.UUID
		}
	}
	if merged == "" {
		t.Fatal("the merged note must exist: the cap stopped the trash of the sources, not the merge")
	}
	for _, want := range []string{merged, b, "1 of 2 sources", "cap"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the error must name %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), a) {
		t.Fatalf("the error names the source that WAS trashed as one that was not: %v", err)
	}
	requireNoLeak(t, "the partial merge error", err.Error(), "milk", "stamps", "Shopping", "Errands")
	if !liveNote(t, f.c, a).Trashed || liveNote(t, f.c, b).Trashed {
		t.Fatal("source one must be trashed and source two must not")
	}
}

// The engine reads the session itself, and gosn-v2 changes its shared session on every
// sync. A read tool that runs while a write tool runs would race on it, unless the
// guard's lock covers both. This runs writers, readers and a tag write at once, and the
// race detector must stay quiet. Every write must land: the lock queues them, and a
// queued write must not trip the engine's halt on a stray item.
func TestWriteAndReadToolsDoNotRaceOnTheSession(t *testing.T) {
	f := newFixture(t, notSensitive{}, 100)
	ids := []string{
		seed(t, f.c, "One", "first body"),
		seed(t, f.c, "Two", "second body"),
		seed(t, f.c, "Three", "third body"),
	}

	var wg sync.WaitGroup
	errs := make(chan error, 32)
	run := func(fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(); err != nil {
				errs <- err
			}
		}()
	}
	for i, id := range ids {
		run(func() error { _, err := f.w.NoteEdit(id, fmt.Sprintf("edited body %d", i), false); return err })
	}
	run(func() error { _, err := f.w.TagApply("all", ids, false); return err })
	run(func() error { _, err := f.w.NoteMerge(ids[:2], "Merged", true); return err })
	for range 3 {
		run(func() error { _, err := f.tools.List(0, 0); return err })
		run(func() error { _, err := f.tools.Search("body", 0, 0); return err })
		run(func() error { _, err := f.tools.TagsList(); return err })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	for i, id := range ids {
		if n := liveNote(t, f.c, id); n.Text != fmt.Sprintf("edited body %d", i) {
			t.Errorf("edit %d did not land: %q", i, n.Text)
		}
	}
	if g := tagOf(t, f.c, mustTag(t, f.c, "all")); !slices.Equal(sorted(g.NoteUUIDs), sorted(ids)) {
		t.Errorf("tag all holds %v, want all three notes", g.NoteUUIDs)
	}
}

// mustTag returns the uuid of the tag with this title.
func mustTag(t *testing.T, c *snclient.Client, title string) string {
	t.Helper()
	g, err := c.FindTag(title)
	if err != nil || g == nil {
		t.Fatalf("no tag %q: %v", title, err)
	}
	return g.UUID
}

// A Writer whose engine wraps another client than the guard's would run engine reads
// outside the guard's lock. The tools must refuse to run.
func TestWriterRefusesAnEngineThatIsNotOnTheGuardedSession(t *testing.T) {
	guarded := signIn(t)
	other := signIn(t)
	led, err := writeengine.OpenLedger(filepath.Join(t.TempDir(), "ledger.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	id := seed(t, guarded, "Shopping", "milk and eggs")
	w := mcptools.NewWriter(snclient.NewGuard(guarded, ""), writeengine.NewEngine(other, led, 10), gate.New(notSensitive{}, 0.5))
	for _, dry := range []bool{true, false} {
		if _, err := w.NoteTrash(id, dry); err == nil || !strings.Contains(err.Error(), "guarded session") {
			t.Fatalf("dry=%v: got %v, want a refusal that names the guarded session", dry, err)
		}
	}
	if liveNote(t, guarded, id).Trashed {
		t.Fatal("a miswired Writer changed a note")
	}
}
