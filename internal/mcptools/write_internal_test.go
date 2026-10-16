package mcptools

// Tests of the write tools that look inside the package. Most need no server, so the
// privacy paths of the write side run on every `go test`, even with
// SN_TEST_SERVER=off. They use the REAL gate (scanner, forced kinds, fail-closed jev)
// with the fake prober of read_internal_test.go. The one test that needs the Docker
// server uses testsupport.NewAccount, which skips cleanly without it. The live tests
// of the tools are in write_test.go.

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/smirnov-labs/standard-notes-mcp/internal/gate"
	"github.com/smirnov-labs/standard-notes-mcp/internal/snclient"
	"github.com/smirnov-labs/standard-notes-mcp/internal/testsupport"
	"github.com/smirnov-labs/standard-notes-mcp/internal/writeengine"
)

// The write tools use the same gate as the read tools. For every way the gate can say
// "sensitive" without jev, the Writer must hold no note, and a result built the way
// noteChange builds one must hold no telltale. A tool that built its own gate.Note
// could forget the kind, and the authenticator rows below would pass. The result is a
// trash preview: trash and untrash are the note tools that still work on a sensitive
// note, because edit and rename refuse one.
func TestWriterGatesEveryKindOfSensitiveNoteLikeTheReadTools(t *testing.T) {
	w := &Writer{gt: gate.New(prober{}, 0.5)}
	for _, sn := range secretNotes {
		t.Run(sn.name, func(t *testing.T) {
			g := w.gated(sn.note)
			if g.note != nil || g.stub != gate.Stub(sn.note.UUID) {
				t.Fatalf("a sensitive note must leave only a stub: %+v", g)
			}
			// What noteChange puts in a preview: the gated note as a GetResult. This is the
			// whole of the result that can hold a note.
			res := NoteWriteResult{DryRun: true, Action: "note_trash", Before: g.detail()}
			body := wire(t, res)
			for _, tell := range sn.telltales {
				if strings.Contains(body, tell) {
					t.Fatalf("LEAK: %q is in the preview: %s", tell, body)
				}
			}
			want := `{"DryRun":true,"Action":"note_trash","Before":` + stubJSON(sn.note.UUID) + `}`
			if body != want {
				t.Fatalf("a preview of a sensitive note must be the stub and nothing else:\n got %s\nwant %s", body, want)
			}
		})
	}
	if g := w.gated(nv("n-ok", "Shopping", "milk and eggs")); g.note == nil {
		t.Fatal("a normal note must not be over-stubbed")
	}
}

// Both the read tools and the write tools classify through gateNote, so the verdict
// is the same for the same note, on every row of the fixtures.
func TestReadAndWriteToolsAgreeOnWhatIsSensitive(t *testing.T) {
	gt := gate.New(prober{}, 0.5)
	r, w := &Tools{gt: gt}, &Writer{gt: gt}
	fixtures := []*snclient.NoteView{nv("n-ok", "Shopping", "milk and eggs")}
	for _, sn := range secretNotes {
		fixtures = append(fixtures, sn.note)
	}
	for _, n := range fixtures {
		if a, b := r.gated(n), w.gated(n); (a.note == nil) != (b.note == nil) || a.stub != b.stub {
			t.Fatalf("the read and write tools disagree about %s: %+v vs %+v", n.UUID, a, b)
		}
	}
}

// Nothing an upstream error says may reach the orchestrator. gosn-v2 puts decrypted
// item content in some of its error strings. Every error path of the write tools must
// give fixed text, and keep the cause reachable.
func TestWriteErrorsCarryNoContent(t *testing.T) {
	leaky := errors.New(`DecryptAndParse | unhandled type2 'SN|Weird' {"title":"prod keys","text":"AKIAIOSFODNN7EXAMPLE"}`)
	causes := map[string]error{
		"a plain error":                    leaky,
		"a note that is gone":              fmt.Errorf("%w: %v", snclient.ErrNoteNotFound, leaky),
		"a tag that is gone":               fmt.Errorf("%w: %v", snclient.ErrTagNotFound, leaky),
		"the cap, with detail":             fmt.Errorf("%w: %v", writeengine.ErrCapReached, leaky),
		"a kill, with detail":              fmt.Errorf("%w: %v", writeengine.ErrKilled, leaky),
		"a duplicate, with detail":         fmt.Errorf("%w: %v", writeengine.ErrDuplicated, leaky),
		"a failed verify, with detail":     fmt.Errorf("%w: %v", writeengine.ErrVerifyFailed, leaky),
		"a client verify, with detail":     fmt.Errorf("%w: %v", snclient.ErrVerifyFailed, leaky),
		"a push that was not saved":        fmt.Errorf("%w: %v", snclient.ErrPushNotSaved, leaky),
		"a coverage failure, with detail":  fmt.Errorf("%w: %v", writeengine.ErrCoverage, leaky),
		"a wrapped error that wraps again": fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", leaky)),
	}
	bad := []string{"AKIA", "prod keys", "unhandled", "SN|Weird", "DecryptAndParse", "outer", "inner"}
	paths := map[string]func(error) error{
		"readFailure":   readFailure,
		"commitFailure": commitFailure,
		"safeError":     safeError,
		"partialMerge": func(err error) error {
			return partialMerge("note-1", []MergeSource{{UUID: "s1"}, {UUID: "s2"}}, 1, commitFailure(err))
		},
	}
	for pname, path := range paths {
		for cname, cause := range causes {
			t.Run(pname+"/"+cname, func(t *testing.T) {
				got := path(cause)
				if got == nil {
					t.Fatal("want an error")
				}
				for _, text := range []string{got.Error(), fmt.Sprintf("%v|%+v|%s|%q", got, got, got, got)} {
					for _, b := range bad {
						if strings.Contains(text, b) {
							t.Fatalf("the error text holds %q: %s", b, text)
						}
					}
				}
				// The cause stays reachable for the server's own use. The two kinds of
				// "not found" are answers, so they come back as the bare sentinel.
				var we *WriteError
				if !errors.As(got, &we) && !errors.Is(got, ErrNotFound) && !errors.Is(got, ErrTagNotFound) {
					t.Fatalf("want a *WriteError or a bare not-found, got %T", got)
				}
			})
		}
	}

	// The cause is reachable through the WriteError, so a caller can still tell a cap
	// from a kill. Only the text is fixed.
	if err := commitFailure(fmt.Errorf("%w: %v", writeengine.ErrCapReached, leaky)); !errors.Is(err, writeengine.ErrCapReached) {
		t.Fatal("the cause must stay reachable with errors.Is")
	}
	if err := readFailure(fmt.Errorf("%w: %v", snclient.ErrNoteNotFound, leaky)); err != ErrNotFound {
		t.Fatalf("an upstream not-found must come back as the bare ErrNotFound, got %v", err)
	}
	if err := readFailure(fmt.Errorf("%w: %v", snclient.ErrTagNotFound, leaky)); err != ErrTagNotFound {
		t.Fatalf("an upstream tag not-found must come back as the bare ErrTagNotFound, got %v", err)
	}
	if err := readFailure(fmt.Errorf("%w: %v", writeengine.ErrCoverage, leaky)); !strings.Contains(err.Error(), "run the merge again") {
		t.Fatalf("a coverage failure must tell the caller to run the merge again: %v", err)
	}
}

// safeError is the last check before an error leaves a tool. It lets this file's own
// errors through, unchanged, and wraps every other one.
func TestSafeErrorLetsOnlyOurOwnTextThrough(t *testing.T) {
	if safeError(nil) != nil {
		t.Fatal("no error must stay no error")
	}
	for _, own := range safeErrors {
		if got := safeError(own); got != own {
			t.Fatalf("our own error %q must pass unchanged, got %v", own, got)
		}
		wrapped := fmt.Errorf("%w (source 2)", own)
		if got := safeError(wrapped); got != wrapped {
			t.Fatalf("our own error with a position, %q, must pass unchanged, got %v", wrapped, got)
		}
	}
	leaky := errors.New("a title 'prod keys' and AKIAIOSFODNN7EXAMPLE")
	got := safeError(leaky)
	var we *WriteError
	if !errors.As(got, &we) || strings.Contains(got.Error(), "AKIA") || got.Error() != msgWrite {
		t.Fatalf("a foreign error must become the fixed WriteError text, got %v", got)
	}
	if !errors.Is(got, leaky) {
		t.Fatal("the cause must stay reachable")
	}
	// A WriteError, however it got here, already has fixed text.
	own := &WriteError{msg: "fixed", cause: leaky}
	if safeError(own) != own {
		t.Fatal("a WriteError must pass unchanged")
	}
}

// The fixed error texts are part of what the orchestrator reads, and none may echo an
// argument. A test pins the ones the spec names.
func TestFixedErrorTexts(t *testing.T) {
	for err, want := range map[error]string{
		ErrSensitiveMerge: "cannot merge a sensitive note; it is walled off",
		ErrSensitiveEdit:  "cannot edit a sensitive note; it is walled off from the assistant",
		ErrNotFound:       "note not found",
		ErrTagNotFound:    "tag not found",
	} {
		if err.Error() != want {
			t.Fatalf("error text %q, want %q", err, want)
		}
	}
}

// The tools check their arguments before they touch the session. A Writer with no
// guard, engine or gate would panic on its first read, so a refusal here proves that
// the check runs first, and that no read, plan or write is reached.
func TestToolsRefuseBadArgumentsBeforeAnyRead(t *testing.T) {
	w := &Writer{}
	const id = "00000000-0000-4000-8000-000000000001"
	for name, tc := range map[string]struct {
		call func() error
		want error
	}{
		"edit, blank uuid":         {func() error { _, err := w.NoteEdit(" ", "x", false); return err }, ErrEmptyUUID},
		"edit, blank text":         {func() error { _, err := w.NoteEdit(id, " \n ", false); return err }, ErrEmptyText},
		"rename, blank uuid":       {func() error { _, err := w.NoteRename("", "x", false); return err }, ErrEmptyUUID},
		"rename, blank title":      {func() error { _, err := w.NoteRename(id, " ", false); return err }, ErrEmptyTitle},
		"trash, blank uuid":        {func() error { _, err := w.NoteTrash("", false); return err }, ErrEmptyUUID},
		"untrash, blank uuid":      {func() error { _, err := w.NoteUntrash("", false); return err }, ErrEmptyUUID},
		"merge, no sources":        {func() error { _, err := w.NoteMerge(nil, "t", false); return err }, ErrMergeNeedsTwo},
		"merge, one source":        {func() error { _, err := w.NoteMerge([]string{id}, "t", false); return err }, ErrMergeNeedsTwo},
		"merge, the same twice":    {func() error { _, err := w.NoteMerge([]string{id, " " + id}, "t", false); return err }, ErrMergeNeedsTwo},
		"merge, blank uuid":        {func() error { _, err := w.NoteMerge([]string{id, ""}, "t", false); return err }, ErrEmptyUUID},
		"merge, blank title":       {func() error { _, err := w.NoteMerge([]string{id, "b"}, " ", false); return err }, ErrEmptyTitle},
		"apply, blank tag":         {func() error { _, err := w.TagApply(" ", []string{id}, false); return err }, ErrEmptyTitle},
		"apply, no notes":          {func() error { _, err := w.TagApply("t", nil, false); return err }, ErrNoNotes},
		"apply, blank note":        {func() error { _, err := w.TagApply("t", []string{" "}, false); return err }, ErrEmptyUUID},
		"detach, blank tag":        {func() error { _, err := w.TagDetach("", []string{id}, false); return err }, ErrEmptyUUID},
		"detach, no notes":         {func() error { _, err := w.TagDetach(id, nil, false); return err }, ErrNoNotes},
		"create, blank title":      {func() error { _, err := w.TagCreate("  ", false); return err }, ErrEmptyTitle},
		"tag rename, blank uuid":   {func() error { _, err := w.TagRename("", "t", false); return err }, ErrEmptyUUID},
		"tag rename, blank title":  {func() error { _, err := w.TagRename(id, "", false); return err }, ErrEmptyTitle},
		"tag trash, blank uuid":    {func() error { _, err := w.TagTrash(" ", false); return err }, ErrEmptyUUID},
		"a dry run is checked too": {func() error { _, err := w.NoteEdit("", "x", true); return err }, ErrEmptyUUID},
	} {
		t.Run(name, func(t *testing.T) {
			if err := tc.call(); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestNewWriterRefusesToServeWithoutAGuardAnEngineOrAGate(t *testing.T) {
	g := snclient.NewGuard(nil, "")
	e := writeengine.NewEngine(nil, nil, 1)
	gt := gate.New(prober{}, 0.5)
	for name, build := range map[string]func(){
		"no guard":  func() { NewWriter(nil, e, gt) },
		"no engine": func() { NewWriter(g, nil, gt) },
		"no gate":   func() { NewWriter(g, e, nil) },
		"nothing":   func() { NewWriter(nil, nil, nil) },
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("NewWriter must panic: the tools must not run ungated or unguarded")
				}
			}()
			build()
		})
	}
	if NewWriter(g, e, gt) == nil {
		t.Fatal("a complete wiring must give a Writer")
	}
}

func TestCleanUUIDs(t *testing.T) {
	got, err := cleanUUIDs([]string{" b ", "a", "b", "a ", "c"})
	if err != nil || !slices.Equal(got, []string{"b", "a", "c"}) {
		t.Fatalf("got %v, %v; want [b a c]: trimmed, a repeat dropped, first-seen order", got, err)
	}
	if got, err := cleanUUIDs(nil); err != nil || got == nil || len(got) != 0 {
		t.Fatalf("no uuids: got %#v, %v; want an empty list", got, err)
	}
	for _, in := range [][]string{{""}, {"a", "  "}, {"\t"}} {
		if _, err := cleanUUIDs(in); !errors.Is(err, ErrEmptyUUID) {
			t.Fatalf("cleanUUIDs(%q): got %v, want ErrEmptyUUID", in, err)
		}
	}
}

// PlanMerge checks the coverage of each source byte for byte. The merged text must
// copy the text of each source exactly, whatever it holds: CRLF, trailing spaces,
// blank lines, Unicode, a NUL, text that looks like the separator.
func TestMergeBodyCopiesEachSourceByteForByte(t *testing.T) {
	texts := []string{
		"line one\r\nline two  \r\n\r\n",
		"  leading and trailing space  ",
		"日本語 café — naïve\u00a0nbsp\ufeffbom",
		"nul\x00byte",
		"looks like a separator\n\n---\n\nbut is text",
		"",
		"\n\n\n",
		"# markdown\n\n```go\nfmt.Println(\"x\")\n```\n",
	}
	var srcs []*snclient.NoteView
	for i, text := range texts {
		srcs = append(srcs, nv(fmt.Sprintf("u%d", i), fmt.Sprintf("title %d", i), text))
	}
	body := mergeBody(srcs)
	for i, text := range texts {
		if !strings.Contains(body, text) {
			t.Fatalf("source %d is not in the merged text byte for byte: %q", i, text)
		}
		if t2 := strings.TrimSpace(text); t2 != "" && !strings.Contains(body, t2) { // the check PlanMerge makes
			t.Fatalf("source %d fails the coverage check of PlanMerge", i)
		}
	}
	// The layout: a title, a blank line, the text. A line of dashes between sources.
	want := "title 0\n\n" + texts[0] + "\n\n---\n\n" + "title 1\n\n" + texts[1]
	if got := mergeBody(srcs[:2]); got != want {
		t.Fatalf("layout:\n got %q\nwant %q", got, want)
	}
	if got := mergeBody([]*snclient.NoteView{nv("u", " ", "x"), nv("v", "", "y")}); got != "(untitled)\n\nx\n\n---\n\n(untitled)\n\ny" {
		t.Fatalf("a source with no title is named (untitled): %q", got)
	}
}

// The tag trash notice is a fact the caller must have. It says what the change is
// and what it is not: the official app does not hide a trashed tag, and the removal
// is the user's step.
func TestTagTrashNoticeStatesTheLimits(t *testing.T) {
	for _, must := range []string{"trashed", "reversible", "official", "does not hide", "step for the user", "never deletes"} {
		if !strings.Contains(tagTrashNotice, must) {
			t.Fatalf("the notice must say %q: %s", must, tagTrashNotice)
		}
	}
}

// Task 2 concern 7: the typed helpers of snclient lose fields, and the raw layer is
// the engine's own. The write tools go only through the engine's Plan methods and
// Commit. This parses write.go and fails if it names any call that writes some other
// way. It reads the syntax tree, so a doc comment may name a helper.
func TestWriterNamesNoLossyOrRawWriteHelper(t *testing.T) {
	forbidden := map[string]string{
		"ApplyTextEdit":   "lossy typed edit",
		"SetTrashed":      "lossy typed trash",
		"Raw":             "lossy typed push of a note",
		"RawTag":          "lossy typed push of a tag",
		"SetTagRefs":      "lossy typed tag references",
		"NewTag":          "makes a tag outside the engine",
		"Push":            "typed push",
		"PushEncrypted":   "the engine's raw push",
		"EncryptMutated":  "the engine's raw encrypt",
		"FetchRawOne":     "the engine's raw read",
		"FetchRawTag":     "the engine's raw read",
		"EditNoteText":    "a snclient template, not a tool path",
		"SeedNote":        "test helper",
		"SeedRawNote":     "test helper",
		"SeedRawTag":      "test helper",
		"SeedNoteWithRef": "test helper",
		"PlanCreateNote":  "merge goes through PlanMerge",
		"Kill":            "the kill switch is the server's, not a tool's",
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "write.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(file, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok {
			if why, bad := forbidden[sel.Sel.Name]; bad {
				t.Errorf("write.go:%d calls %s (%s)", fset.Position(sel.Pos()).Line, sel.Sel.Name, why)
			}
		}
		return true
	})

	// Commit has one call site, in apply, and apply does not reach it in a dry run. So
	// a dry run cannot write, and no tool can commit by another way around apply.
	var commits []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Commit" {
					commits = append(commits, fn.Name.Name)
				}
			}
			return true
		})
	}
	if !slices.Equal(commits, []string{"apply"}) {
		t.Errorf("write.go calls Commit in %v, want exactly one call, in apply", commits)
	}

	// Every engine call is one of the Plan methods, Commit or Client. A method added
	// to the engine later is not let through by default.
	allowed := map[string]bool{
		"PlanEditNote": true, "PlanRenameNote": true, "PlanTrashNote": true, "PlanUntrashNote": true,
		"PlanMerge": true, "PlanTagApply": true, "PlanTagAddNotes": true, "PlanTagDetach": true, "PlanTagCreate": true,
		"PlanTagRename": true, "PlanTagTrash": true, "Commit": true, "Client": true,
	}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			if recv, ok := sel.X.(*ast.SelectorExpr); ok && recv.Sel.Name == "eng" && !allowed[sel.Sel.Name] {
				t.Errorf("write.go:%d calls the engine method %s, which is not on the list of the write tools", fset.Position(call.Pos()).Line, sel.Sel.Name)
			}
		}
		return true
	})
}

// The second step of a merge moves a source to the trash only if the merged text
// still holds its text. A source that someone edited since the merge read it stays
// out: its new text is not in the merged note, and trashing it would hide that text.
// This drives trashMergeSource against the live server, with a body that is the text
// before the edit. A real merge cannot be held between its two steps, so the test
// calls the step directly.
func TestTrashMergeSourceLeavesASourceThatChanged(t *testing.T) {
	email, pw := testsupport.NewAccount(t) // skips cleanly if the Docker server is down
	c, err := snclient.SignIn(snclient.Config{Server: testsupport.TestServer}, email, pw,
		func(string) (string, error) { return "", nil })
	if err != nil {
		t.Fatal(err)
	}
	ledger := filepath.Join(t.TempDir(), "ledger.jsonl")
	led, err := writeengine.OpenLedger(ledger)
	if err != nil {
		t.Fatal(err)
	}
	w := NewWriter(snclient.NewGuard(c, ""), writeengine.NewEngine(c, led, 100), gate.New(prober{}, 0.5))

	unchanged, err := c.SeedNote(t, "Errands", "buy stamps")
	if err != nil {
		t.Fatal(err)
	}
	changed, err := c.SeedNote(t, "Plans", "call Bob")
	if err != nil {
		t.Fatal(err)
	}
	blank, err := c.SeedNote(t, "Empty", "")
	if err != nil {
		t.Fatal(err)
	}
	body := "Errands\n\nbuy stamps\n\n---\n\nPlans\n\ncall Bob\n\n---\n\nEmpty\n\n"

	// Another writer edits "Plans" after the merge read it.
	if err := c.EditNoteText(changed, "call Bob and Eve"); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name      string
		id        string
		wantTrash bool
	}{
		{"a source the merged text still holds", unchanged, true},
		{"a source edited since the merge read it", changed, false},
		{"a source with no text holds nothing to lose", blank, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := w.trashMergeSource(tc.id, body)
			if err != nil || got != tc.wantTrash {
				t.Fatalf("trashed = %v (err %v), want %v", got, err, tc.wantTrash)
			}
			n, err := c.FetchOne(tc.id)
			if err != nil || n == nil {
				t.Fatalf("the source is gone: %v", err)
			}
			if n.Trashed != tc.wantTrash {
				t.Fatalf("the note is trashed=%v, want %v", n.Trashed, tc.wantTrash)
			}
		})
	}

	// A source that is already in the trash is reported as trashed, and costs no write.
	written := ledgerRecords(t, ledger)
	if got, err := w.trashMergeSource(unchanged, body); err != nil || !got {
		t.Fatalf("a source already in the trash: trashed=%v err=%v, want true", got, err)
	}
	if now := ledgerRecords(t, ledger); now != written {
		t.Fatalf("a source already in the trash must cost no write: the ledger went from %d to %d records", written, now)
	}
	if _, err := w.trashMergeSource("00000000-0000-4000-8000-000000000000", body); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a source that is gone: got %v, want ErrNotFound", err)
	}
	// The one source that was edited cost no write either: two trashes, three states each.
	if got := ledgerRecords(t, ledger); got != 6 {
		t.Fatalf("the ledger holds %d records, want 6 (two trashes: the edited source was left alone)", got)
	}
}

// ledgerRecords counts the records in a ledger file.
func ledgerRecords(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(string(b), "\n")
}
