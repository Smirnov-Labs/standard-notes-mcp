package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/zalando/go-keyring"

	"github.com/smirnov-labs/standard-notes-mcp/internal/gate"
	"github.com/smirnov-labs/standard-notes-mcp/internal/mcptools"
	"github.com/smirnov-labs/standard-notes-mcp/internal/snclient"
	"github.com/smirnov-labs/standard-notes-mcp/internal/testsupport"
)

// serverBin is the sn-mcp executable, built once for the whole run. Every test
// drives this real binary over stdio, so the stdout and stderr wiring in main is
// covered along with the MCP behavior.
//
// The server signs in before it serves. A test that needs a running server uses a
// throwaway account on the Docker SN server and a fake jev, and skips when that
// server is down. The fail-fast tests need no server.
var serverBin string

// testLedger is the write ledger that every test server uses unless a test sets its
// own. Without it, the server would put the ledger in the config directory of the
// person who runs the tests.
var testLedger string

func TestMain(m *testing.M) { os.Exit(runTests(m)) }

// runTests exists so the deferred cleanup runs before os.Exit.
func runTests(m *testing.M) int {
	dir, err := os.MkdirTemp("", "sn-mcp-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "sn-mcp tests: temp dir:", err)
		return 1
	}
	defer os.RemoveAll(dir)

	serverBin = filepath.Join(dir, "sn-mcp")
	testLedger = filepath.Join(dir, "ledger.jsonl")
	if out, err := exec.Command("go", "build", "-o", serverBin, ".").CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "sn-mcp tests: go build: %v\n%s", err, out)
		return 1
	}
	return m.Run()
}

// cleanEnv is the whole environment a test gives the server: the two variables a
// process needs, a ledger in the test's own temp directory, and what the test adds.
// It never passes on the SN_* variables of the person who runs the tests. A real
// login must not reach a test. A later value of a variable wins, so a test can
// replace SN_LEDGER.
func cleanEnv(extra ...string) []string {
	return append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "SN_LEDGER=" + testLedger}, extra...)
}

// fakeJev serves a jev that rates every note 0, so only the scanner and the note
// kind decide what the gate stubs. It returns the base URL.
func fakeJev(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"answers":{"sensitive":{"noul":0}}}`)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// loginEnv is the environment of a server that signs in to the account with a
// password, with the fake jev as its gate.
func loginEnv(t *testing.T, email, password string, extra ...string) []string {
	t.Helper()
	return cleanEnv(append([]string{
		"SN_SERVER=" + testsupport.TestServer,
		"SN_EMAIL=" + email,
		"SN_PASSWORD=" + password,
		"TYPESAFE_BASE_URL=" + fakeJev(t),
	}, extra...)...)
}

// newVault registers a throwaway account, puts one note in it so the account has an
// items key, and returns the environment for a server that signs in to it. The test
// is skipped when the Docker server is down.
func newVault(t *testing.T) (env []string, email, password string, seed *snclient.Client) {
	t.Helper()
	email, password = testsupport.NewAccount(t)
	seed, err := snclient.SignIn(snclient.Config{Server: testsupport.TestServer}, email, password,
		func(string) (string, error) { return "", nil })
	if err != nil {
		t.Fatalf("sign in to the throwaway account: %v", err)
	}
	return loginEnv(t, email, password), email, password, seed
}

// The server speaks MCP over stdio. This uses the SDK's own client against the
// real binary: initialize handshake, tools/list, and a tools/call of every tool.
// The account holds a normal note and a secret one. The secret must be a bare stub
// in every result, and the text the server sends must hold none of it.
func TestToolsOverStdio(t *testing.T) {
	env, _, password, seed := newVault(t)
	normal, err := seed.SeedNote(t, "Shopping", "milk and eggs")
	if err != nil {
		t.Fatal(err)
	}
	secret, err := seed.SeedNote(t, "prod keys", "AKIAIOSFODNN7EXAMPLE")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, serverBin)
	cmd.Env = env
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	client := mcp.NewClient(&mcp.Implementation{Name: "sn-mcp-test", Version: "v0.0.0"}, nil)
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connect (initialize handshake): %v\nserver stderr:\n%s", err, &stderr)
	}
	defer session.Close()

	if got := session.InitializeResult().ServerInfo.Name; got != "standard-notes" {
		t.Errorf("serverInfo.name = %q, want %q", got, "standard-notes")
	}

	requireToolList(t, ctx, session)

	// leaks collects the whole text of every result, for one check at the end.
	var leaks strings.Builder
	call := func(name string, args map[string]any, out any) {
		t.Helper()
		var arguments any // stays nil for a call with no arguments: a nil map would send null
		if args != nil {
			arguments = args
		}
		res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: arguments})
		if err != nil {
			t.Fatalf("tools/call %s %v: %v", name, args, err)
		}
		text := resultText(t, res)
		if res.IsError {
			t.Fatalf("tools/call %s %v is a tool error: %s", name, args, text)
		}
		if res.StructuredContent == nil {
			t.Errorf("tools/call %s %v has no structured content", name, args)
		}
		// Decode into a zero value. A reused Row would keep a Note pointer that the
		// next result does not set.
		reflect.ValueOf(out).Elem().SetZero()
		if err := json.Unmarshal([]byte(text), out); err != nil {
			t.Fatalf("tools/call %s %v: text is not the result JSON: %v\n%s", name, args, err, text)
		}
		leaks.WriteString(text)
	}
	isStub := func(r *mcptools.Row, uuid string) bool {
		return r != nil && r.Note == nil && r.Stub != nil && *r.Stub == gate.Stub(uuid)
	}
	rowOf := func(rs mcptools.RowSet, uuid string) *mcptools.Row {
		for i := range rs.Rows {
			if r := &rs.Rows[i]; (r.Note != nil && r.Note.UUID == uuid) || (r.Stub != nil && r.Stub.UUID == uuid) {
				return r
			}
		}
		return nil
	}

	var all mcptools.RowSet
	call("notes_list", nil, &all)
	if r := rowOf(all, normal); len(all.Rows) != 2 || r == nil || r.Note == nil || r.Note.Title != "Shopping" {
		t.Fatalf("notes_list: want the normal note readable and one more row: %+v", all)
	}
	if !isStub(rowOf(all, secret), secret) {
		t.Fatalf("notes_list: the secret note is not a bare stub: %+v", all)
	}

	// Paging goes over the wire. Two pages of one row hold both notes once, and a
	// page past the end is an empty list, not null.
	var first, second, past mcptools.RowSet
	call("notes_list", map[string]any{"limit": 1}, &first)
	call("notes_list", map[string]any{"limit": 1, "offset": 1}, &second)
	call("notes_list", map[string]any{"offset": 2}, &past)
	inFirst, inSecond := rowOf(first, normal) != nil, rowOf(second, normal) != nil
	if len(first.Rows) != 1 || len(second.Rows) != 1 || inFirst == inSecond {
		t.Fatalf("two pages of one row must hold both notes once: %+v %+v", first, second)
	}
	if past.Rows == nil || len(past.Rows) != 0 {
		t.Fatalf("a page past the end must be an empty list: %+v", past)
	}

	var hits mcptools.RowSet
	call("notes_search", map[string]any{"query": "MILK"}, &hits)
	if r := rowOf(hits, normal); len(hits.Rows) != 1 || r == nil || r.Note == nil || !strings.Contains(r.Note.Snippet, "milk and eggs") {
		t.Fatalf("notes_search MILK: want the normal note with a snippet: %+v", hits)
	}
	call("notes_search", map[string]any{"query": "keys", "limit": 5}, &hits)
	if len(hits.Rows) != 1 || !isStub(&hits.Rows[0], secret) {
		t.Fatalf("notes_search keys: want the secret note as a bare stub: %+v", hits)
	}

	var got mcptools.GetResult
	call("notes_get", map[string]any{"uuid": normal}, &got)
	if got.Note == nil || got.Stub != nil || got.Note.Text != "milk and eggs" {
		t.Fatalf("notes_get on the normal note: %+v", got)
	}
	call("notes_get", map[string]any{"uuid": secret}, &got)
	if got.Note != nil || got.Stub == nil || *got.Stub != gate.Stub(secret) {
		t.Fatalf("notes_get on the secret note is not a bare stub: %+v", got)
	}

	var tags mcptools.TagList
	call("tags_list", nil, &tags)
	if tags.Tags == nil || len(tags.Tags) != 0 {
		t.Fatalf("tags_list on an account with no tags: %+v", tags)
	}

	// A tool error carries the tool's fixed text. A bad call is a tool error too, so
	// the model sees it and can correct the call.
	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "notes_get",
		Arguments: map[string]any{"uuid": "00000000-0000-4000-8000-000000000000"}})
	if err != nil || !res.IsError || resultText(t, res) != "note not found" {
		t.Fatalf("notes_get on an unknown uuid: err=%v result=%+v", err, res)
	}
	res, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "notes_search", Arguments: map[string]any{}})
	if err != nil || !res.IsError {
		t.Fatalf("notes_search without a query must be a tool error: err=%v result=%+v", err, res)
	}

	// Nothing the server wrote, on stdout or on stderr, holds the secret note or the
	// password.
	for _, bad := range []string{"AKIA", "prod keys", password} {
		if strings.Contains(leaks.String(), bad) {
			t.Errorf("LEAK: %q is in the results the server sent", bad)
		}
	}

	// Closing stdin is the client's shutdown signal. A clean exit (status 0)
	// makes Close return nil, and a log.Fatalf exit makes it return the error.
	if err := session.Close(); err != nil {
		t.Errorf("server did not exit cleanly on stdin EOF: %v\nserver stderr:\n%s", err, &stderr)
	}
	for _, bad := range []string{"AKIA", "prod keys", "Shopping", "milk and eggs", password} {
		if strings.Contains(stderr.String(), bad) {
			t.Errorf("LEAK: %q is in the server's stderr:\n%s", bad, &stderr)
		}
	}
}

// The tools, and the properties each one requires. The read tools are read-only. The
// write tools are not, and each one has an optional dry_run.
var (
	readToolsRequire = map[string][]string{
		"notes_search": {"query"}, "notes_get": {"uuid"}, "notes_list": nil, "tags_list": nil,
	}
	writeToolsRequire = map[string][]string{
		"note_edit": {"uuid", "text"}, "note_rename": {"uuid", "title"},
		"note_trash": {"uuid"}, "note_untrash": {"uuid"}, "note_merge": {"uuids", "title"},
		"tag_apply": {"tag", "note_uuids"}, "tag_detach": {"tag_uuid", "note_uuids"},
		"tag_create": {"title"}, "tag_rename": {"tag_uuid", "title"}, "tag_trash": {"tag_uuid"},
		"tag_merge": {"keeper_uuid", "source_uuids"},
	}
)

// sensitiveSays is what the description of a note tool must say about a sensitive note.
// The model reads it, and it must match what the tool does: edit and rename refuse such
// a note, merge refuses a sensitive source, and trash and untrash show a stub.
var sensitiveSays = map[string]string{
	"note_edit":    "refuses a note that the privacy gate flags as sensitive",
	"note_rename":  "refuses a note that the privacy gate flags as sensitive",
	"note_merge":   "refused when any source is sensitive",
	"note_trash":   "the result is a stub",
	"note_untrash": "the result is a stub",
}

// requireToolList checks tools/list: the four read tools and the eleven write tools, and
// nothing else. Every read tool is read-only. NO write tool is marked read-only: a
// client must not treat a tool that writes as one that does not. Every tool has an
// output schema. Optional inputs must stay optional: a call that leaves out limit,
// offset or dry_run has to be valid. No write tool takes a content_type, and the input
// schema of each allows no property it does not list, so a call that sends one is
// refused.
func requireToolList(t *testing.T, ctx context.Context, session *mcp.ClientSession) {
	t.Helper()
	list, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	var names []string
	for _, tool := range list.Tools {
		names = append(names, tool.Name)
		wantRequired, isRead := readToolsRequire[tool.Name]
		isWrite := false
		if !isRead {
			wantRequired, isWrite = writeToolsRequire[tool.Name]
		}
		switch {
		case isRead:
			if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
				t.Errorf("%s is not marked read-only", tool.Name)
			}
		case isWrite:
			if tool.Annotations != nil && tool.Annotations.ReadOnlyHint {
				t.Errorf("%s writes, and must NOT be marked read-only", tool.Name)
			}
		default:
			t.Errorf("unexpected tool %q", tool.Name)
		}
		if tool.OutputSchema == nil {
			t.Errorf("%s has no output schema", tool.Name)
		}
		var in struct {
			Required             []string
			Properties           map[string]json.RawMessage
			AdditionalProperties json.RawMessage
		}
		raw, _ := json.Marshal(tool.InputSchema)
		if err := json.Unmarshal(raw, &in); err != nil {
			t.Fatalf("%s input schema: %v", tool.Name, err)
		}
		if !slices.Equal(in.Required, wantRequired) {
			t.Errorf("%s requires %v, want %v", tool.Name, in.Required, wantRequired)
		}
		if isWrite {
			if _, ok := in.Properties["dry_run"]; !ok || slices.Contains(in.Required, "dry_run") {
				t.Errorf("%s must take an optional dry_run: %s", tool.Name, raw)
			}
			for prop := range in.Properties {
				if strings.Contains(strings.ToLower(prop), "content_type") || strings.Contains(strings.ToLower(prop), "deleted") {
					t.Errorf("%s takes a %q property, which no write tool may take", tool.Name, prop)
				}
			}
			if string(in.AdditionalProperties) != "false" {
				t.Errorf("%s must refuse a property it does not list (additionalProperties false): %s", tool.Name, raw)
			}
			if strings.TrimSpace(tool.Description) == "" {
				t.Errorf("%s has no description", tool.Name)
			}
			if want, ok := sensitiveSays[tool.Name]; ok && !strings.Contains(tool.Description, want) {
				t.Errorf("the description of %s must say %q, because that is what it does with a sensitive note:\n%s", tool.Name, want, tool.Description)
			}
		}
	}
	slices.Sort(names)
	var want []string
	for name := range readToolsRequire {
		want = append(want, name)
	}
	for name := range writeToolsRequire {
		want = append(want, name)
	}
	slices.Sort(want)
	if !slices.Equal(names, want) {
		t.Fatalf("tools/list = %v, want %v", names, want)
	}
}

// The write tools go over the wire, through the real binary, with the engine, the
// ledger and the cap that main wires in. The vault holds a normal note and a secret
// one. A dry run of a trash on the secret note must show only its stub. An edit or a
// rename of the secret note must be refused with fixed text, in a dry run and in a
// write, and the refusal must not use the cap. A write must change the normal note.
// The third write is past the cap of 2 and must be refused, with fixed text. No
// result, no log and no ledger line may hold the secret.
func TestWriteToolsOverStdio(t *testing.T) {
	env, _, password, seed := newVault(t)
	normal, err := seed.SeedNote(t, "Shopping", "milk and eggs")
	if err != nil {
		t.Fatal(err)
	}
	other, err := seed.SeedNote(t, "Errands", "buy stamps")
	if err != nil {
		t.Fatal(err)
	}
	secret, err := seed.SeedNote(t, "prod keys", "AKIAIOSFODNN7EXAMPLE")
	if err != nil {
		t.Fatal(err)
	}
	ledger := filepath.Join(t.TempDir(), "state", "ledger.jsonl") // the server makes the folder
	env = append(env, "SN_LEDGER="+ledger, "SN_MAX_WRITES=2")

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, serverBin)
	cmd.Env = env
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	client := mcp.NewClient(&mcp.Implementation{Name: "sn-mcp-test", Version: "v0.0.0"}, nil)
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connect: %v\nserver stderr:\n%s", err, &stderr)
	}
	defer session.Close()

	requireToolList(t, ctx, session)

	// everything collects the text of every result, for the leak check at the end.
	var everything strings.Builder
	call := func(name string, args map[string]any) (*mcp.CallToolResult, string) {
		t.Helper()
		res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			t.Fatalf("tools/call %s %v: %v", name, args, err)
		}
		text := resultText(t, res)
		everything.WriteString(text)
		return res, text
	}
	okNote := func(name string, args map[string]any) mcptools.NoteWriteResult {
		t.Helper()
		res, text := call(name, args)
		if res.IsError {
			t.Fatalf("tools/call %s %v is a tool error: %s", name, args, text)
		}
		if res.StructuredContent == nil {
			t.Errorf("tools/call %s %v has no structured content", name, args)
		}
		var out mcptools.NoteWriteResult
		if err := json.Unmarshal([]byte(text), &out); err != nil {
			t.Fatalf("tools/call %s %v: text is not the result JSON: %v\n%s", name, args, err, text)
		}
		if out.Action != name {
			t.Errorf("tools/call %s: result names the action %q", name, out.Action)
		}
		return out
	}
	live := func(id string) *snclient.NoteView { // read through the seeding client, not the server
		t.Helper()
		n, err := seed.FetchOne(id)
		if err != nil || n == nil {
			t.Fatalf("note %s: %v", id, err)
		}
		return n
	}

	// A dry run of a trash on the secret note: a stub, and nothing written.
	out := okNote("note_trash", map[string]any{"uuid": secret, "dry_run": true})
	if !out.DryRun || out.Before.Note != nil || out.Before.Stub == nil || *out.Before.Stub != gate.Stub(secret) || out.OpID != "" {
		t.Fatalf("note_trash dry run on the secret note: %+v", out)
	}
	// An edit and a rename of the secret note are refused, in a dry run and in a write. The
	// refusal is a tool error with fixed text. It writes nothing and uses none of the cap.
	for _, tc := range []struct {
		tool string
		args map[string]any
	}{
		{"note_edit", map[string]any{"uuid": secret, "text": "replacement body", "dry_run": true}},
		{"note_edit", map[string]any{"uuid": secret, "text": "replacement body"}},
		{"note_rename", map[string]any{"uuid": secret, "title": "Renamed", "dry_run": true}},
		{"note_rename", map[string]any{"uuid": secret, "title": "Renamed"}},
	} {
		res, text := call(tc.tool, tc.args)
		if !res.IsError || text != "cannot edit a sensitive note; it is walled off from the assistant" {
			t.Fatalf("%s %v on the secret note: error=%v text=%q", tc.tool, tc.args, res.IsError, text)
		}
	}
	if n := live(secret); n.Text != "AKIAIOSFODNN7EXAMPLE" || n.Title != "prod keys" || n.Trashed {
		t.Fatal("a dry run or a refused call changed the secret note")
	}
	// A dry run on the normal note shows what it holds now.
	out = okNote("note_edit", map[string]any{"uuid": normal, "text": "milk, eggs and butter", "dry_run": true})
	if out.Before.Note == nil || out.Before.Note.Text != "milk and eggs" || out.Before.Note.Title != "Shopping" {
		t.Fatalf("note_edit dry run on the normal note: %+v", out)
	}

	// The schema refuses a property the tool does not list. A content_type must never
	// reach the engine, so the note must stay as it is.
	res, text := call("note_edit", map[string]any{"uuid": normal, "text": "x", "content_type": "Tag"})
	if !res.IsError {
		t.Fatalf("a call with a content_type must be refused: %s", text)
	}
	if n := live(normal); n.Text != "milk and eggs" {
		t.Fatal("a refused call changed the note")
	}

	// A merge that holds the secret note is refused, with fixed text.
	res, text = call("note_merge", map[string]any{"uuids": []string{normal, secret}, "title": "Merged", "dry_run": true})
	if !res.IsError || text != "cannot merge a sensitive note; it is walled off" {
		t.Fatalf("note_merge with a sensitive source: error=%v text=%q", res.IsError, text)
	}

	// Two writes, within the cap: trash, then untrash. A read tool shows each state.
	out = okNote("note_trash", map[string]any{"uuid": normal})
	if out.DryRun || out.OpID == "" || out.Before.Note == nil || out.Before.Note.Trashed {
		t.Fatalf("note_trash: %+v", out)
	}
	if !live(normal).Trashed {
		t.Fatal("note_trash did not trash the note")
	}
	var got mcptools.GetResult
	res, text = call("notes_get", map[string]any{"uuid": normal})
	if res.IsError || json.Unmarshal([]byte(text), &got) != nil || got.Note == nil || !got.Note.Trashed || got.Note.Text != "milk and eggs" {
		t.Fatalf("notes_get after note_trash: %s", text)
	}
	out = okNote("note_untrash", map[string]any{"uuid": normal})
	if out.DryRun || out.OpID == "" || live(normal).Trashed {
		t.Fatalf("note_untrash: %+v trashed=%v", out, live(normal).Trashed)
	}

	// The third write is past the cap. It is refused with fixed text, and it changes nothing.
	res, text = call("note_trash", map[string]any{"uuid": other})
	if !res.IsError || !strings.Contains(text, "cap") || strings.Contains(text, "Errands") {
		t.Fatalf("a write past the cap: error=%v text=%q", res.IsError, text)
	}
	if live(other).Trashed {
		t.Fatal("a write past the cap changed the note")
	}
	// A dry run still works at the cap: it never commits.
	out = okNote("note_trash", map[string]any{"uuid": other, "dry_run": true})
	if !out.DryRun || out.Before.Note == nil || out.Before.Note.Title != "Errands" {
		t.Fatalf("a dry run at the cap: %+v", out)
	}

	// The ledger has every step of the two writes, and nothing of any note.
	b, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatalf("the server must make the ledger folder and file: %v", err)
	}
	records := strings.Count(string(b), "\n")
	if records != 6 || strings.Count(string(b), `"State":"verified"`) != 2 {
		t.Fatalf("the ledger holds %d records, want 6 (two writes, three steps each):\n%s", records, b)
	}
	if st, err := os.Stat(ledger); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("the ledger must be private to the user: %v %v", st, err)
	}
	for _, bad := range []string{"AKIA", "prod keys", "Shopping", "milk", "Errands", "stamps"} {
		if strings.Contains(string(b), bad) {
			t.Errorf("LEAK: %q is in the ledger:\n%s", bad, b)
		}
	}

	// No result, and no log line, holds the secret note or the password.
	for _, bad := range []string{"AKIA", "prod keys", password} {
		if strings.Contains(everything.String(), bad) {
			t.Errorf("LEAK: %q is in the results the server sent", bad)
		}
	}
	if err := session.Close(); err != nil {
		t.Errorf("server did not exit cleanly on stdin EOF: %v\nserver stderr:\n%s", err, &stderr)
	}
	for _, bad := range []string{"AKIA", "prod keys", "Shopping", "milk and eggs", "Errands", "buy stamps", "replacement body", password} {
		if strings.Contains(stderr.String(), bad) {
			t.Errorf("LEAK: %q is in the server's stderr:\n%s", bad, &stderr)
		}
	}
	if !strings.Contains(stderr.String(), "eleven write tools") || !strings.Contains(stderr.String(), ledger) || !strings.Contains(stderr.String(), "at most 2 writes") {
		t.Errorf("the start-up line must name the write tools, the ledger and the cap:\n%s", &stderr)
	}
}

// The SDK checks every result against the output schema it infers from the result
// type, and a result that fails is a protocol error, not a tool result. Direct calls
// of the Writer cannot see that. This calls all eleven write tools through the real
// binary, as a dry run and as a write, and decodes each result. It then reads the
// vault back, through the seeding client, to check that the writes landed.
func TestEveryWriteToolOverStdio(t *testing.T) {
	env, _, _, seed := newVault(t)
	var ids [3]string
	for i, n := range [][2]string{{"Shopping", "milk and eggs"}, {"Errands", "buy stamps"}, {"Plans", "call Bob"}} {
		id, err := seed.SeedNote(t, n[0], n[1])
		if err != nil {
			t.Fatal(err)
		}
		ids[i] = id
	}
	a, b, c := ids[0], ids[1], ids[2]

	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, serverBin)
	cmd.Env = env
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	client := mcp.NewClient(&mcp.Implementation{Name: "sn-mcp-test", Version: "v0.0.0"}, nil)
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connect: %v\nserver stderr:\n%s", err, &stderr)
	}
	defer session.Close()

	// call runs a tool, fails on a tool error or a protocol error, and decodes the
	// result into out. The structured content is the result as the schema saw it.
	call := func(name string, args map[string]any, out any) {
		t.Helper()
		res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			t.Fatalf("tools/call %s %v: %v", name, args, err)
		}
		text := resultText(t, res)
		if res.IsError {
			t.Fatalf("tools/call %s %v is a tool error: %s", name, args, text)
		}
		if res.StructuredContent == nil {
			t.Fatalf("tools/call %s %v has no structured content", name, args)
		}
		reflect.ValueOf(out).Elem().SetZero()
		if err := json.Unmarshal([]byte(text), out); err != nil {
			t.Fatalf("tools/call %s %v: text is not the result JSON: %v\n%s", name, args, err, text)
		}
	}
	var tg mcptools.TagWriteResult
	var nw mcptools.NoteWriteResult
	var mg mcptools.MergeResult
	var tm mcptools.TagMergeResult

	// tag_create, then tag_apply, tag_detach and tag_rename on that tag.
	call("tag_create", map[string]any{"title": "project", "dry_run": true}, &tg)
	if !tg.DryRun || tg.Action != "tag_create" || !tg.Created || tg.Tag.UUID != "" || tg.Tag.Title != "project" || tg.OpID != "" {
		t.Fatalf("tag_create dry run: %+v", tg)
	}
	call("tag_create", map[string]any{"title": "project"}, &tg)
	if tg.DryRun || !tg.Created || tg.Tag.UUID == "" || tg.OpID == "" {
		t.Fatalf("tag_create: %+v", tg)
	}
	project := tg.Tag.UUID

	call("tag_apply", map[string]any{"tag": "project", "note_uuids": []string{a, b}, "dry_run": true}, &tg)
	if !tg.DryRun || tg.Action != "tag_apply" || tg.NotesChanged != 2 || tg.Tag.UUID != project {
		t.Fatalf("tag_apply dry run: %+v", tg)
	}
	call("tag_apply", map[string]any{"tag": "project", "note_uuids": []string{a, b}}, &tg)
	if tg.DryRun || tg.NotesChanged != 2 || tg.OpID == "" {
		t.Fatalf("tag_apply: %+v", tg)
	}
	call("tag_detach", map[string]any{"tag_uuid": project, "note_uuids": []string{b, c}, "dry_run": true}, &tg)
	if !tg.DryRun || tg.Action != "tag_detach" || tg.NotesChanged != 1 || tg.NotesSkipped != 1 {
		t.Fatalf("tag_detach dry run: %+v", tg)
	}
	call("tag_detach", map[string]any{"tag_uuid": project, "note_uuids": []string{b}}, &tg)
	if tg.DryRun || tg.NotesChanged != 1 || tg.OpID == "" {
		t.Fatalf("tag_detach: %+v", tg)
	}
	call("tag_rename", map[string]any{"tag_uuid": project, "title": "projects/alpha", "dry_run": true}, &tg)
	if !tg.DryRun || tg.Action != "tag_rename" || tg.NewTitle == nil || *tg.NewTitle != "projects/alpha" || tg.Tag.Title != "project" {
		t.Fatalf("tag_rename dry run: %+v", tg)
	}
	call("tag_rename", map[string]any{"tag_uuid": project, "title": "projects/alpha"}, &tg)
	if tg.DryRun || tg.OpID == "" {
		t.Fatalf("tag_rename: %+v", tg)
	}

	// tag_merge: a second tag, merged into the project tag by uuid, then trashed.
	call("tag_create", map[string]any{"title": "scratch"}, &tg)
	scratch := tg.Tag.UUID
	call("tag_apply", map[string]any{"tag": "scratch", "note_uuids": []string{c}}, &tg)
	call("tag_merge", map[string]any{"keeper_uuid": project, "source_uuids": []string{scratch}, "dry_run": true}, &tm)
	if !tm.DryRun || tm.Action != "tag_merge" || tm.Keeper.UUID != project || len(tm.Sources) != 1 || tm.NotesAdded != 1 {
		t.Fatalf("tag_merge dry run: %+v", tm)
	}
	call("tag_merge", map[string]any{"keeper_uuid": project, "source_uuids": []string{scratch}}, &tm)
	if tm.DryRun || len(tm.OpIDs) == 0 || tm.Notice == "" {
		t.Fatalf("tag_merge: %+v", tm)
	}

	// The note tools: rename, edit, trash and untrash.
	call("note_rename", map[string]any{"uuid": c, "title": "Plans for May", "dry_run": true}, &nw)
	if !nw.DryRun || nw.Action != "note_rename" || nw.Before.Note == nil || nw.Before.Note.Title != "Plans" || nw.NewTitle == nil || *nw.NewTitle != "Plans for May" {
		t.Fatalf("note_rename dry run: %+v", nw)
	}
	call("note_rename", map[string]any{"uuid": c, "title": "Plans for May"}, &nw)
	call("note_edit", map[string]any{"uuid": c, "text": "call Bob and Eve"}, &nw)
	if nw.DryRun || nw.Action != "note_edit" || nw.OpID == "" || nw.NewText == nil || *nw.NewText != "call Bob and Eve" {
		t.Fatalf("note_edit: %+v", nw)
	}
	call("note_trash", map[string]any{"uuid": c, "dry_run": true}, &nw)
	call("note_trash", map[string]any{"uuid": c}, &nw)
	call("note_untrash", map[string]any{"uuid": c, "dry_run": true}, &nw)
	call("note_untrash", map[string]any{"uuid": c}, &nw)
	if nw.DryRun || nw.Action != "note_untrash" || nw.Before.Note == nil || !nw.Before.Note.Trashed {
		t.Fatalf("note_untrash: %+v", nw)
	}

	// note_merge: the dry run lists the plan, the write makes the note and trashes the sources.
	call("note_merge", map[string]any{"uuids": []string{a, b}, "title": "All", "dry_run": true}, &mg)
	if !mg.DryRun || mg.NoteUUID != "" || mg.Title != "All" || len(mg.Sources) != 2 || mg.Bytes == 0 || mg.Sources[0].Title != "Shopping" {
		t.Fatalf("note_merge dry run: %+v", mg)
	}
	call("note_merge", map[string]any{"uuids": []string{a, b}, "title": "All"}, &mg)
	if mg.DryRun || mg.NoteUUID == "" || mg.OpID == "" || len(mg.Sources) != 2 || !mg.Sources[0].Trashed || !mg.Sources[1].Trashed || mg.Notice != "" {
		t.Fatalf("note_merge: %+v", mg)
	}

	// tag_trash: marks the tag, says what that means, and deletes nothing.
	call("tag_trash", map[string]any{"tag_uuid": project, "dry_run": true}, &tg)
	if !tg.DryRun || tg.Action != "tag_trash" || !strings.Contains(tg.Notice, "official") {
		t.Fatalf("tag_trash dry run: %+v", tg)
	}
	call("tag_trash", map[string]any{"tag_uuid": project}, &tg)
	if tg.DryRun || tg.OpID == "" || tg.Tag.Title != "projects/alpha" {
		t.Fatalf("tag_trash: %+v", tg)
	}

	// The vault, read through the seeding client, holds the result of every write.
	notes, tags, err := seed.Fetch()
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]*snclient.NoteView{}
	for _, n := range notes {
		byID[n.UUID] = n
	}
	if n := byID[c]; n == nil || n.Title != "Plans for May" || n.Text != "call Bob and Eve" || n.Trashed {
		t.Fatalf("the note Plans: %+v", n)
	}
	for _, id := range []string{a, b} {
		if n := byID[id]; n == nil || !n.Trashed {
			t.Fatalf("source %s must be in the trash, and not deleted: %+v", id, n)
		}
	}
	if n := byID[mg.NoteUUID]; n == nil || n.Title != "All" || n.Trashed ||
		n.Text != "Shopping\n\nmilk and eggs\n\n---\n\nErrands\n\nbuy stamps" {
		t.Fatalf("the merged note: %+v", n)
	}
	// Two tags survive (nothing is deleted): the project tag, trashed by tag_trash and
	// holding a plus the c that tag_merge moved onto it, and the scratch tag, trashed by
	// the merge and still holding c.
	byTag := map[string]*snclient.TagView{}
	for _, g := range tags {
		byTag[g.UUID] = g
	}
	if len(tags) != 2 {
		t.Fatalf("want 2 tags (projects/alpha and scratch), got %d: %+v", len(tags), tags)
	}
	if g := byTag[project]; g == nil || g.Title != "projects/alpha" || !slices.Equal(g.NoteUUIDs, []string{a, c}) {
		t.Fatalf("the project tag: %+v", g)
	}
	if g := byTag[scratch]; g == nil || g.Title != "scratch" || !slices.Equal(g.NoteUUIDs, []string{c}) {
		t.Fatalf("the scratch tag: %+v", g)
	}
	for _, id := range []string{project, scratch} {
		if raw, err := seed.FetchRawTag(id); err != nil || !strings.Contains(raw.Content(), `"trashed":true`) {
			t.Fatalf("tag %s must be trashed and kept: %v", id, err)
		}
	}
}

// A cap that is not a whole number of 0 or more stops the server at the start. It does
// not fall back to the default: a typo must not become a different cap. The check needs
// no sign-in, so it comes first.
func TestBadMaxWritesFailsFast(t *testing.T) {
	for _, v := range []string{"lots", "-1", "1.5", "1e3", "0x10"} {
		t.Run(v, func(t *testing.T) {
			requireFailedStart(t, runRaw(t, 0, cleanEnv("SN_MAX_WRITES="+v)), "SN_MAX_WRITES")
		})
	}
}

// A ledger that cannot be opened stops the server at the start, and says so. The
// engine must not run without one.
func TestUnusableLedgerFailsFast(t *testing.T) {
	email, password := testsupport.NewAccount(t)
	file := filepath.Join(t.TempDir(), "a-file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A folder cannot be made under a file.
	run := runRaw(t, 0, loginEnv(t, email, password, "SN_LEDGER="+filepath.Join(file, "sub", "ledger.jsonl")))
	requireFailedStart(t, run, "write ledger")
	if strings.Contains(run.stderr, password) {
		t.Errorf("the password is in stderr: %q", run.stderr)
	}
}

// With no SN_LEDGER, the ledger is ledger.jsonl in a standard-notes-mcp folder of the
// user's config directory, and the folder and the file are private to the user. The
// test moves HOME to a temp directory, so that it writes nothing of its own to the
// real one.
func TestDefaultLedgerIsInTheConfigDirectory(t *testing.T) {
	email, password := testsupport.NewAccount(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	cfgDir, err := os.UserConfigDir() // the same call the server makes, under the moved HOME
	if err != nil {
		t.Skipf("no config directory here: %v", err)
	}
	want := filepath.Join(cfgDir, "standard-notes-mcp", "ledger.jsonl")

	run := runRaw(t, 0, loginEnv(t, email, password, "HOME="+home, "SN_LEDGER="))
	if run.exit != nil || !strings.Contains(run.stderr, "ledger "+want) {
		t.Fatalf("the start-up line must name the default ledger %s: %v\n%s", want, run.exit, run.stderr)
	}
	if st, err := os.Stat(want); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("the default ledger %s: %v %v", want, st, err)
	}
	if st, err := os.Stat(filepath.Dir(want)); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("the ledger folder must be private to the user: %v %v", st, err)
	}
}

// resultText is the text of a tool result: one block of text.
func resultText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) != 1 {
		t.Fatalf("result has %d content blocks, want 1: %+v", len(res.Content), res)
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("result content is %T, want text", res.Content[0])
	}
	return text.Text
}

// The stdio transport owns stdout, so one stray byte there corrupts the client's
// JSON-RPC stream. This speaks raw JSON-RPC to the binary and requires that every
// line it writes to stdout is a JSON-RPC 2.0 message, and that no call fails. The
// tools/call frames omit "arguments" (the SDK client always sends {}), because
// these tools take none that is required.
func TestStdoutCarriesOnlyProtocolFrames(t *testing.T) {
	env, _, _, seed := newVault(t)
	if _, err := seed.SeedNote(t, "Shopping", "milk and eggs"); err != nil {
		t.Fatal(err)
	}
	run := runRaw(t, 4, env,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"raw-test","version":"0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"notes_list"}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"tags_list"}}`,
	)

	answered := map[string]bool{}
	for _, line := range run.stdout {
		f := parseFrame(t, line)
		if f.Error != nil || f.Result.IsError {
			t.Errorf("error response: %s", line)
		}
		answered[string(f.ID)] = true
	}
	for _, id := range []string{"1", "2", "3", "4"} {
		if !answered[id] {
			t.Errorf("no response to request id %s\nstdout lines: %q\nstderr:\n%s", id, run.stdout, run.stderr)
		}
	}
	if run.exit != nil {
		t.Errorf("server did not exit cleanly after stdin closed: %v\nstderr:\n%s", run.exit, run.stderr)
	}
}

// When the server dies it must say so on stderr and leave stdout alone. The SDK
// treats a malformed line as a fatal transport error, so this drives the
// log.Fatalf path in main that runs after a successful start.
func TestFatalErrorGoesToStderr(t *testing.T) {
	env, _, _, _ := newVault(t)
	run := runRaw(t, 0, env, "this line is not JSON-RPC")

	var exitErr *exec.ExitError
	if !errors.As(run.exit, &exitErr) {
		t.Fatalf("server exit = %v, want a non-zero exit status\nstdout: %q\nstderr: %q", run.exit, run.stdout, run.stderr)
	}
	if !strings.Contains(run.stderr, "sn-mcp:") {
		t.Errorf("fatal error was not logged to stderr; stderr = %q", run.stderr)
	}
	for _, line := range run.stdout {
		parseFrame(t, line) // flags the log line if it went to stdout
	}
}

// requireFailedStart fails unless the server stopped at once with a non-zero exit,
// said want on stderr, and wrote nothing to stdout.
func requireFailedStart(t *testing.T, run rawRun, want string) {
	t.Helper()
	var exitErr *exec.ExitError
	if !errors.As(run.exit, &exitErr) {
		t.Fatalf("server exit = %v, want a non-zero exit status\nstderr: %q", run.exit, run.stderr)
	}
	if len(run.stdout) != 0 {
		t.Errorf("stdout must stay empty, got %q", run.stdout)
	}
	if !strings.Contains(run.stderr, "sn-mcp:") || !strings.Contains(run.stderr, want) {
		t.Errorf("stderr must say %q, got %q", want, run.stderr)
	}
}

// The server signs in before it serves. When it cannot, it must stop at once, say
// why on stderr, and write nothing to stdout.
func TestStartupFailsFast(t *testing.T) {
	t.Run("no login at all", func(t *testing.T) {
		requireFailedStart(t, runRaw(t, 0, cleanEnv()), "SN_EMAIL")
	})
	t.Run("a saved session that is not there, and no password", func(t *testing.T) {
		requireFailedStart(t, runRaw(t, 0, cleanEnv("SN_SESSION_REF=sn-mcp-test-no-such-session")), "cannot use the saved session")
	})
	t.Run("a wrong password", func(t *testing.T) {
		email, password := testsupport.NewAccount(t)
		run := runRaw(t, 0, loginEnv(t, email, "not-"+password))
		requireFailedStart(t, run, "sign in")
		// The log files of an MCP server are not behind the deny rules. A password
		// in one would be in reach of Claude.
		for _, secret := range []string{password, "not-" + password} {
			if strings.Contains(run.stderr, secret) {
				t.Errorf("the password is in stderr: %q", run.stderr)
			}
		}
	})
}

// SN_SESSION_REF is how the sample config signs in. A start that signs in with a
// password saves the session in the keyring under the ref. A later start with the
// ref and no password restores it, and reads the vault.
func TestSavedSessionIsRestored(t *testing.T) {
	_, email, password, seed := newVault(t)
	if _, err := seed.SeedNote(t, "Shopping", "milk and eggs"); err != nil {
		t.Fatal(err)
	}
	ref := "sn-mcp-test-" + email
	t.Cleanup(func() { _ = snclient.ForgetSession(ref) })

	first := runRaw(t, 0, loginEnv(t, email, password, "SN_SESSION_REF="+ref))
	if first.exit != nil {
		t.Fatalf("first start: %v\nstderr:\n%s", first.exit, first.stderr)
	}
	if strings.Contains(first.stderr, "could not save the session") {
		t.Skipf("no usable keyring here:\n%s", first.stderr)
	}
	if !strings.Contains(first.stderr, "saved the session") {
		t.Fatalf("the first start did not save the session:\n%s", first.stderr)
	}

	second := runRaw(t, 2, cleanEnv(
		"SN_SERVER="+testsupport.TestServer, "SN_SESSION_REF="+ref, "TYPESAFE_BASE_URL="+fakeJev(t)),
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"raw-test","version":"0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"tags_list"}}`,
	)
	if second.exit != nil || !strings.Contains(second.stderr, "restored the saved session") {
		t.Fatalf("second start did not restore the session: %v\nstderr:\n%s", second.exit, second.stderr)
	}
	if len(second.stdout) != 2 {
		t.Fatalf("second start answered %d requests, want 2: %q", len(second.stdout), second.stdout)
	}
	for _, line := range second.stdout {
		if f := parseFrame(t, line); f.Error != nil || f.Result.IsError {
			t.Errorf("error response from the restored session: %s", line)
		}
	}
}

// A saved session can go stale. The server must find that at the start, and say
// why. A password must then be enough to recover: the server signs in again and
// replaces the saved session.
func TestStaleSavedSessionFallsBackToThePassword(t *testing.T) {
	_, email, password, _ := newVault(t)
	ref := "sn-mcp-test-stale-" + email
	t.Cleanup(func() { _ = snclient.ForgetSession(ref) })

	// A session whose tokens ran out long ago. The fields are those of the blob that
	// snclient saves. The service name is snclient's keyring service.
	stale := `{"Server":"` + testsupport.TestServer + `","MasterKey":"stale","AccessToken":"stale","RefreshToken":"stale","AccessExp":1,"RefreshExp":1}`
	if err := keyring.Set("standard-notes-mcp", ref, stale); err != nil {
		t.Skipf("no usable keyring here: %v", err)
	}

	refOnly := cleanEnv("SN_SERVER="+testsupport.TestServer, "SN_SESSION_REF="+ref)
	requireFailedStart(t, runRaw(t, 0, refOnly), "refresh token expired")

	run := runRaw(t, 0, loginEnv(t, email, password, "SN_SESSION_REF="+ref))
	if run.exit != nil || !strings.Contains(run.stderr, "signing in with SN_EMAIL instead") || !strings.Contains(run.stderr, "saved the session") {
		t.Fatalf("a password must replace a stale session: %v\nstderr:\n%s", run.exit, run.stderr)
	}

	again := runRaw(t, 0, refOnly)
	if again.exit != nil || !strings.Contains(again.stderr, "restored the saved session") {
		t.Fatalf("the new session must be saved under the ref: %v\nstderr:\n%s", again.exit, again.stderr)
	}
}

// frame is the part of a JSON-RPC 2.0 message that the tests read.
type frame struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Error   json.RawMessage `json:"error"`
	Result  struct {
		IsError bool `json:"isError"` // a tools/call result that is a tool error
	} `json:"result"`
}

// parseFrame reports an error unless line is a JSON-RPC 2.0 message. A log line,
// a stray Println or a blank line on stdout all fail here.
func parseFrame(t *testing.T, line string) frame {
	t.Helper()
	var f frame
	if err := json.Unmarshal([]byte(line), &f); err != nil || f.JSONRPC != "2.0" {
		t.Errorf("stdout carries non-protocol output: %q", line)
	}
	return f
}

type rawRun struct {
	stdout []string // every line the server wrote to stdout, in order
	stderr string
	exit   error // nil when the server exited with status 0
}

// runRaw starts the real binary with env and writes frames to its stdin, one per
// line. It closes stdin only after it has read awaitLines lines from stdout, as a
// real client does: EOF cancels the requests still in flight, so closing at once
// would race the responses. It then reads stdout to the end and waits for the exit.
func runRaw(t *testing.T, awaitLines int, env []string, frames ...string) rawRun {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, serverBin)
	cmd.Env = env
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	for _, f := range frames {
		fmt.Fprintln(stdin, f) // a server that already died shows in the assertions on its output
	}
	if awaitLines == 0 {
		stdin.Close()
	}
	var lines []string
	sc := bufio.NewScanner(stdout)
	for sc.Scan() {
		lines = append(lines, sc.Text())
		if len(lines) == awaitLines {
			stdin.Close()
		}
	}
	if err := sc.Err(); err != nil {
		t.Errorf("reading stdout: %v", err)
	}
	exit := cmd.Wait() // before stderr.String(): Wait finishes the copy from the stderr pipe
	return rawRun{stdout: lines, stderr: stderr.String(), exit: exit}
}
