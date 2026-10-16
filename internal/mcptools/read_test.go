package mcptools_test

// Live tests for the gated read tools. They need the Docker SN server and skip
// cleanly without it (testsupport.NewAccount probes the server and honors
// SN_TEST_SERVER=off). The privacy paths are also tested without a server, in
// read_internal_test.go.
//
// The rule under test: a sensitive note's title, body or snippet never appears in
// a tool result. A sensitive note is only ever a gate.Stubbed (uuid and label).
// Every leak check here runs over the JSON of the WHOLE result, which is what the
// MCP SDK sends to the orchestrator. A check on the fields a test thought to read
// would miss a field it did not.

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jonhadfield/gosn-v2/items"
	"github.com/smirnov-labs/standard-notes-mcp/internal/gate"
	"github.com/smirnov-labs/standard-notes-mcp/internal/mcptools"
	"github.com/smirnov-labs/standard-notes-mcp/internal/snclient"
	"github.com/smirnov-labs/standard-notes-mcp/internal/testsupport"
)

// notSensitive is a jev prober that always says "not sensitive". A test that uses
// it proves that the DETERMINISTIC scanner, or the forced note kind, alone stubs
// a note. (gate.New takes an unexported interface. A value of any type with this
// method satisfies it.)
type notSensitive struct{}

func (notSensitive) SensitiveProbability(string) (float64, error) { return 0, nil }

// jevDown is a jev prober that always fails. The gate must read that as
// sensitive, so every note with text is stubbed.
type jevDown struct{}

func (jevDown) SensitiveProbability(string) (float64, error) { return 0, errors.New("jev is down") }

func signIn(t *testing.T) *snclient.Client {
	t.Helper()
	email, pw := testsupport.NewAccount(t) // skips cleanly if the Docker server is down
	c, err := snclient.SignIn(snclient.Config{Server: testsupport.TestServer}, email, pw,
		func(string) (string, error) { return "", nil })
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func seed(t *testing.T, c *snclient.Client, title, text string) string {
	t.Helper()
	id, err := c.SeedNote(t, title, text)
	if err != nil {
		t.Fatalf("seed %q: %v", title, err)
	}
	return id
}

// seedWith pushes a note whose metadata the test sets. SeedNote cannot do that.
func seedWith(t *testing.T, c *snclient.Client, title, text string, edit func(*items.NoteContent)) string {
	t.Helper()
	n, err := items.NewNote(title, text, nil)
	if err != nil {
		t.Fatalf("new note %q: %v", title, err)
	}
	edit(&n.Content)
	n.Content.SetUpdateTime(time.Now().UTC())
	if _, err := c.Push(items.Items{&n}); err != nil {
		t.Fatalf("push %q: %v", title, err)
	}
	return n.GetUUID()
}

// wire is the result as the MCP layer sends it: the SDK marshals the value a tool
// returns to JSON.
func wire(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// requireNoLeak fails, naming the leak, if any telltale is in the JSON of v.
func requireNoLeak(t *testing.T, where string, v any, telltales ...string) {
	t.Helper()
	body := wire(t, v)
	for _, s := range telltales {
		if strings.Contains(body, s) {
			t.Fatalf("LEAK through %s: %q is in the result:\n%s", where, s, body)
		}
	}
}

// find returns the row for uuid, or nil.
func find(rs mcptools.RowSet, uuid string) *mcptools.Row {
	for i := range rs.Rows {
		r := &rs.Rows[i]
		if (r.Note != nil && r.Note.UUID == uuid) || (r.Stub != nil && r.Stub.UUID == uuid) {
			return r
		}
	}
	return nil
}

// requireStub fails unless uuid is in rs as a stub and nothing else.
func requireStub(t *testing.T, where string, rs mcptools.RowSet, uuid string) {
	t.Helper()
	r := find(rs, uuid)
	if r == nil {
		t.Fatalf("%s: no row for the sensitive note %s; want a stub", where, uuid)
	}
	if r.Note != nil || r.Stub == nil || *r.Stub != gate.Stub(uuid) {
		t.Fatalf("%s: the sensitive note %s is not a bare stub: %s", where, uuid, wire(t, r))
	}
}

// requireReadable fails unless uuid is in rs as a note with this title.
func requireReadable(t *testing.T, where string, rs mcptools.RowSet, uuid, title string) *mcptools.NoteRow {
	t.Helper()
	r := find(rs, uuid)
	if r == nil || r.Note == nil || r.Stub != nil || r.Note.Title != title {
		t.Fatalf("%s: want %s as the readable note %q, got %s", where, uuid, title, wire(t, r))
	}
	return r.Note
}

// The plan's acceptance test: seed a normal note and a secret one, and check that
// the secret is a stub on every tool. The prober says "not sensitive" for
// everything, so the deterministic scanner alone must catch the secret.
func TestReadToolsStubSensitive(t *testing.T) {
	c := signIn(t)
	normal := seed(t, c, "Shopping", "milk and eggs")
	secret := seed(t, c, "prod keys", "AKIAIOSFODNN7EXAMPLE")

	tools := mcptools.New(snclient.NewGuard(c, ""), gate.New(notSensitive{}, 0.5))

	out, err := tools.Search("keys", 0, 0) // matches the secret's TITLE
	if err != nil {
		t.Fatal(err)
	}
	body := wire(t, out)
	if strings.Contains(body, "AKIAIOSFODNN7EXAMPLE") || strings.Contains(body, "prod keys") {
		t.Fatalf("secret note title/body leaked through notes_search: %s", body)
	}
	requireStub(t, "notes_search", out, secret) // a sensitive match is a stub, not a gap
	if find(out, normal) != nil {
		t.Fatal("notes_search \"keys\" returned a note that does not match")
	}

	got, err := tools.Get(secret)
	if err != nil {
		t.Fatal(err)
	}
	if got.Note != nil || got.Stub == nil || *got.Stub != gate.Stub(secret) {
		t.Fatalf("notes_get must stub a sensitive note: %s", wire(t, got))
	}
	requireNoLeak(t, "notes_get", got, "AKIAIOSFODNN7EXAMPLE", "prod keys")

	got, err = tools.Get(normal)
	if err != nil {
		t.Fatal(err)
	}
	if got.Stub != nil || got.Note == nil || got.Note.Text != "milk and eggs" || got.Note.Title != "Shopping" {
		t.Fatalf("a normal note must pass through: %s", wire(t, got))
	}

	all, err := tools.List(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	requireReadable(t, "notes_list", all, normal, "Shopping")
	requireStub(t, "notes_list", all, secret)
	requireNoLeak(t, "notes_list", all, "AKIAIOSFODNN7EXAMPLE", "prod keys")
}

// A note the scanner cannot flag must still be stubbed when it is an
// authenticator note (spec 6.1: authentication is force-flagged). The texts below
// are plain words, so only the note kind can be the reason. Each marker is tried
// alone: Standard Notes writes both, but another client may write one.
func TestReadToolsEndToEnd(t *testing.T) {
	c := signIn(t)

	const (
		tokenVault = "org.standardnotes.token-vault" // FeatureIdentifier.TokenVaultEditor
		authType   = "authentication"                // NoteType.Authentication
	)
	setBoth := func(n *items.NoteContent) { n.NoteType, n.EditorIdentifier = authType, tokenVault }
	setType := func(n *items.NoteContent) { n.NoteType = authType }
	setEditor := func(n *items.NoteContent) { n.EditorIdentifier = tokenVault }
	trash := func(n *items.NoteContent) { n.SetTrashed(true) }

	normal := seed(t, c, "Shopping", "milk and eggs")
	prodKeys := seed(t, c, "prod keys", "AKIAIOSFODNN7EXAMPLE")
	bodyOnly := seed(t, c, "scratch pad", "deploy with AKIAI44QH8DHBEXAMPLE tonight")
	vaultBoth := seedWith(t, c, "Authenticator vault", "zebra-quartz-17 accounts", setBoth)
	vaultType := seedWith(t, c, "Banking codes", "walrus-basalt-29 accounts", setType)
	vaultEditor := seedWith(t, c, "Email codes", "heron-granite-41 accounts", setEditor)
	twin := seed(t, c, "Plain accounts", "otter-marble-53 accounts") // no marker: readable
	trashedPlain := seedWith(t, c, "Old plan", "buy paint", trash)
	trashedSecret := seedWith(t, c, "retired keys", "AKIAIOSFODNN7EXAMPLE", trash)

	// A tag over a readable and a sensitive note.
	tag, err := c.NewTag("project")
	if err != nil {
		t.Fatal(err)
	}
	c.SetTagRefs(tag, []string{normal, prodKeys})
	if _, err := c.Push(c.RawTag(tag)); err != nil {
		t.Fatalf("push tag: %v", err)
	}

	guard := snclient.NewGuard(c, "")
	tools := mcptools.New(guard, gate.New(notSensitive{}, 0.5))

	sensitive := []string{prodKeys, bodyOnly, vaultBoth, vaultType, vaultEditor}
	// Everything a sensitive note holds. The vault texts are the proof for the
	// forced kind: nothing else marks them.
	telltales := []string{
		"AKIAIOSFODNN7EXAMPLE", "AKIAI44QH8DHBEXAMPLE",
		"prod keys", "scratch pad", "deploy with", "retired keys",
		"Authenticator vault", "Banking codes", "Email codes",
		"zebra-quartz-17", "walrus-basalt-29", "heron-granite-41",
	}

	t.Run("list", func(t *testing.T) {
		rs, err := tools.List(0, 0)
		if err != nil {
			t.Fatal(err)
		}
		requireReadable(t, "list", rs, normal, "Shopping")
		requireReadable(t, "list", rs, twin, "Plain accounts")
		for _, id := range sensitive {
			requireStub(t, "list", rs, id)
		}
		if len(rs.Rows) != 2+len(sensitive) {
			t.Fatalf("list has %d rows, want %d (trashed notes are not listed): %s", len(rs.Rows), 2+len(sensitive), wire(t, rs))
		}
		requireNoLeak(t, "list", rs, telltales...)
	})

	t.Run("search", func(t *testing.T) {
		tests := []struct {
			query      string
			readable   map[string]string // uuid -> title
			stubs      []string
			snippetOf  string // uuid whose snippet must hold snippetHas
			snippetHas string
		}{
			{query: "keys", stubs: []string{prodKeys}},          // title match; the trashed "retired keys" is not listed
			{query: "AKIAI44QH8DHB", stubs: []string{bodyOnly}}, // body-only match
			{query: "MILK", readable: map[string]string{normal: "Shopping"}, snippetOf: normal, snippetHas: "milk and eggs"},
			{query: "accounts", readable: map[string]string{twin: "Plain accounts"}, stubs: []string{vaultBoth, vaultType, vaultEditor}},
			{query: "paint"}, // matches only a trashed note
			{query: "no-such-term-xyzzy"},
		}
		for _, tc := range tests {
			t.Run(tc.query, func(t *testing.T) {
				rs, err := tools.Search(tc.query, 0, 0)
				if err != nil {
					t.Fatal(err)
				}
				if want := len(tc.readable) + len(tc.stubs); len(rs.Rows) != want {
					t.Fatalf("search %q has %d rows, want %d: %s", tc.query, len(rs.Rows), want, wire(t, rs))
				}
				for id, title := range tc.readable {
					n := requireReadable(t, "search", rs, id, title)
					if tc.snippetOf == id && !strings.Contains(n.Snippet, tc.snippetHas) {
						t.Fatalf("snippet %q does not hold %q", n.Snippet, tc.snippetHas)
					}
				}
				for _, id := range tc.stubs {
					requireStub(t, "search", rs, id)
				}
				requireNoLeak(t, "search "+tc.query, rs, telltales...)
				if rs.Rows == nil {
					t.Fatal("an empty search must be an empty list, not null")
				}
			})
		}
	})

	t.Run("get", func(t *testing.T) {
		for _, id := range slices.Concat(sensitive, []string{trashedSecret}) {
			got, err := tools.Get(id)
			if err != nil {
				t.Fatal(err)
			}
			if got.Note != nil || got.Stub == nil || *got.Stub != gate.Stub(id) {
				t.Fatalf("notes_get %s is not a bare stub: %s", id, wire(t, got))
			}
			requireNoLeak(t, "notes_get", got, telltales...)
		}

		got, err := tools.Get(twin)
		if err != nil || got.Note == nil || got.Stub != nil || got.Note.Text != "otter-marble-53 accounts" {
			t.Fatalf("the unmarked twin must pass through: %v %s", err, wire(t, got))
		}
		// A trashed note is not listed, but a lookup by uuid still reads it.
		got, err = tools.Get(trashedPlain)
		if err != nil || got.Note == nil || !got.Note.Trashed || got.Note.Text != "buy paint" {
			t.Fatalf("a trashed note must be readable by uuid and say it is trashed: %v %s", err, wire(t, got))
		}
		if _, err := tools.Get("00000000-0000-4000-8000-000000000000"); !errors.Is(err, mcptools.ErrNotFound) {
			t.Fatalf("unknown uuid: got %v, want ErrNotFound", err)
		}
	})

	t.Run("tags", func(t *testing.T) {
		tl, err := tools.TagsList()
		if err != nil {
			t.Fatal(err)
		}
		if len(tl.Tags) != 1 || tl.Tags[0].UUID != tag.UUID || tl.Tags[0].Title != "project" {
			t.Fatalf("want the one project tag, got %s", wire(t, tl))
		}
		if got := tl.Tags[0].NoteUUIDs; len(got) != 2 {
			t.Fatalf("project tag holds %v, want the two notes", got)
		}
		requireNoLeak(t, "tags_list", tl, telltales...)
	})

	// When jev is down the gate fails closed, so the tools must stub every note
	// that has text. The scanner and the kind are not what decides here.
	t.Run("jev down stubs everything", func(t *testing.T) {
		down := mcptools.New(guard, gate.New(jevDown{}, 0.5))
		rs, err := down.List(0, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range slices.Concat(sensitive, []string{normal, twin}) {
			requireStub(t, "list with jev down", rs, id)
		}
		requireNoLeak(t, "list with jev down", rs, slices.Concat(telltales, []string{"Shopping", "milk and eggs", "otter-marble-53"})...)
		got, err := down.Get(normal)
		if err != nil || got.Note != nil || got.Stub == nil {
			t.Fatalf("notes_get with jev down must stub the note: %v %s", err, wire(t, got))
		}
		rs, err = down.Search("milk", 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		requireStub(t, "search with jev down", rs, normal)
		requireNoLeak(t, "search with jev down", rs, "Shopping", "milk and eggs")
	})
}
