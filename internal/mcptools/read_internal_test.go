package mcptools

// Tests that need no server. A fake reader stands in for Standard Notes, so the
// privacy paths run on every `go test`, even with SN_TEST_SERVER=off. They use the
// REAL gate (scanner, forced kinds, fail-closed jev) with a fake prober. The live
// tests are in read_test.go.

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/jonhadfield/gosn-v2/items"
	"github.com/smirnov-labs/standard-notes-mcp/internal/gate"
	"github.com/smirnov-labs/standard-notes-mcp/internal/snclient"
)

// prober is a jev stand-in with a fixed answer. The zero value says "not
// sensitive", so the scanner and the kind are the only signals in play.
type prober struct {
	p   float64
	err error
}

func (p prober) SensitiveProbability(string) (float64, error) { return p.p, p.err }

// fakeReader serves fixtures and counts reads. With shuffle set, every fetch gives
// the notes in a new random order, as gosn-v2 does.
type fakeReader struct {
	notes   []*snclient.NoteView
	tags    []*snclient.TagView
	err     error
	reads   int
	shuffle bool
}

func (f *fakeReader) fetch() ([]*snclient.NoteView, []*snclient.TagView, error) {
	f.reads++
	if f.err != nil {
		return nil, nil, f.err
	}
	notes := f.notes
	if f.shuffle {
		notes = slices.Clone(f.notes)
		rand.Shuffle(len(notes), func(i, j int) { notes[i], notes[j] = notes[j], notes[i] })
	}
	return notes, f.tags, nil
}

func (f *fakeReader) fetchOne(uuid string) (*snclient.NoteView, error) {
	f.reads++
	if f.err != nil {
		return nil, f.err
	}
	for _, n := range f.notes {
		if n.UUID == uuid {
			return n, nil
		}
	}
	return nil, nil
}

func newTools(src reader, p prober) *Tools { return &Tools{src: src, gt: gate.New(p, 0.5)} }

func nv(uuid, title, text string) *snclient.NoteView {
	return &snclient.NoteView{UUID: uuid, Title: title, Text: text}
}

func wire(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// stubJSON is the whole of a stub row on the wire. A sensitive row must equal it
// exactly, so a stub has a uuid and a label and nothing else.
func stubJSON(uuid string) string {
	return fmt.Sprintf(`{"Stub":{"UUID":%q,"Label":"[sensitive — withheld]"}}`, uuid)
}

// secretNotes is one note per way the gate can say "sensitive" without jev. Every
// title and body holds a telltale that must never reach a result.
var secretNotes = []struct {
	name      string
	note      *snclient.NoteView
	telltales []string
}{
	{"pem key", nv("s-pem", "zq-title-pem", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAzqbodypem\n-----END RSA PRIVATE KEY-----"),
		[]string{"zq-title-pem", "zqbodypem", "MIIEowIBAAKCAQEA"}},
	{"aws key", nv("s-aws", "zq-title-aws", "key AKIAIOSFODNN7EXAMPLE"),
		[]string{"zq-title-aws", "AKIAIOSFODNN7EXAMPLE"}},
	{"otp uri", nv("s-otp", "zq-title-otp", "otpauth://totp/Acme:me?secret=JBSWY3DPEHPK3PXP"),
		[]string{"zq-title-otp", "JBSWY3DPEHPK3PXP"}},
	{"card number", nv("s-card", "zq-title-card", "card 4111 1111 1111 1111 on file"),
		[]string{"zq-title-card", "4111 1111 1111 1111"}},
	{"password-manager export", nv("s-pwm", "zq-title-pwm", "Bitwarden vault export, keep it safe"),
		[]string{"zq-title-pwm", "Bitwarden"}},
	{"secret only in the title", nv("s-ttl", "AKIAI44QH8DHBEXAMPLE", "nothing to see"),
		[]string{"AKIAI44QH8DHBEXAMPLE", "nothing to see"}},
	// Plain words: only the forced kind marks these.
	{"authenticator note by type", &snclient.NoteView{UUID: "s-aty", Title: "zq-title-aty", Text: "zq-body-aty words", NoteType: "authentication"},
		[]string{"zq-title-aty", "zq-body-aty"}},
	{"authenticator note by editor", &snclient.NoteView{UUID: "s-aed", Title: "zq-title-aed", Text: "zq-body-aed words", EditorIdentifier: "org.standardnotes.token-vault"},
		[]string{"zq-title-aed", "zq-body-aed"}},
}

// Every tool, every way to reach a sensitive note, must give a bare stub and no
// telltale. Searches use the title word, a body word and a case change, so a hit
// on the title and a hit on the body are both covered.
func TestSensitiveNeverLeaksOnAnyTool(t *testing.T) {
	var fixtures []*snclient.NoteView
	var telltales []string
	for _, sn := range secretNotes {
		fixtures = append(fixtures, sn.note)
		telltales = append(telltales, sn.telltales...)
	}
	fixtures = append(fixtures, nv("n-ok", "Shopping", "milk and eggs"))
	tools := newTools(&fakeReader{notes: fixtures}, prober{})

	noLeak := func(where string, v any) {
		t.Helper()
		body := wire(t, v)
		for _, s := range telltales {
			if strings.Contains(body, s) {
				t.Fatalf("LEAK through %s: %q is in the result: %s", where, s, body)
			}
		}
	}

	all, err := tools.List(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	noLeak("List", all)
	for _, sn := range secretNotes {
		if sn.note.UUID == "" {
			t.Fatal("fixture without a uuid")
		}
		row := rowFor(t, all, sn.note.UUID)
		if got := wire(t, row); got != stubJSON(sn.note.UUID) {
			t.Fatalf("List row for %s is not a bare stub:\n got %s\nwant %s", sn.name, got, stubJSON(sn.note.UUID))
		}

		got, err := tools.Get(sn.note.UUID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Note != nil || got.Stub == nil || *got.Stub != gate.Stub(sn.note.UUID) {
			t.Fatalf("Get %s is not a bare stub: %s", sn.name, wire(t, got))
		}
		if body := wire(t, got); body != stubJSON(sn.note.UUID) {
			t.Fatalf("Get %s has more than a stub on the wire: %s", sn.name, body)
		}
		noLeak("Get "+sn.name, got)

		// Search for every telltale this note holds, in upper case too.
		for _, q := range sn.telltales {
			for _, query := range []string{q, strings.ToUpper(q)} {
				rs, err := tools.Search(query, 0, 0)
				if err != nil {
					t.Fatal(err)
				}
				noLeak("Search "+query, rs)
				for _, r := range rs.Rows {
					if r.Note != nil && !strings.HasPrefix(r.Note.UUID, "n-") {
						t.Fatalf("Search %q returned a sensitive note as a readable row: %s", query, wire(t, r))
					}
				}
			}
		}
	}

	// The control: a normal note is not over-stubbed by these fixtures.
	if r := rowFor(t, all, "n-ok"); r.Note == nil || r.Note.Title != "Shopping" {
		t.Fatalf("a normal note must be readable: %s", wire(t, r))
	}
}

func rowFor(t *testing.T, rs RowSet, uuid string) Row {
	t.Helper()
	for _, r := range rs.Rows {
		if (r.Note != nil && r.Note.UUID == uuid) || (r.Stub != nil && r.Stub.UUID == uuid) {
			return r
		}
	}
	t.Fatalf("no row for %s in %s", uuid, wire(t, rs))
	return Row{}
}

// The gate says "sensitive" when jev errors, and when jev's probability is at or
// over the threshold. Both must reach the tools as stubs.
func TestToolsStubWhenJevFailsOrFlags(t *testing.T) {
	for name, p := range map[string]prober{
		"jev error":  {err: errors.New("jev is down")},
		"jev flags":  {p: 0.9},
		"jev is NaN": {p: math.NaN()},
	} {
		t.Run(name, func(t *testing.T) {
			tools := newTools(&fakeReader{notes: []*snclient.NoteView{nv("n1", "Shopping", "milk and eggs")}}, p)
			rs, err := tools.List(0, 0)
			if err != nil {
				t.Fatal(err)
			}
			if got := wire(t, rs); got != `{"Rows":[`+stubJSON("n1")+`]}` {
				t.Fatalf("List: %s", got)
			}
			rs, err = tools.Search("milk", 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			if got := wire(t, rs); got != `{"Rows":[`+stubJSON("n1")+`]}` {
				t.Fatalf("Search: %s", got)
			}
			g, err := tools.Get("n1")
			if err != nil {
				t.Fatal(err)
			}
			if got := wire(t, g); got != stubJSON("n1") {
				t.Fatalf("Get: %s", got)
			}
		})
	}
}

// With a prober that says "not sensitive", a note with no secret and no marker
// passes. This pins that the tools do not stub by default.
func TestNormalNotePassesThrough(t *testing.T) {
	tools := newTools(&fakeReader{notes: []*snclient.NoteView{
		{UUID: "n1", Title: "Shopping", Text: "milk and eggs", NoteType: "plain-text", EditorIdentifier: "com.standardnotes.plain-text"},
	}}, prober{})
	g, err := tools.Get("n1")
	if err != nil {
		t.Fatal(err)
	}
	want := `{"Note":{"UUID":"n1","Title":"Shopping","Text":"milk and eggs","NoteType":"plain-text","EditorIdentifier":"com.standardnotes.plain-text","Trashed":false}}`
	if got := wire(t, g); got != want {
		t.Fatalf("Get:\n got %s\nwant %s", got, want)
	}
	rs, err := tools.List(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	want = `{"Rows":[{"Note":{"UUID":"n1","Title":"Shopping","Snippet":"milk and eggs"}}]}`
	if got := wire(t, rs); got != want {
		t.Fatalf("List:\n got %s\nwant %s", got, want)
	}
}

// Search matches title and text, ignores case, skips trashed notes, orders by
// uuid (not by title or text), and classifies only what matches. A sensitive match
// is a stub. A sensitive note that does not match is absent.
func TestSearchMatching(t *testing.T) {
	trashed := func(n *snclient.NoteView) *snclient.NoteView { n.Trashed = true; return n }
	r := &fakeReader{notes: []*snclient.NoteView{
		nv("u3", "Zebra", "milk run"),                             // text match
		nv("u1", "Milk", "plain"),                                 // title match
		nv("u2", "bank", "AKIAIOSFODNN7EXAMPLE and milk"),         // sensitive, matches
		nv("u4", "other", "other"),                                // no match
		trashed(nv("u5", "tagged milk", "x")),                     // trashed: skipped
		trashed(nv("u6", "old", "AKIAIOSFODNN7EXAMPLE and milk")), // trashed, sensitive: skipped
		nv("u7", "key", "AKIAIOSFODNN7EXAMPLE"),                   // sensitive, no match: absent
	}}
	tools := newTools(r, prober{})

	rs, err := tools.Search("  MiLk ", 0, 0) // case and padding do not matter
	if err != nil {
		t.Fatal(err)
	}
	want := `{"Rows":[` +
		`{"Note":{"UUID":"u1","Title":"Milk","Snippet":"plain"}},` +
		stubJSON("u2") + `,` +
		`{"Note":{"UUID":"u3","Title":"Zebra","Snippet":"milk run"}}]}`
	if got := wire(t, rs); got != want {
		t.Fatalf("Search:\n got %s\nwant %s", got, want)
	}

	// The query is literal text. These would match everything, or fail to
	// compile, if they were read as a pattern.
	for _, q := range []string{".*", "(", "[a-z]+", `\`, "milk|bank"} {
		rs, err := tools.Search(q, 0, 0)
		if err != nil {
			t.Fatalf("Search(%q): %v", q, err)
		}
		if len(rs.Rows) != 0 {
			t.Fatalf("Search(%q) matched as a pattern: %s", q, wire(t, rs))
		}
	}
}

func TestListSkipsTrashedAndOrdersByUUID(t *testing.T) {
	trashed := &snclient.NoteView{UUID: "t", Title: "gone", Text: "gone", Trashed: true}
	// Three orders that all differ. Fetch: c a b. Title: c (Alpha) b (Mike) a (Zulu).
	// Uuid: a b c.
	tools := newTools(&fakeReader{notes: []*snclient.NoteView{
		nv("c", "Alpha", "x"), trashed, nv("a", "Zulu", "z"), nil, nv("b", "Mike", "m"),
	}}, prober{})
	rs, err := tools.List(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, r := range rs.Rows {
		order = append(order, r.Note.UUID)
	}
	// Uuid order, not title order: sorting by title would let a stub's place in the
	// list reveal where its hidden title falls in the alphabet. Not fetch order
	// either, because gosn-v2 does not fetch in a fixed order.
	if !slices.Equal(order, []string{"a", "b", "c"}) {
		t.Fatalf("rows are %v, want uuid order [a b c] without the trashed note", order)
	}
}

// limit and offset cut a window from the rows in uuid order, for both List and
// Search. A trashed note does not count toward offset. A sensitive note inside the
// window is still a bare stub, and its content is not in the page.
func TestPagingCutsAWindowOfTheRows(t *testing.T) {
	tools := newTools(&fakeReader{notes: []*snclient.NoteView{ // fetch order is not uuid order
		nv("n3", "Three", "milk 3"),
		nv("n0", "Zero", "milk 0"),
		{UUID: "tr", Title: "Trashed", Text: "milk", Trashed: true}, // never listed, never counted
		nv("n4", "Four", "milk 4"),
		nv("n2", "prod keys", "AKIAIOSFODNN7EXAMPLE and milk"), // sensitive: a stub in its place
		nv("n1", "One", "milk 1"),
	}}, prober{})
	all := []string{"n0", "n1", "n2", "n3", "n4"}

	for _, tc := range []struct {
		name          string
		limit, offset int
		want          []string // uuids in order. n2 must be a stub.
	}{
		{"first page", 2, 0, []string{"n0", "n1"}},
		{"a stub inside the page", 2, 2, []string{"n2", "n3"}},
		{"short last page", 2, 4, []string{"n4"}},
		{"offset at the end", 2, 5, nil},
		{"offset past the end", 2, 99, nil},
		{"huge offset", 2, math.MaxInt, nil},
		{"no limit gives the default page", 0, 0, all},
		{"negative limit and offset", -1, -7, all},
		{"negative offset starts at the top", 2, -4, []string{"n0", "n1"}},
	} {
		for tool, call := range map[string]func() (RowSet, error){
			"List":   func() (RowSet, error) { return tools.List(tc.limit, tc.offset) },
			"Search": func() (RowSet, error) { return tools.Search("milk", tc.limit, tc.offset) },
		} {
			t.Run(tc.name+"/"+tool, func(t *testing.T) {
				rs, err := call()
				if err != nil {
					t.Fatal(err)
				}
				if rs.Rows == nil {
					t.Fatal("an empty page must be an empty list, not null")
				}
				var got []string
				for _, r := range rs.Rows {
					switch {
					case r.Note != nil:
						got = append(got, r.Note.UUID)
					case r.Stub != nil:
						got = append(got, r.Stub.UUID)
						if wire(t, r) != stubJSON("n2") {
							t.Fatalf("a stub row has more than a stub: %s", wire(t, r))
						}
					}
				}
				if !slices.Equal(got, tc.want) {
					t.Fatalf("page is %v, want %v", got, tc.want)
				}
				for _, leak := range []string{"AKIAIOSFODNN7EXAMPLE", "prod keys"} {
					if strings.Contains(wire(t, rs), leak) {
						t.Fatalf("LEAK through the page: %q is in %s", leak, wire(t, rs))
					}
				}
			})
		}
	}
}

// gosn-v2 gives the notes in a different order on each fetch. Pages must not
// depend on it: a caller that reads page after page has to see every note once.
// Without the sort, this reader would give pages that overlap and leave gaps.
func TestPagesDoNotDependOnTheFetchOrder(t *testing.T) {
	var notes []*snclient.NoteView
	var want []string
	for i := range 40 {
		id := fmt.Sprintf("n%02d", i)
		notes = append(notes, nv(id, "title", "milk"))
		want = append(want, id)
	}
	tools := newTools(&fakeReader{notes: notes, shuffle: true}, prober{})
	for tool, page := range map[string]func(limit, offset int) (RowSet, error){
		"List":   tools.List,
		"Search": func(limit, offset int) (RowSet, error) { return tools.Search("milk", limit, offset) },
	} {
		t.Run(tool, func(t *testing.T) {
			var got []string
			for offset := 0; offset < len(want); offset += 7 { // the last page is short
				rs, err := page(7, offset)
				if err != nil {
					t.Fatal(err)
				}
				for _, r := range rs.Rows {
					got = append(got, r.Note.UUID)
				}
			}
			if !slices.Equal(got, want) {
				t.Fatalf("the pages hold %v, want every note once, in uuid order: %v", got, want)
			}
		})
	}
}

// countingProber counts the notes the gate sends to jev.
type countingProber struct{ calls int }

func (c *countingProber) SensitiveProbability(string) (float64, error) { c.calls++; return 0, nil }

// A page never holds more than maxLimit rows, and the gate only sees the notes on
// the page. Its cost follows the page, not the vault.
func TestPagingBoundsTheRowsAndTheGateCalls(t *testing.T) {
	var notes []*snclient.NoteView
	for i := range 600 {
		notes = append(notes, nv(fmt.Sprintf("n%03d", i), "note", fmt.Sprintf("body %d", i)))
	}
	for _, tc := range []struct {
		name          string
		limit, offset int
		rows          int
	}{
		{"no limit gives the default", 0, 0, defaultLimit},
		{"a huge limit gives the cap", 1 << 30, 0, maxLimit},
		{"the cap leaves the rest to offset", 10_000, 550, 50},
		{"a small page in the middle", 7, 100, 7},
	} {
		for tool, call := range map[string]func(*Tools) (RowSet, error){
			"List":   func(t *Tools) (RowSet, error) { return t.List(tc.limit, tc.offset) },
			"Search": func(t *Tools) (RowSet, error) { return t.Search("body", tc.limit, tc.offset) },
		} {
			t.Run(tc.name+"/"+tool, func(t *testing.T) {
				cp := &countingProber{}
				rs, err := call(&Tools{src: &fakeReader{notes: notes}, gt: gate.New(cp, 0.5)})
				if err != nil {
					t.Fatal(err)
				}
				if len(rs.Rows) != tc.rows {
					t.Fatalf("page has %d rows, want %d", len(rs.Rows), tc.rows)
				}
				if cp.calls != tc.rows {
					t.Fatalf("the gate was asked about %d notes, want the %d on the page", cp.calls, tc.rows)
				}
			})
		}
	}
}

// gosn-v2 puts decrypted item content in some of its error strings
// (items.go: "unhandled type2 '%s' %s"). Whatever the reader fails with, the text
// that leaves the tools is fixed.
func TestReadErrorsAreContentFree(t *testing.T) {
	leaky := errors.New(`DecryptAndParse | unhandled type2 'SN|Weird' {"title":"prod keys","text":"AKIAIOSFODNN7EXAMPLE"}`)
	tools := newTools(&fakeReader{err: leaky}, prober{})
	calls := map[string]func() (any, error){
		"List":     func() (any, error) { return tools.List(0, 0) },
		"Search":   func() (any, error) { return tools.Search("keys", 0, 0) },
		"Get":      func() (any, error) { return tools.Get("u1") },
		"TagsList": func() (any, error) { return tools.TagsList() },
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			out, err := call()
			if err == nil {
				t.Fatal("want an error")
			}
			for _, text := range []string{err.Error(), fmt.Sprintf("%v|%+v|%s|%q|%#v", err, err, err, err, out)} {
				for _, bad := range []string{"AKIA", "prod keys", "unhandled", "SN|Weird", "DecryptAndParse"} {
					if strings.Contains(text, bad) {
						t.Fatalf("the error text holds %q: %s", bad, text)
					}
				}
			}
			var re *ReadError
			if !errors.As(err, &re) {
				t.Fatalf("want a *ReadError, got %T", err)
			}
			// The cause stays reachable, for the server's own logs. The text
			// above is all the orchestrator sees.
			if !errors.Is(err, leaky) {
				t.Fatal("the cause must stay reachable through Unwrap")
			}
		})
	}
}

func TestBadQueriesAreRefusedBeforeAnyRead(t *testing.T) {
	r := &fakeReader{notes: []*snclient.NoteView{nv("u1", "a", "b")}}
	tools := newTools(r, prober{})
	for query, want := range map[string]error{
		"":                                   ErrEmptyQuery,
		"   \t\n":                            ErrEmptyQuery,
		strings.Repeat("a", maxQueryBytes+1): ErrQueryTooLong,
	} {
		if _, err := tools.Search(query, 0, 0); !errors.Is(err, want) {
			t.Fatalf("Search(%.20q): got %v, want %v", query, err, want)
		}
	}
	if r.reads != 0 {
		t.Fatalf("a refused query cost %d reads", r.reads)
	}

	// The longest legal query: padding is trimmed before the length check. An
	// invalid UTF-8 query is cleaned. Neither is an error, and neither panics.
	for _, query := range []string{" " + strings.Repeat("a", maxQueryBytes) + " ", "a\xffb"} {
		if _, err := tools.Search(query, 0, 0); err != nil {
			t.Fatalf("Search(%.20q): %v", query, err)
		}
	}
}

func TestGetUnknownAndBlankUUID(t *testing.T) {
	r := &fakeReader{notes: []*snclient.NoteView{nv("u1", "a", "b")}}
	tools := newTools(r, prober{})
	if _, err := tools.Get("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown uuid: got %v, want ErrNotFound", err)
	}
	if got, want := ErrNotFound.Error(), "note not found"; got != want { // never echoes the uuid
		t.Fatalf("ErrNotFound text %q, want %q", got, want)
	}
	reads := r.reads
	for _, blank := range []string{"", "  \t"} {
		if _, err := tools.Get(blank); !errors.Is(err, ErrNotFound) {
			t.Fatalf("blank uuid %q: got %v", blank, err)
		}
	}
	if r.reads != reads {
		t.Fatal("a blank uuid must not cost a read")
	}
	// A uuid with padding is the same uuid.
	if g, err := tools.Get(" u1 "); err != nil || g.Note == nil {
		t.Fatalf("padded uuid: %v %s", err, wire(t, g))
	}
}

func TestEmptyResultsAreEmptyListsNotNull(t *testing.T) {
	tools := newTools(&fakeReader{tags: []*snclient.TagView{{UUID: "g1", Title: "empty"}}}, prober{})
	for name, got := range map[string]func() (any, error){
		"List":     func() (any, error) { return tools.List(0, 0) },
		"Search":   func() (any, error) { return tools.Search("zzz", 0, 0) },
		"TagsList": func() (any, error) { return tools.TagsList() },
	} {
		out, err := got()
		if err != nil {
			t.Fatal(err)
		}
		// null would fail the output schema the SDK infers from these types.
		if body := wire(t, out); strings.Contains(body, "null") {
			t.Fatalf("%s has a null: %s", name, body)
		}
	}
}

func TestTagsListPassesTagsThrough(t *testing.T) {
	ids := []string{"n1", "n2"}
	r := &fakeReader{tags: []*snclient.TagView{{UUID: "g1", Title: "project", NoteUUIDs: ids}}}
	tl, err := newTools(r, prober{}).TagsList()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := wire(t, tl), `{"Tags":[{"UUID":"g1","Title":"project","NoteUUIDs":["n1","n2"]}]}`; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
	tl.Tags[0].NoteUUIDs[0] = "changed"
	if ids[0] != "n1" {
		t.Fatal("the result shares its slice with the fetched tag")
	}
}

// gated is the one place a note's content is let through. For a sensitive note it
// must hold no NoteView at all, so nothing downstream can read the content.
func TestGatedHoldsNoContentForASensitiveNote(t *testing.T) {
	tools := newTools(&fakeReader{}, prober{})
	g := tools.gated(nv("u1", "prod keys", "AKIAIOSFODNN7EXAMPLE"))
	if g.note != nil || g.stub != gate.Stub("u1") {
		t.Fatalf("a sensitive note must leave only a stub: %+v", g)
	}
	g = tools.gated(nv("u2", "Shopping", "milk and eggs"))
	if g.note == nil || g.note.UUID != "u2" {
		t.Fatalf("a normal note must be held: %+v", g)
	}
}

func TestNewRefusesToServeWithoutAGuardOrAGate(t *testing.T) {
	for name, build := range map[string]func(){
		"no guard": func() { New(nil, gate.New(prober{}, 0.5)) },
		"no gate":  func() { New(snclient.NewGuard(nil, ""), nil) },
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("New must panic: the tools must not run ungated")
				}
			}()
			build()
		})
	}
}

// noteKind is where the forced "authentication" kind comes from. The values are
// Standard Notes' own: NoteType.Authentication and FeatureIdentifier.
// TokenVaultEditor in @standardnotes/features. The "Authenticator" editor sets
// both, and a client that wrote only one must still be caught.
func TestNoteKind(t *testing.T) {
	tests := []struct {
		name                string
		noteType, editor, w string
	}{
		{"no metadata", "", "", kindNote},
		{"plain text, SN spelling", "plain-text", "com.standardnotes.plain-text", kindNote},
		{"plain text, gosn-v2 spelling", "com.standardnotes.plain-text", "", kindNote},
		{"super", "super", "com.standardnotes.super-editor", kindNote},
		{"spreadsheet", "spreadsheet", "org.standardnotes.standard-sheets", kindNote},
		{"task", "task", "org.standardnotes.simple-task-editor", kindNote},
		{"rich text", "rich-text", "org.standardnotes.plus-editor", kindNote},
		{"code", "code", "org.standardnotes.code-editor", kindNote},
		{"markdown", "markdown", "org.standardnotes.advanced-markdown-editor", kindNote},
		{"unknown type", "unknown", "", kindNote},
		{"authenticator, both set", "authentication", "org.standardnotes.token-vault", kindAuthentication},
		{"type only", "authentication", "", kindAuthentication},
		{"editor only", "", "org.standardnotes.token-vault", kindAuthentication},
		{"editor only, type says plain", "com.standardnotes.plain-text", "org.standardnotes.token-vault", kindAuthentication},
		{"type only, editor says super", "authentication", "com.standardnotes.super-editor", kindAuthentication},
		{"case and padding", " Authentication\n", "", kindAuthentication},
		{"case and padding, editor", "", "  ORG.StandardNotes.Token-Vault ", kindAuthentication},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := noteKind(&snclient.NoteView{NoteType: tc.noteType, EditorIdentifier: tc.editor})
			if got != tc.w {
				t.Fatalf("noteKind(type=%q, editor=%q) = %q, want %q", tc.noteType, tc.editor, got, tc.w)
			}
		})
	}
}

// The two literals come from Standard Notes' source. Pin them to the two other
// places that must agree: gosn-v2's own editor list, and the kind the gate forces.
func TestAuthenticationValuesAgreeWithTheirSources(t *testing.T) {
	var found bool
	for _, e := range items.BuiltInEditors() {
		if e.Name == "Authenticator" {
			found = true
			if e.Identifier != editorTokenVault {
				t.Fatalf("gosn-v2 lists the Authenticator editor as %q, noteKind uses %q", e.Identifier, editorTokenVault)
			}
		}
	}
	if !found {
		t.Fatal("gosn-v2 no longer lists an Authenticator editor: recheck editorTokenVault")
	}

	g := gate.New(prober{}, 0.5)
	if !g.Classify(gate.Note{Title: "t", Text: "plain words", Kind: kindAuthentication}).Sensitive {
		t.Fatal("the gate no longer forces kindAuthentication: noteKind would not stub authenticator notes")
	}
	if g.Classify(gate.Note{Title: "t", Text: "plain words", Kind: kindNote}).Sensitive {
		t.Fatal("kindNote must not force a stub")
	}
}

// A match deep in a long body must show up in the snippet. A snippet from the
// start of the text would show the orchestrator nothing about why the note hit.
func TestSearchSnippetCentersOnTheMatch(t *testing.T) {
	body := strings.Repeat("x", 300) + "needle" + strings.Repeat("y", 300)
	tools := newTools(&fakeReader{notes: []*snclient.NoteView{nv("u1", "Long note", body)}}, prober{})
	rs, err := tools.Search("NEEDLE", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	row := rowFor(t, rs, "u1")
	if row.Note == nil || !strings.Contains(row.Note.Snippet, "needle") || !strings.HasPrefix(row.Note.Snippet, "…") {
		t.Fatalf("snippet does not center on the match: %s", wire(t, row))
	}
	// A title-only match has no body hit, so the snippet is the start of the body.
	rs, err = tools.Search("long note", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if row := rowFor(t, rs, "u1"); row.Note == nil || !strings.HasPrefix(row.Note.Snippet, "xxx") {
		t.Fatalf("a title match should show the start of the body: %s", wire(t, row))
	}
}

func TestExcerpt(t *testing.T) {
	t.Run("short text comes back whole", func(t *testing.T) {
		if got := excerpt("short text", 0); got != "short text" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("empty and blank", func(t *testing.T) {
		for _, s := range []string{"", " \n\t "} {
			if got := excerpt(s, 0); got != "" {
				t.Fatalf("excerpt(%q) = %q", s, got)
			}
		}
	})
	t.Run("long text is cut and marked", func(t *testing.T) {
		got := excerpt(strings.Repeat("abcdefghi ", 100), 0)
		if !strings.HasSuffix(got, "…") || strings.HasPrefix(got, "…") {
			t.Fatalf("want a trailing mark only: %q", got)
		}
		if n := utf8.RuneCountInString(got); n > snippetMax+1 {
			t.Fatalf("%d runes, want at most %d", n, snippetMax+1)
		}
	})
	t.Run("a match in the middle keeps a little lead", func(t *testing.T) {
		text := strings.Repeat("x", 300) + "NEEDLE" + strings.Repeat("y", 300)
		got := excerpt(text, 300)
		body, ok := strings.CutPrefix(got, "…")
		if !ok || !strings.HasSuffix(got, "…") {
			t.Fatalf("want marks on both ends: %q", got)
		}
		if i := strings.Index(body, "NEEDLE"); i != snippetLead {
			t.Fatalf("NEEDLE at %d, want after %d runes of lead: %q", i, snippetLead, got)
		}
		if n := utf8.RuneCountInString(got); n > snippetMax+2 {
			t.Fatalf("%d runes, want at most %d", n, snippetMax+2)
		}
	})
	t.Run("multibyte text is cut on rune boundaries", func(t *testing.T) {
		text := strings.Repeat("日本語", 200)
		for _, at := range []int{0, 3, 900, 901, 902, len(text) - 1, len(text)} { // 901, 902 are mid-rune
			got := excerpt(text, at)
			if !utf8.ValidString(got) {
				t.Fatalf("at %d: invalid UTF-8 %q", at, got)
			}
			if n := utf8.RuneCountInString(got); n > snippetMax+2 {
				t.Fatalf("at %d: %d runes", at, n)
			}
		}
	})
	t.Run("whitespace is collapsed to one line", func(t *testing.T) {
		if got := excerpt("a\n\n b\t\tc  d\r\ne", 0); got != "a b c d e" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("an offset out of range does not panic", func(t *testing.T) {
		for _, at := range []int{-5, -1, 3, 4, 99, 1 << 40} {
			_ = excerpt("abc", at)
		}
	})
	t.Run("invalid UTF-8 does not panic", func(t *testing.T) {
		text := "ab\xff\xfe\xc3cd" + strings.Repeat("\xe6\x97", 300)
		for at := -1; at <= len(text)+1; at++ {
			_ = excerpt(text, at)
		}
	})
}

// A snippet is a piece of the note's own text. Get returns all of that text for a
// readable note, so a snippet gives away nothing that Get would not.
func TestSnippetIsAPieceOfTheText(t *testing.T) {
	collapse := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	texts := []string{
		"Shopping list: Milk, eggs,\n\tbread and more milk",
		strings.Repeat("lorem ipsum dolor sit amet\n", 80) + "MILK at the end",
		"日本語 milk 日本語 " + strings.Repeat("ö", 400) + " milk",
	}
	re, err := queryRegexp("milk")
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range texts {
		for _, r := range []*regexp.Regexp{re, nil} {
			s := snippetOf(text, r)
			if inner := strings.Trim(s, "…"); !strings.Contains(collapse(text), inner) {
				t.Fatalf("snippet %q is not part of the text", s)
			}
		}
	}
	if s := snippetOf("Shopping list: Milk, eggs", re); !strings.Contains(s, "Milk") {
		t.Fatalf("snippet %q misses the match", s)
	}
	if s := snippetOf("nothing here", re); s != "nothing here" { // no match in the text: start of the text
		t.Fatalf("snippet %q", s)
	}
}
