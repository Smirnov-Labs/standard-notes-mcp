// Package mcptools holds the tools the MCP server offers to the orchestrator.
//
// The rule for every tool here: a sensitive note's title, body and snippet never
// appear in a result. A note the gate flags comes back as a gate.Stubbed (a uuid
// and a fixed label) and as nothing else.
//
// How the read tools keep that rule:
//
//   - Every note goes through (*Tools).gated before any code copies its content.
//     A gatedNote holds the note only when the gate cleared it. For a sensitive
//     note it holds the stub alone, so no later line can read the content.
//   - The stub arm of each result is a gate.Stubbed. It has two fields and no room
//     for content. The gate package stops the build if it gains one.
//   - Errors carry fixed text. gosn-v2 builds some errors from decrypted item
//     content, so no message ever holds an upstream error.
//   - Rows come in uuid order. gosn-v2 gives the notes in a different order on each
//     fetch, and a page needs a fixed one. A uuid says nothing about a note's
//     content. A sort on title or text would show where a stub's hidden title falls,
//     so no sort uses them.
//   - Nothing here logs.
package mcptools

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/smirnov-labs/standard-notes-mcp/internal/gate"
	"github.com/smirnov-labs/standard-notes-mcp/internal/snclient"
)

// Row is one entry of a Search or List result. Exactly one field is set. Stub
// stands in for a sensitive note.
type Row struct {
	Note *NoteRow      `json:",omitempty"`
	Stub *gate.Stubbed `json:",omitempty"`
}

// NoteRow is a note the gate cleared, as a list entry.
type NoteRow struct {
	UUID, Title string
	// Snippet is a short, one-line piece of the note's text. It is part of text
	// that Get returns whole for the same note, so it shows nothing more.
	Snippet string
}

// RowSet is the result of Search and List. Rows is never nil, so an empty result
// is [] on the wire and not null.
type RowSet struct{ Rows []Row }

// NoteDetail is a note the gate cleared, in full.
type NoteDetail struct {
	UUID, Title, Text string
	NoteType          string `json:",omitempty"`
	EditorIdentifier  string `json:",omitempty"`
	Trashed           bool
}

// GetResult is the result of Get. Exactly one field is set. Stub stands in for a
// sensitive note.
type GetResult struct {
	Note *NoteDetail   `json:",omitempty"`
	Stub *gate.Stubbed `json:",omitempty"`
}

// TagRow is one tag with the notes it holds.
type TagRow struct {
	UUID, Title string
	NoteUUIDs   []string
}

// TagList is the result of TagsList. Tags is never nil.
type TagList struct{ Tags []TagRow }

// Errors with fixed text. None of them echoes its input.
var (
	ErrNotFound     = errors.New("note not found")
	ErrEmptyQuery   = errors.New("query is empty")
	ErrQueryTooLong = fmt.Errorf("query is longer than %d bytes", maxQueryBytes)

	errBadQuery = errors.New("query cannot be searched")
)

// ReadError is the error a tool returns when Standard Notes cannot be read. Its
// text is fixed and holds nothing from the cause. gosn-v2 builds some errors from
// decrypted item content ("unhandled type2 '%s' %s" in items/items.go). The MCP
// SDK sends a handler's error text to the orchestrator. The cause stays reachable
// with errors.Unwrap, for the server's own use. Never send the cause, or its
// text, to the orchestrator.
type ReadError struct{ cause error }

func (*ReadError) Error() string { return "could not read notes from Standard Notes" }

func (e *ReadError) Unwrap() error { return e.cause }

// reader is the read side of Standard Notes. The tools use guarded. Tests use
// fixtures.
type reader interface {
	fetch() ([]*snclient.NoteView, []*snclient.TagView, error)
	fetchOne(uuid string) (*snclient.NoteView, error)
}

// guarded reads Standard Notes. It is the only code in this package that touches
// the session, and it does so only inside Guard.Do. The guard serializes session
// access and refreshes the token first. The note views that come back are plain
// data, so the tools classify them after Do has released the lock. A slow jev
// call then never holds the session.
type guarded struct{ g *snclient.Guard }

func (r guarded) fetch() ([]*snclient.NoteView, []*snclient.TagView, error) {
	var (
		notes []*snclient.NoteView
		tags  []*snclient.TagView
	)
	err := r.g.Do(func(c *snclient.Client) error {
		var err error
		notes, tags, err = c.Fetch()
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return notes, tags, nil
}

func (r guarded) fetchOne(uuid string) (*snclient.NoteView, error) {
	var n *snclient.NoteView
	err := r.g.Do(func(c *snclient.Client) error {
		var err error
		n, err = c.FetchOne(uuid)
		return err
	})
	if err != nil {
		return nil, err
	}
	return n, nil
}

// Tools is the set of gated read tools. It holds no state that changes, so it is
// safe for concurrent use. The guard serializes session access, and the gate is
// safe for concurrent use when its prober is.
type Tools struct {
	src reader
	gt  *gate.Gate
}

// New returns the read tools. A nil guard or gate is a wiring bug, and New panics
// on it: the tools must never run ungated.
func New(g *snclient.Guard, gt *gate.Gate) *Tools {
	if g == nil || gt == nil {
		panic("mcptools: New needs a guard and a gate; the tools must not run ungated")
	}
	return &Tools{src: guarded{g}, gt: gt}
}

// Search returns the live notes whose title or text holds query, ignoring case. The
// query is literal text, not a pattern. Search skips trashed notes. A sensitive
// note that matches comes back as a stub, and one that does not match is absent.
// Rows come in uuid order. limit and offset cut a page from them: see window.
//
// The stub has a cost. Spec 5.1 asks for it, but a stub in the result tells the
// orchestrator that a sensitive note holds the query. A caller that can search
// without limit can use that to probe the note's text, one character at a time.
// No content is returned: the match itself is the leak. The plan 2a red-team
// (task 9) must decide whether to keep stubs for matches.
//
// Only the notes on the page go to the gate, so a search costs at most limit gate
// calls.
func (t *Tools) Search(query string, limit, offset int) (RowSet, error) {
	re, err := queryRegexp(query)
	if err != nil {
		return RowSet{}, err
	}
	notes, _, err := t.src.fetch()
	if err != nil {
		return RowSet{}, &ReadError{err}
	}
	var hits []*snclient.NoteView
	for _, n := range notes {
		if listable(n) && (re.MatchString(n.Title) || re.MatchString(n.Text)) {
			hits = append(hits, n)
		}
	}
	sortByUUID(hits)
	lo, hi := window(len(hits), limit, offset)
	rows := make([]Row, 0, hi-lo)
	for _, n := range hits[lo:hi] {
		rows = append(rows, t.gated(n).row(re))
	}
	return RowSet{Rows: rows}, nil
}

// List returns the live notes in uuid order. Trashed notes are left out, and they
// do not count toward offset. A sensitive note is a stub. limit and offset cut a
// page: see window. Only the notes on the page go to the gate, so a call costs at
// most limit gate calls, however large the vault is (the gate caches by content).
func (t *Tools) List(limit, offset int) (RowSet, error) {
	notes, _, err := t.src.fetch()
	if err != nil {
		return RowSet{}, &ReadError{err}
	}
	live := make([]*snclient.NoteView, 0, len(notes))
	for _, n := range notes {
		if listable(n) {
			live = append(live, n)
		}
	}
	sortByUUID(live)
	lo, hi := window(len(live), limit, offset)
	rows := make([]Row, 0, hi-lo)
	for _, n := range live[lo:hi] {
		rows = append(rows, t.gated(n).row(nil))
	}
	return RowSet{Rows: rows}, nil
}

// The size of a page of rows. A call that sets no limit gets defaultLimit rows, and
// no call gets more than maxLimit. A vault can hold tens of thousands of notes, and
// one result must not carry them all to the orchestrator.
const (
	defaultLimit = 50
	maxLimit     = 500
)

// window returns the rows [lo, hi) of a page out of n rows in uuid order. A limit of
// 0 or less means defaultLimit, and a limit over maxLimit means maxLimit. A
// negative offset means 0, and an offset past the last row gives an empty page.
//
// A page is a cut of the rows in their fixed order, so the same call gives the same
// page while the vault does not change, and a caller that reads page after page
// sees every note once. The tools cut BEFORE they run the gate. Every note makes
// exactly one row, a stub or a note, so the page is the same as a cut after the
// gate, and the gate only sees the notes on the page.
func window(n, limit, offset int) (lo, hi int) {
	if limit <= 0 {
		limit = defaultLimit
	}
	limit = min(limit, maxLimit)
	lo = min(max(offset, 0), n)
	return lo, lo + min(limit, n-lo)
}

// sortByUUID puts notes in uuid order. gosn-v2 does not fetch the notes in a fixed
// order: two fetches of one vault give two orders, and pages cut from them would
// overlap and leave gaps. The sort key is the uuid and nothing from the content.
// The sort is stable, so equal uuids keep the order of the fetch.
func sortByUUID(notes []*snclient.NoteView) {
	slices.SortStableFunc(notes, func(a, b *snclient.NoteView) int { return strings.Compare(a.UUID, b.UUID) })
}

// Get returns one note by uuid: in full when the gate clears it, as a stub when it
// does not. A trashed note is still returned, with Trashed set. A lookup by uuid
// is explicit, and the write tools will need to read a note they have trashed.
func (t *Tools) Get(uuid string) (GetResult, error) {
	id := strings.TrimSpace(uuid)
	if id == "" {
		return GetResult{}, ErrNotFound
	}
	n, err := t.src.fetchOne(id)
	if err != nil {
		return GetResult{}, &ReadError{err}
	}
	if n == nil {
		return GetResult{}, ErrNotFound
	}
	return t.gated(n).detail(), nil
}

// TagsList returns every tag with the uuids of its notes.
//
// Plan 2a does NOT gate tags. They are organizational metadata, and the spec puts
// the gate on note content. A tag title is text the user wrote. A tag's note list
// can say what a stubbed note is about, such as a tag called "passwords" over a
// stub. Plan 3 must decide whether that is acceptable.
func (t *Tools) TagsList() (TagList, error) {
	_, tags, err := t.src.fetch()
	if err != nil {
		return TagList{}, &ReadError{err}
	}
	out := make([]TagRow, 0, len(tags))
	for _, tag := range tags {
		if tag == nil {
			continue
		}
		ids := append(make([]string, 0, len(tag.NoteUUIDs)), tag.NoteUUIDs...)
		out = append(out, TagRow{UUID: tag.UUID, Title: tag.Title, NoteUUIDs: ids})
	}
	return TagList{Tags: out}, nil
}

// listable reports whether a note belongs in Search and List results. Trashed
// notes do not: Standard Notes' own lists hide them, and the cleanup works on live
// notes. Fetch keeps them and sets Trashed, so this is the tools' choice.
func listable(n *snclient.NoteView) bool { return n != nil && !n.Trashed }

// gatedNote is the outcome of putting one note through the gate. It is the ONLY
// way a tool reaches a note's content. The note field is set when the gate cleared
// the note. It is nil for a sensitive note, which leaves only the stub. Build every
// result from a gatedNote, never from a NoteView.
type gatedNote struct {
	note *snclient.NoteView // nil unless the gate cleared the note
	stub gate.Stubbed       // the stand-in when note is nil
}

// gated asks the gate about n. n must not be nil. The gate unions the forced kind,
// the scanner and jev. It errs toward sensitive: a jev failure gives a stub.
func (t *Tools) gated(n *snclient.NoteView) gatedNote { return gateNote(t.gt, n) }

// gateNote is the one place that decides whether a note's content may leave the
// server. The read tools and the write tools both call it, so "sensitive" means one
// thing on every path: the same kind, the same scanner, the same jev, the same
// fail-closed rule. A path that built its own gate.Note could forget the kind, and
// an authenticator note with plain words would then pass.
func gateNote(gt *gate.Gate, n *snclient.NoteView) gatedNote {
	v := gt.Classify(gate.Note{UUID: n.UUID, Title: n.Title, Text: n.Text, Kind: noteKind(n)})
	if v.Sensitive {
		return gatedNote{stub: gate.Stub(n.UUID)}
	}
	return gatedNote{note: n}
}

// row is the list entry for the note. A non-nil re centers the snippet on its first
// match in the text. A nil re starts the snippet at the top of the text.
func (g gatedNote) row(re *regexp.Regexp) Row {
	if g.note == nil {
		stub := g.stub
		return Row{Stub: &stub}
	}
	return Row{Note: &NoteRow{UUID: g.note.UUID, Title: g.note.Title, Snippet: snippetOf(g.note.Text, re)}}
}

// detail is the full note. NoteType and EditorIdentifier are metadata, not note
// content. The gate decides on the title, the text and the kind, and does not scan
// these two fields.
func (g gatedNote) detail() GetResult {
	if g.note == nil {
		stub := g.stub
		return GetResult{Stub: &stub}
	}
	n := g.note
	return GetResult{Note: &NoteDetail{
		UUID: n.UUID, Title: n.Title, Text: n.Text,
		NoteType: n.NoteType, EditorIdentifier: n.EditorIdentifier, Trashed: n.Trashed,
	}}
}

// The kinds noteKind gives the gate. The gate forces "authentication" to
// sensitive (spec 6.1). The other kind is not forced.
const (
	kindAuthentication = "authentication"
	kindNote           = "note"
)

// The values that mark an authenticator (TOTP secrets) note. Both come from
// Standard Notes' own @standardnotes/features. The self-hosted server bundles that
// package (v1.59.7, read 2026-10-05), and the upstream main branch agrees:
//
//	NoteType.Authentication            = "authentication"
//	FeatureIdentifier.TokenVaultEditor = "org.standardnotes.token-vault"
//
// The second is the "Authenticator" editor, whose note_type is the first.
// gosn-v2 lists the same editor identifier in items/editors.go. It has no NoteType
// enum. A test pins the identifier to that list.
const (
	noteTypeAuthentication = "authentication"
	editorTokenVault       = "org.standardnotes.token-vault"
)

// noteKind maps a note's type and editor to the kind the gate takes. It returns
// "authentication" for an authenticator note, which the gate always stubs, and
// "note" for everything else. Either marker is enough. Standard Notes writes both,
// and another client can write one. A note from a client that wrote neither is
// left to the scanner and jev.
func noteKind(n *snclient.NoteView) string {
	if fold(n.NoteType) == noteTypeAuthentication || fold(n.EditorIdentifier) == editorTokenVault {
		return kindAuthentication
	}
	return kindNote
}

func fold(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// maxQueryBytes is the longest query Search takes. A search term is short. The
// limit keeps a pasted page from becoming a very large pattern.
const maxQueryBytes = 256

// queryRegexp turns a query into a case-insensitive literal match. It needs match
// offsets in the ORIGINAL text, so it uses a regexp and not strings.ToLower.
// Lowering can change a string's length for some letters. An offset from the
// lowered copy then points into the wrong place.
func queryRegexp(query string) (*regexp.Regexp, error) {
	q := strings.TrimSpace(query)
	switch {
	case q == "":
		return nil, ErrEmptyQuery
	case len(q) > maxQueryBytes:
		return nil, ErrQueryTooLong
	}
	q = strings.ToValidUTF8(q, "\uFFFD")
	re, err := regexp.Compile("(?i)" + regexp.QuoteMeta(q))
	if err != nil {
		// A quoted literal of valid UTF-8 under the length limit always compiles.
		// The error text holds the query, so this code does not pass it on.
		return nil, errBadQuery
	}
	return re, nil
}

const (
	snippetMax  = 160 // runes in a snippet, not counting its two marks
	snippetLead = 40  // runes of text kept before a match
)

// snippetOf returns a short piece of text. Call it only for a note the gate
// cleared. It is the one function here that cuts content out of a note body.
func snippetOf(text string, re *regexp.Regexp) string {
	at := 0
	if re != nil {
		if loc := re.FindStringIndex(text); loc != nil {
			at = loc[0]
		}
	}
	return excerpt(text, at)
}

// excerpt returns the text near byte offset at, as one line of at most snippetMax
// runes. It keeps up to snippetLead runes before at. It collapses every run of
// whitespace to one space and marks a cut with "…". It moves by whole runes, so
// it never splits a character. It clamps at, so a bad offset cannot panic.
func excerpt(text string, at int) string {
	at = max(0, min(at, len(text)))
	start := at
	for i := 0; i < snippetLead && start > 0; i++ {
		_, size := utf8.DecodeLastRuneInString(text[:start])
		start -= size
	}
	end := start
	for i := 0; i < snippetMax && end < len(text); i++ {
		_, size := utf8.DecodeRuneInString(text[end:])
		end += size
	}
	s := strings.Join(strings.Fields(text[start:end]), " ")
	if start > 0 {
		s = "…" + s
	}
	if end < len(text) {
		s += "…"
	}
	return s
}
