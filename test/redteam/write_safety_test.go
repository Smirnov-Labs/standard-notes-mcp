package redteam

// The write-safety red-team. It is the acceptance gate of Plan 2b. It tests the whole
// write surface together, through mcptools.Writer, on an account that looks like the demo
// account. The read red-team (redteam_test.go) asks whether the orchestrator can learn what
// a sensitive note says. This test asks what the write tools can do to a vault, and whether
// they can show a sensitive note. The assertions are the result.
//
// The test builds the write side as cmd/sn-mcp builds it: a client, a guard, an engine with a
// ledger, a gate and the Writer. Each pass makes a new account and plants these items:
//
//	rich       a note with every field that the typed model of gosn-v2 drops
//	Alpha      a plain note. Beta is another.
//	prod keys  a sensitive note: an AWS access key
//	projects   a tag with fields of its own, over Beta and the sensitive note
//
// Six invariants, one phase each:
//
//  1. Metadata. note_edit, note_rename, note_trash and note_untrash change the key that they
//     name and client_updated_at, and nothing else. Every other field of the rich note keeps
//     the bytes of its seed. The seed has odd spacing and number forms, so a value that was
//     parsed and written again would not match.
//  2. Trash is reversible. A trash sets a flag inside the note. The note stays fetchable, and
//     an untrash clears the flag. The envelope deleted flag is set on no item.
//  3. Merge is additive. The merged note holds each source verbatim. The sources are in the
//     trash, whole.
//  4. Sensitive notes are walled off. An edit, a rename and a merge refuse the note, in a dry
//     run and in a write, and change nothing. A trash is allowed and shows a stub.
//  5. Tags. Apply, detach, create, rename and trash do what they say and keep every field
//     that they do not name. A trashed tag stays on the server.
//  6. The write cap and the ledger. A second write over the cap is refused and writes
//     nothing. Dry runs still work. The ledger holds every write that landed.
//
// Phase 4 also shows that a jev outage closes the wall around every note. Phase 5 also shows
// that a note tool given the uuid of a tag, and a tag tool given the uuid of a note, write
// nothing.
//
// Two checks hold every phase to account.
//
//   - After every call, a second session lists every item on the server (see auditor). The
//     items that changed must be exactly the items that the call names. A dry run and a
//     refused call change none. No item is deleted, and none vanishes. This is the check on
//     "a write changes only what it names" and on "nothing is deleted anywhere".
//   - The test keeps every result and error that a tool returned. At the end, the sweep looks
//     in them, and in the ledgers, for the sensitive note. It uses the leak checker of the
//     read red-team.
//
// A check that cannot fail proves nothing. TestWriteSafetyCheckersCanFail gives each checker a
// failure that it must find. It needs no server.
//
// The test runs twice, as the read red-team does. The first pass uses the real gate: real
// jev at the real threshold. It skips when jev does not answer. The second pass uses a jev
// that rates every note 0, so only the scanner and the note kind can wall a note off. It
// shows that no privacy rule rests on nimble.
//
// This file must not make an item deleted, and it names no call that does. A guard in
// internal/writeengine fails when non-test source does. Here the test only reads the flag.

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jonhadfield/gosn-v2/auth"
	"github.com/jonhadfield/gosn-v2/common"
	"github.com/jonhadfield/gosn-v2/items"
	gosnsession "github.com/jonhadfield/gosn-v2/session"
	"github.com/smirnov-labs/standard-notes-mcp/internal/gate"
	"github.com/smirnov-labs/standard-notes-mcp/internal/mcptools"
	"github.com/smirnov-labs/standard-notes-mcp/internal/snclient"
	"github.com/smirnov-labs/standard-notes-mcp/internal/testsupport"
	"github.com/smirnov-labs/standard-notes-mcp/internal/writeengine"
)

// ---- the items that the test plants ----

const (
	// The plain notes. The gate must clear every one of them, with the real jev too.
	richTitle    = "Reading list"
	richText     = "finish the Go concurrency book; skim the Raft paper"
	richNewText  = richText + "; re-read the SN protocol notes"
	richNewTitle = "Reading list 2026"

	// The sensitive note. It holds an AWS access key: the public example of the AWS
	// documentation. Tier 0 (the scanner) flags it with no help from jev.
	keysTitle = "prod keys"
	keysText  = "AKIAIOSFODNN7EXAMPLE"

	// The raw content of the sensitive note. It has fields of its own, so the checks can
	// show that the trash of a sensitive note keeps them.
	keysSeed = `{"title":"prod keys","text":"AKIAIOSFODNN7EXAMPLE","references":[],"starred":true,` +
		`"appData":{"org.standardnotes.sn":{"client_updated_at":"2020-01-01T00:00:00.000Z","pinned":true},` +
		`"dev.example.editor":{"theme":"dark"}},"future_unknown_key":{"keep":"me"}}`
)

// keysNote is the sensitive note as the leak checker of the read red-team takes it.
var keysNote = note{name: "prod-keys", title: keysTitle, body: keysText,
	telltales: []string{keysText, "AKIA", keysTitle}}

// richSeed is the raw content of the rich note. It has every kind of field that the typed
// model of gosn-v2 drops: top-level flags, flags inside the appData domain of Standard Notes,
// a third-party appData domain, an unknown key, a spellcheck flag and a reference. The values
// that the typed model does not know are written with odd spacing and number forms (17.0,
// 1e2, a space before a colon, a \u escape, a null). A value that went through a parse and a
// write would come back in another form. Only a copy of the bytes matches.
func richSeed(linked string) string {
	return `{"title":"` + richTitle + `","text":"` + richText + `",` +
		`"references":[{"uuid":"` + linked + `","content_type":"Note"}],` +
		`"protected":true,"starred":true,` +
		`"appData":{"org.standardnotes.sn":{"client_updated_at":"2020-01-01T00:00:00.000Z","archived":true,"locked":true},` +
		`"dev.example.editor":{ "theme" : "dark", "fontSize":17.0, "zoom":1e2, "keys":["a" , "b"] }},` +
		`"spellcheck":false,"future_unknown_key":{"z":1, "a":[1.0,2.50,"caf\u00e9"],"n":null}}`
}

// tagSeed is the raw content of the tag. It holds two note references, and it has an
// unknown key and a third-party appData domain. The references have no spaces between them,
// so an apply followed by a detach gives the same bytes back.
func tagSeed(beta, keys string) string {
	return `{"title":"projects",` +
		`"references":[{"uuid":"` + beta + `","content_type":"Note"},{"uuid":"` + keys + `","content_type":"Note"}],` +
		`"expanded":true,"iconString":"hashtag",` +
		`"appData":{"org.standardnotes.sn":{"client_updated_at":"2020-01-01T00:00:00.000Z"},"dev.example.tags":{ "color" : "teal" }},` +
		`"future_tag_key":{"z":1, "a":[1.0,2.50]}}`
}

// snDomain is the appData domain that holds client_updated_at.
const snDomain = "org.standardnotes.sn"

// cuaKeys is the path of client_updated_at, and cuaPath is the same in the form of
// changedPaths.
var cuaKeys = []string{"appData", snDomain, "client_updated_at"}

const cuaPath = "appData." + snDomain + ".client_updated_at"

// richExtras are the fields of the rich note that no write tool may touch. Each is named in
// the spec, and each is checked by its own bytes.
var richExtras = []struct {
	name string
	path []string
}{
	{"protected", []string{"protected"}},
	{"starred", []string{"starred"}},
	{"archived", []string{"appData", snDomain, "archived"}},
	{"locked", []string{"appData", snDomain, "locked"}},
	{"dev.example.editor", []string{"appData", "dev.example.editor"}},
	{"future_unknown_key", []string{"future_unknown_key"}},
	{"spellcheck", []string{"spellcheck"}},
	{"the reference", []string{"references"}},
}

// ledgerKind is the kind that the engine writes in the ledger for each tool.
var ledgerKind = map[string]string{
	"note_edit": "edit", "note_rename": "rename", "note_trash": "trash", "note_untrash": "untrash",
	"tag_apply": "tag", "tag_detach": "detach", "tag_create": "tag-create",
	"tag_rename": "tag-rename", "tag_trash": "tag-trash",
}

// jevOffline is a jev that fails every call, as a jev that is down does.
type jevOffline struct{}

func (jevOffline) SensitiveProbability(string) (float64, error) {
	return 0, errors.New("jev is down")
}

// ---- the checkers ----
//
// These are plain functions, so that TestWriteSafetyCheckersCanFail can test them with no
// server.

// itemState is what the server shows about one item to a client that holds no key: its type,
// the deleted flag of its envelope, the updated_at_timestamp that the server sets on every
// save, and a digest of the ciphertext. A write encrypts again, with a new nonce and a new
// item key, so the digest changes on every write that reaches the server, even when the
// plain bytes stay the same. A call changed an item exactly when its itemState changed.
type itemState struct {
	ContentType string
	Deleted     bool
	UpdatedAt   int64
	Cipher      [sha256.Size]byte
}

// statesOf maps the items of a sync to their states.
func statesOf(encrypted items.EncryptedItems) map[string]itemState {
	out := make(map[string]itemState, len(encrypted))
	for _, e := range encrypted {
		out[e.UUID] = itemState{
			ContentType: e.ContentType,
			Deleted:     e.Deleted,
			UpdatedAt:   e.UpdatedAtTimestamp,
			Cipher:      sha256.Sum256([]byte(e.Content + "\x00" + e.EncItemKey)),
		}
	}
	return out
}

// changedItems lists, in order, the uuids of the items that are new, gone or different in
// after.
func changedItems(before, after map[string]itemState) []string {
	var out []string
	for id, a := range after {
		if b, ok := before[id]; !ok || b != a {
			out = append(out, id)
		}
	}
	for id := range before {
		if _, ok := after[id]; !ok {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return out
}

// deletedItems lists, in order, the uuids whose envelope is marked deleted.
func deletedItems(states map[string]itemState) []string {
	var out []string
	for id, s := range states {
		if s.Deleted {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return out
}

// rawObject splits the content of an item into its top-level raw values. Each value keeps
// the bytes that it has in the content, spaces and number forms included.
func rawObject(content []byte) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(content, &m); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errors.New("value is null")
	}
	return m, nil
}

// keysOf lists, in order, the keys of the objects.
func keysOf(objects ...map[string]json.RawMessage) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range objects {
		for k := range m {
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	slices.Sort(out)
	return out
}

// rawAt returns the bytes at a path of object keys, or nil when a step is missing.
func rawAt(content string, path ...string) json.RawMessage {
	cur := json.RawMessage(content)
	for _, k := range path {
		m, err := rawObject(cur)
		if err != nil {
			return nil
		}
		next, ok := m[k]
		if !ok {
			return nil
		}
		cur = next
	}
	return cur
}

// rawString decodes a raw JSON string. It returns "" for anything else.
func rawString(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

// later reports whether the raw client_updated_at a is after b.
func later(a, b json.RawMessage) bool {
	ta, errA := time.Parse(common.TimeLayout, rawString(a))
	tb, errB := time.Parse(common.TimeLayout, rawString(b))
	return errA == nil && errB == nil && ta.After(tb)
}

// changedPaths lists, in order, every place where two contents of one item differ in bytes. A
// place is a top-level key, a domain of appData, or a key of the appData domain of Standard
// Notes. A key that only one side has differs. The order of the keys in an object does not
// count, and the spacing inside a value does: a value is a copy or it is not.
func changedPaths(before, after string) ([]string, error) {
	b, err := rawObject([]byte(before))
	if err != nil {
		return nil, fmt.Errorf("the content before is not a JSON object: %w", err)
	}
	a, err := rawObject([]byte(after))
	if err != nil {
		return nil, fmt.Errorf("the content after is not a JSON object: %w", err)
	}
	var out []string
	for _, k := range keysOf(b, a) {
		switch {
		case bytes.Equal(b[k], a[k]):
		case k == "appData":
			out = append(out, appDataPaths(b[k], a[k])...)
		default:
			out = append(out, k)
		}
	}
	return out, nil
}

// appDataPaths is changedPaths one level down. Each domain of appData is one place, and the
// domain of Standard Notes is looked at key by key. A value that is not an object on both
// sides differs as a whole.
func appDataPaths(before, after json.RawMessage) []string {
	b, errB := rawObject(before)
	a, errA := rawObject(after)
	if errB != nil || errA != nil {
		return []string{"appData"}
	}
	var out []string
	for _, d := range keysOf(b, a) {
		switch {
		case bytes.Equal(b[d], a[d]):
		case d == snDomain:
			out = append(out, domainPaths("appData."+d, b[d], a[d])...)
		default:
			out = append(out, "appData."+d)
		}
	}
	return out
}

func domainPaths(prefix string, before, after json.RawMessage) []string {
	b, errB := rawObject(before)
	a, errA := rawObject(after)
	if errB != nil || errA != nil {
		return []string{prefix}
	}
	var out []string
	for _, k := range keysOf(b, a) {
		if !bytes.Equal(b[k], a[k]) {
			out = append(out, prefix+"."+k)
		}
	}
	return out
}

// ledgerOp is one op of a ledger: all the lines that share an OpID.
type ledgerOp struct {
	ID, Kind, UUID string
	States         []string
}

// ledgerOps reads the text of a ledger file. It groups the lines by op, in the order of the
// first line of each op.
func ledgerOps(text string) ([]ledgerOp, error) {
	var ops []ledgerOp
	at := map[string]int{}
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var rec struct{ OpID, Kind, UUID, State string }
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return nil, fmt.Errorf("a ledger line is not JSON: %w", err)
		}
		i, ok := at[rec.OpID]
		if !ok {
			i = len(ops)
			at[rec.OpID] = i
			ops = append(ops, ledgerOp{ID: rec.OpID, Kind: rec.Kind, UUID: rec.UUID})
		}
		ops[i].States = append(ops[i].States, rec.State)
	}
	return ops, nil
}

// landed is what the ledger holds for an op that went through: it was meant, the server
// acked it, and the read-after-write check passed.
var landed = []string{"intended", "acked", "verified"}

// ---- the auditor ----

// auditor reads the server as a second session. It signs in on its own, so it shares no state
// with the client that the write tools use, and it only reads.
//
// A delete shows in two ways. A full sync leaves out the items that are deleted, so a deleted
// item is missing from the list of every item. And the auditor follows the sync token: a sync
// that starts from the last token lists the items that changed since then, deleted ones too,
// with the deleted flag of their envelope. That flag is the permanent delete, and no typed
// read shows it.
type auditor struct {
	sess  *gosnsession.Session
	token string // the sync token that the last call of states ended on
}

func newAuditor(t testing.TB, email, password string) *auditor {
	t.Helper()
	hc := common.NewHTTPClient()
	so, err := auth.SignIn(auth.SignInInput{HTTPClient: hc, Email: email, Password: password, APIServer: testsupport.TestServer})
	if err != nil {
		t.Fatalf("the audit session cannot sign in: %v", err)
	}
	return &auditor{sess: &gosnsession.Session{
		HTTPClient: hc, Server: testsupport.TestServer, FilesServerUrl: so.Session.FilesServerUrl,
		MasterKey: so.Session.MasterKey, KeyParams: so.KeyParams,
		AccessToken: so.Session.AccessToken, RefreshToken: so.Session.RefreshToken,
		AccessExpiration: so.Session.AccessExpiration, RefreshExpiration: so.Session.RefreshExpiration,
		AccessTokenCookie: so.Session.AccessTokenCookie, RefreshTokenCookie: so.Session.RefreshTokenCookie,
		PasswordNonce: so.Session.PasswordNonce,
	}}
}

// states reads every item of the account. It also returns the uuids of the items that were
// deleted since the last call.
func (a *auditor) states(t testing.TB) (all map[string]itemState, deleted []string) {
	t.Helper()
	full, err := items.Sync(items.SyncInput{Session: a.sess})
	if err != nil {
		t.Fatalf("the audit session cannot read the server: %v", err)
	}
	since, err := items.Sync(items.SyncInput{Session: a.sess, SyncToken: a.token})
	if err != nil {
		t.Fatalf("the audit session cannot read the changes since the last check: %v", err)
	}
	a.token = since.SyncToken
	return statesOf(full.Items), deletedItems(statesOf(since.Items))
}

// ---- the rig ----

// seeds are the items of the demo-like account.
type seeds struct {
	rich, alpha, beta, keys, tag string // uuids
	richRaw, keysRaw, tagRaw     string // the content of each, as planted
	merged                       string // the merged note. Phase 3 makes it.
}

// writeRig is the write side as the server wires it, plus the means to check it. The tools
// run through w. The test reads the vault back through c, and through the read tools.
type writeRig struct {
	t *testing.T // the test that is running now: see run

	email, password string
	c               *snclient.Client
	guard           *snclient.Guard
	gt              *gate.Gate
	eng             *writeengine.Engine
	w               *mcptools.Writer // the tools under test
	tools           *mcptools.Tools  // the read tools: what the orchestrator reads with
	ledger          string           // the ledger of eng
	extraLedgers    []string         // the ledgers of the other engines that a phase makes
	au              *auditor
	s               seeds

	mark  map[string]itemState // the server as it was after the last check
	names map[string]string    // uuid -> a name for a failure message

	caps     []capture // every result and error that a tool returned, for the sweep
	wrote    []string  // the ledger kind of each op that the writes of w must have made, in order
	opIDs    []string  // the OpID that each write of w returned
	refusals int       // how many sensitive-note refusals the sweep covers
	stubs    int       // how many stub results it covers
}

func newWriteRig(t *testing.T, email, password string, gt *gate.Gate) *writeRig {
	t.Helper()
	c, err := snclient.SignIn(snclient.Config{Server: testsupport.TestServer}, email, password,
		func(string) (string, error) { return "", nil })
	if err != nil {
		t.Fatal(err)
	}
	ledger := filepath.Join(t.TempDir(), "ledger.jsonl")
	led, err := writeengine.OpenLedger(ledger)
	if err != nil {
		t.Fatal(err)
	}
	guard := snclient.NewGuard(c, "")
	eng := writeengine.NewEngine(c, led, 1000)
	return &writeRig{
		t: t, email: email, password: password, c: c, guard: guard, gt: gt, eng: eng,
		w: mcptools.NewWriter(guard, eng, gt), tools: mcptools.New(guard, gt),
		ledger: ledger, au: newAuditor(t, email, password), names: map[string]string{},
	}
}

// run runs one phase as a subtest. The helpers of the rig fail the test in r.t, so run
// points r.t at the subtest while the phase runs. Phases run one after another.
func (r *writeRig) run(name string, phase func()) {
	parent := r.t
	parent.Run(name, func(t *testing.T) {
		r.t = t
		defer func() { r.t = parent }()
		r.rebase()
		phase()
	})
}

func (r *writeRig) name(id string) string {
	if n, ok := r.names[id]; ok {
		return n
	}
	return id
}

func (r *writeRig) label(ids []string) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = r.name(id)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func (r *writeRig) mustOK(what string, err error) {
	r.t.Helper()
	if err != nil {
		r.t.Fatalf("%s: %v", what, err)
	}
}

// seed plants the items. It checks the premises that the phases rest on: the gate clears every
// plain note, and the scanner alone walls off the sensitive one.
func (r *writeRig) seed() {
	t, c := r.t, r.c
	plant := func(what string, seed func() (string, error)) string {
		t.Helper()
		id, err := seed()
		if err != nil {
			t.Fatalf("plant %s: %v", what, err)
		}
		return id
	}
	r.s.alpha = plant("Alpha", func() (string, error) { return c.SeedNote(t, "Alpha", "one") })
	r.s.beta = plant("Beta", func() (string, error) { return c.SeedNote(t, "Beta", "two") })
	r.s.richRaw = richSeed(r.s.alpha)
	r.s.rich = plant("the rich note", func() (string, error) { return c.SeedRawNote(t, r.s.richRaw) })
	r.s.keysRaw = keysSeed
	r.s.keys = plant("the sensitive note", func() (string, error) { return c.SeedRawNote(t, r.s.keysRaw) })
	r.s.tagRaw = tagSeed(r.s.beta, r.s.keys)
	r.s.tag = plant("the tag", func() (string, error) { return c.SeedRawTag(t, r.s.tagRaw) })
	for id, n := range map[string]string{
		r.s.rich: "the rich note", r.s.alpha: "Alpha", r.s.beta: "Beta",
		r.s.keys: "the sensitive note", r.s.tag: "the tag projects",
	} {
		r.names[id] = n
	}

	for _, v := range [][2]string{
		{richTitle, richText}, {richTitle, richNewText}, {richNewTitle, richNewText},
		{"Alpha", "one"}, {"Beta", "two"},
	} {
		if verdict := r.gt.Classify(gate.Note{Title: v[0], Text: v[1], Kind: "note"}); verdict.Sensitive {
			t.Fatalf("premise broken: the gate walls off the plain note %q (%v), so no write tool can act on it. Pick plainer text, or check jev.", v[0], verdict.Reasons)
		}
	}
	if !gate.Scan(keysTitle + "\n" + keysText).Sensitive {
		t.Fatal("premise broken: tier 0 does not flag the sensitive note, so its wall would rest on jev")
	}
	r.rebase()
}

// ---- checking the server ----

// rebase takes the server as it is now as the base for the next check. It still insists that
// nothing is deleted and that nothing vanished since the last check.
func (r *writeRig) rebase() {
	r.t.Helper()
	now, deleted := r.au.states(r.t)
	r.requireIntact("between two phases", now, deleted)
	r.mark = now
}

// requireIntact fails when an item has its envelope deleted, or when an item that the last
// check saw is not there. deleted holds the items that the sync of the auditor lists as deleted
// since the last check. now holds the items that a full sync lists, and a full sync leaves
// out the deleted ones.
func (r *writeRig) requireIntact(what string, now map[string]itemState, deleted []string) {
	r.t.Helper()
	for id := range r.mark {
		if _, ok := now[id]; !ok {
			r.t.Errorf("INVARIANT BROKEN, %s: %s vanished from the server. No write tool may remove an item.", what, r.name(id))
		}
	}
	gone := slices.Clone(deleted)
	gone = append(gone, deletedItems(now)...)
	slices.Sort(gone)
	if gone = slices.Compact(gone); len(gone) > 0 {
		r.t.Errorf("INVARIANT BROKEN, %s: the envelope of %s is marked deleted. That removes an item for good. No write tool may set it.", what, r.label(gone))
	}
}

// expect checks the server after one call. Exactly the items in want must have changed since
// the last check. An item changed when it is new, gone, or written. A call that must write
// nothing, which is a dry run or a refused call, passes no uuid. No item may be deleted, and
// none may vanish.
func (r *writeRig) expect(what string, want ...string) {
	r.t.Helper()
	now, deleted := r.au.states(r.t)
	got := changedItems(r.mark, now)
	want = slices.Clone(want)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		r.t.Errorf("INVARIANT BROKEN, %s: the items that changed on the server are %s, want exactly %s.", what, r.label(got), r.label(want))
	}
	r.requireIntact(what, now, deleted)
	r.mark = now
}

// requirePaths fails unless the two contents differ at exactly these places.
func (r *writeRig) requirePaths(what, before, after string, want ...string) {
	r.t.Helper()
	got, err := changedPaths(before, after)
	if err != nil {
		r.t.Fatalf("%s: %v", what, err)
	}
	want = slices.Clone(want)
	slices.Sort(want)
	want = slices.Compact(want)
	if !slices.Equal(got, want) {
		r.t.Errorf("INVARIANT BROKEN, %s: the content differs at %v, want exactly %v.\n  before: %s\n  after:  %s", what, got, want, before, after)
	}
}

// ---- reading back ----

// raw returns the decrypted content of a note, as the server holds it. It fails the test when
// the note is not there: FetchRawOne refuses a note that is deleted.
func (r *writeRig) raw(id string) string {
	r.t.Helper()
	n, err := r.c.FetchRawOne(id)
	if err != nil {
		r.t.Fatalf("%s cannot be read raw (a note that is gone or deleted fails here): %v", r.name(id), err)
	}
	return n.Content()
}

// rawTag is raw for a tag.
func (r *writeRig) rawTag(id string) string {
	r.t.Helper()
	n, err := r.c.FetchRawTag(id)
	if err != nil {
		r.t.Fatalf("%s cannot be read raw (a tag that is gone or deleted fails here): %v", r.name(id), err)
	}
	return n.Content()
}

// liveNote reads a note through the typed path, and fails the test when it is gone.
func (r *writeRig) liveNote(id string) *snclient.NoteView {
	r.t.Helper()
	n, err := r.c.FetchOne(id)
	if err != nil {
		r.t.Fatal(err)
	}
	if n == nil {
		r.t.Fatalf("%s is gone. No write tool may delete a note.", r.name(id))
	}
	return n
}

// The read tools, as the orchestrator calls them. Their results go to the sweep too.

func (r *writeRig) get(id string) mcptools.GetResult {
	r.t.Helper()
	res, err := r.tools.Get(id)
	r.see("notes_get("+r.name(id)+")", res, err)
	r.mustOK("notes_get", err)
	return res
}

func (r *writeRig) list() mcptools.RowSet {
	r.t.Helper()
	res, err := r.tools.List(500, 0)
	r.see("notes_list()", res, err)
	r.mustOK("notes_list", err)
	return res
}

func (r *writeRig) tagList() mcptools.TagList {
	r.t.Helper()
	res, err := r.tools.TagsList()
	r.see("tags_list()", res, err)
	r.mustOK("tags_list", err)
	return res
}

// ---- the write tools, with their results kept ----

// see keeps the result and the error of a call for the sweep. It counts the refusals and the
// stubs, so that the sweep can show that it saw some.
func (r *writeRig) see(call string, res any, err error) {
	r.t.Helper()
	r.caps = append(r.caps, newCapture(r.t, call, res))
	if err != nil {
		r.caps = append(r.caps, errCapture(call+" (error)", err))
		if errors.Is(err, mcptools.ErrSensitiveEdit) || errors.Is(err, mcptools.ErrSensitiveMerge) {
			r.refusals++
		}
	}
	switch v := res.(type) {
	case mcptools.NoteWriteResult:
		if v.Before.Stub != nil {
			r.stubs++
		}
	case mcptools.GetResult:
		if v.Stub != nil {
			r.stubs++
		}
	}
}

// keep is see for a call of w. It also notes what the ledger must hold for the call: nothing
// for a dry run or an error, and one op for a write. A merge makes the merged note, and then
// trashes each source that it moved.
func (r *writeRig) keep(call string, res any, err error) {
	r.t.Helper()
	r.see(call, res, err)
	if err != nil {
		return
	}
	switch v := res.(type) {
	case mcptools.NoteWriteResult:
		r.ledgerEntry(call, v.DryRun, v.OpID, ledgerKind[v.Action])
	case mcptools.TagWriteResult:
		if v.Action == "tag_create" && !v.Created {
			return // the tag was there, so the call writes nothing
		}
		r.ledgerEntry(call, v.DryRun, v.OpID, ledgerKind[v.Action])
	case mcptools.MergeResult:
		if r.ledgerEntry(call, v.DryRun, v.OpID, "merge") {
			for _, src := range v.Sources {
				if src.Trashed {
					r.wrote = append(r.wrote, "trash")
				}
			}
		}
	}
}

// ledgerEntry notes the op that a result must have in the ledger. A dry run has no OpID and
// no op. A write has an OpID and one op. It reports whether the result is a write.
func (r *writeRig) ledgerEntry(call string, dry bool, opID, kind string) bool {
	r.t.Helper()
	if dry {
		if opID != "" {
			r.t.Errorf("INVARIANT BROKEN, %s: a dry run has the ledger id %q, so it reached Commit", call, opID)
		}
		return false
	}
	if opID == "" || kind == "" {
		r.t.Errorf("%s: a write has the ledger id %q and the kind %q, want both set", call, opID, kind)
		return false
	}
	r.wrote = append(r.wrote, kind)
	r.opIDs = append(r.opIDs, opID)
	return true
}

func kept[T any](r *writeRig, call string, res T, err error) (T, error) {
	r.t.Helper()
	r.keep(call, res, err)
	return res, err
}

func (r *writeRig) noteEdit(id, text string, dry bool) (mcptools.NoteWriteResult, error) {
	res, err := r.w.NoteEdit(id, text, dry)
	return kept(r, fmt.Sprintf("note_edit(%s, dry=%v)", r.name(id), dry), res, err)
}

func (r *writeRig) noteRename(id, title string, dry bool) (mcptools.NoteWriteResult, error) {
	res, err := r.w.NoteRename(id, title, dry)
	return kept(r, fmt.Sprintf("note_rename(%s, dry=%v)", r.name(id), dry), res, err)
}

func (r *writeRig) noteTrash(id string, dry bool) (mcptools.NoteWriteResult, error) {
	res, err := r.w.NoteTrash(id, dry)
	return kept(r, fmt.Sprintf("note_trash(%s, dry=%v)", r.name(id), dry), res, err)
}

func (r *writeRig) noteUntrash(id string, dry bool) (mcptools.NoteWriteResult, error) {
	res, err := r.w.NoteUntrash(id, dry)
	return kept(r, fmt.Sprintf("note_untrash(%s, dry=%v)", r.name(id), dry), res, err)
}

func (r *writeRig) noteMerge(ids []string, title string, dry bool) (mcptools.MergeResult, error) {
	res, err := r.w.NoteMerge(ids, title, dry)
	return kept(r, fmt.Sprintf("note_merge(%s, dry=%v)", r.label(ids), dry), res, err)
}

func (r *writeRig) tagApply(title string, ids []string, dry bool) (mcptools.TagWriteResult, error) {
	res, err := r.w.TagApply(title, ids, dry)
	return kept(r, fmt.Sprintf("tag_apply(%q, %s, dry=%v)", title, r.label(ids), dry), res, err)
}

func (r *writeRig) tagDetach(tag string, ids []string, dry bool) (mcptools.TagWriteResult, error) {
	res, err := r.w.TagDetach(tag, ids, dry)
	return kept(r, fmt.Sprintf("tag_detach(%s, %s, dry=%v)", r.name(tag), r.label(ids), dry), res, err)
}

func (r *writeRig) tagCreate(title string, dry bool) (mcptools.TagWriteResult, error) {
	res, err := r.w.TagCreate(title, dry)
	return kept(r, fmt.Sprintf("tag_create(%q, dry=%v)", title, dry), res, err)
}

func (r *writeRig) tagRename(tag, title string, dry bool) (mcptools.TagWriteResult, error) {
	res, err := r.w.TagRename(tag, title, dry)
	return kept(r, fmt.Sprintf("tag_rename(%s, %q, dry=%v)", r.name(tag), title, dry), res, err)
}

func (r *writeRig) tagTrash(tag string, dry bool) (mcptools.TagWriteResult, error) {
	res, err := r.w.TagTrash(tag, dry)
	return kept(r, fmt.Sprintf("tag_trash(%s, dry=%v)", r.name(tag), dry), res, err)
}

// requireNoteWrite fails unless res is the result of a write of this tool: not a dry run, with
// a ledger id.
func (r *writeRig) requireNoteWrite(res mcptools.NoteWriteResult, action string) {
	r.t.Helper()
	if res.DryRun || res.Action != action || res.OpID == "" {
		r.t.Errorf("%s: a write must say it is not a dry run, name its tool and have a ledger id: %s", action, wire(r.t, res))
	}
}

// ---- phase 1: metadata ----

func (r *writeRig) phaseMetadata() {
	t, s := r.t, &r.s
	seed := s.richRaw
	if got := r.raw(s.rich); got != seed {
		t.Fatalf("premise: the server does not hold the seed of the rich note byte for byte.\n got %s\nwant %s", got, seed)
	}
	for _, x := range richExtras {
		if len(rawAt(seed, x.path...)) == 0 {
			t.Fatalf("premise: the seed has no %s, so a check on it proves nothing", x.name)
		}
	}

	prev := seed
	touched := []string{cuaPath}
	// check holds the rich note to the rules after one write, and returns its new content.
	check := func(tool, key string) string {
		t.Helper()
		r.expect(tool, s.rich) // the rich note changed on the server, and no other item
		now := r.raw(s.rich)
		r.requirePaths(tool+" against the step before", prev, now, key, cuaPath)
		if !slices.Contains(touched, key) {
			touched = append(touched, key)
		}
		r.requirePaths(tool+" against the seed", seed, now, touched...)
		for _, x := range richExtras {
			if want, got := rawAt(seed, x.path...), rawAt(now, x.path...); !bytes.Equal(want, got) {
				t.Errorf("INVARIANT BROKEN, %s: %s is not the seed's bytes.\n  seed: %s\n  now:  %s", tool, x.name, want, got)
			}
		}
		if !later(rawAt(now, cuaKeys...), rawAt(prev, cuaKeys...)) {
			t.Errorf("%s: client_updated_at did not move forward: %s -> %s", tool, rawAt(prev, cuaKeys...), rawAt(now, cuaKeys...))
		}
		prev = now
		return now
	}

	// note_edit. A dry run shows the old text, echoes the new text and writes nothing.
	res, err := r.noteEdit(s.rich, richNewText, true)
	r.mustOK("note_edit dry run", err)
	if n := res.Before.Note; !res.DryRun || n == nil || n.Title != richTitle || n.Text != richText ||
		res.NewText == nil || *res.NewText != richNewText || res.OpID != "" {
		t.Fatalf("note_edit dry run: %s", wire(t, res))
	}
	r.expect("note_edit dry run")

	res, err = r.noteEdit(s.rich, richNewText, false)
	r.mustOK("note_edit", err)
	r.requireNoteWrite(res, "note_edit")
	now := check("note_edit", "text")
	if got := rawString(rawAt(now, "text")); got != richNewText {
		t.Errorf("note_edit: the text is %q, want %q", got, richNewText)
	}

	// note_rename.
	res, err = r.noteRename(s.rich, richNewTitle, false)
	r.mustOK("note_rename", err)
	r.requireNoteWrite(res, "note_rename")
	now = check("note_rename", "title")
	if got := rawString(rawAt(now, "title")); got != richNewTitle {
		t.Errorf("note_rename: the title is %q, want %q", got, richNewTitle)
	}

	// note_trash. The note goes to the trash, and the read tool still returns it.
	res, err = r.noteTrash(s.rich, false)
	r.mustOK("note_trash", err)
	r.requireNoteWrite(res, "note_trash")
	if n := res.Before.Note; n == nil || n.Trashed {
		t.Errorf("note_trash: the result must show the note as it was, out of the trash: %s", wire(t, res))
	}
	now = check("note_trash", "trashed")
	if got := string(rawAt(now, "trashed")); got != "true" {
		t.Errorf("note_trash: trashed is %s, want true", got)
	}
	if g := r.get(s.rich); g.Note == nil || !g.Note.Trashed {
		t.Errorf("notes_get after note_trash must return the note, in the trash: %s", wire(t, g))
	}

	// note_untrash.
	res, err = r.noteUntrash(s.rich, false)
	r.mustOK("note_untrash", err)
	r.requireNoteWrite(res, "note_untrash")
	if n := res.Before.Note; n == nil || !n.Trashed {
		t.Errorf("note_untrash: the result must show the note as it was, in the trash: %s", wire(t, res))
	}
	now = check("note_untrash", "trashed")
	if got := string(rawAt(now, "trashed")); got != "false" {
		t.Errorf("note_untrash: trashed is %s, want false", got)
	}

	// After all four writes, the typed view agrees, and the reference is still counted.
	if g := r.get(s.rich); g.Note == nil || g.Note.Trashed || g.Note.Title != richNewTitle || g.Note.Text != richNewText {
		t.Errorf("after the four writes, notes_get must show the new title and text, out of the trash: %s", wire(t, g))
	}
	if n := r.liveNote(s.rich); n.RefCount() != 1 {
		t.Errorf("the rich note holds %d references, want 1", n.RefCount())
	}
}

// ---- phase 2: trash is reversible ----

func (r *writeRig) phaseTrash() {
	t, s := r.t, &r.s
	id := s.alpha
	seed := r.raw(id)

	// A dry run shows the note and writes nothing.
	res, err := r.noteTrash(id, true)
	r.mustOK("note_trash dry run", err)
	if n := res.Before.Note; !res.DryRun || n == nil || n.Title != "Alpha" || n.Text != "one" || n.Trashed {
		t.Fatalf("note_trash dry run: %s", wire(t, res))
	}
	r.expect("note_trash dry run")

	// The trash: the note is trashed, and it is still there.
	res, err = r.noteTrash(id, false)
	r.mustOK("note_trash", err)
	r.requireNoteWrite(res, "note_trash")
	r.expect("note_trash", id)
	n := r.liveNote(id) // fails when the note is gone
	if !n.Trashed || n.Title != "Alpha" || n.Text != "one" {
		t.Errorf("INVARIANT BROKEN: after note_trash the note must be trashed and whole: %+v", n)
	}
	trashed := r.raw(id) // fails when the envelope is deleted
	r.requirePaths("note_trash", seed, trashed, "trashed", cuaPath)
	if got := string(rawAt(trashed, "trashed")); got != "true" {
		t.Errorf("note_trash: trashed is %s, want true", got)
	}
	// The orchestrator's view: notes_list hides a trashed note, and notes_get still returns it.
	if row := rowFor(r.list(), id); row != nil {
		t.Errorf("notes_list shows a trashed note: %s", wire(t, row))
	}
	if g := r.get(id); g.Note == nil || !g.Note.Trashed || g.Note.Text != "one" {
		t.Errorf("notes_get after note_trash must return the note, in the trash, with its text: %s", wire(t, g))
	}

	// The untrash.
	res, err = r.noteUntrash(id, false)
	r.mustOK("note_untrash", err)
	r.requireNoteWrite(res, "note_untrash")
	r.expect("note_untrash", id)
	if n := r.liveNote(id); n.Trashed || n.Title != "Alpha" || n.Text != "one" {
		t.Errorf("INVARIANT BROKEN: after note_untrash the note must be out of the trash and whole: %+v", n)
	}
	back := r.raw(id)
	r.requirePaths("note_untrash", seed, back, "trashed", cuaPath)
	if got := string(rawAt(back, "trashed")); got != "false" {
		t.Errorf("note_untrash: trashed is %s, want false", got)
	}
	if row := rowFor(r.list(), id); row == nil || row.Note == nil || row.Note.Title != "Alpha" {
		t.Errorf("notes_list must show the note again after note_untrash: %s", wire(t, row))
	}
}

// ---- phase 3: merge ----

func (r *writeRig) phaseMerge() {
	t, s := r.t, &r.s
	srcs := []string{s.alpha, s.beta}
	rawA, rawB := r.raw(s.alpha), r.raw(s.beta)
	a, b := r.liveNote(s.alpha), r.liveNote(s.beta) // the sources, as the server holds them now
	want := []mcptools.MergeSource{{UUID: s.alpha, Title: "Alpha", Trashed: true}, {UUID: s.beta, Title: "Beta", Trashed: true}}

	// A dry run says what would happen, and writes nothing.
	res, err := r.noteMerge(srcs, "Merged", true)
	r.mustOK("note_merge dry run", err)
	if !res.DryRun || res.NoteUUID != "" || res.OpID != "" || res.Title != "Merged" || !slices.Equal(res.Sources, want) {
		t.Fatalf("note_merge dry run: %s", wire(t, res))
	}
	r.expect("note_merge dry run")

	// The write makes one new note, and trashes the two sources.
	res, err = r.noteMerge(srcs, "Merged", false)
	r.mustOK("note_merge", err)
	if res.DryRun || res.NoteUUID == "" || res.OpID == "" || res.Notice != "" || !slices.Equal(res.Sources, want) {
		t.Fatalf("note_merge: %s", wire(t, res))
	}
	s.merged = res.NoteUUID
	r.names[s.merged] = "the merged note"
	if s.merged == s.alpha || s.merged == s.beta {
		t.Fatal("the merged note must be a new note")
	}
	r.expect("note_merge", s.merged, s.alpha, s.beta) // the new note and its two sources, no other item

	m := r.liveNote(s.merged)
	if m.Title != "Merged" || m.Trashed {
		t.Errorf("the merged note: title %q, trashed %v. Want a live note titled Merged.", m.Title, m.Trashed)
	}
	// The merge is additive: the body holds each source verbatim.
	for _, src := range []*snclient.NoteView{a, b} {
		if !strings.Contains(m.Text, src.Text) {
			t.Errorf("INVARIANT BROKEN: the merged text does not hold the text of %q verbatim: %q", src.Title, m.Text)
		}
	}
	if !strings.Contains(m.Text, "one") || !strings.Contains(m.Text, "two") {
		t.Errorf("the merged text must hold one and two: %q", m.Text)
	}
	// The sources are in the trash, whole: still there, with their text, and with every
	// field. A trash changes the flag and the timestamp only.
	for _, c := range []struct {
		id, raw string
		src     *snclient.NoteView
	}{{s.alpha, rawA, a}, {s.beta, rawB, b}} {
		n := r.liveNote(c.id)
		if !n.Trashed || n.Title != c.src.Title || n.Text != c.src.Text {
			t.Errorf("INVARIANT BROKEN: the source %q must be in the trash and whole: %+v", c.src.Title, n)
		}
		r.requirePaths("the trash of the source "+c.src.Title, c.raw, r.raw(c.id), "trashed", cuaPath)
	}
}

// needMerged fails a phase that needs the merged note when phase 3 did not make one. It fails
// and does not skip: a skipped phase would look like a phase that held.
func (r *writeRig) needMerged() {
	r.t.Helper()
	if r.s.merged == "" {
		r.t.Fatal("phase 3 made no merged note, so this phase has no plain live note to work on")
	}
}

// ---- phase 4: sensitive notes are walled off ----

func (r *writeRig) phaseSensitive() {
	t, s := r.t, &r.s
	r.needMerged()
	keys, seed := s.keys, s.keysRaw
	if got := r.raw(keys); got != seed {
		t.Fatalf("premise: the server does not hold the seed of the sensitive note byte for byte.\n got %s\nwant %s", got, seed)
	}
	stub := gate.Stub(keys)

	// bareStub fails unless the result is the stub of the note and nothing else. The test
	// compares the whole JSON, so a field that a later change adds shows here.
	bareStub := func(where, action string, res mcptools.NoteWriteResult, dry bool) {
		t.Helper()
		want := mcptools.NoteWriteResult{DryRun: dry, Action: action, Before: mcptools.GetResult{Stub: &stub}, OpID: res.OpID}
		if got, w := wire(t, res), wire(t, want); got != w {
			t.Errorf("LEAK or extra field in %s. A result for a sensitive note must be the bare stub and nothing else.\n  got:  %s\n  want: %s", where, got, w)
		}
		if dry == (res.OpID != "") {
			t.Errorf("%s: a dry run has no ledger id and a write has one. Got dry=%v and the id %q.", where, dry, res.OpID)
		}
	}

	// An edit and a rename refuse the note, in a dry run and in a write.
	const editRefusal = "cannot edit a sensitive note; it is walled off from the assistant"
	for _, dry := range []bool{true, false} {
		for _, c := range []struct {
			tool string
			call func() (mcptools.NoteWriteResult, error)
		}{
			{"note_edit", func() (mcptools.NoteWriteResult, error) { return r.noteEdit(keys, "replacement text", dry) }},
			{"note_rename", func() (mcptools.NoteWriteResult, error) { return r.noteRename(keys, "Renamed", dry) }},
		} {
			where := fmt.Sprintf("%s of the sensitive note, dry=%v", c.tool, dry)
			res, err := c.call()
			switch {
			case !errors.Is(err, mcptools.ErrSensitiveEdit):
				t.Errorf("INVARIANT BROKEN, %s: got %v, want ErrSensitiveEdit", where, err)
			case err.Error() != editRefusal:
				t.Errorf("%s: the refusal says %q, want %q", where, err.Error(), editRefusal)
			}
			if !reflect.DeepEqual(res, mcptools.NoteWriteResult{}) {
				t.Errorf("LEAK or extra field in %s: a refused call must return no result: %s", where, wire(t, res))
			}
			r.expect(where) // nothing changed on the server
		}
	}

	// A merge refuses the note as a source, whatever its place and whether it is a dry run.
	const mergeRefusal = "cannot merge a sensitive note; it is walled off"
	for _, srcs := range [][]string{{s.merged, keys}, {keys, s.rich}, {s.merged, keys, s.rich}} {
		for _, dry := range []bool{true, false} {
			where := fmt.Sprintf("note_merge of %d notes, the sensitive one at place %d, dry=%v", len(srcs), slices.Index(srcs, keys)+1, dry)
			res, err := r.noteMerge(srcs, "Merged again", dry)
			switch {
			case !errors.Is(err, mcptools.ErrSensitiveMerge):
				t.Errorf("INVARIANT BROKEN, %s: got %v, want ErrSensitiveMerge", where, err)
			case err.Error() != mergeRefusal:
				t.Errorf("%s: the refusal says %q, want %q", where, err.Error(), mergeRefusal)
			}
			if !reflect.DeepEqual(res, mcptools.MergeResult{}) {
				t.Errorf("LEAK or extra field in %s: a refused merge must return no result: %s", where, wire(t, res))
			}
			r.expect(where)
		}
	}
	// None of the refused calls changed a byte of the note.
	if got := r.raw(keys); got != seed {
		t.Errorf("INVARIANT BROKEN: a refused call changed the sensitive note.\n  seed: %s\n  now:  %s", seed, got)
	}

	// A preview of a trash and of an untrash shows the stub and nothing else.
	for _, c := range []struct {
		tool string
		call func() (mcptools.NoteWriteResult, error)
	}{
		{"note_trash", func() (mcptools.NoteWriteResult, error) { return r.noteTrash(keys, true) }},
		{"note_untrash", func() (mcptools.NoteWriteResult, error) { return r.noteUntrash(keys, true) }},
	} {
		res, err := c.call()
		r.mustOK(c.tool+" preview of the sensitive note", err)
		bareStub(c.tool+" preview", c.tool, res, true)
		r.expect(c.tool + " preview of the sensitive note")
	}

	// The control: the same four previews on a plain note show its title and text. So the
	// walls above come from the gate, and not from a tool that stubs everything.
	for _, c := range []struct {
		tool string
		call func() (mcptools.NoteWriteResult, error)
	}{
		{"note_edit", func() (mcptools.NoteWriteResult, error) { return r.noteEdit(s.merged, "replacement text", true) }},
		{"note_rename", func() (mcptools.NoteWriteResult, error) { return r.noteRename(s.merged, "Renamed", true) }},
		{"note_trash", func() (mcptools.NoteWriteResult, error) { return r.noteTrash(s.merged, true) }},
		{"note_untrash", func() (mcptools.NoteWriteResult, error) { return r.noteUntrash(s.merged, true) }},
	} {
		res, err := c.call()
		r.mustOK(c.tool+" preview of a plain note", err)
		if n := res.Before.Note; res.Before.Stub != nil || n == nil || n.UUID != s.merged || n.Title != "Merged" || !strings.Contains(n.Text, "one") {
			t.Errorf("%s preview of a plain note must show its title and text: %s", c.tool, wire(t, res))
		}
		r.expect(c.tool + " preview of a plain note")
	}

	// A trash goes by uuid and sets no content, so it is allowed on the sensitive note. The
	// result is the stub. The note keeps every field, and an untrash puts it back.
	res, err := r.noteTrash(keys, false)
	r.mustOK("note_trash of the sensitive note", err)
	bareStub("note_trash", "note_trash", res, false)
	r.expect("note_trash of the sensitive note", keys)
	trashed := r.raw(keys)
	r.requirePaths("note_trash of the sensitive note", seed, trashed, "trashed", cuaPath)
	if got := string(rawAt(trashed, "trashed")); got != "true" {
		t.Errorf("note_trash of the sensitive note: trashed is %s, want true", got)
	}
	if g := r.get(keys); g.Note != nil || g.Stub == nil || *g.Stub != stub {
		t.Errorf("LEAK: notes_get must still wall off a trashed sensitive note: %s", wire(t, g))
	}
	res, err = r.noteUntrash(keys, false)
	r.mustOK("note_untrash of the sensitive note", err)
	bareStub("note_untrash", "note_untrash", res, false)
	r.expect("note_untrash of the sensitive note", keys)
	back := r.raw(keys)
	r.requirePaths("note_untrash of the sensitive note", seed, back, "trashed", cuaPath)
	if got := string(rawAt(back, "trashed")); got != "false" {
		t.Errorf("note_untrash of the sensitive note: trashed is %s, want false", got)
	}

	// With jev down, the gate cannot clear any note. A tool that sets or copies text refuses
	// even a plain note, and a preview shows the stub. A jev outage cannot turn the write
	// tools into a way to author notes that the gate could not check.
	down := mcptools.NewWriter(r.guard, r.eng, gate.New(jevOffline{}, threshold))
	for _, dry := range []bool{true, false} {
		resE, err := down.NoteEdit(s.merged, "replacement text", dry)
		r.see("note_edit with jev down", resE, err)
		if !errors.Is(err, mcptools.ErrSensitiveEdit) {
			t.Errorf("INVARIANT BROKEN: with jev down, note_edit dry=%v of a plain note got %v, want ErrSensitiveEdit", dry, err)
		}
		resR, err := down.NoteRename(s.merged, "Renamed", dry)
		r.see("note_rename with jev down", resR, err)
		if !errors.Is(err, mcptools.ErrSensitiveEdit) {
			t.Errorf("INVARIANT BROKEN: with jev down, note_rename dry=%v of a plain note got %v, want ErrSensitiveEdit", dry, err)
		}
		resM, err := down.NoteMerge([]string{s.merged, s.rich}, "Merged again", dry)
		r.see("note_merge with jev down", resM, err)
		if !errors.Is(err, mcptools.ErrSensitiveMerge) {
			t.Errorf("INVARIANT BROKEN: with jev down, note_merge dry=%v of plain notes got %v, want ErrSensitiveMerge", dry, err)
		}
		r.expect(fmt.Sprintf("the calls with jev down, dry=%v", dry))
	}
	resT, err := down.NoteTrash(s.merged, true)
	r.see("note_trash preview with jev down", resT, err)
	r.mustOK("note_trash preview with jev down", err)
	if want := gate.Stub(s.merged); resT.Before.Note != nil || resT.Before.Stub == nil || *resT.Before.Stub != want {
		t.Errorf("with jev down, a preview must show the stub of a plain note: %s", wire(t, resT))
	}
	r.expect("the preview with jev down")
}

// ---- phase 5: tags ----

// tagRenamed is the title that phase 5 gives the rich tag.
const tagRenamed = "projects/2026"

// tagEntry is one entry of the references of a tag.
type tagEntry struct {
	UUID        string `json:"uuid"`
	ContentType string `json:"content_type"`
}

// entriesOf splits the raw references of a tag into its entries.
func entriesOf(raw json.RawMessage) []json.RawMessage {
	var out []json.RawMessage
	_ = json.Unmarshal(raw, &out)
	return out
}

func (r *writeRig) phaseTags() {
	t, s := r.t, &r.s
	r.needMerged()
	tag, seed := s.tag, s.tagRaw
	if got := r.rawTag(tag); got != seed {
		t.Fatalf("premise: the server does not hold the seed of the tag byte for byte.\n got %s\nwant %s", got, seed)
	}
	// A tag result shows the tag and counts. It shows no note title.
	noTitles := func(where string, v any) {
		t.Helper()
		body := wire(t, v)
		for _, title := range []string{"Alpha", "Beta", "Merged", richTitle, keysTitle} {
			if strings.Contains(body, title) {
				t.Errorf("LEAK in %s: a tag result shows the note title %q: %s", where, title, body)
			}
		}
	}
	// held is the notes of a tag, as the read tool shows them.
	held := func(id string) []string {
		t.Helper()
		for _, row := range r.tagList().Tags {
			if row.UUID == id {
				return sorted(row.NoteUUIDs)
			}
		}
		t.Fatalf("tags_list shows no %s", r.name(id))
		return nil
	}
	if got, want := held(tag), sorted([]string{s.beta, s.keys}); !slices.Equal(got, want) {
		t.Fatalf("premise: the tag holds %v, want Beta and the sensitive note", got)
	}

	// tag_apply: a dry run, then the write. The note shows under the tag, and the two
	// references that were there are untouched.
	res, err := r.tagApply("projects", []string{s.merged}, true)
	r.mustOK("tag_apply dry run", err)
	if !res.DryRun || res.Created || res.Tag.UUID != tag || res.NotesChanged != 1 || res.NotesSkipped != 0 || res.OpID != "" {
		t.Fatalf("tag_apply dry run: %s", wire(t, res))
	}
	noTitles("tag_apply dry run", res)
	r.expect("tag_apply dry run")

	res, err = r.tagApply("projects", []string{s.merged}, false)
	r.mustOK("tag_apply", err)
	if res.DryRun || res.Created || res.Tag.UUID != tag || res.NotesChanged != 1 || res.OpID == "" {
		t.Fatalf("tag_apply: %s", wire(t, res))
	}
	noTitles("tag_apply", res)
	r.expect("tag_apply", tag) // the tag, and no note
	if got, want := held(tag), sorted([]string{s.beta, s.keys, s.merged}); !slices.Equal(got, want) {
		t.Errorf("INVARIANT BROKEN: after tag_apply the tag holds %v, want Beta, the sensitive note and the merged note", got)
	}
	applied := r.rawTag(tag)
	r.requirePaths("tag_apply", seed, applied, "references", cuaPath)
	was, is := entriesOf(rawAt(seed, "references")), entriesOf(rawAt(applied, "references"))
	if len(is) != len(was)+1 {
		t.Errorf("tag_apply: the tag holds %d references, want %d", len(is), len(was)+1)
	} else {
		for i := range was {
			if !bytes.Equal(was[i], is[i]) {
				t.Errorf("INVARIANT BROKEN: tag_apply changed a reference that was there.\n  seed: %s\n  now:  %s", was[i], is[i])
			}
		}
		var added tagEntry
		if err := json.Unmarshal(is[len(is)-1], &added); err != nil || added.UUID != s.merged || added.ContentType != "Note" {
			t.Errorf("tag_apply: the new reference is %s, want the merged note as a Note", is[len(is)-1])
		}
	}

	// tag_detach: the note leaves, and the tag is the seed again, byte for byte, except for
	// the timestamp. An apply and a detach undo each other.
	res, err = r.tagDetach(tag, []string{s.merged}, true)
	r.mustOK("tag_detach dry run", err)
	if !res.DryRun || res.NotesChanged != 1 || res.NotesSkipped != 0 || res.Tag != (mcptools.TagRef{UUID: tag, Title: "projects"}) {
		t.Fatalf("tag_detach dry run: %s", wire(t, res))
	}
	r.expect("tag_detach dry run")
	res, err = r.tagDetach(tag, []string{s.merged}, false)
	r.mustOK("tag_detach", err)
	if res.DryRun || res.NotesChanged != 1 || res.OpID == "" {
		t.Fatalf("tag_detach: %s", wire(t, res))
	}
	noTitles("tag_detach", res)
	r.expect("tag_detach", tag)
	if got, want := held(tag), sorted([]string{s.beta, s.keys}); !slices.Equal(got, want) {
		t.Errorf("INVARIANT BROKEN: after tag_detach the tag holds %v, want Beta and the sensitive note", got)
	}
	r.requirePaths("tag_detach against the seed", seed, r.rawTag(tag), cuaPath)

	// tag_create: a dry run makes nothing, and the write makes an empty tag.
	res, err = r.tagCreate("ideas", true)
	r.mustOK("tag_create dry run", err)
	if !res.DryRun || !res.Created || res.Tag.UUID != "" || res.OpID != "" {
		t.Fatalf("tag_create dry run: %s", wire(t, res))
	}
	noTitles("tag_create dry run", res)
	r.expect("tag_create dry run")
	res, err = r.tagCreate("ideas", false)
	r.mustOK("tag_create", err)
	if res.DryRun || !res.Created || res.Tag.UUID == "" || res.OpID == "" {
		t.Fatalf("tag_create: %s", wire(t, res))
	}
	noTitles("tag_create", res)
	ideas := res.Tag.UUID
	r.names[ideas] = "the tag ideas"
	r.expect("tag_create", ideas)
	if got := rawString(rawAt(r.rawTag(ideas), "title")); got != "ideas" {
		t.Errorf("tag_create: the title is %q, want ideas", got)
	}
	if got := held(ideas); len(got) != 0 {
		t.Errorf("tag_create: the new tag holds %v, want no note", got)
	}

	// tag_rename and tag_trash work on the rich tag, and not on the new one: a tag with no
	// references and no fields of its own has nothing to lose. Each write sets its key and the
	// timestamp, and every other byte of the tag is the seed's.
	before := r.rawTag(tag)
	res, err = r.tagRename(tag, tagRenamed, true)
	r.mustOK("tag_rename dry run", err)
	if !res.DryRun || res.NewTitle == nil || *res.NewTitle != tagRenamed || res.Tag.Title != "projects" || res.OpID != "" {
		t.Fatalf("tag_rename dry run: %s", wire(t, res))
	}
	r.expect("tag_rename dry run")
	res, err = r.tagRename(tag, tagRenamed, false)
	r.mustOK("tag_rename", err)
	if res.DryRun || res.OpID == "" {
		t.Fatalf("tag_rename: %s", wire(t, res))
	}
	noTitles("tag_rename", res)
	r.expect("tag_rename", tag)
	renamed := r.rawTag(tag)
	r.requirePaths("tag_rename", before, renamed, "title", cuaPath)
	r.requirePaths("tag_rename against the seed", seed, renamed, "title", cuaPath)
	if got := rawString(rawAt(renamed, "title")); got != tagRenamed {
		t.Errorf("tag_rename: the title is %q, want %q", got, tagRenamed)
	}

	// tag_trash sets a flag inside the tag. The tag stays on the server with its title and its
	// notes, so the trash can be undone. No tool of this server clears the flag, so the
	// proof of that is that nothing but the flag and the timestamp changed.
	res, err = r.tagTrash(tag, true)
	r.mustOK("tag_trash dry run", err)
	if !res.DryRun || res.Notice == "" || res.OpID != "" {
		t.Fatalf("tag_trash dry run: %s", wire(t, res))
	}
	r.expect("tag_trash dry run")
	res, err = r.tagTrash(tag, false)
	r.mustOK("tag_trash", err)
	if res.DryRun || res.OpID == "" || res.Tag.UUID != tag || res.Tag.Title != tagRenamed || !strings.Contains(res.Notice, "reversible") {
		t.Fatalf("tag_trash: %s", wire(t, res))
	}
	noTitles("tag_trash", res)
	r.expect("tag_trash", tag)
	trashed := r.rawTag(tag) // fails when the envelope is deleted
	r.requirePaths("tag_trash", renamed, trashed, "trashed", cuaPath)
	r.requirePaths("tag_trash against the seed", seed, trashed, "title", "trashed", cuaPath)
	if got := string(rawAt(trashed, "trashed")); got != "true" {
		t.Errorf("tag_trash: trashed is %s, want true", got)
	}
	found := false
	for _, row := range r.tagList().Tags {
		if row.UUID == tag {
			found = row.Title == tagRenamed
		}
	}
	if !found {
		t.Errorf("INVARIANT BROKEN: a trashed tag must stay on the server with its title")
	}
	if got, want := held(tag), sorted([]string{s.beta, s.keys}); !slices.Equal(got, want) {
		t.Errorf("INVARIANT BROKEN: a trashed tag must keep its notes: it holds %v, want Beta and the sensitive note", got)
	}

	// A note tool given a tag uuid, and a tag tool given a note uuid, write nothing: no
	// title or reference can land in the wrong kind of item.
	for _, c := range []struct {
		what string
		call func() error
		want error
	}{
		{"note_rename given a tag", func() error { _, err := r.noteRename(tag, "x", false); return err }, mcptools.ErrNotFound},
		{"note_edit given a tag", func() error { _, err := r.noteEdit(tag, "x", false); return err }, mcptools.ErrNotFound},
		{"note_trash given a tag", func() error { _, err := r.noteTrash(tag, false); return err }, mcptools.ErrNotFound},
		{"tag_rename given a note", func() error { _, err := r.tagRename(s.merged, "x", false); return err }, mcptools.ErrTagNotFound},
		{"tag_trash given a note", func() error { _, err := r.tagTrash(s.merged, false); return err }, mcptools.ErrTagNotFound},
		{"tag_detach given a note", func() error { _, err := r.tagDetach(s.merged, []string{s.beta}, false); return err }, mcptools.ErrTagNotFound},
	} {
		if err := c.call(); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.what, err, c.want)
		}
		r.expect(c.what)
	}
}

func sorted(s []string) []string {
	s = slices.Clone(s)
	slices.Sort(s)
	return s
}

// ---- phase 6: the write cap, and the ledger ----

func (r *writeRig) phaseCap() {
	t, s := r.t, &r.s
	r.needMerged()
	// The ledger goes next to the main one, in the folder of the whole pass. The folder of
	// this phase is deleted when the phase ends, and the sweep reads the ledger later.
	capLedger := filepath.Join(filepath.Dir(r.ledger), "cap-ledger.jsonl")
	led, err := writeengine.OpenLedger(capLedger)
	if err != nil {
		t.Fatal(err)
	}
	r.extraLedgers = append(r.extraLedgers, capLedger)
	// A Writer on an engine that allows one write. It shares the client and the guard.
	capped := mcptools.NewWriter(r.guard, writeengine.NewEngine(r.c, led, 1), r.gt)
	const title = "Merged (kept)"

	// The first write is inside the cap, and lands.
	res, err := capped.NoteRename(s.merged, title, false)
	r.see("note_rename under a cap of 1", res, err)
	r.mustOK("the first write under a cap of 1", err)
	r.requireNoteWrite(res, "note_rename")
	r.expect("the first write under a cap of 1", s.merged)
	first := r.liveNote(s.merged)
	if first.Title != title {
		t.Fatalf("the first write must land: the title is %q, want %q", first.Title, title)
	}

	// The second write is over the cap. It returns the cap error, with fixed text, and writes
	// nothing. A write of another kind is stopped too.
	resE, err := capped.NoteEdit(s.merged, "text after the cap", false)
	r.see("note_edit over the cap", resE, err)
	var we *mcptools.WriteError
	if !errors.Is(err, writeengine.ErrCapReached) || !errors.As(err, &we) || !strings.Contains(err.Error(), "cap") {
		t.Errorf("INVARIANT BROKEN: the second write got %v, want a WriteError over ErrCapReached that says cap", err)
	}
	r.expect("the second write over the cap")
	resT, err := capped.TagCreate("over the cap", false)
	r.see("tag_create over the cap", resT, err)
	if !errors.Is(err, writeengine.ErrCapReached) {
		t.Errorf("INVARIANT BROKEN: tag_create over the cap got %v, want ErrCapReached", err)
	}
	r.expect("tag_create over the cap")
	if n := r.liveNote(s.merged); n.Title != title || n.Text != first.Text {
		t.Errorf("a write over the cap changed the note: %q %q", n.Title, n.Text)
	}

	// Dry runs do not use the cap. All ten tools still preview, and none writes.
	for _, c := range []struct {
		tool string
		call func() (any, error)
	}{
		{"note_edit", func() (any, error) { return capped.NoteEdit(s.merged, "x", true) }},
		{"note_rename", func() (any, error) { return capped.NoteRename(s.merged, "x", true) }},
		{"note_trash", func() (any, error) { return capped.NoteTrash(s.merged, true) }},
		{"note_untrash", func() (any, error) { return capped.NoteUntrash(s.merged, true) }},
		{"note_merge", func() (any, error) { return capped.NoteMerge([]string{s.merged, s.rich}, "x", true) }},
		{"tag_apply", func() (any, error) { return capped.TagApply(tagRenamed, []string{s.merged}, true) }},
		{"tag_detach", func() (any, error) { return capped.TagDetach(s.tag, []string{s.beta}, true) }},
		{"tag_create", func() (any, error) { return capped.TagCreate("new", true) }},
		{"tag_rename", func() (any, error) { return capped.TagRename(s.tag, "x", true) }},
		{"tag_trash", func() (any, error) { return capped.TagTrash(s.tag, true) }},
	} {
		res, err := c.call()
		r.see("capped "+c.tool+" dry run", res, err)
		if err != nil {
			t.Errorf("INVARIANT BROKEN: %s dry run after the cap: %v", c.tool, err)
		}
	}
	r.expect("ten dry runs after the cap")

	// The ledger of the capped engine has the one write that landed, in full. The two
	// writes that the cap stopped left no op: the cap check comes before the first record.
	text, err := os.ReadFile(capLedger)
	if err != nil {
		t.Fatal(err)
	}
	ops, err := ledgerOps(string(text))
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 1 || ops[0].Kind != "rename" || ops[0].UUID != s.merged || !slices.Equal(ops[0].States, landed) || ops[0].ID != res.OpID {
		t.Errorf("INVARIANT BROKEN: the ledger of the capped engine holds %+v, want one verified rename of the merged note with the id %s", ops, res.OpID)
	}
}

func (r *writeRig) phaseLedger() {
	t := r.t
	text, err := os.ReadFile(r.ledger)
	if err != nil {
		t.Fatal(err)
	}
	ops, err := ledgerOps(string(text))
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) == 0 {
		t.Fatal("the ledger is empty: no write landed")
	}
	var kinds []string
	for _, op := range ops {
		kinds = append(kinds, op.Kind)
		if !slices.Equal(op.States, landed) {
			t.Errorf("INVARIANT BROKEN: the op %s (%s) went through %v, want %v", op.ID, op.Kind, op.States, landed)
		}
	}
	// The ledger holds the writes that the test made, in order, and no other op. A dry run or
	// a refused call that reached Commit would add one.
	if !slices.Equal(kinds, r.wrote) {
		t.Errorf("INVARIANT BROKEN: the ledger holds the ops %v, but the writes that landed are %v", kinds, r.wrote)
	}
	// Every ledger id that a tool returned is in the ledger.
	for _, id := range r.opIDs {
		if !slices.ContainsFunc(ops, func(op ledgerOp) bool { return op.ID == id }) {
			t.Errorf("the ledger id %s that a tool returned is not in the ledger", id)
		}
	}
	t.Logf("the ledger holds %d ops for %d writes: %s", len(ops), len(r.opIDs), strings.Join(kinds, " "))
}

// ---- the sweep ----

// ledgerCapture is the text of a ledger file, as the sweep takes it.
func ledgerCapture(text string) capture {
	return capture{call: "a ledger", raw: text, decoded: collapse(text)}
}

// phaseSweep looks for the sensitive note in everything that a tool returned in this pass,
// and in the ledgers. This is the check on the leak rule. It covers every call, and not
// only the ones on the sensitive note: a tag result or a merge result could show it too.
func (r *writeRig) phaseSweep() {
	t := r.t
	caps := slices.Clone(r.caps)
	for _, path := range append([]string{r.ledger}, r.extraLedgers...) {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		c := ledgerCapture(string(b))
		c.call = "the ledger " + filepath.Base(path)
		caps = append(caps, c)
	}
	leaks := findLeaks([]note{keysNote}, caps)
	for _, l := range leaks {
		t.Errorf("LEAK through %s: the sensitive note shows in the output (%s).\n  first string: %q\n  output: %s",
			l.call, strings.Join(l.kinds, ", "), l.example, l.context)
	}
	// A sweep that saw nothing proves nothing. It must have covered the refusals and the stubs.
	const wantRefusals, wantStubs = 16, 6
	if r.refusals < wantRefusals || r.stubs < wantStubs {
		t.Errorf("the sweep covered %d refusals and %d stubs, want at least %d and %d: phase 4 did not run in full",
			r.refusals, r.stubs, wantRefusals, wantStubs)
	}
	total := 0
	for _, c := range caps {
		total += len(c.raw)
	}
	t.Logf("%d results and errors, and %d ledgers, hold %d bytes. The sweep covered %d refusals and %d stub results. Leaks: %d.",
		len(r.caps), 1+len(r.extraLedgers), total, r.refusals, r.stubs, len(leaks))
}

// ---- the tests ----

// writeSafetyPass runs the six phases and the sweep on a fresh account.
func writeSafetyPass(t *testing.T, email, password string, gt *gate.Gate) {
	r := newWriteRig(t, email, password, gt)
	r.seed()
	r.run("1 metadata is preserved by edit, rename, trash and untrash", r.phaseMetadata)
	r.run("2 trash is reversible and nothing is deleted", r.phaseTrash)
	r.run("3 merge is additive", r.phaseMerge)
	r.run("4 sensitive notes are walled off", r.phaseSensitive)
	r.run("5 tags", r.phaseTags)
	r.run("6 the write cap stops a second write", r.phaseCap)
	r.run("6 the ledger holds every write that landed", r.phaseLedger)
	r.run("sweep: nothing a tool returned shows the sensitive note", r.phaseSweep)
}

// The write red-team. It plants the demo-like account, drives all ten write tools, and
// checks the six invariants. See the top of this file.
func TestWriteSafetyEndToEnd(t *testing.T) {
	t.Run("real gate", func(t *testing.T) {
		email, password := testsupport.NewAccount(t) // skips when the Docker server is down, or SN_TEST_SERVER=off
		if !jevAnswers(t) {
			t.Skipf("jev does not answer at %s, and this pass needs it. The pass with the scanner alone still runs.", jevURL())
		}
		writeSafetyPass(t, email, password, gate.New(gate.NewJev(jevURL(), "local"), threshold))
	})
	t.Run("scanner and kind alone", func(t *testing.T) {
		email, password := testsupport.NewAccount(t)
		writeSafetyPass(t, email, password, gate.New(jevSaysSafe{}, threshold))
	})
}

// A check that cannot fail proves nothing. Each checker above gets a failure that it must
// find, and a clean case that it must pass. No server is needed.
func TestWriteSafetyCheckersCanFail(t *testing.T) {
	t.Run("the diff of two contents", func(t *testing.T) {
		const sn = `"` + snDomain + `"`
		cases := []struct {
			name          string
			before, after string
			want          []string
		}{
			{"the same bytes, the keys in another order", `{"a":1,"b":{"x":1}}`, `{"b":{"x":1},"a":1}`, nil},
			{"a key is dropped", `{"a":1,"b":2}`, `{"a":1}`, []string{"b"}},
			{"a key is added", `{"a":1}`, `{"a":1,"b":2}`, []string{"b"}},
			{"a number is written in another form", `{"a":{"x":1.0}}`, `{"a":{"x":1}}`, []string{"a"}},
			{"a space is dropped", `{"a":{ "x":1 }}`, `{"a":{"x":1}}`, []string{"a"}},
			{"a flag changes", `{"starred":true}`, `{"starred":false}`, []string{"starred"}},
			{"a third-party domain changes",
				`{"appData":{"d":{"x":1},` + sn + `:{"client_updated_at":"t"}}}`,
				`{"appData":{"d":{"x":2},` + sn + `:{"client_updated_at":"t"}}}`,
				[]string{"appData.d"}},
			{"a third-party domain is dropped",
				`{"appData":{"d":{"x":1},` + sn + `:{"client_updated_at":"t"}}}`,
				`{"appData":{` + sn + `:{"client_updated_at":"t"}}}`,
				[]string{"appData.d"}},
			{"a key of the domain of Standard Notes is dropped",
				`{"appData":{` + sn + `:{"client_updated_at":"t","archived":true}}}`,
				`{"appData":{` + sn + `:{"client_updated_at":"t"}}}`,
				[]string{"appData." + snDomain + ".archived"}},
			{"only the timestamp changes",
				`{"appData":{` + sn + `:{"archived":true,"client_updated_at":"t1"}},"text":"x"}`,
				`{"text":"x","appData":{` + sn + `:{"client_updated_at":"t2","archived":true}}}`,
				[]string{cuaPath}},
			{"appData is dropped", `{"appData":{"d":1},"a":1}`, `{"a":1}`, []string{"appData"}},
		}
		for _, tc := range cases {
			got, err := changedPaths(tc.before, tc.after)
			if err != nil || !slices.Equal(got, tc.want) {
				t.Errorf("%s: changedPaths gave %v (%v), want %v", tc.name, got, err, tc.want)
			}
		}
		if _, err := changedPaths(`[1]`, `{"a":1}`); err == nil {
			t.Error("a content that is not an object must be an error")
		}
		if _, err := changedPaths(`{"a":1}`, `null`); err == nil {
			t.Error("a content that is null must be an error")
		}
		// The seed that the test plants must be valid JSON that the checker reads, and its
		// extras must be at the paths that the test looks at.
		for _, x := range richExtras {
			if len(rawAt(richSeed("u"), x.path...)) == 0 {
				t.Errorf("richSeed has no %s at %v", x.name, x.path)
			}
		}
		if got := string(rawAt(richSeed("u"), "appData", "dev.example.editor")); !strings.Contains(got, "17.0") || !strings.Contains(got, "1e2") || !strings.Contains(got, `"a" , "b"`) {
			t.Errorf("richSeed must keep its odd forms, and rawAt must keep them: %s", got)
		}
		if got := string(rawAt(richSeed("u"), "future_unknown_key")); !strings.Contains(got, string(rune(92))+"u00e9") || !strings.Contains(got, "null") {
			t.Errorf("richSeed must hold a unicode escape and a null in future_unknown_key: %s", got)
		}
		if _, err := changedPaths(tagSeed("b", "k"), tagSeed("b", "k")); err != nil {
			t.Errorf("tagSeed is not valid JSON: %v", err)
		}
		if _, err := changedPaths(keysSeed, keysSeed); err != nil {
			t.Errorf("keysSeed is not valid JSON: %v", err)
		}
	})

	t.Run("what the server shows of an item", func(t *testing.T) {
		// item is one item of a sync, as the server sends it. docs joins items into a sync.
		item := func(uuid, kind, content, key string, ts int, deleted bool) string {
			return fmt.Sprintf(`{"uuid":%q,"content_type":%q,"content":%q,"enc_item_key":%q,"updated_at_timestamp":%d,"deleted":%v}`,
				uuid, kind, content, key, ts, deleted)
		}
		docs := func(parts ...string) map[string]itemState {
			var enc items.EncryptedItems
			if err := json.Unmarshal([]byte("["+strings.Join(parts, ",")+"]"), &enc); err != nil {
				t.Fatal(err)
			}
			return statesOf(enc)
		}
		a, b := item("a", "Note", "c1", "k1", 1, false), item("b", "Note", "c2", "k2", 2, true)
		base := docs(a, b)
		if got := deletedItems(base); !slices.Equal(got, []string{"b"}) {
			t.Errorf("deletedItems gave %v, want [b]", got)
		}
		if got := changedItems(base, base); len(got) != 0 {
			t.Errorf("the same state is a change: %v", got)
		}
		for _, tc := range []struct {
			name string
			now  map[string]itemState
			want []string
		}{
			{"a write that sets the same bytes, so only the ciphertext differs", docs(item("a", "Note", "c1-again", "k1", 1, false), b), []string{"a"}},
			{"a new item key", docs(item("a", "Note", "c1", "k9", 1, false), b), []string{"a"}},
			{"a new timestamp", docs(item("a", "Note", "c1", "k1", 7, false), b), []string{"a"}},
			{"a new item", docs(a, b, item("c", "Tag", "c3", "k3", 3, false)), []string{"c"}},
			{"an item that vanished", docs(a), []string{"b"}},
			{"an item that is marked deleted", docs(item("a", "Note", "c1", "k1", 1, true), b), []string{"a"}},
		} {
			if got := changedItems(base, tc.now); !slices.Equal(got, tc.want) {
				t.Errorf("%s: changedItems gave %v, want %v", tc.name, got, tc.want)
			}
		}
		if got := deletedItems(docs(item("a", "Note", "c", "k", 1, true))); !slices.Equal(got, []string{"a"}) {
			t.Errorf("an item that is marked deleted must show: %v", got)
		}
	})

	t.Run("the ledger", func(t *testing.T) {
		ops, err := ledgerOps(`{"OpID":"o1","Kind":"edit","UUID":"n1","State":"intended"}` + "\n" +
			`{"OpID":"o2","Kind":"trash","UUID":"n2","State":"intended"}` + "\n" +
			`{"OpID":"o1","Kind":"edit","UUID":"n1","State":"acked"}` + "\n" +
			`{"OpID":"o1","Kind":"edit","UUID":"n1","State":"verified"}` + "\n\n")
		want := []ledgerOp{
			{ID: "o1", Kind: "edit", UUID: "n1", States: landed},
			{ID: "o2", Kind: "trash", UUID: "n2", States: []string{"intended"}},
		}
		if err != nil || !reflect.DeepEqual(ops, want) {
			t.Errorf("ledgerOps gave %+v (%v), want %+v", ops, err, want)
		}
		if _, err := ledgerOps("not json\n"); err == nil {
			t.Error("a ledger line that is not JSON must be an error")
		}
		if ops, err := ledgerOps(""); err != nil || len(ops) != 0 {
			t.Errorf("an empty ledger holds no op: %v %v", ops, err)
		}
	})

	t.Run("the sweep", func(t *testing.T) {
		const id = "00000000-0000-4000-8000-00000000000a"
		stub := gate.Stub(id)
		leaks := map[string]capture{
			"a result with the note":        newCapture(t, "x", mcptools.NoteWriteResult{Action: "note_trash", Before: mcptools.GetResult{Note: &mcptools.NoteDetail{UUID: id, Title: keysTitle, Text: keysText}}}),
			"a result that echoes it":       newCapture(t, "x", mcptools.NoteWriteResult{Action: "note_edit", NewText: ptr("the key is " + keysText)}),
			"a merge result with its title": newCapture(t, "x", mcptools.MergeResult{Title: "Merged", Sources: []mcptools.MergeSource{{UUID: id, Title: keysTitle}}}),
			"an error with the title":       errCapture("x", fmt.Errorf("cannot edit %q", keysTitle)),
			"a ledger line with the text":   ledgerCapture(`{"OpID":"tag:` + keysText + `:n","Kind":"tag"}`),
		}
		for name, c := range leaks {
			if got := findLeaks([]note{keysNote}, []capture{c}); len(got) != 1 {
				t.Errorf("%s: the sweep found %d leaks, want 1", name, len(got))
			}
		}
		clean := map[string]capture{
			"a stub result":       newCapture(t, "x", mcptools.NoteWriteResult{Action: "note_trash", Before: mcptools.GetResult{Stub: &stub}, OpID: "trash:" + id + ":n"}),
			"a plain note":        newCapture(t, "x", mcptools.NoteWriteResult{Action: "note_edit", Before: mcptools.GetResult{Note: &mcptools.NoteDetail{UUID: id, Title: "Alpha", Text: "one"}}}),
			"a tag result":        newCapture(t, "x", mcptools.TagWriteResult{Action: "tag_apply", Tag: mcptools.TagRef{UUID: id, Title: "projects"}, NotesChanged: 1}),
			"a merge result":      newCapture(t, "x", mcptools.MergeResult{Title: "Merged", Sources: []mcptools.MergeSource{{UUID: id, Title: "Alpha", Trashed: true}}}),
			"the refusal":         errCapture("x", errors.New("cannot edit a sensitive note; it is walled off from the assistant")),
			"the merge refusal":   errCapture("x", errors.New("cannot merge a sensitive note; it is walled off")),
			"a cap error":         errCapture("x", errors.New("the write cap for this run is reached, so this change was not written")),
			"a clean ledger line": ledgerCapture(`{"OpID":"trash:` + id + `:n","Kind":"trash","UUID":"` + id + `","State":"verified"}`),
		}
		for name, c := range clean {
			if got := findLeaks([]note{keysNote}, []capture{c}); len(got) != 0 {
				t.Errorf("%s: the sweep reports a leak in clean output: %+v", name, got)
			}
		}
	})
}
