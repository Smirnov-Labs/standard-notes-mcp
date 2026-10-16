package writeengine_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jonhadfield/gosn-v2/common"
	"github.com/jonhadfield/gosn-v2/items"
	"github.com/smirnov-labs/standard-notes-mcp/internal/snclient"
	we "github.com/smirnov-labs/standard-notes-mcp/internal/writeengine"
)

func TestTagAppliedInOneWrite(t *testing.T) {
	e := newEngine(t)
	var ids []string
	for i := 0; i < 5; i++ {
		ch, err := e.PlanCreateNote("n", "b", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := e.Commit(ch); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, ch.NoteUUID)
	}

	tagCh, err := e.PlanTagApply("cleanup/trash-candidate", ids)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Commit(tagCh); err != nil {
		t.Fatal(err)
	}

	_, tags, _ := e.Client().Fetch()
	count := 0
	for _, tg := range tags {
		if tg.Title == "cleanup/trash-candidate" {
			count++
			if len(tg.NoteUUIDs) != 5 {
				t.Fatalf("tag references = %d, want 5", len(tg.NoteUUIDs))
			}
		}
	}
	if count != 1 {
		t.Fatalf("want exactly 1 tag item, got %d (hot-tag duplication?)", count)
	}
}

const hotTag = "cleanup/trash-candidate"

// noteIDs creates n notes and returns their uuids.
func noteIDs(t *testing.T, e *we.Engine, n int) []string {
	t.Helper()
	ids := make([]string, n)
	for i := range ids {
		ids[i] = createNote(t, e, fmt.Sprintf("n%d", i), "b")
	}
	return ids
}

// commitTag plans and commits a tag apply. It fails the test on any error.
func commitTag(t *testing.T, e *we.Engine, tag string, ids []string) {
	t.Helper()
	ch, err := e.PlanTagApply(tag, ids)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Commit(ch); err != nil {
		t.Fatalf("tag apply: %v", err)
	}
}

// requireOneTag reads the account live. It fails unless exactly one tag item has
// this title and that tag references exactly the notes in want, each once. A
// second tag item is the hot-tag duplicate. A repeated reference is a bad write.
func requireOneTag(t *testing.T, c *snclient.Client, title string, want []string) {
	t.Helper()
	_, tags, err := c.Fetch()
	if err != nil {
		t.Fatal(err)
	}
	var found []*snclient.TagView
	for _, tg := range tags {
		if tg.Title == title {
			found = append(found, tg)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want exactly 1 tag titled %q, got %d (hot-tag duplication?)", title, len(found))
	}
	got, w := slices.Clone(found[0].NoteUUIDs), slices.Clone(want)
	slices.Sort(got)
	slices.Sort(w)
	if !slices.Equal(got, w) {
		t.Fatalf("tag %q references %v, want exactly %v", title, got, w)
	}
}

// A retry is a Commit of an OpID that the ledger already holds as intended or
// acked. reconcile decides it with a tag-aware live read.
//
//   - Landed: the tag holds every ref, so the retry must not push. A notes-only
//     lookup (FetchOne) cannot see a tag. It says "absent", the retry pushes, and
//     the uuid conflict mints a second copy of the tag. Cap 0 makes a nil error
//     prove that no push happened.
//   - Never landed: the tag is absent, so the retry pushes once.
//   - Tag exists but lacks our refs: it is not landed. A lookup that matches on
//     the title alone would call this landed and drop the refs.
func TestTagApplyRetryIsDecidedByTagAwareRead(t *testing.T) {
	for _, lastState := range []string{we.StateIntended, we.StateAcked} {
		t.Run("landed, ledger says "+lastState, func(t *testing.T) {
			e, path := newEngineAt(t, 100)
			ids := noteIDs(t, e, 3)
			ch, err := e.PlanTagApply(hotTag, ids)
			if err != nil {
				t.Fatal(err)
			}
			if err := e.Commit(ch); err != nil { // the server takes the write
				t.Fatal(err)
			}

			e2 := restartAt(t, e.Client(), path, ch, lastState, 0)
			if err := e2.Commit(ch); err != nil {
				t.Fatalf("retry of a tag apply that already landed: %v", err)
			}
			requireOneTag(t, e.Client(), hotTag, ids)
			states := ledgerStates(t, path, ch.OpID)
			if last := states[len(states)-1]; last != we.StateVerified {
				t.Fatalf("a landed retry must end verified, ledger says %v", states)
			}
		})
	}

	t.Run("never landed", func(t *testing.T) {
		e, path := newEngineAt(t, 100)
		ids := noteIDs(t, e, 3)
		ch, err := e.PlanTagApply(hotTag, ids) // planned, then the process died before the push
		if err != nil {
			t.Fatal(err)
		}

		e2 := restartAt(t, e.Client(), path, ch, we.StateIntended, 100)
		if err := e2.Commit(ch); err != nil {
			t.Fatalf("retry of a tag apply that never landed: %v", err)
		}
		requireOneTag(t, e.Client(), hotTag, ids)
		want := []string{we.StateIntended, we.StateAcked, we.StateVerified}
		if got := ledgerStates(t, path, ch.OpID); !slices.Equal(got, want) {
			t.Fatalf("ledger states = %v, want %v", got, want)
		}
	})

	t.Run("tag exists without our refs", func(t *testing.T) {
		e, path := newEngineAt(t, 100)
		earlier, mine := noteIDs(t, e, 2), noteIDs(t, e, 2)
		commitTag(t, e, hotTag, earlier)
		ch, err := e.PlanTagApply(hotTag, mine)
		if err != nil {
			t.Fatal(err)
		}

		e2 := restartAt(t, e.Client(), path, ch, we.StateAcked, 100)
		if err := e2.Commit(ch); err != nil {
			t.Fatalf("retry onto an existing tag: %v", err)
		}
		requireOneTag(t, e.Client(), hotTag, append(slices.Clone(earlier), mine...))
	})
}

// The hot-tag case: the tag already exists, and a later batch adds more notes.
// The write must update that one tag item. A second tag item means a push went
// out with a stale timestamp and gosn-v2 minted a copy, and the engine halts on
// it. Applying notes the tag already holds changes nothing.
func TestTagApplyExtendsTheExistingTag(t *testing.T) {
	e := newEngine(t)
	first, second := noteIDs(t, e, 3), noteIDs(t, e, 2)

	commitTag(t, e, hotTag, first)
	requireOneTag(t, e.Client(), hotTag, first)

	commitTag(t, e, hotTag, second)
	all := append(slices.Clone(first), second...)
	requireOneTag(t, e.Client(), hotTag, all)

	commitTag(t, e, hotTag, first) // same notes again
	requireOneTag(t, e.Client(), hotTag, all)
}

// A caller can repeat a uuid. gosn-v2's UpsertReferences does not collapse a
// repeat inside the new list, so the tag would carry the same ref twice. Both
// branches matter: a tag with no refs yet, and a tag that already has some.
func TestTagApplyIgnoresRepeatedNoteUUIDs(t *testing.T) {
	e := newEngine(t)
	ids := noteIDs(t, e, 3)

	commitTag(t, e, hotTag, []string{ids[0], ids[1], ids[0], ids[2], ids[1]})
	requireOneTag(t, e.Client(), hotTag, ids)

	more := noteIDs(t, e, 1)
	commitTag(t, e, hotTag, []string{ids[0], more[0], more[0]})
	requireOneTag(t, e.Client(), hotTag, append(slices.Clone(ids), more...))
}

// A Change outlives the Plan call, and a retry replays it. So it must own its
// note list. A batching caller reuses one slice (batch = batch[:0]), and a Change
// that kept that slice would tag the next batch's notes instead.
func TestPlanTagApplyOwnsItsNoteList(t *testing.T) {
	e := newEngine(t)
	ids := noteIDs(t, e, 2)
	batch := slices.Clone(ids)
	ch, err := e.PlanTagApply(hotTag, batch)
	if err != nil {
		t.Fatal(err)
	}
	batch[0], batch[1] = "reused-1", "reused-2" // the caller moves on to its next batch
	if err := e.Commit(ch); err != nil {
		t.Fatal(err)
	}
	requireOneTag(t, e.Client(), hotTag, ids)
}

// Plan checks its input and writes nothing. A blank tag, an empty list, or a
// blank uuid is a caller bug, and it must not become an intent in the ledger or
// a garbage reference on the tag.
func TestPlanTagApplyRejectsBadInput(t *testing.T) {
	e := newEngine(t)
	id := createNote(t, e, "n", "b")
	cases := []struct {
		name string
		tag  string
		ids  []string
	}{
		{"blank tag", "  ", []string{id}},
		{"nil note list", hotTag, nil},
		{"empty note list", hotTag, []string{}},
		{"blank note uuid", hotTag, []string{id, " "}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ch, err := e.PlanTagApply(tc.tag, tc.ids)
			if err == nil || ch != nil {
				t.Fatalf("want an error and no Change, got %v / %+v", err, ch)
			}
		})
	}
	if _, tags, err := e.Client().Fetch(); err != nil || len(tags) != 0 {
		t.Fatalf("a rejected plan left %d tag(s) on the server (err=%v)", len(tags), err)
	}
}

// The tag plans: create, rename, trash, apply and detach. A plan that changes a tag
// that exists goes through the surgical path, as the note plans do. It changes its
// own key and client_updated_at and nothing else. A field that gosn-v2 does not
// model keeps its exact bytes. A new tag has nothing to keep, so create uses the
// typed path. These tests need the Docker SN server (see ops/docker).

const parentTagUUID = "22222222-2222-4222-8222-222222222222"

// parentRef links a child tag to its parent tag. It is not a note reference. A
// change to the notes of a tag must not touch it.
const parentRef = `{"uuid":"` + parentTagUUID + `","content_type":"Tag","reference_type":"TagToParentTag"}`

// richTagTail ends a rich tag. A rich tag has every kind of field that gosn-v2's
// typed tag model drops. It has an unknown top-level key, a third-party appData
// domain, and a flag inside the SN appData domain. It has fields that gosn-v2 does
// model (iconString, expanded, preferences), and a link to a parent tag.
const richTagTail = `"iconString":"star","expanded":true,"preferences":{"sortBy":"title","sortReverse":false},` +
	`"appData":{"org.standardnotes.sn":{"client_updated_at":"2020-01-01T00:00:00.000Z","archived":true},` +
	`"dev.example.tagmeta":{"color":"red","order":3}},` +
	`"future_tag_key":"must survive"}`

// noteRefJSON is a tag to note reference as the official apps write it: no reference_type.
func noteRefJSON(id string) string { return `{"uuid":"` + id + `","content_type":"Note"}` }

// richTagFor returns the content of a rich tag. It holds a reference to each note,
// and then the link to its parent tag.
func richTagFor(title string, noteIDs ...string) string {
	refs := make([]string, 0, len(noteIDs)+1)
	for _, id := range noteIDs {
		refs = append(refs, noteRefJSON(id))
	}
	refs = append(refs, parentRef)
	name, err := json.Marshal(title)
	if err != nil {
		panic(err)
	}
	return `{"title":` + string(name) + `,"references":[` + strings.Join(refs, ",") + `],` + richTagTail
}

// seedTag creates a tag whose content is exactly raw, and returns its uuid.
func seedTag(t *testing.T, e *we.Engine, raw string) string {
	t.Helper()
	id, err := e.Client().SeedRawTag(t, raw)
	if err != nil {
		t.Fatalf("seed tag: %v", err)
	}
	return id
}

// rawTag returns the decrypted content that the server holds for a tag. FetchRawTag
// refuses a tag that is deleted, so a result also shows that the tag is not deleted.
func rawTag(t *testing.T, e *we.Engine, id string) string {
	t.Helper()
	r, err := e.Client().FetchRawTag(id)
	if err != nil {
		t.Fatalf("FetchRawTag(%s): %v", id, err)
	}
	return r.Content()
}

// tagNow is what the tests read from the raw content of a tag.
type tagNow struct {
	title   string
	trashed bool
	notes   []string // the uuid of each note reference
}

func tagNowOf(t *testing.T, e *we.Engine, id string) tagNow {
	t.Helper()
	r, err := e.Client().FetchRawTag(id)
	if err != nil {
		t.Fatalf("FetchRawTag(%s): %v", id, err)
	}
	m := objectOf(t, r.Content())
	var s tagNow
	if err := json.Unmarshal(m["title"], &s.title); err != nil {
		t.Fatalf("title of %s is not a string: %s", id, m["title"])
	}
	s.trashed = string(m["trashed"]) == "true"
	if s.notes, err = r.NoteRefs(); err != nil {
		t.Fatal(err)
	}
	return s
}

// rawRefs returns the entries of the references list of a tag, as the server holds them.
func rawRefs(t *testing.T, e *we.Engine, id string) []string {
	t.Helper()
	var entries []json.RawMessage
	if err := json.Unmarshal(objectOf(t, rawTag(t, e, id))["references"], &entries); err != nil {
		t.Fatalf("references of %s: %v", id, err)
	}
	out := make([]string, len(entries))
	for i, en := range entries {
		out[i] = string(en)
	}
	return out
}

// tagViewOf returns the typed view of a tag. It fails the test if the tag is not there.
func tagViewOf(t *testing.T, e *we.Engine, id string) *snclient.TagView {
	t.Helper()
	_, tags, err := e.Client().Fetch()
	if err != nil {
		t.Fatal(err)
	}
	for _, tg := range tags {
		if tg.UUID == id {
			return tg
		}
	}
	t.Fatalf("tag %s is not on the server", id)
	return nil
}

// tagCount reads the account live and returns how many tags it holds.
func tagCount(t *testing.T, e *we.Engine) int {
	t.Helper()
	_, tags, err := e.Client().Fetch()
	if err != nil {
		t.Fatal(err)
	}
	return len(tags)
}

// writeTag saves a tag with one mutation, as another writer does. It uses the same
// raw primitives as the engine, so the other keys keep their bytes.
func writeTag(t *testing.T, e *we.Engine, id string, mutate func(map[string]json.RawMessage) error) {
	t.Helper()
	c := e.Client()
	r, err := c.FetchRawTag(id)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := c.EncryptMutated(r, mutate)
	if err != nil {
		t.Fatal(err)
	}
	out, err := c.PushEncrypted(items.EncryptedItems{enc})
	if err != nil {
		t.Fatal(err)
	}
	if err := snclient.RequireSaved(out, id); err != nil {
		t.Fatal(err)
	}
}

// tagFixture is a rich tag on the server, and three notes. The tag holds the first
// two. A reference is only a uuid, and nothing checks that the note exists, so the
// notes are not on the server.
type tagFixture struct {
	e     *we.Engine
	id    string   // the tag
	title string   // unique, so that an apply by title finds this tag and no other
	notes []string // three note uuids
	seed  string   // the content that the tag starts with
}

func newTagFixture(t *testing.T, e *we.Engine, name string) tagFixture {
	t.Helper()
	notes := []string{uuid.NewString(), uuid.NewString(), uuid.NewString()}
	title := "rich " + name
	seed := richTagFor(title, notes[0], notes[1])
	return tagFixture{e: e, id: seedTag(t, e, seed), title: title, notes: notes, seed: seed}
}

// tagCase is one kind of change to a tag that exists, with what it must do.
type tagCase struct {
	name string
	kind string // the Kind of the Change, as the ledger records it
	plan func(f tagFixture) (*we.Change, error)
	key  string                            // the one top-level key, other than appData, that the change sets
	done func(f tagFixture, s tagNow) bool // the end state that the change makes
	undo func(t *testing.T, f tagFixture)  // another writer reverses it
}

var tagCases = []tagCase{
	{"rename", "tag-rename",
		func(f tagFixture) (*we.Change, error) { return f.e.PlanTagRename(f.id, "renamed") },
		"title",
		func(_ tagFixture, s tagNow) bool { return s.title == "renamed" },
		func(t *testing.T, f tagFixture) { writeTag(t, f.e, f.id, snclient.SetKey("title", f.title)) }},
	{"trash", "tag-trash",
		func(f tagFixture) (*we.Change, error) { return f.e.PlanTagTrash(f.id) },
		"trashed",
		func(_ tagFixture, s tagNow) bool { return s.trashed },
		func(t *testing.T, f tagFixture) { writeTag(t, f.e, f.id, snclient.SetKey("trashed", false)) }},
	{"apply", "tag",
		func(f tagFixture) (*we.Change, error) { return f.e.PlanTagApply(f.title, f.notes[2:]) },
		"references",
		func(f tagFixture, s tagNow) bool { return slices.Contains(s.notes, f.notes[2]) },
		func(t *testing.T, f tagFixture) { writeTag(t, f.e, f.id, snclient.RemoveNoteRefs(f.notes[2:])) }},
	{"detach", "detach",
		func(f tagFixture) (*we.Change, error) { return f.e.PlanTagDetach(f.id, f.notes[:1]) },
		"references",
		func(f tagFixture, s tagNow) bool { return !slices.Contains(s.notes, f.notes[0]) },
		func(t *testing.T, f tagFixture) { writeTag(t, f.e, f.id, snclient.AddNoteRefs(f.notes[:1])) }},
	{"add", "tag-add",
		func(f tagFixture) (*we.Change, error) { return f.e.PlanTagAddNotes(f.id, f.notes[2:]) },
		"references",
		func(f tagFixture, s tagNow) bool { return slices.Contains(s.notes, f.notes[2]) },
		func(t *testing.T, f tagFixture) { writeTag(t, f.e, f.id, snclient.RemoveNoteRefs(f.notes[2:])) }},
}

// The preservation test at the engine level. Each plan, committed through the
// engine, changes its key and client_updated_at. Every other field, modeled or
// not, known or not, keeps its exact bytes. The apply case fails against the typed
// path that PlanTagApply used before: that path rebuilds the tag from a fixed struct.
func TestTagPlansChangeOnlyTheirTarget(t *testing.T) {
	e := newEngine(t) // one account for all cases: each case seeds its own tag
	for _, tc := range tagCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newTagFixture(t, e, tc.name)
			// Premise: the server holds the seed byte for byte. Without this, a later
			// match proves nothing: the seed can already be damaged.
			if got := rawTag(t, e, f.id); got != f.seed {
				t.Fatalf("premise broken: seeded content did not round-trip\n got: %s\nwant: %s", got, f.seed)
			}
			tags := tagCount(t, e)
			ch, err := tc.plan(f)
			if err != nil {
				t.Fatal(err)
			}
			if got := rawTag(t, e, f.id); got != f.seed {
				t.Fatalf("planning wrote to the tag:\n%s", got)
			}
			if ch.Kind != tc.kind {
				t.Errorf("Kind = %q, want %q", ch.Kind, tc.kind)
			}
			if err := e.Commit(ch); err != nil {
				t.Fatal(err)
			}
			if ch.TagUUID != f.id {
				t.Errorf("TagUUID = %q, want the tag %q", ch.TagUUID, f.id)
			}
			if n := tagCount(t, e); n != tags {
				t.Errorf("want %d tags, got %d: a stale push leaves a copy", tags, n)
			}
			if !tc.done(f, tagNowOf(t, e, f.id)) {
				t.Fatalf("the change did not land:\n%s", rawTag(t, e, f.id))
			}

			before := objectOf(t, f.seed)
			after := objectOf(t, rawTag(t, e, f.id))
			beforeApp, afterApp := objectOf(t, string(before["appData"])), objectOf(t, string(after["appData"]))
			beforeSN := objectOf(t, string(beforeApp["org.standardnotes.sn"]))
			afterSN := objectOf(t, string(afterApp["org.standardnotes.sn"]))

			// client_updated_at changed, and it is the current time.
			var stamp string
			if err := json.Unmarshal(afterSN["client_updated_at"], &stamp); err != nil {
				t.Fatalf("client_updated_at is not a JSON string: %s", afterSN["client_updated_at"])
			}
			at, err := time.Parse(common.TimeLayout, stamp)
			if err != nil {
				t.Fatalf("client_updated_at %q is not in layout %q: %v", stamp, common.TimeLayout, err)
			}
			if d := time.Since(at); d < -time.Minute || d > time.Minute {
				t.Errorf("client_updated_at %q is %v from now", stamp, d)
			}

			// Each field that is named here is byte-identical.
			untouched := []string{"iconString", "expanded", "preferences", "future_tag_key"}
			if tc.key != "references" {
				untouched = append(untouched, "references")
			}
			if tc.key != "title" {
				untouched = append(untouched, "title")
			}
			for _, k := range untouched {
				if string(before[k]) != string(after[k]) {
					t.Errorf("top-level %q changed: %s -> %s", k, show(before, k), show(after, k))
				}
			}
			if string(beforeSN["archived"]) != string(afterSN["archived"]) {
				t.Errorf("appData[org.standardnotes.sn].archived changed: %s -> %s", show(beforeSN, "archived"), show(afterSN, "archived"))
			}
			if string(beforeApp["dev.example.tagmeta"]) != string(afterApp["dev.example.tagmeta"]) {
				t.Errorf("third-party appData changed: %s -> %s",
					show(beforeApp, "dev.example.tagmeta"), show(afterApp, "dev.example.tagmeta"))
			}

			// Whole-object check. At each of the three levels, exactly the intended
			// key changed, and nothing was removed. A trash flag that the tag did
			// not have counts as added.
			changed, added, removed := diffKeys(before, after)
			touched := append(slices.Clone(changed), added...)
			sort.Strings(touched)
			wantTouched := []string{"appData", tc.key}
			sort.Strings(wantTouched)
			requireKeys(t, "content", "touched", touched, wantTouched)
			requireKeys(t, "content", "removed", removed, nil)
			changed, added, removed = diffKeys(beforeApp, afterApp)
			requireKeys(t, "appData", "changed", changed, []string{"org.standardnotes.sn"})
			requireKeys(t, "appData", "added", added, nil)
			requireKeys(t, "appData", "removed", removed, nil)
			changed, added, removed = diffKeys(beforeSN, afterSN)
			requireKeys(t, "appData[org.standardnotes.sn]", "changed", changed, []string{"client_updated_at"})
			requireKeys(t, "appData[org.standardnotes.sn]", "added", added, nil)
			requireKeys(t, "appData[org.standardnotes.sn]", "removed", removed, nil)

			// The typed view still reads the tag, and it is the same tag.
			if tagViewOf(t, e, f.id).UUID != f.id {
				t.Error("the typed view lost the tag")
			}
		})
	}
}

// countOf returns how many times id is in ids.
func countOf(ids []string, id string) int {
	n := 0
	for _, x := range ids {
		if x == id {
			n++
		}
	}
	return n
}

// Apply and detach change the references list. Every entry that they do not change
// keeps its exact bytes. The link to a parent tag is one of them, because it is
// not a note reference. A new entry has no reference_type, as the official apps
// write it. A uuid that the tag holds is not added again, in the list or across calls.
func TestTagApplyAndDetachKeepEveryOtherReference(t *testing.T) {
	e := newEngine(t)
	f := newTagFixture(t, e, "refs")
	n0, n1, n2 := f.notes[0], f.notes[1], f.notes[2]
	requireRefs := func(step string, want ...string) {
		t.Helper()
		if got := rawRefs(t, e, f.id); !slices.Equal(got, want) {
			t.Fatalf("%s: references\n got: %v\nwant: %v", step, got, want)
		}
	}
	commit := func(ch *we.Change, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		if err := e.Commit(ch); err != nil {
			t.Fatal(err)
		}
	}
	// typedHas checks the typed view of the tag, which is what tags_list reads. gosn-v2
	// counts every reference as a note, so the link to the parent tag is in it too.
	typedHas := func(step string, present, absent []string) {
		t.Helper()
		got := tagViewOf(t, e, f.id).NoteUUIDs
		for _, id := range present {
			if n := countOf(got, id); n != 1 {
				t.Errorf("%s: typed NoteUUIDs %v hold %s %d times, want once", step, got, id, n)
			}
		}
		for _, id := range absent {
			if slices.Contains(got, id) {
				t.Errorf("%s: typed NoteUUIDs %v still hold %s", step, got, id)
			}
		}
	}
	requireRefs("premise", noteRefJSON(n0), noteRefJSON(n1), parentRef)

	// n2 is new, and it is in the list twice. n0 is on the tag already.
	commit(e.PlanTagApply(f.title, []string{n2, n0, n2}))
	requireRefs("after apply", noteRefJSON(n0), noteRefJSON(n1), parentRef, noteRefJSON(n2))
	typedHas("after apply", []string{n0, n1, n2}, nil)

	commit(e.PlanTagDetach(f.id, []string{n0}))
	requireRefs("after detach", noteRefJSON(n1), parentRef, noteRefJSON(n2))
	typedHas("after detach", []string{n1, n2}, []string{n0})

	// The caller names the parent tag. It is not a note, so it stays, and nothing is written.
	was := rawTag(t, e, f.id)
	commit(e.PlanTagDetach(f.id, []string{parentTagUUID}))
	if got := rawTag(t, e, f.id); got != was {
		t.Fatalf("a detach that named the parent tag changed the tag:\n%s", got)
	}

	// An unknown entry is not lost either. Another writer adds one, and both plans keep it.
	odd := `{"uuid":"` + uuid.NewString() + `","content_type":"Component","future":[1,2]}`
	writeTag(t, e, f.id, func(m map[string]json.RawMessage) error {
		m["references"] = json.RawMessage(`[` + noteRefJSON(n1) + `,` + odd + `]`)
		return nil
	})
	commit(e.PlanTagApply(f.title, []string{n0}))
	requireRefs("after apply onto an unknown entry", noteRefJSON(n1), odd, noteRefJSON(n0))
	commit(e.PlanTagDetach(f.id, []string{n1}))
	requireRefs("after detach beside an unknown entry", odd, noteRefJSON(n0))
}

// Each plan is one intent, so each plan puts its own nonce in the OpID. A verified
// OpID is a no-op for good. Suppose two plans share an OpID. Another writer puts the
// change back, and the user asks for the same change again. The second Commit finds
// the first one's verified entry, returns nil, and pushes nothing. Every step
// reports success, but the change is not there.
func TestEachTagPlanIsItsOwnIntent(t *testing.T) {
	e := newEngine(t) // one account for all cases: each case seeds its own tag
	for _, tc := range tagCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newTagFixture(t, e, tc.name)

			first, err := tc.plan(f)
			if err != nil {
				t.Fatal(err)
			}
			if err := e.Commit(first); err != nil {
				t.Fatal(err)
			}
			if !tc.done(f, tagNowOf(t, e, f.id)) {
				t.Fatalf("premise: the first %s did not land", tc.name)
			}

			tc.undo(t, f) // another writer puts the change back
			if tc.done(f, tagNowOf(t, e, f.id)) {
				t.Fatal("premise: the other writer did not put the change back")
			}

			second, err := tc.plan(f)
			if err != nil {
				t.Fatal(err)
			}
			if second.OpID == first.OpID {
				t.Fatalf("two plans share the OpID %s", first.OpID)
			}
			if err := e.Commit(second); err != nil {
				t.Fatal(err)
			}
			if !tc.done(f, tagNowOf(t, e, f.id)) {
				t.Fatalf("the second %s did not land", tc.name)
			}
		})
	}
}

// apply must read the tag again right before it pushes. A plan can wait, and the
// server timestamp can move in that time (another device saves the tag). A push
// with a stale timestamp is a sync_conflict. gosn-v2 answers it by minting a copy
// of the tag under a new uuid, and the engine halts. With a fresh read, the change
// lands on top of the other writer's save, and keeps it.
func TestTagPlansReadTheTagFreshBeforePushing(t *testing.T) {
	e := newEngine(t) // one account for all cases: each case seeds its own tag
	for _, tc := range tagCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newTagFixture(t, e, tc.name)
			tags := tagCount(t, e)
			ch, err := tc.plan(f) // a plan that reads the tag, reads it at its current timestamp
			if err != nil {
				t.Fatal(err)
			}

			// Before Commit, another writer saves the tag, so its server timestamp moves on.
			writeTag(t, e, f.id, snclient.SetKey("future_tag_key", "saved by another writer"))

			if err := e.Commit(ch); err != nil {
				t.Fatalf("%s after the server timestamp moved: %v", tc.name, err)
			}
			if !tc.done(f, tagNowOf(t, e, f.id)) {
				t.Errorf("the change did not land")
			}
			if got := show(objectOf(t, rawTag(t, e, f.id)), "future_tag_key"); got != `"saved by another writer"` {
				t.Errorf("the change lost the other writer's save: future_tag_key = %s", got)
			}
			if n := tagCount(t, e); n != tags {
				t.Errorf("want %d tags, got %d: a stale push leaves a copy", tags, n)
			}
		})
	}
}

// Commit treats a change as a retry when the ledger holds intended or acked for its
// OpID. reconcile reads the tag live and decides the retry. If the end state
// already holds, the earlier push landed, so the retry must not push. If it does
// not, the earlier push did not land, so the retry pushes once.
func TestTagRetryIsDecidedByLiveRead(t *testing.T) {
	e, path := newEngineAt(t, 100) // one account and one ledger for all cases: each OpID is its own
	for _, tc := range tagCases {
		t.Run(tc.name+" landed", func(t *testing.T) {
			f := newTagFixture(t, e, tc.name+"-landed")
			tags := tagCount(t, e)
			ch, err := tc.plan(f)
			if err != nil {
				t.Fatal(err)
			}
			if err := e.Commit(ch); err != nil { // the server takes the write
				t.Fatal(err)
			}

			for _, lastState := range []string{we.StateIntended, we.StateAcked} {
				// Cap 0: only a read can succeed, so a nil error proves the retry did not push.
				e2 := restartAt(t, e.Client(), path, ch, lastState, 0)
				if err := e2.Commit(ch); err != nil {
					t.Fatalf("retry of a change that already landed, ledger says %s: %v", lastState, err)
				}
				states := ledgerStates(t, path, ch.OpID)
				if last := states[len(states)-1]; last != we.StateVerified {
					t.Fatalf("a landed retry must end verified, ledger says %v", states)
				}
			}
			if !tc.done(f, tagNowOf(t, e, f.id)) {
				t.Fatalf("the change is not there")
			}
			if n := tagCount(t, e); n != tags {
				t.Fatalf("want %d tags, got %d", tags, n)
			}
		})

		t.Run(tc.name+" never landed", func(t *testing.T) {
			f := newTagFixture(t, e, tc.name+"-never")
			tags := tagCount(t, e)
			ch, err := tc.plan(f) // planned, then the process died before the push
			if err != nil {
				t.Fatal(err)
			}

			e2 := restartAt(t, e.Client(), path, ch, we.StateIntended, 100)
			if err := e2.Commit(ch); err != nil {
				t.Fatalf("retry of a change that never landed: %v", err)
			}
			if !tc.done(f, tagNowOf(t, e, f.id)) {
				t.Fatalf("the change is not there")
			}
			if n := tagCount(t, e); n != tags {
				t.Fatalf("want %d tags, got %d", tags, n)
			}
			want := []string{we.StateIntended, we.StateAcked, we.StateVerified}
			if got := ledgerStates(t, path, ch.OpID); !slices.Equal(got, want) {
				t.Fatalf("ledger states = %v, want %v", got, want)
			}
		})
	}
}

// A plan whose end state already holds writes nothing. The tag keeps its bytes, and
// that includes client_updated_at. The examples are:
//   - apply notes that the tag holds
//   - detach notes that the tag does not hold
//   - trash a tag that is trashed
//   - rename a tag to its own title
//
// The change is not lost, because the tag is as the user asked.
func TestTagPlansThatAlreadyHoldWriteNothing(t *testing.T) {
	e, path := newEngineAt(t, 100)
	for _, tc := range tagCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newTagFixture(t, e, tc.name)
			first, err := tc.plan(f)
			if err != nil {
				t.Fatal(err)
			}
			if err := e.Commit(first); err != nil {
				t.Fatal(err)
			}
			landed := rawTag(t, e, f.id)

			again, err := tc.plan(f) // a new intent, so Commit pushes if it needs to
			if err != nil {
				t.Fatal(err)
			}
			if err := e.Commit(again); err != nil {
				t.Fatal(err)
			}
			if got := rawTag(t, e, f.id); got != landed {
				t.Fatalf("a change that already held still wrote to the tag:\n before: %s\n  after: %s", landed, got)
			}
			want := []string{we.StateIntended, we.StateVerified} // no push, so no ack
			if got := ledgerStates(t, path, again.OpID); !slices.Equal(got, want) {
				t.Fatalf("ledger states = %v, want %v", got, want)
			}
		})
	}
}

// A plan for a tag that is not on the server must fail at once, name the problem,
// and hand back no Change. So must a plan for the uuid of a note: a tag plan must
// never write a title or a reference into a note.
func TestTagPlansRefuseAMissingOrNonTagItem(t *testing.T) {
	e := newEngine(t)
	note := seedRaw(t, e, richContent)
	const missing = "00000000-0000-4000-8000-000000000000"
	plans := map[string]func(id string) (*we.Change, error){
		"rename": func(id string) (*we.Change, error) { return e.PlanTagRename(id, "renamed") },
		"trash":  func(id string) (*we.Change, error) { return e.PlanTagTrash(id) },
		"detach": func(id string) (*we.Change, error) { return e.PlanTagDetach(id, []string{refUUID}) },
	}
	for name, plan := range plans {
		if ch, err := plan(missing); ch != nil || !errors.Is(err, snclient.ErrTagNotFound) {
			t.Errorf("%s of a missing tag gave change=%v err=%v, want nil and ErrTagNotFound", name, ch, err)
		}
		if ch, err := plan(note); ch != nil || err == nil || errors.Is(err, snclient.ErrTagNotFound) {
			t.Errorf("%s of a note gave change=%v err=%v, want nil and a not-a-tag error", name, ch, err)
		}
	}
	if got := rawContent(t, e, note); got != richContent {
		t.Errorf("a tag plan touched a note:\n%s", got)
	}
}

// Plan checks its input and writes nothing. A blank title, an empty list, or a
// blank uuid is a caller bug. It must not become an intent in the ledger or a
// garbage value in a tag.
func TestTagPlansRejectBadInput(t *testing.T) {
	e := newEngine(t)
	f := newTagFixture(t, e, "bad input")
	cases := map[string]func() (*we.Change, error){
		"create: blank title":     func() (*we.Change, error) { return e.PlanTagCreate("  ") },
		"create: empty title":     func() (*we.Change, error) { return e.PlanTagCreate("") },
		"rename: blank title":     func() (*we.Change, error) { return e.PlanTagRename(f.id, "  ") },
		"rename: blank tag uuid":  func() (*we.Change, error) { return e.PlanTagRename(" ", "x") },
		"trash: blank tag uuid":   func() (*we.Change, error) { return e.PlanTagTrash("") },
		"detach: blank tag uuid":  func() (*we.Change, error) { return e.PlanTagDetach(" ", f.notes) },
		"detach: nil note list":   func() (*we.Change, error) { return e.PlanTagDetach(f.id, nil) },
		"detach: empty note list": func() (*we.Change, error) { return e.PlanTagDetach(f.id, []string{}) },
		"detach: blank note uuid": func() (*we.Change, error) { return e.PlanTagDetach(f.id, []string{f.notes[0], " "}) },
		"apply: blank note uuid":  func() (*we.Change, error) { return e.PlanTagApply(f.title, []string{""}) },
	}
	for name, plan := range cases {
		if ch, err := plan(); err == nil || ch != nil {
			t.Errorf("%s: want an error and no Change, got %v / %+v", name, err, ch)
		}
	}
	if got := rawTag(t, e, f.id); got != f.seed {
		t.Errorf("a rejected plan changed the tag:\n%s", got)
	}
	if n := tagCount(t, e); n != 1 {
		t.Errorf("a rejected plan left %d tags, want the 1 that the test made", n)
	}
}

// Create makes a fresh tag. Planning writes nothing. The tag has the title, no
// notes, and an empty references list. ch.TagUUID names the new tag. That stops the
// stray-item halt from reading the tag as a duplicate: pushAndVerify halts the
// engine on any new tag that is not ch.TagUUID.
func TestTagCreate(t *testing.T) {
	e, path := newEngineAt(t, 100)
	ch, err := e.PlanTagCreate("projects/alpha")
	if err != nil {
		t.Fatal(err)
	}
	if ch.Kind != "tag-create" {
		t.Fatalf("Kind = %q, want tag-create", ch.Kind)
	}
	if tv, err := e.Client().FindTag("projects/alpha"); err != nil || tv != nil {
		t.Fatalf("planning created the tag: tag=%v err=%v", tv, err)
	}
	if got := ledgerStates(t, path, ch.OpID); len(got) != 0 {
		t.Fatalf("Plan must not touch the ledger, got %v", got)
	}

	if err := e.Commit(ch); err != nil {
		t.Fatal(err)
	}
	tv, err := e.Client().FindTag("projects/alpha")
	if err != nil || tv == nil {
		t.Fatalf("the tag is not on the server: tag=%v err=%v", tv, err)
	}
	if ch.TagUUID != tv.UUID {
		t.Errorf("TagUUID = %q, want the new tag %q", ch.TagUUID, tv.UUID)
	}
	if n := tagCount(t, e); n != 1 {
		t.Errorf("want 1 tag, got %d", n)
	}
	got := tagNowOf(t, e, tv.UUID)
	if got.title != "projects/alpha" || got.trashed || len(got.notes) != 0 {
		t.Errorf("new tag = %+v, want the title, not trashed, and no notes", got)
	}
	if refs := rawRefs(t, e, tv.UUID); len(refs) != 0 {
		t.Errorf("references = %v, want none", refs)
	}
	want := []string{we.StateIntended, we.StateAcked, we.StateVerified}
	if states := ledgerStates(t, path, ch.OpID); !slices.Equal(states, want) {
		t.Errorf("ledger states = %v, want %v", states, want)
	}
}

// A second create of the same title is a new intent, and it makes no second tag. It
// finds the tag by title, writes nothing, and leaves the tag as it was. That holds
// for a tag that this engine made and for one that it did not.
func TestTagCreateIsIdempotent(t *testing.T) {
	e, path := newEngineAt(t, 100)
	first, err := e.PlanTagCreate("dup")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Commit(first); err != nil {
		t.Fatal(err)
	}
	was := rawTag(t, e, first.TagUUID)

	second, err := e.PlanTagCreate("dup")
	if err != nil {
		t.Fatal(err)
	}
	if second.OpID == first.OpID {
		t.Fatalf("two plans share the OpID %s", first.OpID)
	}
	if err := e.Commit(second); err != nil {
		t.Fatal(err)
	}
	if n := tagCount(t, e); n != 1 {
		t.Fatalf("a second create made %d tags, want 1", n)
	}
	if second.TagUUID != first.TagUUID {
		t.Errorf("second TagUUID = %q, want the first tag %q", second.TagUUID, first.TagUUID)
	}
	if got := rawTag(t, e, first.TagUUID); got != was {
		t.Errorf("a second create wrote to the tag:\n%s", got)
	}
	want := []string{we.StateIntended, we.StateVerified} // no push, so no ack
	if states := ledgerStates(t, path, second.OpID); !slices.Equal(states, want) {
		t.Errorf("ledger states = %v, want %v", states, want)
	}
	if err := e.Commit(first); err != nil { // a replay of a verified change is a no-op
		t.Fatalf("replay: %v", err)
	}

	// A tag that this engine did not make, with fields that it does not know.
	f := newTagFixture(t, e, "existing")
	ch, err := e.PlanTagCreate(f.title)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Commit(ch); err != nil {
		t.Fatal(err)
	}
	if ch.TagUUID != f.id {
		t.Errorf("TagUUID = %q, want the existing tag %q", ch.TagUUID, f.id)
	}
	if got := rawTag(t, e, f.id); got != f.seed {
		t.Errorf("create touched an existing tag:\n%s", got)
	}
	if n := tagCount(t, e); n != 2 { // "dup" and the fixture's tag, and nothing else
		t.Errorf("want 2 tags, got %d", n)
	}
}

// Commit treats a create as a retry when the ledger holds intended or acked for its
// OpID. reconcile looks for the tag by title. If it is there, the earlier push
// landed, so the retry must not push: a push would make a second tag. If it is not
// there, the earlier push did not land, so the retry pushes once.
func TestTagCreateRetryIsDecidedByLiveRead(t *testing.T) {
	for _, lastState := range []string{we.StateIntended, we.StateAcked} {
		t.Run("landed, ledger says "+lastState, func(t *testing.T) {
			e, path := newEngineAt(t, 100)
			ch, err := e.PlanTagCreate("retried")
			if err != nil {
				t.Fatal(err)
			}
			if err := e.Commit(ch); err != nil { // the server takes the write
				t.Fatal(err)
			}
			// Cap 0: only a read can succeed, so a nil error proves the retry did not push.
			e2 := restartAt(t, e.Client(), path, ch, lastState, 0)
			if err := e2.Commit(ch); err != nil {
				t.Fatalf("retry of a create that already landed: %v", err)
			}
			if n := tagCount(t, e); n != 1 {
				t.Fatalf("a retry made a second tag: want 1, got %d", n)
			}
			states := ledgerStates(t, path, ch.OpID)
			if last := states[len(states)-1]; last != we.StateVerified {
				t.Fatalf("a landed retry must end verified, ledger says %v", states)
			}
		})
	}

	t.Run("never landed", func(t *testing.T) {
		e, path := newEngineAt(t, 100)
		ch, err := e.PlanTagCreate("late") // planned, then the process died before the push
		if err != nil {
			t.Fatal(err)
		}
		e2 := restartAt(t, e.Client(), path, ch, we.StateIntended, 100)
		if err := e2.Commit(ch); err != nil {
			t.Fatalf("retry of a create that never landed: %v", err)
		}
		if tv, err := e.Client().FindTag("late"); err != nil || tv == nil {
			t.Fatalf("the tag is not there: tag=%v err=%v", tv, err)
		}
		if n := tagCount(t, e); n != 1 {
			t.Fatalf("want 1 tag, got %d", n)
		}
		want := []string{we.StateIntended, we.StateAcked, we.StateVerified}
		if got := ledgerStates(t, path, ch.OpID); !slices.Equal(got, want) {
			t.Fatalf("ledger states = %v, want %v", got, want)
		}
	})
}

// Delete a tag is trash. The trashed flag sits inside the tag content, and it is
// reversible: another writer, such as an official app, clears it. The tag stays on
// the server, with its title and its references. It is never marked deleted on the
// envelope: that flag is permanent, and guard_test.go fails if any non-test source
// sets it. FetchRawTag refuses a deleted tag, so rawTag succeeding is the proof.
func TestTagTrashIsReversibleAndIsNotADelete(t *testing.T) {
	e := newEngine(t)
	f := newTagFixture(t, e, "trash")

	ch, err := e.PlanTagTrash(f.id)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Kind != "tag-trash" || ch.TagUUID != f.id {
		t.Fatalf("change: kind %q, tag %q, want tag-trash and %q", ch.Kind, ch.TagUUID, f.id)
	}
	if err := e.Commit(ch); err != nil {
		t.Fatal(err)
	}

	got := tagNowOf(t, e, f.id) // fails the test if the tag is deleted or gone
	if !got.trashed || got.title != f.title || !slices.Equal(got.notes, f.notes[:2]) {
		t.Fatalf("after the trash: %+v, want a trashed tag with its title and notes", got)
	}
	if tv := tagViewOf(t, e, f.id); tv.Title != f.title {
		t.Errorf("the typed view reads title %q, want %q", tv.Title, f.title)
	}

	// Reversible: the flag goes back to false, and the tag is whole.
	writeTag(t, e, f.id, snclient.SetKey("trashed", false))
	got = tagNowOf(t, e, f.id)
	if got.trashed || got.title != f.title || !slices.Equal(got.notes, f.notes[:2]) {
		t.Errorf("after the restore: %+v, want an untrashed tag with its title and notes", got)
	}
}

// Apply works for a tag that does not exist yet. It makes the tag, with all its
// references, through the typed path, and ch.TagUUID names the tag. This is the one
// place where a typed push is right, because a new tag has nothing to keep.
func TestTagApplyCreatesTheTagWhenItIsMissing(t *testing.T) {
	e := newEngine(t)
	ids := noteIDs(t, e, 2)
	ch, err := e.PlanTagApply("made/by/apply", ids)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Commit(ch); err != nil {
		t.Fatal(err)
	}
	requireOneTag(t, e.Client(), "made/by/apply", ids)
	tv, err := e.Client().FindTag("made/by/apply")
	if err != nil || tv == nil || ch.TagUUID != tv.UUID {
		t.Fatalf("TagUUID = %q, want the new tag (tag=%v err=%v)", ch.TagUUID, tv, err)
	}
	if got := tagNowOf(t, e, tv.UUID); got.title != "made/by/apply" || got.trashed {
		t.Errorf("new tag = %+v", got)
	}
}

// A plan describes its change in Before and After, so that a caller can show a
// dry run. Plan reads and writes nothing more than it needs: rename and trash read
// the tag, so they know what it holds now. Apply and detach say what the caller asked for.
func TestTagPlansDescribeTheirChange(t *testing.T) {
	e := newEngine(t)
	f := newTagFixture(t, e, "describe")

	rename, err := e.PlanTagRename(f.id, "renamed")
	if err != nil {
		t.Fatal(err)
	}
	trash, err := e.PlanTagTrash(f.id)
	if err != nil {
		t.Fatal(err)
	}
	detach, err := e.PlanTagDetach(f.id, f.notes[:1])
	if err != nil {
		t.Fatal(err)
	}
	apply, err := e.PlanTagApply(f.title, f.notes[2:])
	if err != nil {
		t.Fatal(err)
	}
	create, err := e.PlanTagCreate("brand new")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name          string
		ch            *we.Change
		before, after map[string]any
	}{
		{"rename", rename, map[string]any{"title": f.title}, map[string]any{"title": "renamed"}},
		{"trash", trash, map[string]any{"trashed": false}, map[string]any{"trashed": true}},
		{"detach", detach, nil, map[string]any{"remove_note_uuids": f.notes[:1]}},
		{"apply", apply, nil, map[string]any{"tag": f.title, "add_note_uuids": f.notes[2:]}},
		{"create", create, nil, map[string]any{"title": "brand new"}},
	} {
		if !reflect.DeepEqual(tc.ch.Before, tc.before) {
			t.Errorf("%s: Before = %v, want %v", tc.name, tc.ch.Before, tc.before)
		}
		if !reflect.DeepEqual(tc.ch.After, tc.after) {
			t.Errorf("%s: After = %v, want %v", tc.name, tc.ch.After, tc.after)
		}
	}
	if got := rawTag(t, e, f.id); got != f.seed {
		t.Errorf("planning wrote to the tag:\n%s", got)
	}
}

// The whole surface on a tag that the engine made itself. gosn-v2 writes its own
// fields into a new tag, such as prefersPlainEditor and pinned in the SN appData
// domain. A real run meets this content first. Create, apply, rename, detach and
// trash each change what they name. Nothing is lost, and the account holds one tag.
func TestTagLifecycleOnATagTheEngineMade(t *testing.T) {
	e := newEngine(t)
	ids := noteIDs(t, e, 3)
	step := func(what string, ch *we.Change, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: plan: %v", what, err)
		}
		if err := e.Commit(ch); err != nil {
			t.Fatalf("%s: commit: %v", what, err)
		}
	}

	create, err := e.PlanTagCreate("life/cycle")
	step("create", create, err)
	id := create.TagUUID
	born := objectOf(t, rawTag(t, e, id))
	bornSN := objectOf(t, string(objectOf(t, string(born["appData"]))["org.standardnotes.sn"]))

	apply, err := e.PlanTagApply("life/cycle", ids[:2])
	step("apply", apply, err)
	rename, err := e.PlanTagRename(id, "life/renamed")
	step("rename", rename, err)
	detach, err := e.PlanTagDetach(id, ids[:1])
	step("detach", detach, err)
	trash, err := e.PlanTagTrash(id)
	step("trash", trash, err)

	got := tagNowOf(t, e, id)
	if got.title != "life/renamed" || !got.trashed || !slices.Equal(got.notes, ids[1:2]) {
		t.Fatalf("end state = %+v, want the new title, trashed, and only note %s", got, ids[1])
	}
	if n := tagCount(t, e); n != 1 {
		t.Fatalf("want 1 tag, got %d", n)
	}
	if tv := tagViewOf(t, e, id); tv.Title != "life/renamed" || !slices.Equal(tv.NoteUUIDs, ids[1:2]) {
		t.Errorf("typed view = %q %v, want the new title and only note %s", tv.Title, tv.NoteUUIDs, ids[1])
	}

	// Every key that gosn-v2 wrote into the new tag is still there, and the SN appData
	// domain still holds each field it was born with. Only client_updated_at moved.
	end := objectOf(t, rawTag(t, e, id))
	endSN := objectOf(t, string(objectOf(t, string(end["appData"]))["org.standardnotes.sn"]))
	_, _, removed := diffKeys(born, end)
	requireKeys(t, "content", "removed", removed, nil)
	changed, added, removed := diffKeys(bornSN, endSN)
	requireKeys(t, "appData[org.standardnotes.sn]", "changed", changed, []string{"client_updated_at"})
	requireKeys(t, "appData[org.standardnotes.sn]", "added", added, nil)
	requireKeys(t, "appData[org.standardnotes.sn]", "removed", removed, nil)
}
