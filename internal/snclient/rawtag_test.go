package snclient

// Tests for the tag side of the surgical write path. A tag goes through the same
// raw primitives as a note: FetchRawTag, EncryptMutated and PushEncrypted. A tag
// also holds a list of references, which the tag plans change. NoteRefs,
// AddNoteRefs and RemoveNoteRefs read and change that list on the raw JSON.
// The offline tests need nothing. The integration tests need the Docker SN
// server and skip cleanly without it.

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/jonhadfield/gosn-v2/common"
	"github.com/jonhadfield/gosn-v2/items"
	"github.com/smirnov-labs/standard-notes-mcp/internal/testsupport"
)

const (
	noteA     = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	noteB     = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	noteC     = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	parentTag = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
)

// noteRef is a tag to note reference as the official apps write it: no reference_type.
func noteRef(id string) string { return `{"uuid":"` + id + `","content_type":"Note"}` }

// parentRef is a reference from a child tag to its parent tag. It is not a note
// reference, and gosn-v2 does not model it as one. A change to the notes of a tag
// must keep it.
var parentRef = `{"uuid":"` + parentTag + `","content_type":"Tag","reference_type":"TagToParentTag"}`

// richTag is a tag with every kind of field that gosn-v2's typed tag model drops.
// It has an unknown top-level key, a third-party appData domain, and a flag inside
// the SN appData domain. It has fields that gosn-v2 does model (iconString,
// expanded, preferences). It has two references: a note and a parent tag.
const richTagTail = `"iconString":"star","expanded":true,"preferences":{"sortBy":"title","sortReverse":false},` +
	`"appData":{"org.standardnotes.sn":{"client_updated_at":"2020-01-01T00:00:00.000Z","archived":true},` +
	`"dev.example.tagmeta":{"color":"red","order":3}},` +
	`"future_tag_key":"must survive"}`

var richTag = `{"title":"rich tag","references":[` + noteRef(noteA) + `,` + parentRef + `],` + richTagTail

// rawTagFor wraps content as a RawNote that holds a tag, fetched with fixed envelope timestamps.
func rawTagFor(content string) *RawNote {
	r := rawNoteFor(content)
	r.di.ContentType = common.SNItemTypeTag
	return r
}

// A tag's note references are the entries whose content_type is Note. Anything
// else in the list is not a note reference, and neither is an entry that is not
// an object. Both stay out of the answer. A repeat stays in it: the list is read
// as it is.
func TestNoteRefs(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		want    []string
		wantErr bool
	}{
		{"no references key", `{"title":"t"}`, nil, false},
		{"null", `{"references":null}`, nil, false},
		{"empty", `{"references":[]}`, nil, false},
		{"in order", `{"references":[` + noteRef(noteB) + `,` + noteRef(noteA) + `]}`, []string{noteB, noteA}, false},
		{"skips a parent tag reference", `{"references":[` + parentRef + `,` + noteRef(noteA) + `]}`, []string{noteA}, false},
		{"skips entries that are not objects", `{"references":[7,"x",null,[],` + noteRef(noteA) + `]}`, []string{noteA}, false},
		{"skips an entry with no uuid", `{"references":[{"content_type":"Note"},` + noteRef(noteA) + `]}`, []string{noteA}, false},
		{"skips an entry with a blank uuid", `{"references":[{"uuid":"","content_type":"Note"}]}`, nil, false},
		{"keeps a repeat", `{"references":[` + noteRef(noteA) + `,` + noteRef(noteA) + `]}`, []string{noteA, noteA}, false},
		{"references is an object", `{"references":{}}`, nil, true},
		{"references is a string", `{"references":"oops"}`, nil, true},
		{"content is not an object", `[]`, nil, true},
		{"content is truncated", `{"references":`, nil, true},
	} {
		got, err := rawTagFor(tc.content).NoteRefs()
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: err = %v, want error: %v", tc.name, err, tc.wantErr)
			continue
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: refs = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// applyRefs runs a mutation on the content and returns the result as top-level raw values.
func applyRefs(t *testing.T, content string, mutate func(map[string]json.RawMessage) error) (map[string]json.RawMessage, error) {
	t.Helper()
	m := objectOf(t, []byte(content))
	err := mutate(m)
	return m, err
}

// AddNoteRefs appends one reference per note. A note that the tag already holds is
// skipped, and so is a repeat inside the list. The new entry has no reference_type,
// as in the official apps. Every entry that was there keeps its exact bytes,
// including an entry that this code does not understand.
func TestAddNoteRefs(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		add     []string
		want    string // the bytes that the references key must hold after
	}{
		{"no references key", `{"title":"t"}`, []string{noteA}, `[` + noteRef(noteA) + `]`},
		{"null references", `{"references":null}`, []string{noteA}, `[` + noteRef(noteA) + `]`},
		{"empty references", `{"references":[]}`, []string{noteA}, `[` + noteRef(noteA) + `]`},
		{"appends in order, after the entries that are there",
			`{"references":[` + noteRef(noteA) + `]}`, []string{noteB, noteC},
			`[` + noteRef(noteA) + `,` + noteRef(noteB) + `,` + noteRef(noteC) + `]`},
		{"skips a note the tag already holds",
			`{"references":[` + noteRef(noteA) + `]}`, []string{noteA, noteB},
			`[` + noteRef(noteA) + `,` + noteRef(noteB) + `]`},
		{"skips a repeat inside the list", `{"references":[]}`, []string{noteB, noteB, noteB}, `[` + noteRef(noteB) + `]`},
		{"keeps an existing entry byte for byte",
			`{"references":[ {"uuid":"` + noteA + `", "content_type":"Note", "reference_type":"x", "n":1.50} ]}`, []string{noteB},
			`[{"uuid":"` + noteA + `", "content_type":"Note", "reference_type":"x", "n":1.50},` + noteRef(noteB) + `]`},
		{"keeps entries it does not understand",
			`{"references":[7,"x",null,` + parentRef + `]}`, []string{noteA},
			`[7,"x",null,` + parentRef + `,` + noteRef(noteA) + `]`},
		{"nothing to add leaves the list as it was",
			`{"references":[ ` + noteRef(noteA) + ` ]}`, []string{noteA}, `[ ` + noteRef(noteA) + ` ]`},
		{"no notes to add leaves the list as it was", `{"references":[ ]}`, nil, `[ ]`},
	} {
		m, err := applyRefs(t, tc.content, AddNoteRefs(tc.add))
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if got := show(m, "references"); got != tc.want {
			t.Errorf("%s:\n got: %s\nwant: %s", tc.name, got, tc.want)
		}
	}

	t.Run("touches no other key", func(t *testing.T) {
		before := objectOf(t, []byte(richTag))
		after, err := applyRefs(t, richTag, AddNoteRefs([]string{noteB}))
		if err != nil {
			t.Fatal(err)
		}
		changed, added, removed := diffKeys(before, after)
		requireKeys(t, "content", "changed", changed, []string{"references"})
		requireKeys(t, "content", "added", added, nil)
		requireKeys(t, "content", "removed", removed, nil)
	})

	t.Run("a uuid with JSON characters stays one string", func(t *testing.T) {
		const odd = `x","content_type":"Tag","y":"`
		m, err := applyRefs(t, `{"references":[]}`, AddNoteRefs([]string{odd}))
		if err != nil {
			t.Fatal(err)
		}
		var entries []struct {
			UUID        string `json:"uuid"`
			ContentType string `json:"content_type"`
		}
		if err := json.Unmarshal(m["references"], &entries); err != nil || len(entries) != 1 ||
			entries[0].UUID != odd || entries[0].ContentType != "Note" {
			t.Errorf("references = %s (err=%v), want one Note entry whose uuid is %q", m["references"], err, odd)
		}
	})

	t.Run("refuses what it can not change safely", func(t *testing.T) {
		for name, content := range map[string]string{
			"references is an object": `{"references":{}}`,
			"references is a string":  `{"references":"oops"}`,
			"references is a number":  `{"references":7}`,
		} {
			if _, err := applyRefs(t, content, AddNoteRefs([]string{noteA})); err == nil {
				t.Errorf("%s: no error", name)
			}
		}
		for _, bad := range []string{"", "  ", "\t"} {
			if _, err := applyRefs(t, `{"references":[]}`, AddNoteRefs([]string{noteA, bad})); err == nil {
				t.Errorf("a blank uuid %q was accepted", bad)
			}
		}
	})
}

// RemoveNoteRefs drops the note reference of each uuid, and every repeat of it.
// It drops no other entry, even when the caller names its uuid. A parent tag link
// is not a note. Every entry that stays keeps its exact bytes. A list with nothing
// to drop stays as it was.
func TestRemoveNoteRefs(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		drop    []string
		want    string // the bytes that the references key must hold after
	}{
		{"removes the entry", `{"references":[` + noteRef(noteA) + `,` + noteRef(noteB) + `]}`, []string{noteA}, `[` + noteRef(noteB) + `]`},
		{"removes every repeat", `{"references":[` + noteRef(noteA) + `,` + noteRef(noteB) + `,` + noteRef(noteA) + `]}`,
			[]string{noteA}, `[` + noteRef(noteB) + `]`},
		{"removes several", `{"references":[` + noteRef(noteA) + `,` + noteRef(noteB) + `,` + noteRef(noteC) + `]}`,
			[]string{noteA, noteC}, `[` + noteRef(noteB) + `]`},
		{"the last entry leaves an empty list", `{"references":[` + noteRef(noteA) + `]}`, []string{noteA}, `[]`},
		{"keeps what stays, byte for byte",
			`{"references":[ {"uuid":"` + noteA + `", "content_type":"Note"}, {"uuid":"` + noteB + `", "content_type":"Note", "n":1.50} ]}`,
			[]string{noteA}, `[{"uuid":"` + noteB + `", "content_type":"Note", "n":1.50}]`},
		{"never removes a reference that is not a note reference",
			`{"references":[` + parentRef + `,` + noteRef(noteA) + `]}`, []string{parentTag}, `[` + parentRef + `,` + noteRef(noteA) + `]`},
		{"keeps entries it does not understand",
			`{"references":[7,"x",null,` + noteRef(noteA) + `]}`, []string{noteA}, `[7,"x",null]`},
		{"nothing to remove leaves the list as it was",
			`{"references":[ ` + noteRef(noteA) + ` , ` + noteRef(noteB) + ` ]}`, []string{noteC},
			`[ ` + noteRef(noteA) + ` , ` + noteRef(noteB) + ` ]`},
		{"no notes to remove leaves the list as it was", `{"references":[ ]}`, nil, `[ ]`},
	} {
		m, err := applyRefs(t, tc.content, RemoveNoteRefs(tc.drop))
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if got := show(m, "references"); got != tc.want {
			t.Errorf("%s:\n got: %s\nwant: %s", tc.name, got, tc.want)
		}
	}

	t.Run("an absent or null list stays as it is", func(t *testing.T) {
		m, err := applyRefs(t, `{"title":"t"}`, RemoveNoteRefs([]string{noteA}))
		if err != nil {
			t.Fatal(err)
		}
		if got := show(m, "references"); got != "<missing>" {
			t.Errorf("an absent list became %s", got)
		}
		m, err = applyRefs(t, `{"references":null}`, RemoveNoteRefs([]string{noteA}))
		if err != nil {
			t.Fatal(err)
		}
		if got := show(m, "references"); got != "null" {
			t.Errorf("a null list became %s", got)
		}
	})

	t.Run("touches no other key", func(t *testing.T) {
		before := objectOf(t, []byte(richTag))
		after, err := applyRefs(t, richTag, RemoveNoteRefs([]string{noteA}))
		if err != nil {
			t.Fatal(err)
		}
		changed, added, removed := diffKeys(before, after)
		requireKeys(t, "content", "changed", changed, []string{"references"})
		requireKeys(t, "content", "added", added, nil)
		requireKeys(t, "content", "removed", removed, nil)
		if got := show(after, "references"); got != `[`+parentRef+`]` {
			t.Errorf("references = %s, want only the parent tag link", got)
		}
	})

	t.Run("refuses a list that is not an array", func(t *testing.T) {
		for _, content := range []string{`{"references":{}}`, `{"references":"oops"}`, `{"references":7}`} {
			if _, err := applyRefs(t, content, RemoveNoteRefs([]string{noteA})); err == nil {
				t.Errorf("%s: no error", content)
			}
		}
	})
}

// A tag runs through EncryptMutated like a note. The envelope keeps the Tag
// content type, and the mutation changes its own key and client_updated_at and
// nothing else. Every field that gosn-v2 does not model keeps its exact bytes.
func TestEncryptMutatedWorksOnATag(t *testing.T) {
	c, key := offlineClient()
	for name, mutate := range map[string]func(map[string]json.RawMessage) error{
		"rename": SetKey("title", "renamed"),
		"trash":  SetKey("trashed", true),
		"add":    AddNoteRefs([]string{noteB}),
		"remove": RemoveNoteRefs([]string{noteA}),
		"no-op":  func(map[string]json.RawMessage) error { return nil },
		"2 steps": func(m map[string]json.RawMessage) error {
			m["title"] = json.RawMessage(`"x"`)
			return AddNoteRefs([]string{noteC})(m)
		},
	} {
		r := rawTagFor(richTag)
		enc, err := c.EncryptMutated(r, mutate)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if enc.ContentType != common.SNItemTypeTag || enc.UUID != r.UUID || enc.ItemsKeyID != key.UUID || enc.Deleted {
			t.Errorf("%s: envelope type=%s uuid=%s items_key_id=%s deleted=%v", name, enc.ContentType, enc.UUID, enc.ItemsKeyID, enc.Deleted)
		}
		before, after := objectOf(t, []byte(richTag)), objectOf(t, []byte(openOffline(t, c, enc)))
		for _, k := range []string{"iconString", "expanded", "preferences", "future_tag_key"} {
			if string(before[k]) != string(after[k]) {
				t.Errorf("%s: top-level %q changed: %s -> %s", name, k, show(before, k), show(after, k))
			}
		}
		beforeApp, afterApp := objectOf(t, before["appData"]), objectOf(t, after["appData"])
		if string(beforeApp["dev.example.tagmeta"]) != string(afterApp["dev.example.tagmeta"]) {
			t.Errorf("%s: third-party appData changed: %s -> %s", name, show(beforeApp, "dev.example.tagmeta"), show(afterApp, "dev.example.tagmeta"))
		}
		changed, added, removed := diffKeys(objectOf(t, beforeApp["org.standardnotes.sn"]), objectOf(t, afterApp["org.standardnotes.sn"]))
		requireKeys(t, name+": appData[org.standardnotes.sn]", "changed", changed, []string{"client_updated_at"})
		requireKeys(t, name+": appData[org.standardnotes.sn]", "added", added, nil)
		requireKeys(t, name+": appData[org.standardnotes.sn]", "removed", removed, nil)
		_, _, removed = diffKeys(before, after)
		requireKeys(t, name+": content", "removed", removed, nil)
	}
}

// FetchRawTag says "not found" as an error, never as a nil tag: a write path that
// gets nil would panic. It refuses an item that is not a tag. A note's uuid given
// to a tag plan must not put a title or a reference into the note. FetchRawOne
// refuses the other way round: see TestFetchRawOneRejectsMissingAndNonNoteItems.
func TestFetchRawTagRejectsMissingAndNonTagItems(t *testing.T) {
	email, pw := testsupport.NewAccount(t)
	c := signInInternal(t, email, pw)
	noteID, err := c.SeedRawNote(t, richContent) // also makes the account's items key
	if err != nil {
		t.Fatalf("seed note: %v", err)
	}
	tagID, err := c.SeedRawTag(t, richTag)
	if err != nil {
		t.Fatalf("seed tag: %v", err)
	}

	// A tag comes back as the server holds it, byte for byte. The envelope is a Tag.
	r, err := c.FetchRawTag(tagID)
	if err != nil {
		t.Fatalf("FetchRawTag: %v", err)
	}
	if r.UUID != tagID || r.Content() != richTag {
		t.Errorf("premise broken: the tag did not round-trip\n got: %s\nwant: %s", r.Content(), richTag)
	}
	if enc := storedEncrypted(t, c, tagID); enc.ContentType != common.SNItemTypeTag || enc.Deleted {
		t.Errorf("stored tag: type=%s deleted=%v", enc.ContentType, enc.Deleted)
	}

	if r, err := c.FetchRawTag(items.GenUUID()); r != nil || !errors.Is(err, ErrTagNotFound) {
		t.Errorf("unknown uuid: tag=%v err=%v, want nil and ErrTagNotFound", r, err)
	}
	if errors.Is(ErrTagNotFound, ErrNoteNotFound) || errors.Is(ErrNoteNotFound, ErrTagNotFound) {
		t.Error("ErrTagNotFound and ErrNoteNotFound must be different errors")
	}
	if r, err := c.FetchRawTag(noteID); r != nil || err == nil || errors.Is(err, ErrTagNotFound) {
		t.Errorf("note uuid: tag=%v err=%v, want nil and a not-a-tag error", r, err)
	} else if !strings.Contains(err.Error(), "not a Tag") {
		t.Errorf("note uuid: err = %v, want it to say that the item is not a Tag", err)
	}
	// The note is as it was.
	if got := fetchRawContent(t, c, noteID); got != richContent {
		t.Errorf("FetchRawTag changed a note:\n%s", got)
	}
}

// Control for the tag plans. A tag that is written through the typed path loses the
// fields gosn-v2 does not model, as a note does. This is why the plans change a tag
// that exists through the raw path. It also shows that the preservation tests in
// the write engine can fail. If gosn-v2 ever keeps these fields, this test fails:
// check whether the surgical tag path is still needed.
func TestTypedTagWriteDropsUnmodeledFields(t *testing.T) {
	email, pw := testsupport.NewAccount(t)
	c := signInInternal(t, email, pw)
	id, err := c.SeedRawTag(t, richTag)
	if err != nil {
		t.Fatalf("seed tag: %v", err)
	}
	tv, err := c.FindTag("rich tag")
	if err != nil || tv == nil || tv.UUID != id {
		t.Fatalf("FindTag: tag=%v err=%v", tv, err)
	}
	c.SetTagRefs(tv, []string{noteB})
	if _, err := c.Push(c.RawTag(tv)); err != nil {
		t.Fatalf("typed push: %v", err)
	}

	r, err := c.FetchRawTag(id)
	if err != nil {
		t.Fatal(err)
	}
	after := objectOf(t, []byte(r.Content()))
	if _, ok := after["future_tag_key"]; ok {
		t.Error("control: the typed write kept the unknown top-level key")
	}
	if _, ok := objectOf(t, after["appData"])["dev.example.tagmeta"]; ok {
		t.Error("control: the typed write kept the third-party appData domain")
	}
}
