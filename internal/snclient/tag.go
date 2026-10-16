package snclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jonhadfield/gosn-v2/common"
	"github.com/jonhadfield/gosn-v2/items"
)

// FindTag returns the tag with the given title, or nil if none exists.
func (c *Client) FindTag(title string) (*TagView, error) {
	_, tags, err := c.Fetch()
	if err != nil {
		return nil, err
	}
	for _, t := range tags {
		if t.Title == title {
			return t, nil
		}
	}
	return nil, nil
}

// NewTag mints a new (unsynced) tag item with the given title.
func (c *Client) NewTag(title string) (*TagView, error) {
	t, err := items.NewTag(title, nil)
	if err != nil {
		return nil, err
	}
	return &TagView{UUID: t.GetUUID(), Title: title, raw: &t}, nil
}

// SetTagRefs upserts note references onto the tag, so all N refs live on one tag
// item, and bumps the update time. It also refreshes the view's NoteUUIDs.
//
// gosn-v2's UpsertReferences skips a uuid the tag already holds. It does NOT
// collapse a repeat inside the new list: the server then stores the same ref
// twice. So SetTagRefs drops repeats from noteUUIDs first.
func (c *Client) SetTagRefs(tv *TagView, noteUUIDs []string) {
	var refs items.ItemReferences
	seen := make(map[string]bool, len(noteUUIDs))
	for _, id := range noteUUIDs {
		if seen[id] {
			continue
		}
		seen[id] = true
		// No ReferenceType: the official app keys tag→note membership on a
		// reference's content_type=="Note" alone, and its canonical tag→note
		// reference carries no reference_type. "TagToNote" is not a real enum
		// value; omitting it matches exactly what the official client writes
		// (verified against standardnotes/app, 2026-10-05). gosn-v2's field is
		// omitempty, so the zero value drops it from the wire JSON.
		refs = append(refs, items.ItemReference{
			UUID: id, ContentType: common.SNItemTypeNote,
		})
	}
	tv.raw.Content.UpsertReferences(refs)
	tv.raw.Content.SetUpdateTime(time.Now().UTC())
	tv.NoteUUIDs = tv.NoteUUIDs[:0]
	for _, r := range tv.raw.Content.GetNoteReferences() {
		tv.NoteUUIDs = append(tv.NoteUUIDs, r.UUID)
	}
}

// RawTag exposes the underlying tag item for the engine to push. A push of it is
// lossy for a tag that exists, as it is for a note. gosn-v2 rebuilds the tag from
// a fixed struct, and it drops every field that the struct lacks (see
// TestTypedTagWriteDropsUnmodeledFields). So the engine pushes a tag this way
// only when it creates the tag. It changes a tag that exists through FetchRawTag,
// EncryptMutated and PushEncrypted.
func (c *Client) RawTag(tv *TagView) items.Items { return items.Items{tv.raw} }

// The raw side of a tag's references. A tag holds one reference for each note on
// it. SetTagRefs changes them through the typed path, which is lossy for a tag
// that exists. The functions below work on the raw JSON. They change only the
// entries that they name. Every other entry keeps its exact bytes, whether or not
// they understand it. So does every other key of the tag.
//
// A note reference is an entry with a uuid and a content_type of Note. Any other
// entry is not one. A link from a child tag to its parent tag is an example: its
// content_type is Tag. A tag keeps such an entry when its notes change.

// refEntries splits the value of a references key into its entries, each as raw
// JSON. An absent key and a JSON null hold no entries. Any other value that is not
// an array is an error, so that data of an unknown shape is never overwritten.
func refEntries(raw json.RawMessage) ([]json.RawMessage, error) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("references is not a JSON array: %w", err)
	}
	return entries, nil
}

// noteRefUUID returns the uuid of an entry that is a note reference. It reports
// false for any other entry, including an entry that is not an object.
func noteRefUUID(entry json.RawMessage) (string, bool) {
	var ref struct {
		UUID        string `json:"uuid"`
		ContentType string `json:"content_type"`
	}
	if err := json.Unmarshal(entry, &ref); err != nil || ref.UUID == "" || ref.ContentType != common.SNItemTypeNote {
		return "", false
	}
	return ref.UUID, true
}

// joinEntries writes entries as one JSON array. It copies each entry as it is. It
// does not parse or re-encode one, so an entry keeps every byte. json.Marshal would
// compact an entry and write <, > and & as escapes.
func joinEntries(entries []json.RawMessage) json.RawMessage {
	var b bytes.Buffer
	b.WriteByte('[')
	for i, e := range entries {
		if i > 0 {
			b.WriteByte(',')
		}
		b.Write(e)
	}
	b.WriteByte(']')
	return b.Bytes()
}

// NoteRefs returns the uuid of each note reference in the raw content of the item,
// in the order of the list. A repeat comes back as often as the list holds it. It
// returns an error when the content is not a JSON object, or when its references
// value is not an array.
func (r *RawNote) NoteRefs() ([]string, error) {
	m, err := decodeObject([]byte(r.di.Content))
	if err != nil {
		return nil, fmt.Errorf("item %s: content is not a JSON object: %w", r.UUID, err)
	}
	entries, err := refEntries(m["references"])
	if err != nil {
		return nil, fmt.Errorf("item %s: %w", r.UUID, err)
	}
	var ids []string
	for _, e := range entries {
		if id, ok := noteRefUUID(e); ok {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// AddNoteRefs returns a mutation for EncryptMutated that adds a note reference for
// each uuid. It skips a note that the tag holds, and a repeat inside noteUUIDs. It
// writes the entry as the official apps do, with no reference_type: see
// SetTagRefs. It adds the entries after the ones that are there. When it adds
// nothing, it leaves the list as it was. A blank uuid is an error, so that the tag
// never gets a reference to nothing.
func AddNoteRefs(noteUUIDs []string) func(map[string]json.RawMessage) error {
	noteUUIDs = slices.Clone(noteUUIDs) // a later change to the caller's slice must not change this mutation
	return func(m map[string]json.RawMessage) error {
		entries, err := refEntries(m["references"])
		if err != nil {
			return err
		}
		have := make(map[string]bool, len(entries)+len(noteUUIDs))
		for _, e := range entries {
			if id, ok := noteRefUUID(e); ok {
				have[id] = true
			}
		}
		added := false
		for _, id := range noteUUIDs {
			if strings.TrimSpace(id) == "" {
				return errors.New("add note refs: a note uuid is blank")
			}
			if have[id] {
				continue
			}
			have[id] = true
			ref, err := jsonValue(struct {
				UUID        string `json:"uuid"`
				ContentType string `json:"content_type"`
			}{id, common.SNItemTypeNote})
			if err != nil {
				return err
			}
			entries = append(entries, ref)
			added = true
		}
		if added {
			m["references"] = joinEntries(entries)
		}
		return nil
	}
}

// RemoveNoteRefs returns a mutation for EncryptMutated that removes the note
// reference of each uuid, and every repeat of it. It removes an entry that is a
// note reference and no other, even when noteUUIDs names the uuid of the other. The
// entries that stay keep their exact bytes. When it removes nothing, it leaves the
// list as it was.
func RemoveNoteRefs(noteUUIDs []string) func(map[string]json.RawMessage) error {
	drop := make(map[string]bool, len(noteUUIDs))
	for _, id := range noteUUIDs {
		drop[id] = true
	}
	return func(m map[string]json.RawMessage) error {
		entries, err := refEntries(m["references"])
		if err != nil {
			return err
		}
		kept := make([]json.RawMessage, 0, len(entries))
		for _, e := range entries {
			if id, ok := noteRefUUID(e); ok && drop[id] {
				continue
			}
			kept = append(kept, e)
		}
		if len(kept) < len(entries) {
			m["references"] = joinEntries(kept)
		}
		return nil
	}
}
