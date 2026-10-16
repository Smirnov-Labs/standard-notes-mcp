package snclient

import (
	"time"

	"github.com/jonhadfield/gosn-v2/items"
)

// RefCount is the number of references (tags/links) on the note.
func (nv *NoteView) RefCount() int { return len(nv.raw.Content.References()) }

// ApplyTextEdit changes the text of the note through gosn-v2's typed path. Then
// it pushes, and it checks by read-after-write that the text, the title and the
// number of references are right. It assumes nv was freshly fetched (its
// timestamp is current). The conflict-safe refresh discipline is the write
// engine's job, not this primitive's.
//
// THIS PATH IS LOSSY. The typed parse keeps the fields that gosn-v2 models, such
// as title, references and noteType. It drops every other field: starred,
// protected, archived, a third-party appData domain, and any key that it does not
// know (see TestTypedEditDropsUnmodeledFields). So the engine does not use it. The
// engine edits a note through EditNoteText's path: FetchRawOne, EncryptMutated,
// PushEncrypted. Tests use ApplyTextEdit as a stand-in for another writer.
func (c *Client) ApplyTextEdit(nv *NoteView, newText string) error {
	refsBefore := len(nv.raw.Content.References())
	title := nv.raw.Content.GetTitle()

	nv.raw.Content.SetText(newText)
	nv.raw.Content.SetUpdateTime(time.Now().UTC())
	if _, err := c.Push(items.Items{nv.raw}); err != nil {
		return err
	}

	after, err := c.FetchOne(nv.UUID)
	if err != nil {
		return err
	}
	if after == nil || after.Text != newText || after.Title != title ||
		len(after.raw.Content.References()) != refsBefore {
		return ErrVerifyFailed
	}
	nv.Text = newText
	return nil
}

// SetTrashed sets the reversible trashed flag INSIDE the note content (never
// the permanent envelope deleted flag) and bumps the client update time. It acts
// on the typed note, so a push of that note is lossy: see ApplyTextEdit. The
// engine trashes a note with PlanTrashNote, which does not use this function.
// Tests use it to stand in for an official app that restores a note.
func (c *Client) SetTrashed(nv *NoteView, v bool) error {
	nv.raw.Content.SetTrashed(v)
	nv.raw.Content.SetUpdateTime(time.Now().UTC())
	return nil
}

// Raw exposes the underlying typed item. A push of it is lossy: see
// ApplyTextEdit. The engine does not push a note this way.
func (c *Client) Raw(nv *NoteView) items.Items { return items.Items{nv.raw} }

// SeedNoteWithRef is a TEST-ONLY helper creating a note carrying one reference.
func (c *Client) SeedNoteWithRef(t interface{ Helper() }, title, text, refUUID string) (string, error) {
	t.Helper()
	refs := items.ItemReferences{{UUID: refUUID, ContentType: "Note", ReferenceType: "note-to-note"}}
	n, err := items.NewNote(title, text, refs)
	if err != nil {
		return "", err
	}
	n.Content.SetUpdateTime(time.Now().UTC())
	if _, err := c.Push(items.Items{&n}); err != nil {
		return "", err
	}
	return n.GetUUID(), nil
}
