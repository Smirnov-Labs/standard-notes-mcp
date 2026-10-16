package writeengine

// The tag plans: create, rename, trash, apply and detach.
//
// A change to a tag that exists goes through the surgical path in snclient, as a
// change to a note does. The path has four steps. Read the raw content of the tag.
// Change the keys that the plan names. Encrypt that exact JSON. Push it. The typed
// path (Push of an items.Tag) rebuilds the tag from a fixed struct. It drops every
// field that the struct lacks, such as a key that a later app version adds or a
// third-party appData domain. So no change to a tag that exists can use it. A new
// tag has nothing to keep, so a create uses the typed path (see createTag).
//
// "Delete a tag" is trash. The plan sets the trashed key inside the tag content,
// and another writer can set it back. No plan sets the permanent deleted flag on
// the item envelope. guard_test.go fails if any non-test source does.

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jonhadfield/gosn-v2/items"

	"github.com/smirnov-labs/standard-notes-mcp/internal/snclient"
)

// PlanTagCreate makes a tag with this title. It never makes a second tag with the
// same title. If a tag has the title, the change finds it and writes nothing. So a
// repeat of a create is safe. The new tag holds no notes.
//
// Plan rejects a blank title, and writes nothing.
//
// Both closures look the tag up by title, live.
//
//   - reconcile answers a retry. If a tag has the title, the change landed, so
//     Commit does not push.
//   - apply looks again right before it pushes. If a tag has the title now, there
//     is nothing to make. If none has, apply makes the tag with createTag.
//     createTag sets ch.TagUUID to the new tag, so the stray-item check does not
//     read that tag as a duplicate. Any other new note or tag does halt the engine.
func (e *Engine) PlanTagCreate(title string) (*Change, error) {
	if strings.TrimSpace(title) == "" {
		return nil, errors.New("tag title is empty")
	}
	nonce := uuid.NewString() // one intent per invocation (verified OpID is a permanent no-op)
	ch := &Change{
		OpID: "tag-create:" + title + ":" + nonce, Kind: "tag-create",
		After: map[string]any{"title": title},
	}
	ch.reconcile = func() (bool, error) { // retry: live tag-aware read, no write
		tv, err := e.cl.FindTag(title)
		return tv != nil, err
	}
	ch.apply = func() error {
		tv, err := e.cl.FindTag(title)
		if err != nil {
			return err
		}
		if tv != nil { // the tag exists: nothing to make
			ch.TagUUID = tv.UUID
			return nil
		}
		return e.createTag(ch, title, nil)
	}
	return ch, nil
}

// PlanTagRename sets the title of a tag. It changes the title key and
// client_updated_at, and no other part of the tag. See planTagChange.
//
// Plan rejects a blank title and a blank uuid, and writes nothing. It does not
// check that another tag has the title. A caller that wants one tag per title must
// check first.
func (e *Engine) PlanTagRename(tagUUID, newTitle string) (*Change, error) {
	if strings.TrimSpace(newTitle) == "" {
		return nil, errors.New("tag title is empty")
	}
	return e.planTagChange(tagUUID, "tag-rename", func(cur tagState) tagEdit {
		return tagEdit{
			mutate: snclient.SetKey("title", newTitle),
			done:   func(s tagState) bool { return s.Title == newTitle },
			before: map[string]any{"title": cur.Title}, after: map[string]any{"title": newTitle},
		}
	})
}

// PlanTagTrash moves a tag to the trash. It sets the reversible trashed flag,
// inside the tag content. The tag stays on the server with its title and its
// references, and another writer can set the flag back. It never sets the
// permanent deleted flag on the item envelope. guard_test.go fails if any non-test
// source does.
//
// It changes the trashed key and client_updated_at, and no other part of the tag.
// See planTagChange.
func (e *Engine) PlanTagTrash(tagUUID string) (*Change, error) {
	return e.planTagChange(tagUUID, "tag-trash", func(cur tagState) tagEdit {
		return tagEdit{
			mutate: snclient.SetKey("trashed", true),
			done:   func(s tagState) bool { return s.Trashed },
			before: map[string]any{"trashed": cur.Trashed}, after: map[string]any{"trashed": true},
		}
	})
}

// PlanTagDetach takes the tag off every note in noteUUIDs. It removes the note
// reference of each uuid from the tag, and no other entry of the list. A link to a
// parent tag stays, even when a caller names its uuid. The plan skips a note that
// the tag does not hold. It changes the references key and client_updated_at, and
// no other part of the tag. See planTagChange.
//
// Plan rejects an empty list and a blank uuid, and writes nothing. The Change keeps
// its own copy of the list.
func (e *Engine) PlanTagDetach(tagUUID string, noteUUIDs []string) (*Change, error) {
	if err := checkNoteUUIDs(noteUUIDs, "no notes to detach"); err != nil {
		return nil, err
	}
	noteUUIDs = slices.Clone(noteUUIDs)
	return e.planTagChange(tagUUID, "detach", func(tagState) tagEdit {
		return tagEdit{
			mutate: snclient.RemoveNoteRefs(noteUUIDs),
			done:   func(s tagState) bool { return !containsAny(s.Refs, noteUUIDs) },
			drops:  noteUUIDs,
			after:  map[string]any{"remove_note_uuids": slices.Clone(noteUUIDs)},
		}
	})
}

// PlanTagAddNotes adds a note reference for every note in noteUUIDs to the tag,
// found by its UUID, not its title. That is what a tag merge needs: when two tags
// share a title, PlanTagApply (which finds a tag by title) is ambiguous, but this
// adds to the exact tag. A note the tag already holds is not added again. A link to a
// parent tag and every other entry keep their bytes. It changes the references key
// and client_updated_at, and no other part of the tag. See planTagChange.
//
// Plan rejects an empty list and a blank uuid, and writes nothing. The Change keeps
// its own copy of the list.
func (e *Engine) PlanTagAddNotes(tagUUID string, noteUUIDs []string) (*Change, error) {
	if err := checkNoteUUIDs(noteUUIDs, "no notes to add"); err != nil {
		return nil, err
	}
	noteUUIDs = slices.Clone(noteUUIDs)
	return e.planTagChange(tagUUID, "tag-add", func(tagState) tagEdit {
		return tagEdit{
			mutate: snclient.AddNoteRefs(noteUUIDs),
			done:   func(s tagState) bool { return containsAll(s.Refs, noteUUIDs) },
			after:  map[string]any{"add_note_uuids": slices.Clone(noteUUIDs)},
		}
	})
}

// PlanTagApply puts the tag on every note in noteUUIDs, with one write to the one
// tag. The caller names the tag by its title. If no tag has the title, apply makes
// it, with all the references, through the typed path (see createTag). If a tag has
// it, apply goes through the surgical path, so it adds the references and changes
// no other part of the tag. A note that the tag holds is not added again. See
// planTagChange for the steps of a change to a tag that exists.
//
// reconcile uses a tag-aware lookup. Plan rejects a blank tag, an empty list, and a
// blank uuid, and writes nothing. It does not check that the notes exist, so the
// caller must pass uuids from a live read. The Change keeps its own copy of the
// list, because a retry replays the Change and a caller can reuse the slice it
// passed.
func (e *Engine) PlanTagApply(tag string, noteUUIDs []string) (*Change, error) {
	if strings.TrimSpace(tag) == "" {
		return nil, errors.New("tag title is empty")
	}
	if err := checkNoteUUIDs(noteUUIDs, "no notes to tag"); err != nil {
		return nil, err
	}
	noteUUIDs = slices.Clone(noteUUIDs)

	nonce := uuid.NewString() // one intent per invocation (verified OpID is a permanent no-op)
	ch := &Change{
		OpID: "tag:" + tag + ":" + nonce, Kind: "tag",
		After: map[string]any{"tag": tag, "add_note_uuids": slices.Clone(noteUUIDs)},
	}

	ch.reconcile = func() (bool, error) { // retry: live tag-aware read, no write
		tv, err := e.cl.FindTag(tag)
		if err != nil {
			return false, err
		}
		if tv == nil {
			return false, nil // tag absent: safe to push
		}
		return containsAll(tv.NoteUUIDs, noteUUIDs), nil // all refs present = landed
	}

	ch.apply = func() error {
		tv, err := e.cl.FindTag(tag) // fresh: names the tag whose timestamp the write must carry
		if err != nil {
			return err
		}
		if tv == nil {
			return e.createTag(ch, tag, noteUUIDs)
		}
		ch.TagUUID = tv.UUID
		return e.applyTagEdit(ch, tagEdit{
			mutate: snclient.AddNoteRefs(noteUUIDs),
			done:   func(s tagState) bool { return containsAll(s.Refs, noteUUIDs) },
		})
	}
	return ch, nil
}

// tagState is the part of the raw content of a tag that the tag plans read.
type tagState struct {
	Title   string
	Trashed bool
	Refs    []string // the uuid of each note reference
}

// readTagState reads the state of a tag from its raw content. It returns an error
// for a tag of an unknown shape, and the engine never changes such a tag. These
// are the shapes it refuses:
//   - content that is not a JSON object
//   - a title that is not a string
//   - a trashed value that is not a bool
//   - a references value that is not an array
func readTagState(r *snclient.RawNote) (tagState, error) {
	var c struct {
		Title   string `json:"title"`
		Trashed bool   `json:"trashed"`
	}
	if err := json.Unmarshal([]byte(r.Content()), &c); err != nil {
		return tagState{}, fmt.Errorf("tag %s: read content: %w", r.UUID, err)
	}
	refs, err := r.NoteRefs()
	if err != nil {
		return tagState{}, err
	}
	return tagState{Title: c.Title, Trashed: c.Trashed, Refs: refs}, nil
}

// tagEdit is one change to the raw content of a tag that exists.
type tagEdit struct {
	// mutate is the change. It is a mutation for EncryptMutated, so it sets its own
	// keys, and client_updated_at is set for it.
	mutate func(map[string]json.RawMessage) error

	// done reports whether a tag already holds the end state that the change makes.
	// reconcile uses it to decide a retry. applyTagEdit uses it to skip the write
	// when there is nothing to write, and to check that the write landed.
	done func(tagState) bool

	// drops lists the note references that the change removes on purpose. After the
	// write, every other reference that the tag held must still be there.
	drops []string

	// before and after describe the change for a preview. They are optional.
	before, after map[string]any
}

// planTagChange builds the Change for an edit of one tag that exists. build gets
// the tag as it is now, and returns the edit.
//
// Plan reads the tag and writes nothing. It refuses a blank uuid, and a uuid that
// is missing, deleted, or not a tag. It hands back no Change then. A note's uuid is
// not a tag: a tag plan must never write a title or a reference into a note.
//
// Each call is one intent, so each call puts a fresh nonce in the OpID. A verified
// OpID is a no-op for good. Without the nonce, a second change to a tag after
// someone undid the first returns nil and does nothing. Every step reports
// success, but the tag is not changed.
//
// Both closures read the tag live.
//
//   - reconcile answers a retry. If the tag already holds the end state, the change
//     landed, so Commit does not push. If it does not, Commit pushes. If the tag is
//     gone, reconcile returns the error and Commit does not push.
//   - apply reads the tag again right before the push. See applyTagEdit.
func (e *Engine) planTagChange(tagUUID, kind string, build func(cur tagState) tagEdit) (*Change, error) {
	if strings.TrimSpace(tagUUID) == "" {
		return nil, errors.New("tag uuid is empty")
	}
	r, err := e.cl.FetchRawTag(tagUUID)
	if err != nil {
		return nil, err
	}
	cur, err := readTagState(r)
	if err != nil {
		return nil, err
	}
	ed := build(cur)
	nonce := uuid.NewString() // one intent per invocation, so a repeat after an undo is not a no-op
	ch := &Change{
		OpID: kind + ":" + tagUUID + ":" + nonce, Kind: kind, TagUUID: tagUUID,
		Before: ed.before, After: ed.after,
	}
	ch.reconcile = func() (bool, error) { // retry: live read, no write
		r, err := e.cl.FetchRawTag(tagUUID)
		if err != nil {
			return false, err
		}
		live, err := readTagState(r)
		if err != nil {
			return false, err
		}
		return ed.done(live), nil // true = already holds (landed); false = safe to push
	}
	ch.apply = func() error { return e.applyTagEdit(ch, ed) }
	return ch, nil
}

// applyTagEdit changes the tag ch.TagUUID through the surgical path, then reads the
// tag back and checks the result.
//
//  1. Read the tag fresh, right before the push, so that the push carries the
//     server's current timestamp. A stale timestamp is a sync_conflict, and gosn-v2
//     answers it by minting a copy. The change lands on top of any save that
//     another writer made since the plan, and keeps that save.
//  2. If the tag already holds the end state, write nothing. The write changes
//     only client_updated_at.
//  3. Change the raw content, encrypt it, and push it with pushRawAndVerify. That
//     checks the engine's stray-item halt and that the server saved the item.
//  4. Read the tag back. pushRawAndVerify can check a note only, so a tag change
//     checks itself. The tag must hold the end state, and it must still hold every
//     note reference that the edit did not mean to remove. That second check
//     finds a write that lost a reference.
func (e *Engine) applyTagEdit(ch *Change, ed tagEdit) error {
	r, err := e.cl.FetchRawTag(ch.TagUUID)
	if err != nil {
		return err
	}
	was, err := readTagState(r)
	if err != nil {
		return err
	}
	if ed.done(was) {
		return nil
	}
	enc, err := e.cl.EncryptMutated(r, ed.mutate)
	if err != nil {
		return err
	}
	if err := e.pushRawAndVerify(ch, items.EncryptedItems{enc}, noNoteToCheck); err != nil {
		return err
	}
	back, err := e.cl.FetchRawTag(ch.TagUUID)
	if err != nil {
		return fmt.Errorf("%w: read the tag back: %w", ErrVerifyFailed, err)
	}
	now, err := readTagState(back)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrVerifyFailed, err)
	}
	if !ed.done(now) || !containsAll(now.Refs, minus(was.Refs, ed.drops)) {
		return ErrVerifyFailed
	}
	return nil
}

// createTag makes a new tag with this title and these note references, and checks
// that it landed. It goes through the typed path: a new tag has nothing to keep.
//
// It sets ch.TagUUID to the new tag before the push. The stray-item check in
// pushAndVerify counts a new note or tag that is not ch.NoteUUID or ch.TagUUID as
// a duplicate, and halts the engine. Without this line, the tag that the change
// makes halts the engine. With it, that one tag passes, and a second new tag, such
// as a conflict copy, still halts the engine.
//
// To prove the landing it reads the tag back raw, by uuid. The tag must have the
// title and every reference.
func (e *Engine) createTag(ch *Change, title string, noteUUIDs []string) error {
	tv, err := e.cl.NewTag(title)
	if err != nil {
		return err
	}
	ch.TagUUID = tv.UUID
	if len(noteUUIDs) > 0 {
		e.cl.SetTagRefs(tv, noteUUIDs)
	}
	if err := e.pushAndVerify(ch, e.cl.RawTag(tv), noNoteToCheck); err != nil {
		return err
	}
	back, err := e.cl.FetchRawTag(tv.UUID)
	if err != nil {
		return fmt.Errorf("%w: read the new tag back: %w", ErrVerifyFailed, err)
	}
	now, err := readTagState(back)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrVerifyFailed, err)
	}
	if now.Title != title || !containsAll(now.Refs, noteUUIDs) {
		return ErrVerifyFailed
	}
	return nil
}

// noNoteToCheck is the ok hook for a tag change. pushAndVerify and pushRawAndVerify
// hand the hook the note of the change, and a tag change has none. Each tag change
// reads the tag back and checks it itself.
func noNoteToCheck(*snclient.NoteView) bool { return true }

// checkNoteUUIDs rejects an empty list, with the message noNotes, and a blank uuid.
func checkNoteUUIDs(noteUUIDs []string, noNotes string) error {
	if len(noteUUIDs) == 0 {
		return errors.New(noNotes)
	}
	for _, id := range noteUUIDs {
		if strings.TrimSpace(id) == "" {
			return errors.New("note uuid is empty")
		}
	}
	return nil
}

func containsAll(have, want []string) bool {
	set := make(map[string]bool, len(have))
	for _, h := range have {
		set[h] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}

// containsAny reports whether have holds at least one element of want.
func containsAny(have, want []string) bool {
	set := make(map[string]bool, len(have))
	for _, h := range have {
		set[h] = true
	}
	for _, w := range want {
		if set[w] {
			return true
		}
	}
	return false
}

// minus returns the elements of have that are not in drop.
func minus(have, drop []string) []string {
	if len(drop) == 0 {
		return have
	}
	gone := make(map[string]bool, len(drop))
	for _, d := range drop {
		gone[d] = true
	}
	var out []string
	for _, h := range have {
		if !gone[h] {
			out = append(out, h)
		}
	}
	return out
}
