package mcptools

// The write tools. Each one changes Standard Notes through the write engine
// (internal/writeengine). The engine is conflict-safe, writes a ledger, stops at a
// cap, and can be killed. Every change to a note or a tag that exists goes through
// its surgical path, which keeps each field the change does not set. This file calls
// the engine's Plan methods and Commit and nothing else that writes: the typed
// helpers in snclient (ApplyTextEdit, SetTrashed, Raw and the like) lose fields, and
// a test fails if this file names one.
//
// The rule of read.go holds here too: a sensitive note's title, body and snippet
// never appear in a result. A preview is a result, so it follows the rule.
//
//   - A note that a tool changes goes through gateNote, as in read.go. The result
//     shows the note as a GetResult: the whole note when the gate cleared it, and a
//     stub when not. The stub has no room for content.
//   - A result never copies Change.Before or Change.After. For an edit, Before holds
//     the whole old text, gated or not. The values in a result come from the
//     caller's own arguments, or from a note that the gate cleared.
//   - A merge refuses a sensitive source. The caller must not assemble text that it
//     is not allowed to see, and a merge copies each source into a new note.
//   - An edit and a rename refuse a sensitive note. Each sets content, the text or
//     the title, for a note that the caller cannot see. The user would approve the
//     change without seeing the old text, and the overwrite is final. The refusal
//     comes before the tool plans or writes anything, in a dry run and in a write.
//   - A trash and an untrash set no content and can be undone, so they stay allowed
//     on a sensitive note. Their result shows the stub.
//   - Errors carry fixed text. gosn-v2 builds some errors from decrypted item
//     content, so no message holds an upstream error. See WriteError.
//   - Nothing here logs.
//
// A tag has no body, and a tag title is the user's own text, so a tag result shows
// it. A tag result shows no note title.

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/smirnov-labs/standard-notes-mcp/internal/gate"
	"github.com/smirnov-labs/standard-notes-mcp/internal/snclient"
	"github.com/smirnov-labs/standard-notes-mcp/internal/writeengine"
)

// NoteWriteResult is the result of note_edit, note_rename, note_trash and
// note_untrash.
type NoteWriteResult struct {
	// DryRun is true when nothing was written. The result then says what WOULD change.
	DryRun bool
	// Action is the tool: note_edit, note_rename, note_trash or note_untrash.
	Action string
	// Before is the note as notes_get shows it, from before the change. It is a stub
	// when the gate flags the note, so a trash or an untrash of a sensitive note never
	// shows the note's title or text, in a preview or after the write. An edit and a
	// rename refuse a sensitive note and return no result.
	Before GetResult
	// NewTitle and NewText are the values that the change sets. They are the caller's
	// own arguments, so the result may echo them. A rename sets NewTitle and an edit
	// sets NewText. A trash or an untrash sets neither.
	NewTitle *string `json:",omitempty"`
	NewText  *string `json:",omitempty"`
	// OpID names the change in the ledger. It is set only when the change was written.
	OpID string `json:",omitempty"`
}

// TagRef names a tag.
type TagRef struct {
	// UUID is empty when a dry run would make the tag, because it has no uuid yet.
	UUID  string `json:",omitempty"`
	Title string
}

// TagWriteResult is the result of tag_apply, tag_detach, tag_create, tag_rename and
// tag_trash. A count that is 0 is left out.
type TagWriteResult struct {
	// DryRun is true when nothing was written. The result then says what WOULD change.
	DryRun bool
	// Action is the tool: tag_apply, tag_detach, tag_create, tag_rename or tag_trash.
	Action string
	// Tag is the tag that the change acts on, as it is before the change.
	Tag TagRef
	// NewTitle is the title that a rename gives the tag.
	NewTitle *string `json:",omitempty"`
	// Created is true when the change makes the tag, and not when the tag exists.
	Created bool `json:",omitempty"`
	// NotesChanged is how many notes gain the tag (apply) or lose it (detach).
	NotesChanged int `json:",omitempty"`
	// NotesSkipped is how many of the notes that the caller named the change leaves
	// alone: they already hold the tag (apply), or they do not hold it (detach).
	NotesSkipped int `json:",omitempty"`
	// OpID names the change in the ledger. It is set only when the change was written.
	OpID string `json:",omitempty"`
	// Notice is a fact the caller must know about the change.
	Notice string `json:",omitempty"`
}

// TagMergeResult is the result of tag_merge.
type TagMergeResult struct {
	// DryRun is true when nothing was written. The result then says what WOULD change.
	DryRun bool
	// Action is the tool: tag_merge.
	Action string
	// Keeper is the tag that survives and gains the sources' notes.
	Keeper TagRef
	// Sources are the tags merged into the keeper and then moved to the trash.
	Sources []TagRef
	// NotesAdded is how many notes the keeper gains: the union of the sources' notes
	// that it did not already hold.
	NotesAdded int `json:",omitempty"`
	// OpIDs name the writes in the ledger: the add to the keeper, then each trash. They
	// are set only for a write.
	OpIDs []string `json:",omitempty"`
	// Notice is a fact the caller must know about the merge.
	Notice string `json:",omitempty"`
}

// MergeSource is one source note of a merge. The gate cleared every source, so its
// title shows.
type MergeSource struct {
	UUID, Title string
	// Trashed is true when the source is in the trash after the merge. A dry run says
	// what will be true.
	Trashed bool
}

// MergeResult is the result of note_merge.
type MergeResult struct {
	// DryRun is true when nothing was written. The result then says what WOULD change.
	DryRun bool
	// Title is the title of the merged note.
	Title string
	// NoteUUID is the uuid of the merged note. A dry run makes no note, so it has none.
	NoteUUID string `json:",omitempty"`
	// Sources are the notes that the merge reads, in the order of the call.
	Sources []MergeSource
	// Bytes is the size of the text of the merged note.
	Bytes int
	// OpID names the change that makes the merged note in the ledger. It is set only
	// when the merge was written.
	OpID string `json:",omitempty"`
	// Notice is a fact the caller must know about the merge.
	Notice string `json:",omitempty"`
}

// Errors with fixed text. None of them echoes its input. A caller may test for them
// with errors.Is.
var (
	ErrEmptyUUID      = errors.New("uuid is empty")
	ErrEmptyTitle     = errors.New("title is empty")
	ErrEmptyText      = errors.New("new text is empty; to remove a note, move it to the trash with note_trash")
	ErrNoNotes        = errors.New("no notes given")
	ErrMergeNeedsTwo  = errors.New("a merge needs at least two different notes")
	ErrSensitiveMerge = errors.New("cannot merge a sensitive note; it is walled off")
	ErrSensitiveEdit  = errors.New("cannot edit a sensitive note; it is walled off from the assistant")
	ErrTagNotFound    = errors.New("tag not found")
	ErrTagTitleTaken  = errors.New("another tag already has that title")
	ErrTagAmbiguous   = errors.New("more than one tag has that title; give them different titles first")
	// ErrTagMergeNeedsSource means a tag merge named no source tag other than the keeper.
	ErrTagMergeNeedsSource = errors.New("a tag merge needs a keeper and at least one other source tag")

	errNotGuarded = errors.New("the write engine does not use the guarded session")
)

// The text of a WriteError that has no better one.
const (
	msgRead  = "could not read notes from Standard Notes; nothing was written"
	msgWrite = "could not finish the write to Standard Notes; read the item again to see whether it changed"
)

// WriteError is the error a write tool returns when Standard Notes cannot be read or
// written. Its text is fixed and holds nothing from the cause: gosn-v2 builds some
// errors from decrypted item content ("unhandled type2 '%s' %s" in items/items.go),
// and the MCP SDK sends a handler's error text to the orchestrator. The cause stays
// reachable with errors.Unwrap, and so with errors.Is, for the server's own use.
// Never send the cause, or its text, to the orchestrator.
type WriteError struct {
	msg   string
	cause error
}

func (e *WriteError) Error() string { return e.msg }

func (e *WriteError) Unwrap() error { return e.cause }

// readFailure is the error for a failure before the change was committed, so nothing
// was written. It keeps the two kinds of "not found" that the caller can act on, and
// it says what a coverage failure of a merge means.
func readFailure(err error) error {
	switch {
	case errors.Is(err, snclient.ErrNoteNotFound):
		return ErrNotFound
	case errors.Is(err, snclient.ErrTagNotFound):
		return ErrTagNotFound
	case errors.Is(err, writeengine.ErrCoverage):
		return &WriteError{msg: "a source note changed while the merge was planned, so nothing was written; run the merge again", cause: err}
	}
	return &WriteError{msg: msgRead, cause: err}
}

// commitFailure is the error for a failure of Commit. It says what the caller can
// rely on: for a cap, a kill and a missing item, nothing was written. For the rest
// the write may have reached the server, so the text says to read the item again.
func commitFailure(err error) error {
	switch {
	case errors.Is(err, writeengine.ErrCapReached):
		return &WriteError{msg: "the write cap for this run is reached, so this change was not written; the user can raise SN_MAX_WRITES and restart the server", cause: err}
	case errors.Is(err, writeengine.ErrKilled):
		return &WriteError{msg: "the write engine is stopped, so this change was not written", cause: err}
	case errors.Is(err, writeengine.ErrDuplicated):
		return &WriteError{msg: "the write engine halted because an item appeared that this change did not make; check Standard Notes for a conflict copy, and restart the server to write again", cause: err}
	case errors.Is(err, writeengine.ErrVerifyFailed), errors.Is(err, snclient.ErrVerifyFailed), errors.Is(err, snclient.ErrPushNotSaved):
		return &WriteError{msg: "the write could not be verified; read the item again to see whether it changed", cause: err}
	case errors.Is(err, snclient.ErrNoteNotFound):
		return ErrNotFound
	case errors.Is(err, snclient.ErrTagNotFound):
		return ErrTagNotFound
	}
	return &WriteError{msg: msgWrite, cause: err}
}

// safeErrors are the errors whose text this file wrote.
var safeErrors = []error{
	ErrNotFound, ErrEmptyUUID, ErrEmptyTitle, ErrEmptyText, ErrNoNotes, ErrMergeNeedsTwo,
	ErrSensitiveMerge, ErrSensitiveEdit, ErrTagNotFound, ErrTagTitleTaken, ErrTagAmbiguous, ErrTagMergeNeedsSource, errNotGuarded,
}

// safeError returns err when its text is one that this file wrote, and a WriteError
// with fixed text for any other error. It is the last check before an error leaves
// a tool. A failure path that forgot to wrap an upstream error would otherwise send
// that error's text, which may hold note content, to the orchestrator.
func safeError(err error) error {
	if err == nil {
		return nil
	}
	var we *WriteError
	if errors.As(err, &we) {
		return err
	}
	for _, ok := range safeErrors {
		if errors.Is(err, ok) {
			return err
		}
	}
	return &WriteError{msg: msgWrite, cause: err}
}

// Writer is the set of gated write tools. It holds no state that changes, so it is
// safe for concurrent use. The guard serializes session access, the engine
// serializes commits, and the gate is safe for concurrent use when its prober is.
//
// Every engine call runs inside one Guard.Do, and the change is built and committed
// inside that one call. Do is not reentrant, so no code here calls it from inside
// it. The engine wraps the same Client as the guard. The engine reads the session
// itself, and only the guard's lock keeps those reads apart from a read tool's.
type Writer struct {
	g   *snclient.Guard
	eng *writeengine.Engine
	gt  *gate.Gate
}

// NewWriter returns the write tools. eng must wrap the Client that g guards. A nil
// guard, engine or gate is a wiring bug, and NewWriter panics on it: the tools must
// never run ungated or unguarded.
func NewWriter(g *snclient.Guard, eng *writeengine.Engine, gt *gate.Gate) *Writer {
	if g == nil || eng == nil || gt == nil {
		panic("mcptools: NewWriter needs a guard, an engine and a gate; the write tools must not run ungated or unguarded")
	}
	return &Writer{g: g, eng: eng, gt: gt}
}

// gated asks the gate about n, as the read tools do. See gateNote.
func (w *Writer) gated(n *snclient.NoteView) gatedNote { return gateNote(w.gt, n) }

// do runs fn under the guard. It refuses to run unless the engine wraps the client
// that the guard guards: with another client, the lock would protect nothing. Every
// error that leaves do has a text that this file wrote: see safeError.
func (w *Writer) do(fn func(c *snclient.Client) error) error {
	ran := false
	err := w.g.Do(func(c *snclient.Client) error {
		ran = true
		if w.eng.Client() != c {
			return errNotGuarded
		}
		return fn(c)
	})
	switch {
	case err == nil:
		return nil
	case !ran: // the guard could not freshen the session, so fn did not run
		return readFailure(err)
	}
	return safeError(err)
}

// gatedOne reads the note with this uuid live, and puts it through the gate. This is
// the only way the note tools reach a note's current content.
func (w *Writer) gatedOne(c *snclient.Client, id string) (gatedNote, error) {
	n, err := c.FetchOne(id)
	if err != nil {
		return gatedNote{}, readFailure(err)
	}
	if n == nil {
		return gatedNote{}, ErrNotFound
	}
	return w.gated(n), nil
}

// apply builds a change with plan and, unless dryRun is set, commits it. It is the
// only code in this file that calls Commit, so a dry run cannot write: a test pins
// that there is one call, and that it is here. It returns the change when it wrote
// it, and nil for a dry run. Every error it returns has fixed text.
func (w *Writer) apply(dryRun bool, plan func() (*writeengine.Change, error)) (*writeengine.Change, error) {
	ch, err := plan()
	if err != nil {
		return nil, readFailure(err)
	}
	if dryRun {
		return nil, nil
	}
	if err := w.eng.Commit(ch); err != nil {
		return nil, commitFailure(err)
	}
	return ch, nil
}

// NoteEdit replaces the text of a note. The change sets the text and
// client_updated_at, and no other part of the note.
//
// It refuses a sensitive note with ErrSensitiveEdit, in a dry run and in a write. The
// refusal comes before the tool plans or commits anything, and its text holds no
// content. A note that the gate cannot check, such as any note while jev is down,
// counts as sensitive.
//
// A concurrent edit of the text between a dry run and the commit is last-writer-wins:
// the commit sets the text whatever the note holds then. Comparing the version of the
// note at commit time is a hardening for a real vault. It is not built here.
func (w *Writer) NoteEdit(uuid, newText string, dryRun bool) (NoteWriteResult, error) {
	id := strings.TrimSpace(uuid)
	if id == "" {
		return NoteWriteResult{}, ErrEmptyUUID
	}
	if strings.TrimSpace(newText) == "" {
		return NoteWriteResult{}, ErrEmptyText
	}
	return w.noteChange("note_edit", id, dryRun, true,
		func() (*writeengine.Change, error) { return w.eng.PlanEditNote(id, newText) },
		func(r *NoteWriteResult) { r.NewText = &newText })
}

// NoteRename sets the title of a note. The change sets the title and
// client_updated_at, and no other part of the note. The title loses its outer
// whitespace.
//
// It refuses a sensitive note with ErrSensitiveEdit, as NoteEdit does. A rename is an
// edit of the title.
//
// A concurrent edit of the title between a dry run and the commit is last-writer-wins,
// as for NoteEdit.
func (w *Writer) NoteRename(uuid, newTitle string, dryRun bool) (NoteWriteResult, error) {
	id := strings.TrimSpace(uuid)
	if id == "" {
		return NoteWriteResult{}, ErrEmptyUUID
	}
	title := strings.TrimSpace(newTitle)
	if title == "" {
		return NoteWriteResult{}, ErrEmptyTitle
	}
	return w.noteChange("note_rename", id, dryRun, true,
		func() (*writeengine.Change, error) { return w.eng.PlanRenameNote(id, title) },
		func(r *NoteWriteResult) { r.NewTitle = &title })
}

// NoteTrash moves a note to the trash. It sets the reversible trashed flag inside the
// note. The note stays on the server with every field, and NoteUntrash undoes the
// change. It never sets the permanent deleted flag on the item envelope. It sets no
// content, so it is allowed on a sensitive note, and then the result shows the stub.
func (w *Writer) NoteTrash(uuid string, dryRun bool) (NoteWriteResult, error) {
	id := strings.TrimSpace(uuid)
	if id == "" {
		return NoteWriteResult{}, ErrEmptyUUID
	}
	return w.noteChange("note_trash", id, dryRun, false,
		func() (*writeengine.Change, error) { return w.eng.PlanTrashNote(id) },
		func(*NoteWriteResult) {})
}

// NoteUntrash takes a note out of the trash. It is the opposite of NoteTrash, and it
// is allowed on a sensitive note for the same reason.
func (w *Writer) NoteUntrash(uuid string, dryRun bool) (NoteWriteResult, error) {
	id := strings.TrimSpace(uuid)
	if id == "" {
		return NoteWriteResult{}, ErrEmptyUUID
	}
	return w.noteChange("note_untrash", id, dryRun, false,
		func() (*writeengine.Change, error) { return w.eng.PlanUntrashNote(id) },
		func(*NoteWriteResult) {})
}

// noteChange is the flow of every change to one note that exists. It reads the note
// and puts it through the gate, plans the change, commits it unless dryRun is set,
// and returns the result. A dry run never reaches Commit. sets copies the values the
// change sets into the result, and those values come from the caller's arguments.
//
// authors is true for a change that sets the text or the title of the note. Such a
// change makes the caller author content for a note, so noteChange refuses a
// sensitive note with ErrSensitiveEdit. The refusal comes right after the gate read
// and before apply, which is the only way to a plan or a commit. So a refused call
// plans nothing and writes nothing, in a dry run and in a write. A change that sets
// no content (trash, untrash) is not refused.
//
// The result holds Before as a GetResult, so a sensitive note shows as a stub in the
// preview and in the result of the write alike. It never holds Change.Before.
func (w *Writer) noteChange(action, id string, dryRun, authors bool, plan func() (*writeengine.Change, error), sets func(*NoteWriteResult)) (NoteWriteResult, error) {
	res := NoteWriteResult{DryRun: dryRun, Action: action}
	err := w.do(func(c *snclient.Client) error {
		g, err := w.gatedOne(c, id)
		if err != nil {
			return err
		}
		if authors && g.note == nil {
			return ErrSensitiveEdit
		}
		res.Before = g.detail()
		sets(&res)
		ch, err := w.apply(dryRun, plan)
		if err != nil {
			return err
		}
		if ch != nil {
			res.OpID = ch.OpID
		}
		return nil
	})
	if err != nil {
		return NoteWriteResult{}, err
	}
	return res, nil
}

// mergeSeparator goes between two sources in the text of a merged note.
const mergeSeparator = "\n\n---\n\n"

// mergeBody builds the text of a merged note. Each source is its title on one line
// and then its text, and mergeSeparator sits between two sources. Code builds it,
// and never a model: PlanMerge checks that each source is in the body byte for byte,
// and a retyped source fails on a CRLF, a trailing space or a Unicode form. The text
// of a source is copied as it is. Call it only for sources that the gate cleared.
func mergeBody(srcs []*snclient.NoteView) string {
	var b strings.Builder
	for i, s := range srcs {
		if i > 0 {
			b.WriteString(mergeSeparator)
		}
		if strings.TrimSpace(s.Title) == "" {
			b.WriteString("(untitled)")
		} else {
			b.WriteString(s.Title)
		}
		b.WriteString("\n\n")
		b.WriteString(s.Text)
	}
	return b.String()
}

// NoteMerge makes one new note that holds the text of two or more notes, then moves
// the sources to the trash. Nothing is deleted: the merge is additive, and each source
// keeps every field in the trash.
//
// It refuses when any source is sensitive. The orchestrator is not allowed to see
// that text, so it cannot assemble it, and a merge would copy the text into a new
// note. The merged text is built in code, from the sources as the server holds them:
// see mergeBody. The merged note has a new uuid. A dry run reads the sources and
// plans the change, and writes nothing.
//
// The merge takes several steps, and each step is one Change in one Guard.Do. The
// first makes the merged note. Then each source is read again, and moved to the trash
// only if the merged text still holds its text. A source that someone edited since
// the read stays out of the trash, so that its new text is not hidden in a note that
// the merge never copied. Splitting the work keeps each Do short. The guard freshens
// the session token only when a Do starts, and a Do that runs past the token's
// expiry kills the process (gosn-v2 calls os.Exit on an expired token). It also keeps
// a long merge from holding the session lock the whole time.
//
// If a step fails after the merged note exists, the error says which note exists and
// which sources are still out of the trash. The merged note is not rolled back: it
// is a note, and nothing is lost.
func (w *Writer) NoteMerge(sourceUUIDs []string, newTitle string, dryRun bool) (MergeResult, error) {
	ids, err := cleanUUIDs(sourceUUIDs)
	if err != nil {
		return MergeResult{}, err
	}
	if len(ids) < 2 {
		return MergeResult{}, ErrMergeNeedsTwo
	}
	title := strings.TrimSpace(newTitle)
	if title == "" {
		return MergeResult{}, ErrEmptyTitle
	}

	res := MergeResult{DryRun: dryRun, Title: title}
	var body string
	err = w.do(func(c *snclient.Client) error {
		notes, _, err := c.Fetch()
		if err != nil {
			return readFailure(err)
		}
		byID := make(map[string]*snclient.NoteView, len(notes))
		for _, n := range notes {
			if n != nil {
				byID[n.UUID] = n
			}
		}
		// Every source goes through the gate before any of its text is copied. A
		// sensitive source ends the merge here, so nothing is built, planned or written.
		srcs := make([]*snclient.NoteView, 0, len(ids))
		for i, id := range ids {
			n := byID[id]
			if n == nil {
				return fmt.Errorf("%w (source %d)", ErrNotFound, i+1)
			}
			g := w.gated(n)
			if g.note == nil {
				return ErrSensitiveMerge
			}
			srcs = append(srcs, g.note)
			res.Sources = append(res.Sources, MergeSource{UUID: g.note.UUID, Title: g.note.Title, Trashed: true})
		}
		body = mergeBody(srcs)
		res.Bytes = len(body)

		create, err := w.apply(dryRun, func() (*writeengine.Change, error) { return w.eng.PlanMerge(ids, title, body) })
		if err != nil {
			return err
		}
		if create != nil {
			res.NoteUUID, res.OpID = create.NoteUUID, create.OpID
		}
		return nil
	})
	if err != nil {
		return MergeResult{}, err
	}
	if dryRun {
		return res, nil
	}

	kept := 0
	for i := range res.Sources {
		trashed, err := w.trashMergeSource(res.Sources[i].UUID, body)
		if err != nil {
			return MergeResult{}, partialMerge(res.NoteUUID, res.Sources, i, err)
		}
		res.Sources[i].Trashed = trashed
		if !trashed {
			kept++
		}
	}
	if kept > 0 {
		res.Notice = fmt.Sprintf("%d source(s) changed while the merge ran. The merged note does not hold their new text, so they are not in the trash.", kept)
	}
	return res, nil
}

// trashMergeSource moves one source to the trash, after it checks that the merged
// text still holds the source's text. It reports whether the source is in the trash.
// It reads the text only to compare it: nothing of it leaves.
func (w *Writer) trashMergeSource(id, body string) (trashed bool, err error) {
	err = w.do(func(c *snclient.Client) error {
		live, err := c.FetchOne(id)
		if err != nil {
			return readFailure(err)
		}
		switch {
		case live == nil:
			return ErrNotFound
		case live.Trashed: // already there: nothing to write
			trashed = true
			return nil
		}
		if t := strings.TrimSpace(live.Text); t != "" && !strings.Contains(body, t) {
			return nil // edited since the merge read it: leave it out of the trash
		}
		if _, err := w.apply(false, func() (*writeengine.Change, error) { return w.eng.PlanTrashNote(id) }); err != nil {
			return err
		}
		trashed = true
		return nil
	})
	return trashed, err
}

// partialMerge is the error for a merge that stopped after it made the merged note.
// It names the merged note and the sources that are not in the trash. The text holds
// uuids and the fixed text of cause, which came from readFailure or commitFailure.
// failed is the index of the source that stopped the merge.
func partialMerge(noteUUID string, sources []MergeSource, failed int, cause error) error {
	var left []string
	for _, s := range sources[failed:] {
		left = append(left, s.UUID)
	}
	return &WriteError{
		msg: fmt.Sprintf("the merge stopped after it made note %s; %d of %d sources are in the trash, and these are not: %s. %s",
			noteUUID, failed, len(sources), strings.Join(left, ", "), cause.Error()),
		cause: cause,
	}
}

// TagApply puts a tag on notes. It finds the tag by its title, and makes the tag when
// none has that title. One write adds all the notes. A note that the tag holds is
// not added again. Every uuid must be a note that exists: a wrong uuid would become
// a reference to nothing that still verifies, so TagApply reads the vault first and
// refuses one. It refuses too when more than one tag has the title, because the
// engine finds a tag by title and could pick either. The title loses its outer
// whitespace.
func (w *Writer) TagApply(tagTitle string, noteUUIDs []string, dryRun bool) (TagWriteResult, error) {
	title := strings.TrimSpace(tagTitle)
	if title == "" {
		return TagWriteResult{}, ErrEmptyTitle
	}
	ids, err := cleanUUIDs(noteUUIDs)
	if err != nil {
		return TagWriteResult{}, err
	}
	if len(ids) == 0 {
		return TagWriteResult{}, ErrNoNotes
	}

	res := TagWriteResult{DryRun: dryRun, Action: "tag_apply", Tag: TagRef{Title: title}}
	err = w.do(func(c *snclient.Client) error {
		notes, tags, err := c.Fetch()
		if err != nil {
			return readFailure(err)
		}
		live := make(map[string]bool, len(notes))
		for _, n := range notes {
			if n != nil {
				live[n.UUID] = true
			}
		}
		for i, id := range ids {
			if !live[id] {
				return fmt.Errorf("%w (note %d)", ErrNotFound, i+1)
			}
		}
		held := map[string]bool{}
		switch found := tagsTitled(tags, title); len(found) {
		case 0:
			res.Created = true
		case 1:
			res.Tag.UUID = found[0].UUID
			for _, id := range found[0].NoteUUIDs {
				held[id] = true
			}
		default:
			return ErrTagAmbiguous
		}
		for _, id := range ids {
			if held[id] {
				res.NotesSkipped++
			} else {
				res.NotesChanged++
			}
		}
		ch, err := w.apply(dryRun, func() (*writeengine.Change, error) { return w.eng.PlanTagApply(title, ids) })
		if err != nil {
			return err
		}
		if ch != nil {
			res.Tag.UUID, res.OpID = ch.TagUUID, ch.OpID
		}
		return nil
	})
	if err != nil {
		return TagWriteResult{}, err
	}
	return res, nil
}

// TagDetach takes a tag off notes. It removes the reference of each note from the
// tag, and no other entry. A note that the tag does not hold is skipped.
func (w *Writer) TagDetach(tagUUID string, noteUUIDs []string, dryRun bool) (TagWriteResult, error) {
	id := strings.TrimSpace(tagUUID)
	if id == "" {
		return TagWriteResult{}, ErrEmptyUUID
	}
	ids, err := cleanUUIDs(noteUUIDs)
	if err != nil {
		return TagWriteResult{}, err
	}
	if len(ids) == 0 {
		return TagWriteResult{}, ErrNoNotes
	}

	res := TagWriteResult{DryRun: dryRun, Action: "tag_detach"}
	err = w.do(func(c *snclient.Client) error {
		_, tags, err := c.Fetch()
		if err != nil {
			return readFailure(err)
		}
		tag := tagWithUUID(tags, id)
		if tag == nil {
			return ErrTagNotFound
		}
		res.Tag = TagRef{UUID: tag.UUID, Title: tag.Title}
		held := make(map[string]bool, len(tag.NoteUUIDs))
		for _, nid := range tag.NoteUUIDs {
			held[nid] = true
		}
		for _, nid := range ids {
			if held[nid] {
				res.NotesChanged++
			} else {
				res.NotesSkipped++
			}
		}
		ch, err := w.apply(dryRun, func() (*writeengine.Change, error) { return w.eng.PlanTagDetach(id, ids) })
		if err != nil {
			return err
		}
		if ch != nil {
			res.OpID = ch.OpID
		}
		return nil
	})
	if err != nil {
		return TagWriteResult{}, err
	}
	return res, nil
}

// TagCreate makes an empty tag with this title. When a tag already has the title, it
// writes nothing and reports that tag. The title loses its outer whitespace.
func (w *Writer) TagCreate(title string, dryRun bool) (TagWriteResult, error) {
	title = strings.TrimSpace(title)
	if title == "" {
		return TagWriteResult{}, ErrEmptyTitle
	}

	res := TagWriteResult{DryRun: dryRun, Action: "tag_create", Tag: TagRef{Title: title}}
	err := w.do(func(c *snclient.Client) error {
		_, tags, err := c.Fetch()
		if err != nil {
			return readFailure(err)
		}
		if found := tagsTitled(tags, title); len(found) > 0 {
			res.Tag.UUID = found[0].UUID // the tag exists: there is nothing to make
			return nil
		}
		res.Created = true
		ch, err := w.apply(dryRun, func() (*writeengine.Change, error) { return w.eng.PlanTagCreate(title) })
		if err != nil {
			return err
		}
		if ch != nil {
			res.Tag.UUID, res.OpID = ch.TagUUID, ch.OpID
		}
		return nil
	})
	if err != nil {
		return TagWriteResult{}, err
	}
	return res, nil
}

// TagRename sets the title of a tag. The change sets the title and client_updated_at,
// and no other part of the tag. It refuses a title that another tag has: the engine
// finds a tag by title, so two tags with one title make tag_apply ambiguous. The title
// loses its outer whitespace.
func (w *Writer) TagRename(tagUUID, newTitle string, dryRun bool) (TagWriteResult, error) {
	id := strings.TrimSpace(tagUUID)
	if id == "" {
		return TagWriteResult{}, ErrEmptyUUID
	}
	title := strings.TrimSpace(newTitle)
	if title == "" {
		return TagWriteResult{}, ErrEmptyTitle
	}

	res := TagWriteResult{DryRun: dryRun, Action: "tag_rename", NewTitle: &title}
	err := w.do(func(c *snclient.Client) error {
		_, tags, err := c.Fetch()
		if err != nil {
			return readFailure(err)
		}
		tag := tagWithUUID(tags, id)
		if tag == nil {
			return ErrTagNotFound
		}
		for _, other := range tags {
			if other != nil && other.UUID != id && other.Title == title {
				return ErrTagTitleTaken
			}
		}
		res.Tag = TagRef{UUID: tag.UUID, Title: tag.Title}
		ch, err := w.apply(dryRun, func() (*writeengine.Change, error) { return w.eng.PlanTagRename(id, title) })
		if err != nil {
			return err
		}
		if ch != nil {
			res.OpID = ch.OpID
		}
		return nil
	})
	if err != nil {
		return TagWriteResult{}, err
	}
	return res, nil
}

// tagTrashNotice is the Notice of a tag_trash result. It says what the change is and
// what it is not.
const tagTrashNotice = "The tag is marked trashed. That is a reversible flag inside the tag: the tag keeps its title and its notes, and a write that clears the flag restores it. " +
	"No tool of this server clears it. The official Standard Notes app does not hide a trashed tag, so the tag still shows there. " +
	"Removing it for good is a step for the user in the app. This server never deletes a tag."

// TagTrash marks a tag as trashed. It sets the reversible trashed flag inside the tag,
// and changes no other part of it. The tag stays on the server with its title and its
// note references, and a write that clears the flag restores it. The official
// Standard Notes app does not hide a trashed tag, so a final removal of the tag is
// something the user does by hand in the app. TagTrash never sets the permanent
// deleted flag on the item envelope.
func (w *Writer) TagTrash(tagUUID string, dryRun bool) (TagWriteResult, error) {
	id := strings.TrimSpace(tagUUID)
	if id == "" {
		return TagWriteResult{}, ErrEmptyUUID
	}

	res := TagWriteResult{DryRun: dryRun, Action: "tag_trash", Notice: tagTrashNotice}
	err := w.do(func(c *snclient.Client) error {
		_, tags, err := c.Fetch()
		if err != nil {
			return readFailure(err)
		}
		tag := tagWithUUID(tags, id)
		if tag == nil {
			return ErrTagNotFound
		}
		res.Tag = TagRef{UUID: tag.UUID, Title: tag.Title}
		ch, err := w.apply(dryRun, func() (*writeengine.Change, error) { return w.eng.PlanTagTrash(id) })
		if err != nil {
			return err
		}
		if ch != nil {
			res.OpID = ch.OpID
		}
		return nil
	})
	if err != nil {
		return TagWriteResult{}, err
	}
	return res, nil
}

// tagMergeNotice ends a tag_merge result. It says the sources are reversibly trashed.
const tagMergeNotice = "The source tags are marked trashed (a reversible flag inside each tag): each keeps its title and its notes, and a write that clears the flag restores it. " +
	"The official Standard Notes app does not hide a trashed tag, so removing them for good is a step for the user in the app. This server never deletes a tag."

// TagMerge merges one or more source tags into a keeper tag, all by uuid, then moves
// the sources to the trash. Every note on a source tag is added to the keeper (a note
// the keeper already holds is not added again), and then each source is trashed. It
// works by uuid, not title, so it merges duplicate tags that share a title — the case
// tag_apply refuses. Nothing is deleted: a source stays trashed with its title and its
// notes, and a write that clears the flag restores it.
//
// It works in steps, each its own Guard.Do, as a note merge does: first one write adds
// the union of the sources' notes to the keeper, then each source is trashed. A source
// that is the keeper is dropped, so a tag never merges into itself. If a step fails
// after the keeper gained the notes, the error names the sources that are not trashed;
// nothing is lost, because the notes are safe on the keeper and the sources are whole.
func (w *Writer) TagMerge(keeperUUID string, sourceUUIDs []string, dryRun bool) (TagMergeResult, error) {
	keeper := strings.TrimSpace(keeperUUID)
	if keeper == "" {
		return TagMergeResult{}, ErrEmptyUUID
	}
	srcIDs, err := cleanUUIDs(sourceUUIDs)
	if err != nil {
		return TagMergeResult{}, err
	}
	// A tag does not merge into itself: drop the keeper from the sources.
	srcIDs = slices.DeleteFunc(srcIDs, func(id string) bool { return id == keeper })
	if len(srcIDs) == 0 {
		return TagMergeResult{}, ErrTagMergeNeedsSource
	}

	res := TagMergeResult{DryRun: dryRun, Action: "tag_merge"}
	var notesToAdd []string
	err = w.do(func(c *snclient.Client) error {
		_, tags, err := c.Fetch()
		if err != nil {
			return readFailure(err)
		}
		keeperTag := tagWithUUID(tags, keeper)
		if keeperTag == nil {
			return ErrTagNotFound
		}
		res.Keeper = TagRef{UUID: keeperTag.UUID, Title: keeperTag.Title}
		have := make(map[string]bool, len(keeperTag.NoteUUIDs))
		for _, id := range keeperTag.NoteUUIDs {
			have[id] = true
		}
		seen := map[string]bool{}
		for i, sid := range srcIDs {
			st := tagWithUUID(tags, sid)
			if st == nil {
				return fmt.Errorf("%w (source %d)", ErrTagNotFound, i+1)
			}
			res.Sources = append(res.Sources, TagRef{UUID: st.UUID, Title: st.Title})
			for _, nid := range st.NoteUUIDs {
				if !have[nid] && !seen[nid] {
					seen[nid] = true
					notesToAdd = append(notesToAdd, nid)
				}
			}
		}
		res.NotesAdded = len(notesToAdd)

		// Step 1: add the sources' notes to the keeper, when there are any.
		if len(notesToAdd) > 0 {
			ch, err := w.apply(dryRun, func() (*writeengine.Change, error) { return w.eng.PlanTagAddNotes(keeper, notesToAdd) })
			if err != nil {
				return err
			}
			if ch != nil {
				res.OpIDs = append(res.OpIDs, ch.OpID)
			}
		}
		return nil
	})
	if err != nil {
		return TagMergeResult{}, err
	}
	if dryRun {
		return res, nil
	}

	// Step 2: trash each source, each in its own Do (as a note merge trashes its sources).
	for i := range res.Sources {
		opID, err := w.trashTag(res.Sources[i].UUID)
		if err != nil {
			return TagMergeResult{}, partialTagMerge(res, i, err)
		}
		if opID != "" {
			res.OpIDs = append(res.OpIDs, opID)
		}
	}
	res.Notice = tagMergeNotice
	return res, nil
}

// trashTag moves one tag to the trash under the guard, and returns the write's OpID
// (empty when the tag was already trashed, so nothing was written).
func (w *Writer) trashTag(tagUUID string) (string, error) {
	var opID string
	err := w.do(func(c *snclient.Client) error {
		ch, err := w.apply(false, func() (*writeengine.Change, error) { return w.eng.PlanTagTrash(tagUUID) })
		if err != nil {
			return err
		}
		if ch != nil {
			opID = ch.OpID
		}
		return nil
	})
	return opID, err
}

// partialTagMerge is the error for a merge that stopped after the keeper gained the
// notes but before every source was trashed. It names the sources still out of the
// trash. Nothing is lost: the notes are on the keeper, and the sources are whole.
func partialTagMerge(res TagMergeResult, failed int, cause error) error {
	var left []string
	for _, s := range res.Sources[failed:] {
		left = append(left, s.UUID)
	}
	return &WriteError{
		msg: fmt.Sprintf("the tag merge added the notes to keeper %s but stopped before trashing every source; %d of %d sources are trashed, and these are not: %s. Nothing was lost. %s",
			res.Keeper.UUID, failed, len(res.Sources), strings.Join(left, ", "), cause.Error()),
		cause: cause,
	}
}

// cleanUUIDs trims each uuid, drops a repeat, and keeps the order of first
// appearance. A blank uuid is an error. A repeat is dropped and not refused: a
// repeat in a merge would copy a note twice, and in a tag change it does nothing.
func cleanUUIDs(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, id := range in {
		id = strings.TrimSpace(id)
		if id == "" {
			return nil, ErrEmptyUUID
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out, nil
}

// tagsTitled returns the tags that have exactly this title, as the engine's FindTag
// compares it.
func tagsTitled(tags []*snclient.TagView, title string) []*snclient.TagView {
	var out []*snclient.TagView
	for _, t := range tags {
		if t != nil && t.Title == title {
			out = append(out, t)
		}
	}
	return out
}

// tagWithUUID returns the tag with this uuid, or nil.
func tagWithUUID(tags []*snclient.TagView, id string) *snclient.TagView {
	for _, t := range tags {
		if t != nil && t.UUID == id {
			return t
		}
	}
	return nil
}
