// Command sn-mcp is a stdio MCP server. It gives Claude access to a Standard Notes
// vault through gated tools. Four of them read: notes_search, notes_list, notes_get
// and tags_list. Ten of them write: note_edit, note_rename, note_trash,
// note_untrash, note_merge, tag_apply, tag_detach, tag_create, tag_rename, tag_trash
// and tag_merge. A note that the sensitivity gate flags comes back as a stub (a uuid and
// a fixed label) and never as content, in a read and in the preview of a write.
// note_edit, note_rename and note_merge refuse such a note: each would make the
// assistant author or copy content that it cannot see. internal/mcptools holds the
// tools.
//
// The write tools go through the write engine (internal/writeengine). Every write is
// recorded in a ledger, counted against a cap, and read back to check that it
// landed. A write tool has a dry_run argument: with it set, the tool writes nothing
// and returns what would change. No tool deletes anything for good: trash is a
// reversible flag, and a tag is only marked trashed. The sample settings in config/
// put every write tool behind an approval prompt.
//
// stdout carries only MCP protocol frames, so every log line goes to stderr. The
// server logs no note content and no tool error cause: a log file is a place that
// Claude may be able to read. The SDK's own logger stays at its default, which
// discards.
//
// Configuration comes from the environment:
//
//	SN_SERVER           server URL (default http://localhost:3000, the Docker test server)
//	SN_SESSION_REF      keyring name of a saved session. When set, the server restores
//	                    that session, and saves a fresh sign-in under it.
//	SN_EMAIL            sign in with these when there is no saved session
//	SN_PASSWORD
//	SN_MFA              a current 2FA code, if the account has 2FA
//	TYPESAFE_BASE_URL   jev for the gate (default http://127.0.0.1:11434)
//	SN_LEDGER           file for the write ledger (default standard-notes-mcp/ledger.jsonl
//	                    in the user's config directory, which is ~/Library/Application
//	                    Support on macOS). One JSON line for each step of each write: the
//	                    op id, the kind, a uuid and the state. It holds no note content.
//	SN_MAX_WRITES       most writes in one run of the server (default 1000). A write
//	                    past it is refused. 0 refuses every write, and a dry run still
//	                    works. The count starts again when the server restarts.
//
// The server exits at once, with a message on stderr, when it cannot sign in, when
// SN_MAX_WRITES is not a whole number, or when it cannot open the ledger.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/smirnov-labs/standard-notes-mcp/internal/gate"
	"github.com/smirnov-labs/standard-notes-mcp/internal/mcptools"
	"github.com/smirnov-labs/standard-notes-mcp/internal/snclient"
	"github.com/smirnov-labs/standard-notes-mcp/internal/writeengine"
)

// gateThreshold is the jev probability at or over which a note is sensitive.
const gateThreshold = 0.5

// defaultMaxWrites is the cap on writes in one run when SN_MAX_WRITES is not set. A
// tag change that names many notes is one write, so 1000 is room for a long session
// of edits, merges and trashes.
const defaultMaxWrites = 1000

func main() {
	log.SetOutput(os.Stderr) // CRITICAL: stdout carries ONLY MCP protocol frames
	tools, writer, err := newTools()
	if err != nil {
		log.Fatalf("sn-mcp: %v", err)
	}
	if err := newServer(tools, writer).Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatalf("sn-mcp: %v", err)
	}
}

// newTools signs in and builds the gated read tools and the gated write tools around
// the session. Both sets share one guard and one gate. The write engine wraps the
// same client as the guard, so the guard's lock covers every read the engine makes.
// It checks the settings that need no network first: a bad SN_MAX_WRITES must not
// wait for a sign-in. It opens the ledger after the sign-in, so a start that cannot
// sign in leaves no file behind.
func newTools() (*mcptools.Tools, *mcptools.Writer, error) {
	maxWrites, err := maxWritesFromEnv()
	if err != nil {
		return nil, nil, err
	}
	guard, client, err := openSession(os.Getenv("SN_SESSION_REF"))
	if err != nil {
		return nil, nil, err
	}
	path, err := ledgerPath()
	if err != nil {
		return nil, nil, err
	}
	led, err := openLedger(path)
	if err != nil {
		return nil, nil, err
	}
	base := jevBase()
	gt := gate.New(gate.NewJev(base, "local"), gateThreshold)
	eng := writeengine.NewEngine(client, led, maxWrites)
	log.Printf("sn-mcp: ready: four read tools and eleven write tools on stdio, gate jev at %s, ledger %s, at most %d writes", base, path, maxWrites)
	return mcptools.New(guard, gt), mcptools.NewWriter(guard, eng, gt), nil
}

// maxWritesFromEnv reads SN_MAX_WRITES, the cap on writes in one run. An unset value
// is defaultMaxWrites. A value that is not a whole number of 0 or more is an error,
// and not the default: a typo must not turn into a different cap.
func maxWritesFromEnv() (int, error) {
	v := strings.TrimSpace(os.Getenv("SN_MAX_WRITES"))
	if v == "" {
		return defaultMaxWrites, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("SN_MAX_WRITES must be a whole number of 0 or more, got %q", v)
	}
	return n, nil
}

// ledgerPath is where the write ledger lives: SN_LEDGER, or ledger.jsonl in a
// standard-notes-mcp folder of the user's config directory. The default is outside
// every repo, so a ledger is never committed by accident, and it outlasts a reboot,
// which a temp directory does not.
func ledgerPath() (string, error) {
	if p := os.Getenv("SN_LEDGER"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("SN_LEDGER is not set, and there is no config directory for the default ledger: %w", err)
	}
	return filepath.Join(dir, "standard-notes-mcp", "ledger.jsonl"), nil
}

// openLedger opens the ledger at path, and makes its folder when it is missing. The
// folder and the file are private to the user: the ledger names the notes that were
// written.
func openLedger(path string) (*writeengine.Ledger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("make the folder of the write ledger %s: %w", path, err)
	}
	led, err := writeengine.OpenLedger(path)
	if err != nil {
		return nil, fmt.Errorf("open the write ledger %s: %w", path, err)
	}
	return led, nil
}

// openSession returns a guard around a usable Standard Notes session, and the client
// that the guard guards. The write engine wraps that same client. When ref names a
// saved session that still works, it uses that one. Otherwise it signs in with
// SN_EMAIL and SN_PASSWORD, and saves the new session under ref. The next start can
// then restore it, and the password can leave the environment. When neither works,
// it says why.
func openSession(ref string) (*snclient.Guard, *snclient.Client, error) {
	cfg := snclient.Config{Server: snclient.EnvServer()}

	var restoreErr error
	if ref != "" {
		g, c, err := restore(cfg, ref)
		if err == nil {
			log.Printf("sn-mcp: restored the saved session %q for %s", ref, cfg.Server)
			return g, c, nil
		}
		restoreErr = fmt.Errorf("cannot use the saved session %q: %w", ref, err)
	}

	email, password := os.Getenv("SN_EMAIL"), os.Getenv("SN_PASSWORD")
	if email == "" || password == "" {
		if restoreErr != nil {
			return nil, nil, fmt.Errorf("%w, and SN_EMAIL and SN_PASSWORD are not set to sign in again", restoreErr)
		}
		return nil, nil, errors.New("no login: set SN_SESSION_REF to a saved session, or SN_EMAIL and SN_PASSWORD to sign in")
	}
	if restoreErr != nil {
		log.Printf("sn-mcp: %v; signing in with SN_EMAIL instead", restoreErr)
	}
	c, err := snclient.SignIn(cfg, email, password, mfaFromEnv)
	if err != nil {
		return nil, nil, fmt.Errorf("sign in to %s failed: %w", cfg.Server, err)
	}
	log.Printf("sn-mcp: signed in to %s", cfg.Server)
	if ref != "" {
		// Best effort, as in the guard: the session works in memory without it.
		if err := c.Persist(ref); err != nil {
			log.Printf("sn-mcp: could not save the session as %q: %v", ref, err)
		} else {
			log.Printf("sn-mcp: saved the session as %q", ref)
		}
	}
	return snclient.NewGuard(c, ref), c, nil
}

// restore loads the session saved under ref and uses it once. A session that has
// gone stale (its token needs a refresh, or its refresh token has expired) fails
// here, with the reason. Left alone, it would fail on the first tool call, whose
// error text is fixed on purpose and says nothing.
func restore(cfg snclient.Config, ref string) (*snclient.Guard, *snclient.Client, error) {
	c, err := snclient.Restore(cfg, ref)
	if err != nil {
		return nil, nil, err
	}
	if !c.Authenticated() {
		return nil, nil, errors.New("it holds no login")
	}
	g := snclient.NewGuard(c, ref)
	if err := g.Do(func(*snclient.Client) error { return nil }); err != nil {
		return nil, nil, err
	}
	return g, c, nil
}

// mfaFromEnv answers a 2FA request with SN_MFA. A code lasts about 30 seconds, so
// set it just before the first start, and not in a file.
func mfaFromEnv(string) (string, error) {
	if code := os.Getenv("SN_MFA"); code != "" {
		return code, nil
	}
	return "", errors.New("the account asks for a 2FA code: set SN_MFA to a current code")
}

// jevBase is where the gate finds jev: TYPESAFE_BASE_URL, or a local nimble.
func jevBase() string {
	if base := strings.TrimRight(os.Getenv("TYPESAFE_BASE_URL"), "/"); base != "" {
		return base
	}
	return "http://127.0.0.1:11434"
}

// The inputs of the tools. The jsonschema tags are the descriptions that the model
// reads. A field with omitempty is optional in the schema, so a call that leaves
// out limit and offset is valid.
type (
	searchInput struct {
		Query  string `json:"query" jsonschema:"text to find in note titles and bodies; case-insensitive, matched literally (it is not a pattern)"`
		Limit  int    `json:"limit,omitempty" jsonschema:"most rows to return; default 50, at most 500"`
		Offset int    `json:"offset,omitempty" jsonschema:"rows to skip before the first row returned, to read the next page; default 0"`
	}
	listInput struct {
		Limit  int `json:"limit,omitempty" jsonschema:"most rows to return; default 50, at most 500"`
		Offset int `json:"offset,omitempty" jsonschema:"rows to skip before the first row returned, to read the next page; default 0"`
	}
	getInput struct {
		UUID string `json:"uuid" jsonschema:"the uuid of the note, as notes_search and notes_list return it"`
	}
	noInput struct{}
)

// The inputs of the write tools. No input has a content_type, a trashed flag or any
// field that sets a part of the item other than the one the tool changes: the schema
// does not allow another property, so the SDK refuses a call that sends one. Each
// input has a dry_run field, which is optional. The text of a jsonschema tag must be a
// literal, so the dry_run text repeats.
type (
	noteEditInput struct {
		UUID   string `json:"uuid" jsonschema:"the uuid of the note, as notes_search and notes_list return it"`
		Text   string `json:"text" jsonschema:"the full new text of the note; it replaces the whole old text, and it must not be blank"`
		DryRun bool   `json:"dry_run,omitempty" jsonschema:"when true, write nothing and return what would change; default false, which makes the change"`
	}
	noteRenameInput struct {
		UUID   string `json:"uuid" jsonschema:"the uuid of the note, as notes_search and notes_list return it"`
		Title  string `json:"title" jsonschema:"the new title of the note; outer whitespace is removed, and it must not be blank"`
		DryRun bool   `json:"dry_run,omitempty" jsonschema:"when true, write nothing and return what would change; default false, which makes the change"`
	}
	noteTrashInput struct {
		UUID   string `json:"uuid" jsonschema:"the uuid of the note, as notes_search and notes_list return it"`
		DryRun bool   `json:"dry_run,omitempty" jsonschema:"when true, write nothing and return what would change; default false, which makes the change"`
	}
	noteMergeInput struct {
		UUIDs  []string `json:"uuids" jsonschema:"the uuids of the notes to merge: at least two different ones; their order is the order in the new note"`
		Title  string   `json:"title" jsonschema:"the title of the new note; outer whitespace is removed, and it must not be blank"`
		DryRun bool     `json:"dry_run,omitempty" jsonschema:"when true, write nothing and return what would change; default false, which makes the change"`
	}
	tagApplyInput struct {
		Tag       string   `json:"tag" jsonschema:"the title of the tag; a tag with exactly this title is used, and one is made when none has it"`
		NoteUUIDs []string `json:"note_uuids" jsonschema:"the uuids of the notes to tag; each must be a note that exists"`
		DryRun    bool     `json:"dry_run,omitempty" jsonschema:"when true, write nothing and return what would change; default false, which makes the change"`
	}
	tagDetachInput struct {
		TagUUID   string   `json:"tag_uuid" jsonschema:"the uuid of the tag, as tags_list returns it"`
		NoteUUIDs []string `json:"note_uuids" jsonschema:"the uuids of the notes to take off the tag"`
		DryRun    bool     `json:"dry_run,omitempty" jsonschema:"when true, write nothing and return what would change; default false, which makes the change"`
	}
	tagCreateInput struct {
		Title  string `json:"title" jsonschema:"the title of the new tag; outer whitespace is removed, and it must not be blank"`
		DryRun bool   `json:"dry_run,omitempty" jsonschema:"when true, write nothing and return what would change; default false, which makes the change"`
	}
	tagRenameInput struct {
		TagUUID string `json:"tag_uuid" jsonschema:"the uuid of the tag, as tags_list returns it"`
		Title   string `json:"title" jsonschema:"the new title of the tag; outer whitespace is removed, and it must not be blank"`
		DryRun  bool   `json:"dry_run,omitempty" jsonschema:"when true, write nothing and return what would change; default false, which makes the change"`
	}
	tagTrashInput struct {
		TagUUID string `json:"tag_uuid" jsonschema:"the uuid of the tag, as tags_list returns it"`
		DryRun  bool   `json:"dry_run,omitempty" jsonschema:"when true, write nothing and return what would change; default false, which makes the change"`
	}
	tagMergeInput struct {
		KeeperUUID  string   `json:"keeper_uuid" jsonschema:"the uuid of the tag to KEEP; it gains every note from the source tags"`
		SourceUUIDs []string `json:"source_uuids" jsonschema:"the uuids of the tags to merge into the keeper and then trash; matched by uuid, so duplicate titles are fine; the keeper is ignored if listed here"`
		DryRun      bool     `json:"dry_run,omitempty" jsonschema:"when true, write nothing and return what would change; default false, which makes the change"`
	}
)

// newServer registers the four read tools and the eleven write tools. A handler returns
// the tool's result and the tool's error as they are. The SDK sends the result as
// structured content and as one text block of the same JSON, and it sends an error as
// a tool error with the error's text. The tools' errors have fixed text that holds no
// note content, so a handler must not wrap one or add to it.
func newServer(tools *mcptools.Tools, writer *mcptools.Writer) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "standard-notes", Version: "v0.3.0"}, nil)
	readOnly := &mcp.ToolAnnotations{ReadOnlyHint: true}

	mcp.AddTool(s, &mcp.Tool{
		Name: "notes_search",
		Description: "Search live (not trashed) notes for text in the title or the body. The match ignores " +
			"case and is literal, not a pattern. Each row is a note (UUID, Title, Snippet) or, when the privacy " +
			"gate flags the note as sensitive, a stub with only its UUID and a label: a stub never shows content. " +
			"Rows come in a fixed order (by UUID), so pages do not overlap. A page holds at most limit rows " +
			"(default 50, max 500) after offset rows are skipped, and a page with fewer than limit rows is the last one.",
		Annotations: readOnly,
	}, func(_ context.Context, _ *mcp.CallToolRequest, in searchInput) (*mcp.CallToolResult, mcptools.RowSet, error) {
		out, err := tools.Search(in.Query, in.Limit, in.Offset)
		return nil, out, err
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "notes_list",
		Description: "List live (not trashed) notes in a fixed order (by UUID), so pages do not overlap. Each row is a " +
			"note (UUID, Title, Snippet) or, when the privacy gate flags the note as sensitive, a stub with only its " +
			"UUID and a label: a stub never shows content. A page holds at most limit rows (default 50, max 500) " +
			"after offset rows are skipped, and a page with fewer than limit rows is the last one.",
		Annotations: readOnly,
	}, func(_ context.Context, _ *mcp.CallToolRequest, in listInput) (*mcp.CallToolResult, mcptools.RowSet, error) {
		out, err := tools.List(in.Limit, in.Offset)
		return nil, out, err
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "notes_get",
		Description: "Read one note in full by its uuid. A trashed note is returned with Trashed set. When the " +
			"privacy gate flags the note as sensitive, the result is a stub (the UUID and a label) and the content " +
			"is withheld.",
		Annotations: readOnly,
	}, func(_ context.Context, _ *mcp.CallToolRequest, in getInput) (*mcp.CallToolResult, mcptools.GetResult, error) {
		out, err := tools.Get(in.UUID)
		return nil, out, err
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "tags_list",
		Description: "List every tag with its UUID, its title and the UUIDs of the notes it holds.",
		Annotations: readOnly,
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ noInput) (*mcp.CallToolResult, mcptools.TagList, error) {
		out, err := tools.TagsList()
		return nil, out, err
	})

	addWriteTools(s, writer)
	return s
}

// addWrite registers one write tool. Every write tool goes through here, and none
// sets Annotations, so none carries a read-only hint: the sample settings ask the user
// to approve each one, and a client must not treat one as read-only.
func addWrite[In, Out any](s *mcp.Server, name, description string, call func(In) (Out, error)) {
	mcp.AddTool(s, &mcp.Tool{Name: name, Description: description},
		func(_ context.Context, _ *mcp.CallToolRequest, in In) (*mcp.CallToolResult, Out, error) {
			out, err := call(in)
			return nil, out, err
		})
}

// The sentences that end the description of a note tool. They say what the result
// shows and what the tool does with a sensitive note. They are the privacy rule of
// the write tools, said to the model.
//
// noteShown and noteDryRun end every note tool. noteRefused is for the two tools that
// set content, the text or the title, for a note: the orchestrator must not author
// content for a note that it cannot see, so they refuse a sensitive note. noteStubbed
// is for the two tools that set no content: they stay allowed, and their result is
// the stub.
const (
	noteShown  = "The result shows the note as notes_get shows it, from before the change."
	noteDryRun = "With dry_run true, nothing is written and the result shows what would change."

	noteRefused = "The tool refuses a note that the privacy gate flags as sensitive, in a dry run too: it returns the error " +
		"\"cannot edit a sensitive note; it is walled off from the assistant\" and writes nothing. A note that the gate " +
		"cannot check, for example when jev is down, counts as sensitive."

	noteStubbed = "When the privacy gate flags the note as sensitive, the result is a stub (the UUID and a label): the " +
		"current title and text stay hidden, and the change still applies, because it sets no text and no title."
)

// addWriteTools registers the eleven write tools. Each description says what the tool
// changes, what it never does, and what its result shows.
func addWriteTools(s *mcp.Server, w *mcptools.Writer) {
	addWrite(s, "note_edit",
		"Replace the whole text of one note. Only the text changes: the title, the tags and every other field of the "+
			"note stay as they are. Send the full new text, not a patch. A blank text is refused: to remove a note, use "+
			"note_trash. "+noteRefused+" "+noteShown+" "+noteDryRun,
		func(in noteEditInput) (mcptools.NoteWriteResult, error) {
			return w.NoteEdit(in.UUID, in.Text, in.DryRun)
		})

	addWrite(s, "note_rename",
		"Change the title of one note. Only the title changes. A blank title is refused. "+noteRefused+" "+noteShown+" "+noteDryRun,
		func(in noteRenameInput) (mcptools.NoteWriteResult, error) {
			return w.NoteRename(in.UUID, in.Title, in.DryRun)
		})

	addWrite(s, "note_trash",
		"Move one note to the trash. This is reversible: the note stays in Standard Notes with all its fields, and "+
			"note_untrash brings it back. No tool of this server deletes a note for good. "+noteShown+" "+noteStubbed+" "+noteDryRun,
		func(in noteTrashInput) (mcptools.NoteWriteResult, error) { return w.NoteTrash(in.UUID, in.DryRun) })

	addWrite(s, "note_untrash",
		"Take one note out of the trash. It is the opposite of note_trash. "+noteShown+" "+noteStubbed+" "+noteDryRun,
		func(in noteTrashInput) (mcptools.NoteWriteResult, error) { return w.NoteUntrash(in.UUID, in.DryRun) })

	addWrite(s, "note_merge",
		"Make one new note from two or more notes, then move the sources to the trash. The new note holds each source "+
			"in the order you give: its title on one line, then its text exactly as it is, with a line of --- between "+
			"sources. Nothing is deleted: each source stays in the trash with all its fields, and note_untrash brings it "+
			"back. A source that someone edits while the merge runs stays out of the trash, and the result says so. The "+
			"merge is refused when any source is sensitive, because it cannot copy text that you are not allowed to see. "+
			"A note that the privacy gate cannot check, for example when jev is down, counts as sensitive. The result "+
			"lists the sources with their titles, and the size of the new text. With dry_run true, nothing is written.",
		func(in noteMergeInput) (mcptools.MergeResult, error) {
			return w.NoteMerge(in.UUIDs, in.Title, in.DryRun)
		})

	addWrite(s, "tag_apply",
		"Put a tag on notes. The tag is found by its exact title and made when no tag has it. One write adds all the "+
			"notes, and a note that already has the tag is skipped. Every uuid must be a note that exists. It is refused "+
			"when more than one tag has the title. The result counts the notes that gain the tag and shows no note "+
			"titles. With dry_run true, nothing is written.",
		func(in tagApplyInput) (mcptools.TagWriteResult, error) {
			return w.TagApply(in.Tag, in.NoteUUIDs, in.DryRun)
		})

	addWrite(s, "tag_detach",
		"Take a tag off notes. A note that does not have the tag is skipped. The result counts the notes that lose the "+
			"tag. With dry_run true, nothing is written.",
		func(in tagDetachInput) (mcptools.TagWriteResult, error) {
			return w.TagDetach(in.TagUUID, in.NoteUUIDs, in.DryRun)
		})

	addWrite(s, "tag_create",
		"Make an empty tag with this title. When a tag already has the title, nothing is written and the result is "+
			"that tag. With dry_run true, nothing is written.",
		func(in tagCreateInput) (mcptools.TagWriteResult, error) { return w.TagCreate(in.Title, in.DryRun) })

	addWrite(s, "tag_rename",
		"Change the title of a tag. The tag keeps its notes. It is refused when another tag has the new title. With "+
			"dry_run true, nothing is written.",
		func(in tagRenameInput) (mcptools.TagWriteResult, error) {
			return w.TagRename(in.TagUUID, in.Title, in.DryRun)
		})

	addWrite(s, "tag_trash",
		"Mark a tag as trashed. The mark is a reversible flag inside the tag: the tag keeps its title and its notes, and "+
			"nothing is deleted. The official Standard Notes app does not hide a trashed tag, so the tag still shows "+
			"there until the user removes it in the app. No tool of this server clears the flag or deletes a tag. With "+
			"dry_run true, nothing is written.",
		func(in tagTrashInput) (mcptools.TagWriteResult, error) { return w.TagTrash(in.TagUUID, in.DryRun) })

	addWrite(s, "tag_merge",
		"Merge one or more source tags into a keeper tag, all by uuid, then move the sources to the trash. Every note on "+
			"a source tag is added to the keeper; a note the keeper already holds is not added again. It works by uuid, "+
			"not title, so it merges duplicate tags that share a title, which tag_apply refuses. Nothing is deleted: each "+
			"source stays trashed with its title and notes, and the official Standard Notes app does not hide a trashed "+
			"tag, so a final removal is a step for the user. The result names the keeper and the sources and counts the "+
			"notes the keeper gained. With dry_run true, nothing is written.",
		func(in tagMergeInput) (mcptools.TagMergeResult, error) {
			return w.TagMerge(in.KeeperUUID, in.SourceUUIDs, in.DryRun)
		})
}
