// Command sn-tag puts one tag (default "exported") on a set of notes, as the
// "captured" marker for notes already copied into Obsidian. It gathers the notes
// from two optional sources and tags their union:
//
//   - -from-tag diary  : the live, non-trashed members of the named tag.
//   - -from-map PATH   : the keys of a routing JSON ({uuid: {...}}), e.g. the
//     idea-routing map the idea export used.
//
// Tagging is a uuid-only write: it adds note references to the tag and changes no
// note, so it is safe on sensitive notes and never touches their content. The write
// goes through the validated path (mcptools.Writer.TagApply -> engine PlanTagApply):
// find-or-create the tag by title, add each note once (idempotent), verify the tag
// landed and kept every reference it already held. Trashed and not-found uuids are
// skipped (a trashed diary was never exported). Nothing is ever removed.
//
// Dry-run by default: it prints what it WOULD tag and writes nothing. Pass -apply to
// write. It prints only counts, tag titles, uuids and the op id, never note content.
//
// Usage:
//
//	SN_SESSION_REF=sn-main go run ./cmd/sn-tag -from-tag diary [-tag exported] [-apply]
//	SN_SESSION_REF=sn-main go run ./cmd/sn-tag -from-map .local/idea-routing.json -apply
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/smirnov-labs/standard-notes-mcp/internal/gate"
	"github.com/smirnov-labs/standard-notes-mcp/internal/mcptools"
	"github.com/smirnov-labs/standard-notes-mcp/internal/snclient"
	"github.com/smirnov-labs/standard-notes-mcp/internal/writeengine"
)

func main() {
	tagName := flag.String("tag", "exported", "tag to put on the notes")
	fromTag := flag.String("from-tag", "", "tag whose live members are tagged, e.g. diary")
	fromMap := flag.String("from-map", "", "routing JSON whose keys are tagged, e.g. .local/idea-routing.json")
	apply := flag.Bool("apply", false, "write; without it, dry-run (print only)")
	ledgerFlag := flag.String("ledger", "", "write-ledger path (default: SN_LEDGER, else the user config dir)")
	maxWrites := flag.Int("max-writes", 1000, "engine write cap for this run")
	flag.Parse()

	if strings.TrimSpace(*fromTag) == "" && strings.TrimSpace(*fromMap) == "" {
		fatal("nothing to tag: pass -from-tag and/or -from-map")
	}

	cfg := snclient.Config{Server: snclient.EnvServer()}
	ref := strings.TrimSpace(os.Getenv("SN_SESSION_REF"))
	c, how, err := connect(cfg, ref)
	if err != nil {
		fatal("%v", err)
	}
	fmt.Fprintf(os.Stderr, "sn-tag: %s\n", how)

	notes, tags, err := c.Fetch()
	if err != nil {
		fatal("fetch: %v", err)
	}

	// Every live note's state, so selectTargets can keep only live, non-trashed ones.
	status := make(map[string]noteStatus, len(notes))
	for _, n := range notes {
		if n == nil {
			continue
		}
		if n.Trashed {
			status[n.UUID] = statusTrashed
		} else {
			status[n.UUID] = statusLive
		}
	}

	var sources [][]string
	if t := strings.TrimSpace(*fromTag); t != "" {
		members, found := tagMembers(tags, t)
		if !found {
			fatal("no tag titled %q in the vault", t)
		}
		fmt.Printf("from-tag %q: %d members\n", t, len(members))
		sources = append(sources, members)
	}
	if m := strings.TrimSpace(*fromMap); m != "" {
		keys, err := mapKeys(m)
		if err != nil {
			fatal("read map %s: %v", m, err)
		}
		fmt.Printf("from-map %s: %d keys\n", m, len(keys))
		sources = append(sources, keys)
	}

	ids, st := selectTargets(sources, status)
	fmt.Printf("selected %d live notes to tag %q (skipped %d trashed, %d not-found; %d duplicate refs)\n",
		st.Kept, *tagName, st.SkippedTrashed, st.SkippedMissing, st.Duplicates)
	if len(ids) == 0 {
		fatal("no live notes to tag")
	}

	// The guard and the engine must wrap the SAME client, or Writer.do refuses to run
	// (its lock would guard nothing). The gate is required by NewWriter but TagApply
	// never calls it: tagging is a uuid-only write, so it needs no sensitivity check.
	led, err := openLedger(*ledgerFlag)
	if err != nil {
		fatal("%v", err)
	}
	guard := snclient.NewGuard(c, ref)
	eng := writeengine.NewEngine(c, led, *maxWrites)
	gt := gate.New(gate.NewJev(jevBase(), "local"), 0.5)
	w := mcptools.NewWriter(guard, eng, gt)

	res, err := w.TagApply(*tagName, ids, !*apply)
	if err != nil {
		fatal("tag apply: %v", err)
	}

	tagVerb := "use existing tag"
	if res.Created {
		tagVerb = "create tag"
	}
	fmt.Println(strings.Repeat("-", 64))
	if res.DryRun {
		fmt.Printf("DRY-RUN: would %s %q and add %d notes (%d already tagged)\n",
			tagVerb, res.Tag.Title, res.NotesChanged, res.NotesSkipped)
		fmt.Println("nothing written; pass -apply to write")
		return
	}
	fmt.Printf("APPLIED: %s %q, added %d notes (%d already tagged)\n",
		tagVerb, res.Tag.Title, res.NotesChanged, res.NotesSkipped)
	fmt.Printf("op: %s  tag-uuid: %s\n", res.OpID, res.Tag.UUID)
}

// tagMembers returns the note uuids of every tag whose title matches (ignoring case
// and outer whitespace), unioned. found is false when no tag has the title. It
// matches sn-export-diary: when two tags share a title, their members are unioned.
func tagMembers(tags []*snclient.TagView, title string) (members []string, found bool) {
	for _, tg := range tags {
		if tg != nil && strings.EqualFold(strings.TrimSpace(tg.Title), title) {
			found = true
			members = append(members, tg.NoteUUIDs...)
		}
	}
	return members, found
}

// mapKeys reads a routing JSON object ({uuid: {...}}) and returns its keys. Only the
// keys (uuids) are read; the values are never looked at here.
func mapKeys(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys, nil
}

// openLedger opens the write ledger at flagPath, else SN_LEDGER, else the default in
// the user's config dir (the same file sn-mcp uses, so writes share one audit log).
func openLedger(flagPath string) (*writeengine.Ledger, error) {
	path := strings.TrimSpace(flagPath)
	if path == "" {
		path = strings.TrimSpace(os.Getenv("SN_LEDGER"))
	}
	if path == "" {
		dir, err := os.UserConfigDir()
		if err != nil {
			return nil, fmt.Errorf("no -ledger, no SN_LEDGER, and no config dir: %w", err)
		}
		path = filepath.Join(dir, "standard-notes-mcp", "ledger.jsonl")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("make the ledger folder: %w", err)
	}
	led, err := writeengine.OpenLedger(path)
	if err != nil {
		return nil, fmt.Errorf("open the ledger %s: %w", path, err)
	}
	return led, nil
}

// connect restores the session named by SN_SESSION_REF (code-free) or signs in with
// SN_EMAIL/SN_PASSWORD(+SN_MFA) and saves it. Mirrors sn-triage / sn-export-*.
func connect(cfg snclient.Config, ref string) (*snclient.Client, string, error) {
	if ref != "" {
		if c, err := snclient.Restore(cfg, ref); err == nil && c.Authenticated() {
			return c, fmt.Sprintf("restored saved session %q (no 2FA needed)", ref), nil
		}
	}
	c, err := snclient.SignIn(cfg, os.Getenv("SN_EMAIL"), os.Getenv("SN_PASSWORD"), mfaFromEnv)
	if err != nil {
		return nil, "", fmt.Errorf("sign in to %s: %w", cfg.Server, err)
	}
	if !c.Authenticated() {
		return nil, "", fmt.Errorf("sign in to %s: 2FA code rejected or expired", cfg.Server)
	}
	if ref != "" {
		_ = c.Persist(ref)
	}
	return c, "signed in", nil
}

func mfaFromEnv(string) (string, error) {
	if code := strings.TrimSpace(os.Getenv("SN_MFA")); code != "" {
		return code, nil
	}
	return "", fmt.Errorf("account needs a 2FA code; set SN_MFA")
}

func jevBase() string { return envOr("SN_JEV_BASE", "http://127.0.0.1:11434") }

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func fatal(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "sn-tag: "+f+"\n", a...)
	os.Exit(1)
}
