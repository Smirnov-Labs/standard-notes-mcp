// Command sn-export-diary exports Standard Notes diary entries (notes carrying the
// diary tag) into the Obsidian vault as diary/YYYY/MM/DD.md, matching the vault's
// template. It is a READ from Standard Notes plus a LOCAL file WRITE — it NEVER
// writes to Standard Notes.
//
// Placement is by the note's created-date, so a sensitive diary's content is written
// straight to local disk and is never printed: stdout shows only date, path, action
// and byte size, so nothing sensitive reaches the terminal (or the assistant).
// Existing day-files are only ever appended to, never overwritten, and an entry
// already present in its target file is skipped, so re-runs never duplicate.
//
// Dry-run by default: it prints what it WOULD write and changes nothing. Pass -apply
// to write the files.
//
// Usage:
//
//	SN_SESSION_REF=sn-main go run ./cmd/sn-export-diary \
//	  [-vault ~/obsidian] [-tag diary] [-month 2024-03] [-limit 0] [-apply]
//
// The vault defaults to $OBSIDIAN_VAULT.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/smirnov-labs/standard-notes-mcp/internal/obsidian"
	"github.com/smirnov-labs/standard-notes-mcp/internal/snclient"
)

func main() {
	vault := flag.String("vault", os.Getenv("OBSIDIAN_VAULT"), "Obsidian vault root (default $OBSIDIAN_VAULT)")
	tag := flag.String("tag", "diary", "SN tag whose notes are diary entries")
	month := flag.String("month", "", "only entries in this month (YYYY-MM); for a sample run")
	limit := flag.Int("limit", 0, "export at most this many entries (0 = all)")
	apply := flag.Bool("apply", false, "write files; without it, dry-run (print only)")
	flag.Parse()
	if *vault == "" {
		fatal("set -vault or OBSIDIAN_VAULT to the Obsidian vault root")
	}

	server := envOr("SN_SERVER", "https://api.standardnotes.com")
	c, how, err := connect(snclient.Config{Server: server}, strings.TrimSpace(os.Getenv("SN_SESSION_REF")))
	if err != nil {
		fatal("%v", err)
	}
	fmt.Fprintf(os.Stderr, "export-diary: %s\n", how)

	notes, tags, err := c.Fetch()
	if err != nil {
		fatal("fetch: %v", err)
	}

	// Build the diary note set from the tag's membership.
	want := map[string]bool{}
	found := false
	for _, tg := range tags {
		if strings.EqualFold(strings.TrimSpace(tg.Title), *tag) {
			found = true
			for _, id := range tg.NoteUUIDs {
				want[id] = true
			}
		}
	}
	if !found {
		fatal("no tag titled %q in the vault", *tag)
	}

	type entry struct {
		date        time.Time
		rel         string
		title, body string
		bytes       int
	}
	var entries []entry
	var skipTrash, skipDate, skipMonth int
	for _, n := range notes {
		if !want[n.UUID] {
			continue
		}
		if n.Trashed {
			skipTrash++
			continue
		}
		date, ok := parseSNTime(n.CreatedAt)
		if !ok {
			skipDate++
			continue
		}
		if *month != "" && date.Format("2006-01") != *month {
			skipMonth++
			continue
		}
		entries = append(entries, entry{date: date, rel: obsidian.DiaryRelPath(date), title: n.Title, body: n.Text, bytes: len(n.Text)})
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].date.Before(entries[j].date) })
	if *limit > 0 && *limit < len(entries) {
		entries = entries[:*limit]
	}

	created, appended, skipped := 0, 0, 0
	for _, e := range entries {
		abs := filepath.Join(*vault, e.rel)
		existing, _ := os.ReadFile(abs) // nil when the day-file does not exist yet
		body := strings.TrimRight(e.body, "\n")

		var action string
		switch {
		case body != "" && strings.Contains(string(existing), body):
			// Already present (from a prior run, or earlier in this one). Skip it so
			// re-running — or resuming after an interruption — never duplicates an entry.
			action, skipped = "SKIP", skipped+1
		case len(existing) == 0:
			action, created = "CREATE", created+1
		default:
			action, appended = "APPEND", appended+1
		}
		fmt.Printf("  %s  %-22s  %-6s  %d bytes\n", e.date.Format("2006-01-02"), e.rel, action, e.bytes)
		if !*apply || action == "SKIP" {
			continue
		}
		if err := writeEntry(abs, action == "APPEND", e.date, e.title, e.body); err != nil {
			fatal("write %s: %v", e.rel, err)
		}
	}

	mode := "DRY-RUN (nothing written; pass -apply to write)"
	if *apply {
		mode = "APPLIED"
	}
	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf("%s: %d entries → %d new files, %d appends, %d already-present (skipped)\n", mode, len(entries), created, appended, skipped)
	if skipTrash+skipDate+skipMonth > 0 {
		fmt.Printf("skipped: %d trashed, %d unparseable-date, %d outside -month\n", skipTrash, skipDate, skipMonth)
	}
	fmt.Printf("vault: %s\n", *vault)
}

func writeEntry(abs string, appendMode bool, date time.Time, title, body string) error {
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return err
	}
	var out string
	if appendMode {
		cur, err := os.ReadFile(abs)
		if err != nil {
			return err
		}
		out = obsidian.AppendedContents(string(cur), date, title, body)
	} else {
		out = obsidian.NewFileContents(date, title, body)
	}
	return os.WriteFile(abs, []byte(out), 0o644)
}

// parseSNTime parses the server's created_at (ISO 8601, usually RFC3339 with a
// fractional second and Z), returning the time in UTC.
func parseSNTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.999999Z07:00", "2006-01-02T15:04:05Z07:00"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// connect restores the session named by SN_SESSION_REF (code-free) or signs in with
// SN_EMAIL/SN_PASSWORD(+SN_MFA) and saves it. Mirrors sn-triage.
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

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func fatal(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "sn-export-diary: "+f+"\n", a...)
	os.Exit(1)
}
