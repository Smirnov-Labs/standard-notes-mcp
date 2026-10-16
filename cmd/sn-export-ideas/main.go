// Command sn-export-ideas consolidates the idea-cluster notes into the Obsidian vault
// per a routing map (.local/idea-routing.json: uuid -> {dest, slug, title}). It is a
// READ from Standard Notes plus LOCAL file writes; it NEVER writes to Standard Notes.
// Bodies go SN->disk and are never printed (only title/path/action), so intimate
// content stays off the terminal. Existing files are only appended to, and a note
// whose body is already present is skipped (idempotent re-runs). Dry-run by default;
// pass -apply to write.
//
// Usage:
//
//	SN_SESSION_REF=sn-main go run ./cmd/sn-export-ideas [-vault ~/obsidian]
//	  [-map .local/idea-routing.json] [-apply]
//
// The vault defaults to $OBSIDIAN_VAULT.
package main

import (
	"encoding/json"
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

type route struct {
	Dest  string `json:"dest"`
	Slug  string `json:"slug"`
	Title string `json:"title"`
}

var destFolder = map[string]string{
	"journeys":         "journeys",
	"health":           "personal/health",
	"nsfw":             "personal/nsfw",
	"musings":          "personal/musings",
	"book":             "notes/book",
	"blog":             "blog",
	"idea":             "idea",
	"people":           "people",
	"reference":        "reference",
	"project":          "project",
	"personal":         "personal",
	"personal-medical": "personal/medical",
	"personal-nsfw":    "personal/nsfw",
}

var destTag = map[string]string{
	"journeys": "journey", "health": "health", "nsfw": "nsfw",
	"musings": "musing", "book": "book-notes", "blog": "blog",
	"idea": "idea", "people": "person", "reference": "reference", "project": "project",
	"personal": "personal", "personal-medical": "medical", "personal-nsfw": "nsfw",
}

func isPrivate(dest string) bool {
	switch dest {
	case "journeys", "health", "nsfw", "musings", "personal", "personal-medical", "personal-nsfw":
		return true
	}
	return false
}

func main() {
	vault := flag.String("vault", os.Getenv("OBSIDIAN_VAULT"), "Obsidian vault root (default $OBSIDIAN_VAULT)")
	mapPath := flag.String("map", ".local/idea-routing.json", "routing map: uuid -> {dest,slug,title}")
	apply := flag.Bool("apply", false, "write files; without it, dry-run (print only)")
	quiet := flag.Bool("quiet", false, "suppress per-note title/path lines (counts only) — for sensitive exports")
	flag.Parse()
	if *vault == "" {
		fatal("set -vault or OBSIDIAN_VAULT to the Obsidian vault root")
	}

	raw, err := os.ReadFile(*mapPath)
	if err != nil {
		fatal("read map: %v", err)
	}
	var routes map[string]route
	if err := json.Unmarshal(raw, &routes); err != nil {
		fatal("parse map: %v", err)
	}

	server := envOr("SN_SERVER", "https://api.standardnotes.com")
	c, how, err := connect(snclient.Config{Server: server}, strings.TrimSpace(os.Getenv("SN_SESSION_REF")))
	if err != nil {
		fatal("%v", err)
	}
	fmt.Fprintf(os.Stderr, "export-ideas: %s\n", how)

	notes, _, err := c.Fetch()
	if err != nil {
		fatal("fetch: %v", err)
	}
	byUUID := map[string]*snclient.NoteView{}
	for _, n := range notes {
		byUUID[n.UUID] = n
	}

	type item struct {
		r    route
		note *snclient.NoteView
		date time.Time
	}
	var items []item
	missing := 0
	for uuid, r := range routes {
		n := byUUID[uuid]
		if n == nil {
			missing++
			continue
		}
		d, _ := parseSNTime(n.CreatedAt)
		items = append(items, item{r, n, d})
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].r.Dest != items[j].r.Dest {
			return items[i].r.Dest < items[j].r.Dest
		}
		if !items[i].date.Equal(items[j].date) {
			return items[i].date.Before(items[j].date)
		}
		return items[i].r.Slug < items[j].r.Slug
	})

	counts := map[string]int{}
	created, appended, skipped := 0, 0, 0
	for _, it := range items {
		var rel string
		if it.r.Dest == "diary" {
			// Diary entries are placed by created-date into diary/YYYY/MM/DD.md, using
			// the same template as the diary export (title kept as a bold lead line).
			if it.date.IsZero() {
				if !*quiet {
					fmt.Printf("  %-8s %-42s -> SKIP (no parseable date)\n", it.r.Dest, trunc(it.note.Title, 42))
				}
				continue
			}
			rel = obsidian.DiaryRelPath(it.date)
		} else {
			folder := destFolder[it.r.Dest]
			if folder == "" {
				fatal("unknown dest %q for %q", it.r.Dest, it.r.Title)
			}
			name := it.r.Slug + ".md"
			switch {
			case it.r.Slug == "": // sensitive maps carry no slug: place by created-date
				ds := "undated"
				if !it.date.IsZero() {
					ds = it.date.Format("2006-01-02")
				}
				name = ds + ".md"
			case it.r.Dest == "journeys":
				ds := "0000-00-00"
				if !it.date.IsZero() {
					ds = it.date.Format("2006-01-02")
				}
				name = ds + "-" + it.r.Slug + ".md"
			}
			rel = filepath.Join(folder, name)
		}
		abs := filepath.Join(*vault, rel)

		existing, _ := os.ReadFile(abs)
		body := strings.TrimRight(it.note.Text, "\n")
		var action string
		switch {
		case body != "" && strings.Contains(string(existing), body):
			action, skipped = "SKIP", skipped+1
		case len(existing) == 0:
			action, created = "CREATE", created+1
		default:
			action, appended = "APPEND", appended+1
		}
		counts[it.r.Dest]++
		if !*quiet {
			fmt.Printf("  %-8s %-42s -> %s  [%s]\n", it.r.Dest, trunc(it.note.Title, 42), rel, action)
		}

		if !*apply || action == "SKIP" {
			continue
		}
		if err := writeItem(abs, it.r.Dest, it.note.Title, it.date, body, len(existing) > 0); err != nil {
			fatal("write %s: %v", rel, err)
		}
	}

	mode := "DRY-RUN (nothing written; pass -apply to write)"
	if *apply {
		mode = "APPLIED"
	}
	fmt.Println(strings.Repeat("-", 64))
	fmt.Printf("%s: %d notes -> %d new, %d appends, %d skipped\n", mode, len(items), created, appended, skipped)
	for _, d := range []string{"diary", "journeys", "health", "nsfw", "musings", "book", "blog", "idea", "people", "reference", "project", "personal", "personal-medical", "personal-nsfw"} {
		fmt.Printf("  %-9s %d\n", d, counts[d])
	}
	if missing > 0 {
		fmt.Printf("WARNING: %d mapped uuids were not found in the vault (changed/trashed since triage)\n", missing)
	}
	fmt.Printf("vault: %s\n", *vault)
}

// writeItem creates a new file (frontmatter + heading + body) or appends the body
// under a titled heading to an existing one. It only ever grows a file.
func writeItem(abs, dest, title string, date time.Time, body string, appendMode bool) error {
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return err
	}
	if dest == "diary" {
		if appendMode {
			cur, err := os.ReadFile(abs)
			if err != nil {
				return err
			}
			return os.WriteFile(abs, []byte(obsidian.AppendedContents(string(cur), date, title, body)), 0o644)
		}
		return os.WriteFile(abs, []byte(obsidian.NewFileContents(date, title, body)), 0o644)
	}
	var out string
	if appendMode {
		cur, err := os.ReadFile(abs)
		if err != nil {
			return err
		}
		out = strings.TrimRight(string(cur), "\n") + "\n\n## " + title + "\n\n" + body + "\n"
	} else {
		var b strings.Builder
		b.WriteString("---\n")
		if isPrivate(dest) {
			b.WriteString("private: true\n")
		}
		b.WriteString("tags:\n  - " + destTag[dest] + "\n")
		if dest == "journeys" && !date.IsZero() {
			b.WriteString("date: " + date.Format("2006-01-02") + "\n")
		}
		b.WriteString("---\n\n## " + title + "\n\n" + body + "\n")
		out = b.String()
	}
	return os.WriteFile(abs, []byte(out), 0o644)
}

func trunc(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}

func parseSNTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.999999Z07:00"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

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
	fmt.Fprintf(os.Stderr, "sn-export-ideas: "+f+"\n", a...)
	os.Exit(1)
}
