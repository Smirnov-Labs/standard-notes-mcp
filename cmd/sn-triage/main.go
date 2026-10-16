// Command sn-triage reads every note in an account, classifies each with the
// sensitivity gate (deterministic scanner + checksum BIP-39 + local jev), and writes
// a worklist. It is READ-ONLY: it never writes to Standard Notes.
//
// The worklist holds NO content for a sensitive note — only its uuid, verdict and
// reasons — so the hybrid-privacy wall holds in the output too, and the file is safe
// for the assistant to read. A non-sensitive note carries its title, a snippet and
// its size. Tag titles are the user's own text and are not gated, so every note
// lists its tags.
//
// It also times the full sync, so a sample run gives the per-note cost that decides
// whether the O(vault)-per-write path needs the incremental-sync work before the bulk
// phase.
//
// Usage:
//
//	SN_SERVER=.. SN_EMAIL=.. SN_PASSWORD=.. TYPESAFE_BASE_URL=http://127.0.0.1:11434 \
//	  go run ./cmd/sn-triage [-out .local/worklist.jsonl] [-threshold 0.5] [-workers 8] [-limit 0]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/smirnov-labs/standard-notes-mcp/internal/gate"
	"github.com/smirnov-labs/standard-notes-mcp/internal/snclient"
)

func main() {
	out := flag.String("out", ".local/worklist.jsonl", "worklist output path (gitignored dir)")
	threshold := flag.Float64("threshold", 0.5, "jev sensitivity cutoff; a note at or over this is sensitive")
	workers := flag.Int("workers", 8, "number of concurrent gate workers (jev is the bottleneck)")
	limit := flag.Int("limit", 0, "classify at most this many notes (0 = all); a sample run for timing")
	flag.Parse()

	server := envOr("SN_SERVER", "http://localhost:3000")
	base := envOr("TYPESAFE_BASE_URL", "http://127.0.0.1:11434")
	key := envOr("TYPESAFE_KEY", "local")

	c, how, err := connect(snclient.Config{Server: server}, strings.TrimSpace(os.Getenv("SN_SESSION_REF")))
	if err != nil {
		fatal("%v", err)
	}
	fmt.Fprintf(os.Stderr, "triage: %s\n", how)

	// One full read of the vault. Time it: this is the O(vault) cost each write pays
	// today, so it feeds the incremental-sync decision.
	t0 := time.Now()
	notes, tags, err := c.Fetch()
	if err != nil {
		fatal("fetch: %v", err)
	}
	fetchDur := time.Since(t0)

	tagsByNote := map[string][]string{}
	for _, tg := range tags {
		for _, id := range tg.NoteUUIDs {
			tagsByNote[id] = append(tagsByNote[id], tg.Title)
		}
	}

	if *limit > 0 && *limit < len(notes) {
		notes = notes[:*limit]
	}

	g := gate.New(gate.NewJev(base, key), *threshold)
	verdicts, classifyDur := classify(g, notes, *workers)

	ws, err := writeWorklist(*out, notes, verdicts, tagsByNote, classifyDur)
	if err != nil {
		fatal("write worklist: %v", err)
	}
	printSummary(server, os.Getenv("SN_EMAIL"), len(tags), fetchDur, ws, *out)
}

// classify runs the gate over every note with a worker pool, and returns the verdicts
// in the notes' order. The gate is safe for concurrent use. Progress goes to stderr so
// stdout stays clean.
func classify(g *gate.Gate, notes []*snclient.NoteView, workers int) ([]gate.Verdict, time.Duration) {
	if workers < 1 {
		workers = 1
	}
	verdicts := make([]gate.Verdict, len(notes))
	jobs := make(chan int)
	var wg sync.WaitGroup
	var done int
	var mu sync.Mutex
	start := time.Now()
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				n := notes[i]
				verdicts[i] = g.Classify(gate.Note{UUID: n.UUID, Title: n.Title, Text: n.Text, Kind: noteKind(n)})
				mu.Lock()
				done++
				d := done
				mu.Unlock()
				if d%200 == 0 || d == len(notes) {
					fmt.Fprintf(os.Stderr, "\rclassified %d/%d (%.0f/s)", d, len(notes), float64(d)/time.Since(start).Seconds())
				}
			}
		}()
	}
	for i := range notes {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	fmt.Fprintln(os.Stderr)
	return verdicts, time.Since(start)
}

// noteKind mirrors mcptools.noteKind so triage classifies exactly as the read tools
// do: a token-vault or authentication note is a forced-sensitive kind.
func noteKind(n *snclient.NoteView) string {
	fold := func(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
	if fold(n.NoteType) == "authentication" || fold(n.EditorIdentifier) == "org.standardnotes.token-vault" {
		return "authentication"
	}
	return "note"
}

// entry is one worklist row. A sensitive note carries NO content: no title, snippet or
// size. Every note lists its tags (tag titles are not gated) and whether it is trashed.
type entry struct {
	UUID      string   `json:"uuid"`
	Sensitive bool     `json:"sensitive"`
	Reasons   []string `json:"reasons,omitempty"`
	Kind      string   `json:"kind,omitempty"`
	Trashed   bool     `json:"trashed,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	Title     string   `json:"title,omitempty"`    // non-sensitive only
	Snippet   string   `json:"snippet,omitempty"`  // non-sensitive only
	TextLen   int      `json:"text_len,omitempty"` // non-sensitive only
}

type stats struct {
	total, live, trashed, sensitive int
	byKind, byReason, byTag         map[string]int
	nonSensitiveBytes               int
	classifyDur                     time.Duration
}

// writeWorklist writes one JSON object per line and returns the stats. It builds a
// sensitive note's row with no content, so nothing sensitive reaches the file.
func writeWorklist(path string, notes []*snclient.NoteView, verdicts []gate.Verdict, tagsByNote map[string][]string, classifyDur time.Duration) (stats, error) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return stats{}, err
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return stats{}, err
	}
	defer f.Close()
	enc := json.NewEncoder(f)

	s := stats{byKind: map[string]int{}, byReason: map[string]int{}, byTag: map[string]int{}}
	for i, n := range notes {
		v := verdicts[i]
		kind := noteKind(n)
		e := entry{UUID: n.UUID, Sensitive: v.Sensitive, Reasons: v.Reasons, Kind: kind, Trashed: n.Trashed, Tags: tagsByNote[n.UUID]}
		if !v.Sensitive {
			e.Title = n.Title
			e.Snippet = snippet(n.Text)
			e.TextLen = len(n.Text)
			s.nonSensitiveBytes += len(n.Text)
		}
		if err := enc.Encode(e); err != nil {
			return stats{}, err
		}

		s.total++
		if n.Trashed {
			s.trashed++
		} else {
			s.live++
		}
		s.byKind[kind]++
		for _, tg := range tagsByNote[n.UUID] {
			s.byTag[tg]++
		}
		if v.Sensitive {
			s.sensitive++
			for _, r := range v.Reasons {
				s.byReason[reasonKey(r)]++
			}
		}
	}
	s.classifyDur = classifyDur
	return s, nil
}

// snippet is the first line of the text, trimmed to a short length.
func snippet(text string) string {
	t := strings.TrimSpace(text)
	if i := strings.IndexByte(t, '\n'); i >= 0 {
		t = t[:i]
	}
	const max = 120
	if len(t) > max {
		t = t[:max] + "…"
	}
	return t
}

// reasonKey collapses a reason to its signal name (the part before any colon), so
// "kind:authentication" and "scanner:aws-key" bucket by signal.
func reasonKey(r string) string {
	if i := strings.IndexByte(r, ':'); i >= 0 {
		return r[:i]
	}
	return r
}

func printSummary(server, email string, nTags int, fetchDur time.Duration, s stats, out string) {
	line := strings.Repeat("-", 64)
	fmt.Println(line)
	fmt.Printf("triage of %s  (%s)\n\n", email, server)
	fmt.Printf("  fetched:    %d notes, %d tags in %s\n", s.total, nTags, fetchDur.Round(time.Millisecond))
	perNote := time.Duration(0)
	if s.total > 0 {
		perNote = s.classifyDur / time.Duration(s.total)
	}
	fmt.Printf("  classified: %d notes in %s  (~%s/note)\n", s.total, s.classifyDur.Round(time.Millisecond), perNote.Round(time.Microsecond))
	fmt.Printf("  live: %d   trashed: %d\n", s.live, s.trashed)
	pct := 0.0
	if s.total > 0 {
		pct = 100 * float64(s.sensitive) / float64(s.total)
	}
	fmt.Printf("  SENSITIVE: %d (%.1f%%)   non-sensitive: %d\n", s.sensitive, pct, s.total-s.sensitive)
	fmt.Printf("  by kind:   %s\n", histLine(s.byKind))
	fmt.Printf("  sensitive by signal: %s\n", histLine(s.byReason))
	fmt.Printf("  top tags:  %s\n", topN(s.byTag, 10))
	fmt.Printf("  non-sensitive text: %d bytes\n", s.nonSensitiveBytes)
	fmt.Println(line)
	fmt.Printf("worklist: %s  (%d entries; sensitive rows carry no content)\n", out, s.total)
	// A rough full-run estimate for a larger vault, from the per-note classify cost.
	if s.total > 0 {
		fmt.Printf("estimate: ~%s to classify 20,000 notes at this rate (plus the one full sync)\n", (perNote * 20000).Round(time.Second))
	}
	fmt.Println(line)
}

func histLine(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, m[k]))
	}
	if len(parts) == 0 {
		return "(none)"
	}
	return strings.Join(parts, ", ")
}

// topN returns the n biggest buckets, largest first.
func topN(m map[string]int, n int) string {
	type kv struct {
		k string
		v int
	}
	pairs := make([]kv, 0, len(m))
	for k, v := range m {
		pairs = append(pairs, kv{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].v != pairs[j].v {
			return pairs[i].v > pairs[j].v
		}
		return pairs[i].k < pairs[j].k
	})
	if len(pairs) > n {
		pairs = pairs[:n]
	}
	parts := make([]string, 0, len(pairs))
	for _, p := range pairs {
		parts = append(parts, fmt.Sprintf("%s=%d", p.k, p.v))
	}
	if len(parts) == 0 {
		return "(none)"
	}
	return strings.Join(parts, ", ")
}

// connect restores the saved session named by SN_SESSION_REF when one exists, so a
// run needs no 2FA code; otherwise it signs in with SN_EMAIL/SN_PASSWORD (+SN_MFA)
// and, if a ref is set, saves the new session for next time. Read-only triage does
// not need the auto-refresh Guard: access tokens last ~30 days, far longer than a run.
// It returns a short description of which path was taken, for the log.
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
	// A rejected/expired 2FA code yields a session with no tokens and no error; catch it.
	if !c.Authenticated() {
		return nil, "", fmt.Errorf("sign in to %s: 2FA code rejected or expired — send a fresh code", cfg.Server)
	}
	if ref != "" {
		if err := c.Persist(ref); err != nil {
			fmt.Fprintf(os.Stderr, "triage: warning: could not save session %q: %v\n", ref, err)
		} else {
			return c, fmt.Sprintf("signed in and saved session %q (next run needs no code)", ref), nil
		}
	}
	return c, "signed in (no SN_SESSION_REF set; session not saved)", nil
}

// mfaFromEnv supplies a 2FA code from SN_MFA when the account needs one. A TOTP code
// expires in about 30 seconds, so set it immediately before the run.
func mfaFromEnv(prompt string) (string, error) {
	if code := strings.TrimSpace(os.Getenv("SN_MFA")); code != "" {
		return code, nil
	}
	return "", fmt.Errorf("account needs a 2FA code (%q); set SN_MFA to the current code and re-run", prompt)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "sn-triage: "+format+"\n", args...)
	os.Exit(1)
}
