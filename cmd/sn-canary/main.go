// Command sn-canary proves, against a LIVE server, that the surgical edit path
// preserves a note's metadata. It is the metadata half of the write canary.
//
// It targets ONE note by uuid and touches no other note. Steps:
//  1. record the note's ORIGINAL decrypted content (to restore it at the end);
//  2. set starred + protected (top-level) and pinned + archived (appData) via the
//     same EncryptMutated path the engine uses — these are the exact fields the
//     typed gosn-v2 path silently drops;
//  3. record the decrypted content now (flags set) = BEFORE;
//  4. edit the note's text through EditNoteText, the surgical path note_edit uses;
//  5. record the decrypted content again = AFTER;
//  6. diff BEFORE vs AFTER and assert ONLY text and client_updated_at changed, and
//     that starred/protected/pinned/archived survived byte-for-byte;
//  7. restore the note to its original text with the flags cleared.
//
// With no uuid it creates its own throwaway note and trashes it at the end. The
// -probe flag runs a gentle read-only health check instead (one read sync, no
// writes), for polling whether a rate-limited/down server is reachable again.
//
// Usage: SN_SERVER=.. SN_SESSION_REF=.. go run ./cmd/sn-canary [-probe] [note-uuid]
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jonhadfield/gosn-v2/items"
	"github.com/smirnov-labs/standard-notes-mcp/internal/snclient"
)

const snDomain = "org.standardnotes.sn"

func main() {
	probe := flag.Bool("probe", false, "read-only health probe: one read sync, report reachable / rate-limited / down; writes nothing")
	pace := flag.Duration("pace", 0, "sleep this long before each write after the create (e.g. 30s), to stay under a server write-rate limit")
	flag.Parse()

	c, how, err := connect(snclient.Config{Server: snclient.EnvServer()}, strings.TrimSpace(os.Getenv("SN_SESSION_REF")))
	if err != nil {
		fatal("%v", err)
	}
	fmt.Fprintf(os.Stderr, "canary: %s\n", how)

	// -probe: a gentle "is SN back?" check. One read sync, no writes and no throwaway,
	// so it is safe to run on a schedule against a throttling API. Build 2's backoff
	// already retries a transient 429/503 inside Fetch, so a failure here is persistent.
	if *probe {
		runProbe(c)
		return
	}

	// pause waits *pace before a write, so the canary's writes do not cluster and trip
	// a write-rate limit on a busy server. It is a no-op at the default pace of 0.
	pause := func(step string) {
		if *pace > 0 {
			fmt.Printf("pacing %s before %s...\n", *pace, step)
			time.Sleep(*pace)
		}
	}

	// Use a given note by uuid; otherwise create a throwaway note on the real vault,
	// canary THAT, and trash it at the end — so no existing note is ever touched.
	var uuid string
	createdThrowaway := false
	if flag.NArg() >= 1 {
		uuid = flag.Arg(0)
	} else {
		n, nerr := items.NewNote("sn-canary throwaway "+time.Now().UTC().Format(time.RFC3339), "canary test note — safe to delete", nil)
		if nerr != nil {
			fatal("create throwaway: %v", nerr)
		}
		n.Content.SetUpdateTime(time.Now().UTC())
		if _, perr := c.Push(items.Items{&n}); perr != nil {
			fatal("create throwaway: %v", perr)
		}
		uuid = n.GetUUID()
		createdThrowaway = true
		fmt.Printf("created throwaway note %s for the canary\n", uuid)
	}

	// 1) ORIGINAL content, kept so we can put the note back exactly.
	orig, err := c.FetchRawOne(uuid)
	if err != nil {
		fatal("fetch original: %v", err)
	}
	origContent := orig.Content()
	origText := stringField(mustObj(origContent, "original"), "text")
	fmt.Printf("target note %s\n  original text: %q\n\n", uuid, origText)

	// 2) Set the four flags the typed path would drop.
	pause("set flags")
	if err := push(c, uuid, orig, setFlags); err != nil {
		fatal("set flags: %v", err)
	}

	// 3) BEFORE = content with flags set, pre-edit.
	beforeItem, err := c.FetchRawOne(uuid)
	if err != nil {
		fatal("fetch before: %v", err)
	}
	before := beforeItem.Content()

	// 4) Edit the text through the surgical path (same as note_edit).
	newText := "edited by sn-canary at " + time.Now().UTC().Format(time.RFC3339)
	pause("edit")
	if err := c.EditNoteText(uuid, newText); err != nil {
		fatal("edit text: %v", err)
	}

	// 5) AFTER = content post-edit.
	afterItem, err := c.FetchRawOne(uuid)
	if err != nil {
		fatal("fetch after: %v", err)
	}
	after := afterItem.Content()

	// 6) Diff and assert.
	ok := diffReport(before, after)

	// 7) Restore the note to its original text, flags cleared.
	cur, err := c.FetchRawOne(uuid)
	if err != nil {
		fatal("fetch for restore: %v", err)
	}
	pause("restore")
	if err := push(c, uuid, cur, restoreMutation(origText)); err != nil {
		fatal("restore: %v", err)
	}
	restored, err := c.FetchRawOne(uuid)
	if err != nil {
		fatal("fetch after restore: %v", err)
	}
	rm := mustObj(restored.Content(), "restored")
	restoreOK := stringField(rm, "text") == origText &&
		!hasKey(rm, "starred") && !hasKey(rm, "protected") &&
		!snFlag(rm, "pinned") && !snFlag(rm, "archived")
	fmt.Printf("\nrestore: text back to original=%v, flags cleared=%v\n",
		stringField(rm, "text") == origText,
		!hasKey(rm, "starred") && !hasKey(rm, "protected") && !snFlag(rm, "pinned") && !snFlag(rm, "archived"))

	if createdThrowaway {
		cur, terr := c.FetchRawOne(uuid)
		if terr != nil {
			fatal("fetch for trash: %v", terr)
		}
		pause("trash")
		if terr := push(c, uuid, cur, func(m map[string]json.RawMessage) error {
			m["trashed"] = json.RawMessage(`true`)
			return nil
		}); terr != nil {
			fatal("trash throwaway: %v", terr)
		}
		fmt.Printf("throwaway note %s trashed (reversible)\n", uuid)
	}

	if ok && restoreOK {
		fmt.Println("\nPASS: the edit preserved starred/protected/pinned/archived; only text and client_updated_at changed; note restored.")
		return
	}
	fmt.Println("\nFAIL")
	os.Exit(1)
}

// runProbe does one read sync and reports whether SN is reachable. It writes
// nothing. It exits non-zero when the sync fails, classifying 429 (reachable but
// throttling) and 503 (down) so a watcher can tell recovery from an outage.
func runProbe(c *snclient.Client) {
	notes, tags, err := c.Fetch()
	if err != nil {
		msg := err.Error()
		switch {
		case strings.Contains(msg, "429"):
			fmt.Println("PROBE: SN rate-limited (429) — reachable but still throttling; not clear yet")
		case strings.Contains(msg, "503"):
			fmt.Println("PROBE: SN unavailable (503) — still down")
		default:
			fmt.Printf("PROBE: read sync failed: %v\n", err)
		}
		os.Exit(1)
	}
	fmt.Printf("PROBE OK: SN answered a read sync (%d notes, %d tags) — the API is reachable again.\n", len(notes), len(tags))
}

// push applies mutate to the fetched item and writes it, checking it saved.
func push(c *snclient.Client, uuid string, r *snclient.RawNote, mutate func(map[string]json.RawMessage) error) error {
	enc, err := c.EncryptMutated(r, mutate)
	if err != nil {
		return err
	}
	out, err := c.PushEncrypted(items.EncryptedItems{enc})
	if err != nil {
		return err
	}
	return snclient.RequireSaved(out, uuid)
}

// setFlags adds the four fields the typed gosn-v2 path drops, in the locations the
// official app uses: starred and protected at the top level, pinned and archived
// inside appData[org.standardnotes.sn]. It keeps every existing appData key.
func setFlags(m map[string]json.RawMessage) error {
	m["starred"] = json.RawMessage(`true`)
	m["protected"] = json.RawMessage(`true`)
	appData := childObject(m, "appData")
	sn := childObject(appData, snDomain)
	sn["pinned"] = json.RawMessage(`true`)
	sn["archived"] = json.RawMessage(`true`)
	return nestBack(m, appData, sn)
}

// restoreMutation sets the text back to orig and removes the four flags.
func restoreMutation(origText string) func(map[string]json.RawMessage) error {
	return func(m map[string]json.RawMessage) error {
		b, err := json.Marshal(origText)
		if err != nil {
			return err
		}
		m["text"] = b
		delete(m, "starred")
		delete(m, "protected")
		appData := childObject(m, "appData")
		sn := childObject(appData, snDomain)
		delete(sn, "pinned")
		delete(sn, "archived")
		return nestBack(m, appData, sn)
	}
}

// nestBack writes sn into appData[snDomain] and appData into m["appData"].
func nestBack(m, appData, sn map[string]json.RawMessage) error {
	snb, err := json.Marshal(sn)
	if err != nil {
		return err
	}
	appData[snDomain] = snb
	adb, err := json.Marshal(appData)
	if err != nil {
		return err
	}
	m["appData"] = adb
	return nil
}

// diffReport prints a per-key comparison and returns whether only the expected
// fields changed: text at the top level, client_updated_at inside appData.sn.
func diffReport(before, after string) bool {
	b := mustObj(before, "before")
	a := mustObj(after, "after")
	ok := true

	fmt.Println("top-level content keys (before edit -> after edit):")
	for _, k := range sortedUnion(b, a) {
		bv, inB := b[k]
		av, inA := a[k]
		switch {
		case inB && !inA:
			fmt.Printf("  DROPPED  %-12s  <- FAIL\n", k)
			ok = false
		case !inB && inA:
			fmt.Printf("  ADDED    %-12s  <- FAIL\n", k)
			ok = false
		case k == "text":
			fmt.Printf("  changed  %-12s  (expected)\n", k)
		case k == "appData":
			if !diffAppData(bv, av) {
				ok = false
			}
		case bytes.Equal(bv, av):
			fmt.Printf("  kept     %-12s = %s\n", k, string(av))
		default:
			fmt.Printf("  CHANGED  %-12s  %s -> %s  <- FAIL\n", k, string(bv), string(av))
			ok = false
		}
	}

	// Explicit assertions: the four flags must be present and true after the edit.
	for _, k := range []string{"starred", "protected"} {
		if string(a[k]) != "true" {
			fmt.Printf("  ASSERT FAIL: top-level %s is not true after edit (got %q)\n", k, string(a[k]))
			ok = false
		}
	}
	if !snFlag(a, "pinned") {
		fmt.Println("  ASSERT FAIL: appData.sn.pinned is not true after edit")
		ok = false
	}
	if !snFlag(a, "archived") {
		fmt.Println("  ASSERT FAIL: appData.sn.archived is not true after edit")
		ok = false
	}
	return ok
}

// diffAppData compares the appData objects. Every domain must match byte-for-byte
// except org.standardnotes.sn, where only client_updated_at may change.
func diffAppData(before, after json.RawMessage) bool {
	b := mustObj(string(before), "before.appData")
	a := mustObj(string(after), "after.appData")
	ok := true
	fmt.Println("  appData:")
	for _, dom := range sortedUnion(b, a) {
		if dom != snDomain {
			if bytes.Equal(b[dom], a[dom]) {
				fmt.Printf("    kept domain %s\n", dom)
			} else {
				fmt.Printf("    CHANGED domain %s  <- FAIL\n", dom)
				ok = false
			}
			continue
		}
		sb := mustObj(string(b[dom]), "before.sn")
		sa := mustObj(string(a[dom]), "after.sn")
		for _, k := range sortedUnion(sb, sa) {
			switch {
			case k == "client_updated_at":
				fmt.Printf("    sn.%-18s changed (expected)\n", k)
			case bytes.Equal(sb[k], sa[k]):
				fmt.Printf("    sn.%-18s = %s kept\n", k, string(sa[k]))
			default:
				fmt.Printf("    sn.%-18s %s -> %s  <- FAIL\n", k, string(sb[k]), string(sa[k]))
				ok = false
			}
		}
	}
	return ok
}

// --- small JSON helpers ---

func mustObj(raw, what string) map[string]json.RawMessage {
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &m); err != nil || m == nil {
		fatal("%s is not a JSON object: %v", what, err)
	}
	return m
}

// childObject returns m[key] as an object, or a fresh empty one.
func childObject(m map[string]json.RawMessage, key string) map[string]json.RawMessage {
	child := map[string]json.RawMessage{}
	if raw := m[key]; len(raw) > 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &child); err != nil {
			fatal("%s is not a JSON object: %v", key, err)
		}
	}
	return child
}

func stringField(m map[string]json.RawMessage, key string) string {
	var s string
	if raw, ok := m[key]; ok {
		_ = json.Unmarshal(raw, &s)
	}
	return s
}

func hasKey(m map[string]json.RawMessage, key string) bool {
	_, ok := m[key]
	return ok
}

// snFlag reports whether appData.org.standardnotes.sn[flag] is JSON true.
func snFlag(content map[string]json.RawMessage, flag string) bool {
	appData := childObject(content, "appData")
	sn := childObject(appData, snDomain)
	return string(sn[flag]) == "true"
}

func sortedUnion(a, b map[string]json.RawMessage) []string {
	seen := map[string]bool{}
	for k := range a {
		seen[k] = true
	}
	for k := range b {
		seen[k] = true
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// connect restores the saved session named by SN_SESSION_REF (code-free) or signs in
// with SN_EMAIL/SN_PASSWORD(+SN_MFA). Mirrors sn-triage / sn-export-diary.
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

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "CANARY FAILED: "+format+"\n", args...)
	os.Exit(1)
}
