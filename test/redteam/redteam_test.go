// Package redteam is the privacy red-team of the read MCP. It is the acceptance gate
// of Plan 2a. The question: can the orchestrator (Claude) learn what a sensitive
// note says, through any read tool? The answer has to be no.
//
// The live test plants real-looking secrets in a throwaway account. It then calls
// every read tool the way the orchestrator does, with the real gate, and keeps the
// JSON of every result. That JSON is what the MCP layer sends, so it is the only
// thing worth checking. A check on the fields that a test thought to read would miss
// a field that it did not think of. The test then looks for every sensitive title,
// body and telltale in that JSON.
//
// Four things keep the check honest.
//
//   - A leak can hide in JSON escapes. JSON writes a newline as \n and an & as a
//     Unicode escape, so a PEM key or an otpauth URL does not match as it is. Each
//     needle is tried in three forms (plain, JSON-escaped, whitespace collapsed)
//     against two views of the output (the JSON text, and its string values after
//     decoding).
//   - A leak can be partial: a snippet cuts the text. The check also looks for every
//     12-byte piece of each sensitive title and body.
//   - A check that cannot fail proves nothing. TestLeakDetectorFindsLeaks gives the
//     checker leaks that it must find and clean results that it must pass.
//   - A test that reads nothing proves nothing. Each sensitive note must come back as
//     a bare stub, each search must return the notes that it should, and the notes
//     that the gate clears must read through.
//
// Every secret here has a shape that tier 0 (the scanner) or the note kind catches
// with no help from jev, so the leak checks do not depend on nimble. The live test
// shows that: it runs the whole battery twice, once with the real gate and once with
// a jev that rates every note "not sensitive".
//
// What this test does not cover, on purpose:
//
//   - Search keeps a stub for a sensitive note that matches (spec 5.1), and this test
//     asserts that the stub is bare. The stub holds no content, but it tells the
//     caller that a sensitive note holds the query. That is a match oracle: a caller
//     that can search without limit can probe a note's text, one query at a time.
//     The comment on mcptools.Search leaves the decision to this red-team. The
//     red-team does not make it. No title, body or snippet is returned, so nothing
//     leaks by the rule that this test checks. But the oracle needs a human decision
//     before the tool reads a real vault.
//   - tags_list is not gated (Plan 2a). A tag title and its note uuids come back as
//     they are. The tags here are plain words, so the test checks only that no note
//     content rides on them.
//   - The deny rules are enforced by Claude Code, not by this repo (config/README.md,
//     section 4). TestSampleSettingsHoldTheCapabilityRules checks that they exist.
//   - The MCP transport. cmd/sn-mcp's own test drives the real binary over stdio. This
//     test calls the tools and marshals what they return, as the SDK does.
package redteam

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jonhadfield/gosn-v2/items"
	"github.com/smirnov-labs/standard-notes-mcp/internal/gate"
	"github.com/smirnov-labs/standard-notes-mcp/internal/mcptools"
	"github.com/smirnov-labs/standard-notes-mcp/internal/snclient"
	"github.com/smirnov-labs/standard-notes-mcp/internal/testsupport"
)

const (
	threshold = 0.5 // the gate threshold that cmd/sn-mcp uses

	unknownUUID = "00000000-0000-4000-8000-000000000000"

	// The ids that make an Authenticator note. Both come from Standard Notes'
	// @standardnotes/features. mcptools forces such a note to be a stub.
	noteTypeAuthentication = "authentication"
	editorTokenVault       = "org.standardnotes.token-vault"
)

// jevURL is where the gate finds jev: local nimble, or TYPESAFE_BASE_URL, as in
// cmd/sn-mcp and the gate's own jev test. A URL that nothing listens on is a way to
// try the test with jev down.
func jevURL() string {
	if base := os.Getenv("TYPESAFE_BASE_URL"); base != "" {
		return base
	}
	return "http://127.0.0.1:11434"
}

// jevSaysSafe is a jev that rates every note 0. With it, only the scanner and the
// note kind can stub a note. (gate.New takes an unexported interface. A value of any
// type with this method satisfies it.)
type jevSaysSafe struct{}

func (jevSaysSafe) SensitiveProbability(string) (float64, error) { return 0, nil }

// ---- the notes the test plants ----

// note is a note that the test plants. A sensitive note has telltales.
type note struct {
	name        string // for failure messages
	title, body string
	telltales   []string // pieces that give the secret away on their own
	// authenticator marks the note as an Authenticator note. Its words are plain, so
	// only the note kind can stub it.
	authenticator bool
	trashed       bool
}

// All of these are fixtures, not real credentials. The PEM body is random bytes. The
// AWS, card, OTP, JWT and seed-phrase values are the public examples from their
// documentation or specs. The tokens are random strings of the right shape.
const (
	// The BIP-39 test vector for all-zero entropy. It is a fixture, not a wallet.
	seedPhrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

	pemKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAJLZtmcloKK40WDbtUZVLWJLtgBuHN/Dbw8r2PUFHicg3ih2j
x/iwaMONIMvcdJUbJwTfF5EAGSMRfo2sLKOztZ9a4MrkGF4XV+IPjEGqgMyR4NjY
3S6adf1iQ+b8ilU9WJRk8FX76+s71PdkzaNiE/IX/bIKSywHzp9Za+FIEx/YbNaz
XeDcd/l4gBH/2z0zonqOxgPR/9gioCmP3HkXnMPJXFKVHprBDfyIW9P7919Ww6D6
iM51de7uZYsrtlsjHrs8NIgoi9YaznpAHLaRdKpAFh2cq3gTx7Wl7WrAsQ2RuKS6
wXeBAe6UzzdwaMy10IRAuOAyB5EdgAk9zDNpUPsqQVwzDPULa0y8sXgSoG0U93mV
hR1rJggWJC8IMVot74MBuNzT6/0FfuB06myr2WckFbXwx0wM+N1IAInuliC4rzzC
Rh3YrMJBJy4Du1ZhZ+o5j5dNnY7mDdvwOWILElVUj9kudYywUYA38laijt+W30tI
ugFVsuxhinq7CHbvtbabBCwxuZqv+WkHjhaVDYB6KblS31b3H9Z37xhuZYvvjjyD
4xTKzDEnbRiBHDfVcm656zDQW88TwcRXfBh0DuieS9xPU53O983NdShOwEfysAz5
Qd0HVJbev9Ai8ULslbDy6udEXnFLWDIFuZQJeFWaAmHvw5cSbfd27fqSqxHbA7y0
s+EalRIzookGUEuvQAWQwskWy8XHMpw90cSFsHPNoJV9KyFsLvcEgP4adswbxuRx
OrVl4epyowP9M1kgKojiWwCgLbxyQrFmu7l49y6Bh+0kFz6Kpuzd6pdOqJJ9A2Js
bniwXKNo8h/IH5Mfb/npCo3mjq76QvYqMGuybtPsHnKrU5kGuGbi+fyuNak2pDW2
jY/juixsvPTkx8xk+niwzzGY1bM09czzA4Gkwu7auWMdLPi7RKjUaVzfTPDkYgNK
vo/pn34Ps8VV1BM4CZ8zKhclJWDIruBKHGf4RGAORFoHEO162TKuYr7GNdOtq7DU
0jQGKGl5qOFxWM0DFCdwz0kVBPrLRs+BUAAjH2elZSRHAekFASXOS2R4+Oy9JCff
n+h/qRDd+2/sExbTfIdjW0qwC5Wop8Fqlec63sTlrRVMuLpzbwyBdPIJJY7wphWb
jBpcDnNaMsA5nMM5ypCwYjPSLR+u4orsOeC8nIyKrpaHFLAGqB1KXYnCUW239oLj
rVBbMro/AQMbOh+0s8SfhRIINzUfg3Arl6erpGa0XA4q9Fn8jrxwkTfI56QFY8ej
5VYAat3udHwC7Ko6eZjEC036C0egdCLyV6xredkXYEgkqlNQEov7vhnZaL5q9jY2
k2i15R06u1zHauceMSPbBIqnPfCYyenJ7FS3SD8yyZr5rvEJJw4y70CPuMCjos0a
Xzn1eQ8Go/FKNOtJDVTBYpcPGkJeocQbl32eDOPv85zp5aQ/dWmw4Oht+wxDVt7m
/FxPBhsPcgwzh6142kuS8Ick9DGD0F+1asFphqcQA8LGz8e2guxOF2/Ms2ARQbU2
NZ0oZ2B0ZXM0U0lkB6ahCWCZkFDxb0XzR+veoIzO2bF4EHUu9bbIz/q/AVnotmPs
NxDEr5ZMJ9jES3Rr43/dc1leHOD7ULxAhd4t8SZzeg8A2cYbCPpv7qSKu/XTlLCs
Gitn+TG3DPoLe3aa4uiv4Y1TrweXgSGuO+Z2YQds
-----END RSA PRIVATE KEY-----`

	jwtToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiJ1c2VyLTQyIiwicm9sZSI6ImFkbWluIiwiZXhwIjoxODkzNDU2MDAwfQ." +
		"e-OFbNffuYMwKhDkOyRie6DJ6rCJKX83MHdgwt_ilUO"

	filler = "We reviewed the hiring plan, the budget and the office move. "
)

// numbered writes a seed phrase as a list, one word to a line, as people copy it down.
func numbered(phrase string) string {
	var b strings.Builder
	for i, w := range strings.Fields(phrase) {
		fmt.Fprintf(&b, "%d. %s\n", i+1, w)
	}
	return strings.TrimSpace(b.String())
}

// sensitive is every note that must never leak. Titles look plain on purpose: the
// title of a sensitive note is withheld too, even when the title itself says nothing.
var sensitive = []note{
	{name: "pem", title: "deploy box ssh key", body: pemKey,
		telltales: []string{"BEGIN RSA PRIVATE KEY", "MIIEowIBAAKCAQEAJLZtmcloKK40", "Gitn+TG3DPoLe3aa4uiv4Y1TrweXgSGuO+Z2YQds"}},
	{name: "aws-key", title: "AWS prod keys",
		body:      "Console login for the prod account.\naccess key id: AKIAIOSFODNN7EXAMPLE\nregion: eu-west-1",
		telltales: []string{"AKIAIOSFODNN7EXAMPLE"}},
	{name: "card", title: "Visa test card",
		body:      "Card: 4111 1111 1111 1111\nExpiry 12/29\nName: V. Tester",
		telltales: []string{"4111 1111 1111 1111", "4111111111111111"}},
	{name: "otp", title: "GitHub 2FA",
		body:      "otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
		telltales: []string{"JBSWY3DPEHPK3PXP", "otpauth://totp/GitHub"}},
	// The gap that Plan 2a closed: a BIP-39 seed phrase. It has no marker and no
	// high-entropy token. Only the checksum finds it. A phrase on one line, and one
	// written down as a list.
	{name: "seed-phrase", title: "recovery words", body: seedPhrase,
		telltales: []string{seedPhrase, "abandon abandon abandon", "abandon about"}},
	{name: "seed-list", title: "backup list", body: numbered(seedPhrase),
		telltales: []string{"1. abandon", "12. about"}},
	{name: "github-token", title: "CI token", body: "ghp_EoUct7L5T5UoQbNmm89y31yTqBik4aOICsjQ",
		telltales: []string{"ghp_EoUct7L5T5UoQbNmm89y31yTqBik4aOICsjQ"}},
	{name: "jwt", title: "staging bearer", body: "Authorization: Bearer " + jwtToken,
		telltales: []string{jwtToken, "e-OFbNffuYMwKhDkOyRie6DJ6rCJKX83MHdgwt_ilUO", "eyJzdWIiOiJ1c2VyLTQyIiwicm9sZSI6ImFkbWluIiwiZXhwIjoxODkzNDU2MDAwfQ"}},
	{name: "postgres-dsn", title: "local postgres",
		body:      "docker compose db:\npostgres://user:s3cretpw@host/db",
		telltales: []string{"s3cretpw", "postgres://user:s3cretpw@host/db"}},
	// The labeled form of an AWS secret. A bare 40-character secret with no label is a
	// documented tier-0 limit that jev backs up, so it is not planted here.
	{name: "aws-secret", title: "aws creds (old laptop)",
		body:      "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		telltales: []string{"wJalrXUtnFEMI", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}},
	// The secret is in the title, and the body is plain.
	{name: "title-only", title: "AKIAI44QH8DHBEXAMPLE", body: "work account",
		telltales: []string{"AKIAI44QH8DHBEXAMPLE"}},
	// The words are plain. Only the Authenticator note type and editor id stub it.
	{name: "authenticator", title: "Authenticator codes", body: "kiwi-basalt-31 accounts",
		telltales: []string{"kiwi-basalt-31"}, authenticator: true},
	// A trashed note is not listed or searched, but notes_get still reads it by uuid.
	{name: "trashed", title: "retired stripe key", body: "sk_live_6LOwzeCOwBqXE80t65ajtjWY",
		telltales: []string{"sk_live_6LOwzeCOwBqXE80t65ajtjWY"}, trashed: true},
	// A long note with the secret at the very end. The scanner must read all of it.
	{name: "long-note", title: "meeting minutes 2026", body: strings.Repeat(filler, 650) + "\nglpat-7DW0p5TYILgp9xaqiTGX",
		telltales: []string{"glpat-7DW0p5TYILgp9xaqiTGX", "We reviewed the hiring plan"}},
}

// benign are notes that the gate clears. They show that the tools read something.
var benign = []note{
	{name: "shopping", title: "Shopping", body: "milk and eggs"},
	{name: "roadmap", title: "Roadmap", body: "ship the thing in Q3"},
}

// queries are what the orchestrator asks notes_search. Most are terms that the
// sensitive notes hold, in a title or in a body. A search that matches a secret must
// not show it.
var queries = []string{
	// terms in the sensitive notes
	"keys", "key", "AKIA", "abandon", "about", "postgres", "aws", "card", "ssh", "BEGIN", "PRIVATE KEY",
	"otpauth", "JBSWY3", "ghp_", "eyJ", "Bearer", "s3cretpw", "wJalr", "4111", "secret", "token",
	"password", "stripe", "glpat", "Authenticator", "recovery", "work account", "  AKIA  ",
	// a whole secret as the query
	"AKIAIOSFODNN7EXAMPLE", "4111 1111 1111 1111", seedPhrase,
	// case does not matter
	"akia", "ABANDON",
	// the query is literal text, so none of these may match everything
	".*", "(?s).", "[a-z]", "%",
	// a one-letter query matches almost every note
	"e",
	// terms in the notes that the gate clears, and a miss
	"milk", "Roadmap", "ship the thing", "Q3", "no-such-term-xyzzy",
}

// walkPage is the page size of the paged walk through notes_list.
const walkPage = 5

// ---- what the orchestrator receives ----

// capture is the output of one tool call, in the two views that the checks use.
type capture struct {
	call string
	// raw is the JSON that the orchestrator receives, byte for byte. For an error it
	// is the error text.
	raw string
	// decoded holds the string values in raw, unescaped, with whitespace collapsed,
	// joined by NUL. A NUL joins them so that no needle can match across two values.
	decoded string
}

func newCapture(t testing.TB, call string, v any) capture {
	t.Helper()
	raw := wire(t, v)
	var doc any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("%s: the result is not JSON: %v", call, err)
	}
	var vals []string
	var walk func(any)
	walk = func(v any) {
		switch v := v.(type) {
		case string:
			vals = append(vals, collapse(v))
		case []any:
			for _, e := range v {
				walk(e)
			}
		case map[string]any:
			for _, e := range v {
				walk(e)
			}
		}
	}
	walk(doc)
	return capture{call: call, raw: raw, decoded: strings.Join(vals, "\x00")}
}

func errCapture(call string, err error) capture {
	return capture{call: call, raw: err.Error(), decoded: collapse(err.Error())}
}

// wire is a result as the MCP layer sends it: the SDK marshals the value that a tool
// returns to JSON.
func wire(t testing.TB, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// collapse turns every run of whitespace into one space. A snippet does the same.
func collapse(s string) string { return strings.Join(strings.Fields(s), " ") }

// jsonEscape is s as JSON writes it inside a string: \n for a newline, and a Unicode
// escape for an &.
func jsonEscape(s string) string {
	b, _ := json.Marshal(s)
	return string(b[1 : len(b)-1])
}

// ---- the leak check ----

// needle is one string that must be in no output.
type needle struct{ note, kind, text string }

// minNeedle is the shortest needle. A shorter one could match by chance.
const minNeedle = 8

// needles lists everything of the note that must not leave: its title, its body,
// each line of its body and each telltale.
func (n note) needles() []needle {
	out := []needle{{n.name, "title", n.title}, {n.name, "body", n.body}}
	for line := range strings.SplitSeq(n.body, "\n") {
		if line = strings.TrimSpace(line); len(line) >= minNeedle {
			out = append(out, needle{n.name, "body line", line})
		}
	}
	for _, t := range n.telltales {
		out = append(out, needle{n.name, "telltale", t})
	}
	return out
}

// fragmentLen is the length of the pieces that the partial-leak check looks for.
const fragmentLen = 12

// fragments indexes every fragmentLen-byte piece of each title and body, with
// whitespace collapsed as a snippet collapses it. Any cut of a sensitive text that
// is at least that long holds one of these pieces.
func fragments(secrets []note) map[string]needle {
	out := map[string]needle{}
	for _, s := range secrets {
		for _, p := range [...]struct{ kind, text string }{{"title", s.title}, {"body", s.body}} {
			c := collapse(p.text)
			for i := 0; i+fragmentLen <= len(c); i++ {
				out[c[i:i+fragmentLen]] = needle{s.name, "fragment of the " + p.kind, c[i : i+fragmentLen]}
			}
		}
	}
	return out
}

// holds reports whether the output has text in any form: plain, JSON-escaped or
// collapsed, in the JSON or in its decoded values.
func (c capture) holds(text string) bool {
	return c.where(text) != ""
}

// where returns a piece of the output around text, or "" when text is not in it.
func (c capture) where(text string) string {
	for _, view := range [...]string{c.raw, c.decoded} {
		for _, form := range [...]string{text, jsonEscape(text), collapse(text)} {
			if form == "" {
				continue
			}
			if i := strings.Index(view, form); i >= 0 {
				end := i + min(len(form), 120) + 60
				return "…" + view[max(0, i-60):min(len(view), end)] + "…"
			}
		}
	}
	return ""
}

// leak is one sensitive note that shows in the output of one call.
type leak struct {
	call, note string
	kinds      []string // which of the note's strings showed
	example    string   // the first string that showed
	context    string   // the output around it
}

// findLeaks looks for every needle of every sensitive note in every capture. It
// returns one leak for each call and note that shows.
func findLeaks(secrets []note, caps []capture) []leak {
	var needles []needle
	for _, s := range secrets {
		needles = append(needles, s.needles()...)
	}
	grams := fragments(secrets)

	var out []leak
	for _, c := range caps {
		hits := map[string]*leak{}
		hit := func(n needle) {
			l := hits[n.note]
			if l == nil {
				l = &leak{call: c.call, note: n.note, example: n.text, context: c.where(n.text)}
				hits[n.note] = l
			}
			if !slices.Contains(l.kinds, n.kind) {
				l.kinds = append(l.kinds, n.kind)
			}
		}
		for _, n := range needles {
			if c.holds(n.text) {
				hit(n)
			}
		}
		for i := 0; i+fragmentLen <= len(c.decoded); i++ {
			if n, ok := grams[c.decoded[i:i+fragmentLen]]; ok {
				hit(n)
			}
		}
		for _, s := range secrets { // in the order of the notes, so the report is stable
			if l := hits[s.name]; l != nil {
				out = append(out, *l)
			}
		}
	}
	return out
}

func ptr[T any](v T) *T { return &v }

func stubRow(uuid string) mcptools.Row { return mcptools.Row{Stub: ptr(gate.Stub(uuid))} }

// ---- tests that need no server ----

// The leak checks assume that tier 0 or the note kind stubs every secret above, with
// no help from jev. This test checks that, on the gate's real scanner, so a gap shows
// here, by name, and not as a leak that only a nimble outage would expose.
func TestSeedsAreCaughtWithoutJev(t *testing.T) {
	for _, n := range sensitive {
		t.Run(n.name, func(t *testing.T) {
			for _, nd := range n.needles() {
				if len(nd.text) < minNeedle {
					t.Errorf("the %s %q is shorter than %d bytes: it could match by chance", nd.kind, nd.text, minNeedle)
				}
			}
			r := gate.Scan(n.title + "\n" + n.body) // the gate scans the title and the body as one text
			if n.authenticator {
				if r.Sensitive {
					t.Errorf("the scanner flags the %s note (%v), so it no longer isolates the note kind: use plainer words", n.name, r.Reasons)
				}
				v := gate.New(jevSaysSafe{}, threshold).Classify(gate.Note{Title: n.title, Text: n.body, Kind: "authentication"})
				if !v.Sensitive {
					t.Errorf("the gate does not stub an authentication note: %+v", v)
				}
				return
			}
			if !r.Sensitive {
				t.Fatalf("tier 0 misses the %s note: it would depend on jev, and leak when jev is down", n.name)
			}
			t.Logf("%s: tier 0 flags it by %s", n.name, strings.Join(r.Reasons, ", "))
		})
	}
	for _, n := range benign {
		if r := gate.Scan(n.title + "\n" + n.body); r.Sensitive {
			t.Errorf("tier 0 flags the benign note %q (%v)", n.name, r.Reasons)
		}
	}
}

// A check that cannot fail proves nothing. Feed the checker the output that the
// tools would give if the gate failed, in every shape that a leak takes. It has to
// find each one. Then feed it the output of a gate that works. It must find nothing.
func TestLeakDetectorFindsLeaks(t *testing.T) {
	const id = "00000000-0000-4000-8000-00000000000a"
	for _, n := range sensitive {
		t.Run(n.name, func(t *testing.T) {
			cut := collapse(n.body)
			mid := cut[len(cut)/3 : min(len(cut), len(cut)/3+60)]
			leaks := map[string]any{
				"notes_get with the note": mcptools.GetResult{Note: &mcptools.NoteDetail{UUID: id, Title: n.title, Text: n.body}},
				"a row with the title":    mcptools.RowSet{Rows: []mcptools.Row{{Note: &mcptools.NoteRow{UUID: id, Title: n.title}}}},
				"a row with the snippet":  mcptools.RowSet{Rows: []mcptools.Row{{Note: &mcptools.NoteRow{UUID: id, Title: "x", Snippet: cut[:min(len(cut), 160)] + "…"}}}},
			}
			if len(mid) >= fragmentLen {
				leaks["a snippet from the middle"] = mcptools.RowSet{Rows: []mcptools.Row{{Note: &mcptools.NoteRow{UUID: id, Title: "x", Snippet: "…" + mid + "…"}}}}
			}
			for name, v := range leaks {
				got := findLeaks([]note{n}, []capture{newCapture(t, name, v)})
				if len(got) != 1 {
					t.Errorf("%s: the checker found %d leaks, want 1", name, len(got))
				}
			}
			// The whole note, with its JSON escapes, must match as a body, and not only
			// through a telltale. The decoded view is what finds a multi-line body.
			got := findLeaks([]note{n}, []capture{newCapture(t, "notes_get", leaks["notes_get with the note"])})
			if len(got) == 1 && !slices.Contains(got[0].kinds, "body") {
				t.Errorf("notes_get with the note: the checker did not match the body, only %v", got[0].kinds)
			}
		})
	}

	stub := gate.Stub(id)
	clean := map[string]any{
		"a stub row":          mcptools.RowSet{Rows: []mcptools.Row{stubRow(id)}},
		"a stub from get":     mcptools.GetResult{Stub: &stub},
		"a note that is fine": mcptools.RowSet{Rows: []mcptools.Row{{Note: &mcptools.NoteRow{UUID: id, Title: "Shopping", Snippet: "milk and eggs"}}}},
		"a tag":               mcptools.TagList{Tags: []mcptools.TagRow{{UUID: id, Title: "work", NoteUUIDs: []string{id}}}},
		"an empty page":       mcptools.RowSet{Rows: []mcptools.Row{}},
	}
	for name, v := range clean {
		if got := findLeaks(sensitive, []capture{newCapture(t, name, v)}); len(got) != 0 {
			t.Errorf("%s: the checker reports a leak in clean output: %+v", name, got)
		}
	}
	for _, text := range []string{"note not found", "query is empty", "query is longer than 256 bytes"} {
		if got := findLeaks(sensitive, []capture{errCapture("an error", fmt.Errorf("%s", text))}); len(got) != 0 {
			t.Errorf("the checker reports a leak in the error %q: %+v", text, got)
		}
	}
}

// The capability half of the boundary. The rules that keep Claude's own tools out of
// the data folder must be in the sample. The live enforcement is Claude Code's job
// (config/README.md, section 4). This test only checks that the rules exist. It needs
// no server.
func TestSampleSettingsHoldTheCapabilityRules(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "config", "settings.sample.json"))
	if err != nil {
		t.Fatal(err)
	}
	var settings struct {
		Permissions struct {
			Deny  []string `json:"deny"`
			Allow []string `json:"allow"`
		} `json:"permissions"`
	}
	if err := json.Unmarshal(raw, &settings); err != nil {
		t.Fatalf("settings.sample.json is not valid JSON: %v", err)
	}
	deny, allow := settings.Permissions.Deny, settings.Permissions.Allow

	// <DATA_PATH> is a placeholder, so the match is on the shape of the rule: a tool,
	// an absolute path (the leading //), and the whole folder below it (/**).
	for _, tool := range []string{"Read", "Bash"} {
		prefix := tool + "(//"
		if !slices.ContainsFunc(deny, func(rule string) bool {
			return strings.HasPrefix(rule, prefix) && strings.HasSuffix(rule, "/**)")
		}) {
			t.Errorf("permissions.deny has no %s…/**) rule that keeps %s out of the data folder: %q", prefix, tool, deny)
		}
	}
	for _, name := range []string{"notes_search", "notes_list", "notes_get", "tags_list"} {
		if want := "mcp__standard-notes__" + name; !slices.Contains(allow, want) {
			t.Errorf("permissions.allow does not hold %q: %q", want, allow)
		}
	}
}

// ---- the live red-team ----

// planted is a note that is in the account.
type planted struct {
	note
	uuid   string
	secret bool // a sensitive note
}

// vault is what the test planted.
type vault struct {
	notes  []planted           // the sensitive notes first, then the benign ones
	byUUID map[string]planted  // the same notes, by uuid
	tags   map[string][]string // tag title -> the names of its notes
}

func (v vault) named(name string) planted {
	for _, p := range v.notes {
		if p.name == name {
			return p
		}
	}
	panic("redteam: no planted note named " + name)
}

// live are the planted notes that are not trashed: the ones that List and Search show.
func (v vault) live() []planted {
	var out []planted
	for _, p := range v.notes {
		if !p.trashed {
			out = append(out, p)
		}
	}
	return out
}

// liveUUIDs are the uuids of the live notes, in the order that the tools use.
func (v vault) liveUUIDs() []string {
	var out []string
	for _, p := range v.live() {
		out = append(out, p.uuid)
	}
	slices.Sort(out)
	return out
}

// holding are the uuids of the live notes whose title or body holds query, ignoring
// case, in the order that the tools use. This is what notes_search has to return,
// as stubs for the sensitive notes. If notes_search ever stops giving a stub for a
// sensitive match, change this model and the stub check with it.
func (v vault) holding(query string) []string {
	q := strings.ToLower(strings.TrimSpace(query))
	var out []string
	for _, p := range v.live() {
		if strings.Contains(strings.ToLower(p.title), q) || strings.Contains(strings.ToLower(p.body), q) {
			out = append(out, p.uuid)
		}
	}
	slices.Sort(out)
	return out
}

func (v vault) secrets() []note {
	var out []note
	for _, p := range v.notes {
		if p.secret {
			out = append(out, p.note)
		}
	}
	return out
}

// liveSecrets counts the sensitive notes that List and Search show.
func (v vault) liveSecrets() int {
	n := 0
	for _, p := range v.live() {
		if p.secret {
			n++
		}
	}
	return n
}

// plant puts every note and two tags in the account.
func plant(t *testing.T, c *snclient.Client) vault {
	t.Helper()
	v := vault{byUUID: map[string]planted{}}
	for _, group := range [...]struct {
		notes  []note
		secret bool
	}{{sensitive, true}, {benign, false}} {
		for _, n := range group.notes {
			p := planted{note: n, uuid: push(t, c, n), secret: group.secret}
			v.notes = append(v.notes, p)
			v.byUUID[p.uuid] = p
		}
	}
	// Tags over a readable note and a sensitive one. A tag holds uuids, not content.
	v.tags = map[string][]string{"work": {"roadmap", "aws-key"}, "personal": {"shopping", "card"}}
	for title, names := range v.tags {
		tag, err := c.NewTag(title)
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, name := range names {
			ids = append(ids, v.named(name).uuid)
		}
		c.SetTagRefs(tag, ids)
		if _, err := c.Push(c.RawTag(tag)); err != nil {
			t.Fatalf("push tag %q: %v", title, err)
		}
	}
	return v
}

// push creates one note and returns its uuid. A plain note goes through SeedNote.
// A note with a type, an editor or a trashed flag needs its content set first.
func push(t *testing.T, c *snclient.Client, n note) string {
	t.Helper()
	if !n.authenticator && !n.trashed {
		id, err := c.SeedNote(t, n.title, n.body)
		if err != nil {
			t.Fatalf("seed %s: %v", n.name, err)
		}
		return id
	}
	nt, err := items.NewNote(n.title, n.body, nil)
	if err != nil {
		t.Fatalf("new note %s: %v", n.name, err)
	}
	if n.authenticator {
		nt.Content.NoteType, nt.Content.EditorIdentifier = noteTypeAuthentication, editorTokenVault
	}
	if n.trashed {
		nt.Content.SetTrashed(true)
	}
	nt.Content.SetUpdateTime(time.Now().UTC())
	if _, err := c.Push(items.Items{&nt}); err != nil {
		t.Fatalf("push %s: %v", n.name, err)
	}
	return nt.GetUUID()
}

// session drives the read tools as the orchestrator does, and keeps what they return.
type session struct {
	t     *testing.T
	tools *mcptools.Tools
	v     vault
	caps  []capture

	// What the red-team saw. A run that sees nothing proves nothing, so the test
	// checks these counts.
	secretRows int // sensitive notes seen as rows in List and Search results
	secretGets int // sensitive notes that notes_get returned as a bare stub
}

func (s *session) list(limit, offset int) mcptools.RowSet {
	s.t.Helper()
	call := fmt.Sprintf("notes_list(limit=%d, offset=%d)", limit, offset)
	rs, err := s.tools.List(limit, offset)
	if err != nil {
		s.t.Fatalf("%s: %v", call, err)
	}
	s.caps = append(s.caps, newCapture(s.t, call, rs))
	s.checkRows(call, rs)
	return rs
}

func (s *session) search(query string) mcptools.RowSet {
	s.t.Helper()
	call := fmt.Sprintf("notes_search(%q, limit=500)", query)
	rs, err := s.tools.Search(query, 500, 0)
	if err != nil {
		s.t.Fatalf("%s: %v", call, err)
	}
	s.caps = append(s.caps, newCapture(s.t, call, rs))
	s.checkRows(call, rs)
	return rs
}

func (s *session) get(p planted) mcptools.GetResult {
	s.t.Helper()
	call := fmt.Sprintf("notes_get(%s, %s)", p.uuid, p.name)
	res, err := s.tools.Get(p.uuid)
	if err != nil {
		s.t.Fatalf("%s: %v", call, err)
	}
	s.caps = append(s.caps, newCapture(s.t, call, res))
	if p.secret {
		// A sensitive note comes back as the stub and as nothing else: not a note, and
		// not one more field. The comparison is on the JSON, so a field that a later
		// change adds to the result shows up here.
		stub := gate.Stub(p.uuid)
		if got, want := wire(s.t, res), wire(s.t, mcptools.GetResult{Stub: &stub}); got != want {
			s.t.Errorf("LEAK through %s: a sensitive note is not a bare stub.\n  got:  %s\n  want: %s", call, got, want)
		}
		if res.Note != nil || res.Stub == nil || *res.Stub != stub {
			s.t.Errorf("%s: want Note == nil and the fixed stub, got %s", call, wire(s.t, res))
		} else {
			s.secretGets++
		}
	}
	return res
}

func (s *session) tags() mcptools.TagList {
	s.t.Helper()
	tl, err := s.tools.TagsList()
	if err != nil {
		s.t.Fatalf("tags_list: %v", err)
	}
	s.caps = append(s.caps, newCapture(s.t, "tags_list()", tl))
	return tl
}

// wantErr keeps the text of an error that the orchestrator would see. A call that
// should fail and does not is a failure.
func (s *session) wantErr(call string, err error) {
	s.t.Helper()
	if err == nil {
		s.t.Errorf("%s: want an error", call)
		return
	}
	s.caps = append(s.caps, errCapture(call+" (error)", err))
}

// checkRows fails unless every sensitive note in rs is a bare stub.
func (s *session) checkRows(call string, rs mcptools.RowSet) {
	s.t.Helper()
	for _, r := range rs.Rows {
		var id string
		switch {
		case r.Note != nil && r.Stub != nil:
			s.t.Errorf("%s: a row holds both a note and a stub: %s", call, wire(s.t, r))
			continue
		case r.Note != nil:
			id = r.Note.UUID
		case r.Stub != nil:
			id = r.Stub.UUID
		default:
			s.t.Errorf("%s: an empty row", call)
			continue
		}
		p, ok := s.v.byUUID[id]
		if !ok {
			s.t.Errorf("%s: a row for a note that the test did not plant: %s", call, wire(s.t, r))
			continue
		}
		if !p.secret {
			continue
		}
		s.secretRows++
		if got, want := wire(s.t, r), wire(s.t, stubRow(id)); got != want {
			s.t.Errorf("LEAK through %s: the sensitive note %q is not a bare stub.\n  got:  %s\n  want: %s", call, p.name, got, want)
		}
	}
}

// rowID is the uuid of a row, whichever arm of it is set.
func rowID(r mcptools.Row) string {
	switch {
	case r.Note != nil:
		return r.Note.UUID
	case r.Stub != nil:
		return r.Stub.UUID
	}
	return ""
}

func rowUUIDs(rs mcptools.RowSet) []string {
	var out []string
	for _, r := range rs.Rows {
		if id := rowID(r); id != "" {
			out = append(out, id)
		}
	}
	return out
}

func rowFor(rs mcptools.RowSet, uuid string) *mcptools.Row {
	for i := range rs.Rows {
		if rowID(rs.Rows[i]) == uuid {
			return &rs.Rows[i]
		}
	}
	return nil
}

// jevAnswers reports whether local jev answers for the benign notes. It asks the same
// way that the gate does. nimble can need more than 20 seconds to load its model when
// it has been idle, and the gate gives up at 20 seconds, so a failed probe is tried
// again, and it warms the model for the gate.
func jevAnswers(t *testing.T) bool {
	t.Helper()
	j := gate.NewJev(jevURL(), "local")
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(2 * time.Second)
		}
		ok := true
		for _, b := range benign {
			p, err := j.SensitiveProbability(b.title + "\n" + b.body)
			if err != nil {
				last, ok = err, false
				break
			}
			t.Logf("jev rates the benign note %q at %.3f (the gate stubs a note at %.2f or more)", b.title, p, threshold)
		}
		if ok {
			return true
		}
	}
	t.Logf("jev does not answer at %s (%v)", jevURL(), last)
	return false
}

// The red-team. It plants the secrets, calls every read tool, and looks for any
// sensitive title, body or telltale in what the tools returned.
func TestReadPathNeverLeaksASensitiveNote(t *testing.T) {
	email, password := testsupport.NewAccount(t) // skips when the Docker server is down, or SN_TEST_SERVER=off
	c, err := snclient.SignIn(snclient.Config{Server: testsupport.TestServer}, email, password,
		func(string) (string, error) { return "", nil })
	if err != nil {
		t.Fatal(err)
	}
	v := plant(t, c)
	guard := snclient.NewGuard(c, "")

	// The gate of cmd/sn-mcp: the real jev at the real threshold. When jev is down the
	// gate stubs every note, even a plain one. That is correct, and it is not a leak.
	// So only the benign notes' reading through depends on jev. The leak checks never do.
	t.Run("real gate", func(t *testing.T) {
		readable := jevAnswers(t)
		tools := mcptools.New(guard, gate.New(gate.NewJev(jevURL(), "local"), threshold))
		battery(t, tools, v, readable)
	})

	// A jev that rates every note 0. Only the scanner and the note kind can stub a
	// note here, so every secret that stays hidden shows that they, and not jev, did it.
	t.Run("scanner and kind alone", func(t *testing.T) {
		tools := mcptools.New(guard, gate.New(jevSaysSafe{}, threshold))
		battery(t, tools, v, true)
	})
}

// battery drives every read tool, then looks for leaks. benignReadable says whether
// the gate can clear the benign notes: it needs jev, or a jev stand-in that says 0.
func battery(t *testing.T, tools *mcptools.Tools, v vault, benignReadable bool) {
	t.Helper()
	s := &session{t: t, tools: tools, v: v}

	// notes_list: one page of 500, then a walk in small pages. Both must hold every
	// live note once, in the same order.
	listed := s.list(500, 0)
	if got, want := rowUUIDs(listed), v.liveUUIDs(); !slices.Equal(got, want) {
		t.Errorf("notes_list(500) returned %v, want the live planted notes %v", got, want)
	}
	var walked []string
	for offset := 0; ; offset += walkPage {
		page := s.list(walkPage, offset)
		walked = append(walked, rowUUIDs(page)...)
		if len(page.Rows) < walkPage {
			break
		}
	}
	if want := rowUUIDs(listed); !slices.Equal(walked, want) {
		t.Errorf("paging notes_list by %d returned %v, want %v", walkPage, walked, want)
	}

	// notes_search: every query. A sensitive note that holds the query must come back as
	// a stub. A note that does not hold it must not come back.
	found := map[string]mcptools.RowSet{}
	for _, q := range queries {
		rs := s.search(q)
		found[q] = rs
		if got, want := rowUUIDs(rs), v.holding(q); !slices.Equal(got, want) {
			t.Errorf("notes_search(%q) returned %v, want the live notes that hold it: %v", q, got, want)
		}
	}

	// notes_get on every planted note, and on the ones that are not there.
	gets := map[string]mcptools.GetResult{}
	for _, p := range v.notes {
		gets[p.name] = s.get(p)
	}
	_, err := tools.Get("")
	s.wantErr(`notes_get("")`, err)
	_, err = tools.Get(unknownUUID)
	s.wantErr("notes_get(<unknown uuid>)", err)
	_, err = tools.Search("", 0, 0)
	s.wantErr(`notes_search("")`, err)
	_, err = tools.Search("   ", 0, 0)
	s.wantErr(`notes_search("   ")`, err)
	_, err = tools.Search(strings.Repeat("a", 300), 0, 0)
	s.wantErr("notes_search(<300 bytes>)", err)

	// tags_list holds the tags that were planted, with the uuids of their notes.
	tagged := map[string][]string{}
	for _, tag := range s.tags().Tags {
		ids := slices.Clone(tag.NoteUUIDs)
		slices.Sort(ids)
		tagged[tag.Title] = ids
	}
	for title, names := range v.tags {
		var want []string
		for _, name := range names {
			want = append(want, v.named(name).uuid)
		}
		slices.Sort(want)
		if !slices.Equal(tagged[title], want) {
			t.Errorf("tags_list: the tag %q holds %v, want %v", title, tagged[title], want)
		}
	}

	// The verdict. None of the sensitive titles, bodies or telltales may be in
	// anything that the orchestrator received.
	leaks := findLeaks(v.secrets(), s.caps)
	for _, l := range leaks {
		t.Errorf("LEAK through %s: the sensitive note %q shows in the output (%s).\n  first string: %q\n  output: %s",
			l.call, l.note, strings.Join(l.kinds, ", "), l.example, l.context)
	}
	// A test that read nothing would pass too, so check that it did read the notes.
	// notes_list shows each live sensitive note twice (one page of 500, and the paged
	// walk), and the searches show more. notes_get must return a bare stub for every
	// sensitive note, trashed or not.
	if live := v.liveSecrets(); s.secretRows < 2*live {
		t.Errorf("only %d sensitive rows came back from notes_list and notes_search, want at least %d: the red-team did not exercise the tools", s.secretRows, 2*live)
	}
	if want := len(v.secrets()); s.secretGets != want {
		t.Errorf("notes_get returned %d bare stubs, want one for each of the %d sensitive notes", s.secretGets, want)
	}

	// The notes that the gate clears must read through. This needs a jev that rates
	// them low, and it is the only check that does. When jev is down the gate stubs
	// every note, which is correct. So this check is skipped, and no other is.
	if benignReadable {
		for _, p := range v.notes {
			if p.secret {
				continue
			}
			row := rowFor(listed, p.uuid)
			if row == nil || row.Note == nil || row.Note.Title != p.title || !strings.Contains(row.Note.Snippet, p.body) {
				t.Errorf("notes_list: want the benign note %q readable with a snippet, got %s", p.name, wire(t, row))
			}
			if g := gets[p.name]; g.Note == nil || g.Stub != nil || g.Note.Title != p.title || g.Note.Text != p.body {
				t.Errorf("notes_get: want the benign note %q in full, got %s", p.name, wire(t, g))
			}
		}
		shopping := v.named("shopping")
		if row := rowFor(found["milk"], shopping.uuid); row == nil || row.Note == nil || !strings.Contains(row.Note.Snippet, "milk and eggs") {
			t.Errorf(`notes_search("milk"): want the benign note with a snippet, got %s`, wire(t, row))
		}
	} else {
		t.Log("jev is not answering: the benign notes are stubs, as they must be, so their read-through is not checked")
	}

	total := 0
	for _, c := range s.caps {
		total += len(c.raw)
	}
	t.Logf("%d tool calls (%d notes_search queries) returned %d bytes of JSON to the orchestrator. %d sensitive notes were planted. They came back as %d bare stub rows from notes_list and notes_search, and as %d bare stubs from notes_get. Leaks: %d.",
		len(s.caps), len(queries), total, len(v.secrets()), s.secretRows, s.secretGets, len(leaks))
}
