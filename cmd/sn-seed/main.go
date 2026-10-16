// Command sn-seed registers a fixed demo account on the LOCAL Docker Standard
// Notes server (localhost:3000) and seeds a mix of normal and sensitive sample
// notes, so the read MCP can be tested end-to-end WITHOUT a real account.
//
// Local test tooling only. The "secrets" below are synthetic: public test
// vectors (the all-zero BIP-39 phrase, AWS doc EXAMPLE keys, a Visa test card)
// and obvious fakes. Nothing here is a real credential.
//
// Re-running adds duplicate notes. To reset the test data, tear the server down
// and back up: `cd ~/sn-test-server && docker compose down -v && docker compose up -d`.
package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/jonhadfield/gosn-v2/auth"
	"github.com/jonhadfield/gosn-v2/common"

	"github.com/smirnov-labs/standard-notes-mcp/internal/snclient"
)

// Defaults target the local Docker demo. Override with SN_SERVER / SN_EMAIL /
// SN_PASSWORD to seed a different account, for example a throwaway cloud test
// account. Registration is attempted only for the demo defaults; an existing
// account (cloud) is seeded as-is, never registered.
const (
	demoServer = "http://localhost:3000"
	demoEmail  = "demo@local.test"
	demoPW     = "demo-password-standard-notes-2026"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// noopT satisfies snclient.SeedNote's `interface{ Helper() }` outside a test.
type noopT struct{}

func (noopT) Helper() {}

type sample struct {
	title, text string
	sensitive   bool // true = the gate is expected to STUB this note
	tags        []string
}

var samples = []sample{
	// --- normal notes: should read through, full content ---
	{title: "Shopping list", text: "milk, eggs, bread, coffee, olive oil", tags: []string{"personal"}},
	{title: "Q3 roadmap", text: "ship the cleanup tool, write the docs, record a demo", tags: []string{"work"}},
	{title: "Deep Work — notes", text: "schedule deep-work blocks in the morning; batch the shallow tasks after lunch"},
	{title: "Team sync 2026-09-30", text: "went over the migration timeline; follow up with the infra team next week"},
	{title: "Carbonara", text: "guanciale, eggs, pecorino romano, lots of black pepper, no cream"},
	{title: "Idea", text: "a little CLI that writes my weekly update from the week's git commits"},
	{title: "Call the dentist", text: "book a cleaning for next month, the one on Oak St"},
	{title: "call dentist", text: "book a cleaning for next month"}, // near-duplicate, for later dedup testing

	// --- sensitive notes: should come back as "[sensitive — withheld]" stubs ---
	{title: "AWS prod", text: "access key AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", sensitive: true, tags: []string{"work"}},
	{title: "server key", text: "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAA\nFAKEfakeFAKEnotarealkeyjustasampleforlocaltesting==\n-----END OPENSSH PRIVATE KEY-----", sensitive: true},
	{title: "wallet backup", text: "recovery phrase (keep safe):\nabandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", sensitive: true, tags: []string{"personal"}},
	{title: "card on file", text: "visa 4111 1111 1111 1111 exp 12/26 cvv 123", sensitive: true, tags: []string{"personal"}},
	{title: "2fa seed", text: "otpauth://totp/Acme:me?secret=JBSWY3DPEHPK3PXP&issuer=Acme", sensitive: true},
	{title: "github", text: "personal access token ghp_abcdefghijklmnopqrstuvwxyz0123456789", sensitive: true, tags: []string{"work"}},
	{title: "db creds", text: "staging db: postgres://admin:s3cretpassword@db.internal:5432/app", sensitive: true},
	{title: "home router", text: "admin panel password: hunter2-very-long-password", sensitive: true},
}

func main() {
	log.SetFlags(0)
	server := env("SN_SERVER", demoServer)
	email := env("SN_EMAIL", demoEmail)
	pw := env("SN_PASSWORD", demoPW)
	isDemo := server == demoServer && email == demoEmail

	if isDemo {
		// Register the fixed demo account. A re-run returns "already registered",
		// which is fine; we sign in either way.
		hc := common.NewHTTPClient()
		if _, err := (auth.RegisterInput{Client: hc, Email: email, Password: pw, APIServer: server}).Register(); err != nil {
			log.Printf("register: %v (continuing — the account probably already exists)", err)
		}
	} else {
		log.Printf("seeding EXISTING account %s on %s (no registration)", email, server)
	}

	c, err := snclient.SignIn(snclient.Config{Server: server}, email, pw, func(string) (string, error) { return "", nil })
	if err != nil {
		log.Fatalf("sign in to %s as %s failed: %v", server, email, err)
	}

	byTag := map[string][]string{}
	var nNormal, nSensitive int
	for _, s := range samples {
		uuid, err := c.SeedNote(noopT{}, s.title, s.text)
		if err != nil {
			log.Fatalf("seed note %q: %v", s.title, err)
		}
		for _, tg := range s.tags {
			byTag[tg] = append(byTag[tg], uuid)
		}
		if s.sensitive {
			nSensitive++
		} else {
			nNormal++
		}
	}

	for _, name := range []string{"work", "personal"} {
		ids := byTag[name]
		if len(ids) == 0 {
			continue
		}
		tag, err := c.NewTag(name)
		if err != nil {
			log.Fatalf("new tag %q: %v", name, err)
		}
		c.SetTagRefs(tag, ids)
		if _, err := c.Push(c.RawTag(tag)); err != nil {
			log.Fatalf("push tag %q: %v", name, err)
		}
	}

	line := strings.Repeat("-", 64)
	fmt.Println(line)
	fmt.Printf("Seeded %s on %s\n\n", email, server)
	fmt.Printf("  notes: %d  (%d normal, %d sensitive → expected stubbed)\n", len(samples), nNormal, nSensitive)
	fmt.Printf("  tags:  work, personal\n")
	if isDemo {
		fmt.Printf("\n  email:    %s\n  password: %s\n", email, pw)
	}
	fmt.Println(line)
}
