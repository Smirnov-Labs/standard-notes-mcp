// Command sn-login signs in ONCE (using SN_MFA for 2FA) and saves the session to the
// macOS keyring under SN_SESSION_REF. Afterward sn-triage / sn-canary / sn-mcp can
// restore that session and run WITHOUT a 2FA code. The saved session is valid for
// about 30 days and auto-refreshes in tools that use the Guard; re-run sn-login with
// a fresh code to refresh a stale session.
//
// It is a fast, ~2-second operation by design: it signs in and stops (no vault
// fetch), so racing the ~30-second TOTP window is cheap — if a code expires in
// transit, just re-run with a new one.
//
// Usage:
//
//	SN_SERVER=https://api.standardnotes.com SN_SESSION_REF=sn-main \
//	  SN_EMAIL=.. SN_PASSWORD=.. SN_MFA=<code> go run ./cmd/sn-login
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/smirnov-labs/standard-notes-mcp/internal/snclient"
)

func main() {
	ref := strings.TrimSpace(os.Getenv("SN_SESSION_REF"))
	if ref == "" {
		fatal("set SN_SESSION_REF to a name for the saved session (e.g. sn-main)")
	}
	server := envOr("SN_SERVER", "https://api.standardnotes.com")
	email, pw := os.Getenv("SN_EMAIL"), os.Getenv("SN_PASSWORD")
	if email == "" || pw == "" {
		fatal("set SN_EMAIL and SN_PASSWORD (and SN_MFA if the account has 2FA)")
	}

	fmt.Printf("signing in %s at %s ...\n", email, server)
	c, err := snclient.SignIn(snclient.Config{Server: server}, email, pw, mfaFromEnv)
	if err != nil {
		fatal("sign in: %v", err)
	}
	// A rejected/expired 2FA code makes gosn-v2 return a session with no tokens and
	// no error (it re-challenged). Catch that here with a clear message.
	if !c.Authenticated() {
		fatal("2FA code rejected or expired — send a FRESH code and re-run")
	}
	if err := c.Persist(ref); err != nil {
		fatal("signed in but could not save the session %q: %v", ref, err)
	}
	fmt.Printf("OK — session saved as %q.\n", ref)
	fmt.Printf("Tools run with SN_SESSION_REF=%s now need no 2FA code (valid ~30 days, auto-refreshing).\n", ref)
}

func mfaFromEnv(string) (string, error) {
	if code := strings.TrimSpace(os.Getenv("SN_MFA")); code != "" {
		return code, nil
	}
	return "", fmt.Errorf("account needs a 2FA code; set SN_MFA to a current code")
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func fatal(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "sn-login: "+f+"\n", a...)
	os.Exit(1)
}
