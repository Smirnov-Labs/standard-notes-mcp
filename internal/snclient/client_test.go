package snclient_test

import (
	"testing"

	"github.com/smirnov-labs/standard-notes-mcp/internal/snclient"
	"github.com/smirnov-labs/standard-notes-mcp/internal/testsupport"
)

func noMFA(string) (string, error) { return "", nil }

func TestSignInPersistRestore(t *testing.T) {
	email, pw := testsupport.NewAccount(t)
	cfg := snclient.Config{Server: testsupport.TestServer}

	c, err := snclient.SignIn(cfg, email, pw, noMFA)
	if err != nil {
		t.Fatalf("sign in: %v", err)
	}
	if !c.Authenticated() {
		t.Fatal("signed-in client not authenticated")
	}

	ref := "test-" + email
	if err := c.Persist(ref); err != nil {
		t.Fatalf("persist: %v", err)
	}
	t.Cleanup(func() { _ = snclient.ForgetSession(ref) })

	r, err := snclient.Restore(cfg, ref)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if !r.Authenticated() {
		t.Fatal("restored client not authenticated — persistence dropped auth material")
	}
}

// Authenticated() only checks that two fields are set. A restored session must
// also work. The server must accept its token. The client must adopt the
// account's items key and decrypt what the first session wrote. Persist keeps no
// items keys, so this test fails if the stored blob lacks anything a sync needs.
func TestRestoredSessionFetchesAndDecrypts(t *testing.T) {
	email, pw := testsupport.NewAccount(t)
	cfg := snclient.Config{Server: testsupport.TestServer}

	c, err := snclient.SignIn(cfg, email, pw, noMFA)
	if err != nil {
		t.Fatalf("sign in: %v", err)
	}
	id, err := c.SeedNote(t, "Round trip", "survives the keyring")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	ref := "test-roundtrip-" + email
	if err := c.Persist(ref); err != nil {
		t.Fatalf("persist: %v", err)
	}
	t.Cleanup(func() { _ = snclient.ForgetSession(ref) })

	r, err := snclient.Restore(cfg, ref)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	got, err := r.FetchOne(id)
	if err != nil {
		t.Fatalf("restored client could not sync: %v", err)
	}
	if got == nil {
		t.Fatal("restored client did not see the seeded note")
	}
	if got.Title != "Round trip" || got.Text != "survives the keyring" {
		t.Fatalf("restored client decrypted %q / %q", got.Title, got.Text)
	}
}
