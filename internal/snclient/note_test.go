package snclient_test

import (
	"testing"

	"github.com/smirnov-labs/standard-notes-mcp/internal/snclient"
	"github.com/smirnov-labs/standard-notes-mcp/internal/testsupport"
)

func TestEditTextPreservesReferences(t *testing.T) {
	email, pw := testsupport.NewAccount(t)
	cfg := snclient.Config{Server: testsupport.TestServer}
	c, err := snclient.SignIn(cfg, email, pw, noMFA)
	if err != nil {
		t.Fatal(err)
	}

	uuid, err := c.SeedNoteWithRef(t, "Doc", "v1", "11111111-1111-4111-8111-111111111111")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	nv, err := c.FetchOne(uuid)
	if err != nil || nv == nil {
		t.Fatalf("fetch: %v", err)
	}
	if err := c.ApplyTextEdit(nv, "v2"); err != nil {
		t.Fatalf("edit: %v", err)
	}
	after, err := c.FetchOne(uuid)
	if err != nil || after == nil {
		t.Fatalf("refetch: %v", err)
	}
	if after.Text != "v2" {
		t.Fatalf("text not updated: %q", after.Text)
	}
	if n := after.RefCount(); n != 1 {
		t.Fatalf("references dropped: want 1, got %d", n) // the data-loss bug this guards
	}
}
