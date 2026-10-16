package snclient_test

import (
	"testing"

	"github.com/smirnov-labs/standard-notes-mcp/internal/snclient"
	"github.com/smirnov-labs/standard-notes-mcp/internal/testsupport"
)

func TestFetchSeededNote(t *testing.T) {
	email, pw := testsupport.NewAccount(t)
	cfg := snclient.Config{Server: testsupport.TestServer}
	c, err := snclient.SignIn(cfg, email, pw, noMFA)
	if err != nil {
		t.Fatal(err)
	}

	uuid, err := c.SeedNote(t, "Shopping", "milk, eggs")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	notes, _, err := c.Fetch()
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	var got *snclient.NoteView
	for _, n := range notes {
		if n.UUID == uuid {
			got = n
		}
	}
	if got == nil {
		t.Fatal("seeded note not returned")
	}
	if got.Title != "Shopping" || got.Text != "milk, eggs" {
		t.Fatalf("bad decrypt: %q / %q", got.Title, got.Text)
	}
	if got.Trashed {
		t.Fatal("new note should not be trashed")
	}
}
