package snclient

import (
	"fmt"
	"testing"

	"github.com/jonhadfield/gosn-v2/items"
)

func TestMergeInto_upsertsAndDeletes(t *testing.T) {
	m := map[string]items.EncryptedItem{
		"a": {UUID: "a", ContentType: "Note", Content: "v1"},
		"b": {UUID: "b", ContentType: "Note", Content: "v1"},
	}
	mergeInto(m, items.EncryptedItems{
		{UUID: "a", ContentType: "Note", Content: "v2"}, // update in place
		{UUID: "c", ContentType: "Note", Content: "v1"}, // insert
		{UUID: "b", Deleted: true},                      // delete tombstone
	})
	if m["a"].Content != "v2" {
		t.Errorf("a should update to v2, got %q", m["a"].Content)
	}
	if _, ok := m["b"]; ok {
		t.Error("b should be removed by its delete tombstone")
	}
	if _, ok := m["c"]; !ok {
		t.Error("c should be inserted")
	}
	if len(m) != 2 {
		t.Errorf("want 2 live items (a, c), got %d", len(m))
	}
}

func TestVaultCache_applyAdvancesTokenAndSnapshots(t *testing.T) {
	vc := newVaultCache()
	if vc.currentToken() != "" {
		t.Errorf("fresh cache token should be empty, got %q", vc.currentToken())
	}
	vc.apply(items.EncryptedItems{
		{UUID: "a", ContentType: "Note", Content: "x"},
		{UUID: "k", ContentType: "SN|ItemsKey", Content: "key"},
	}, "token-1")
	if vc.currentToken() != "token-1" {
		t.Errorf("token should advance to token-1, got %q", vc.currentToken())
	}
	if len(vc.snapshot()) != 2 {
		t.Errorf("snapshot should have 2 items, got %d", len(vc.snapshot()))
	}

	// A later delta that deletes a and advances the token.
	vc.apply(items.EncryptedItems{{UUID: "a", Deleted: true}}, "token-2")
	if vc.currentToken() != "token-2" {
		t.Errorf("token should advance to token-2, got %q", vc.currentToken())
	}
	if _, ok := vc.get("a"); ok {
		t.Error("a should be gone after its delete delta")
	}
	if len(vc.snapshot()) != 1 {
		t.Errorf("snapshot should have 1 item (k) after delete, got %d", len(vc.snapshot()))
	}
}

// TestSyncDelta_usesAndAdvancesToken proves the sync is actually incremental: the
// first sync sends an empty token (full), and each later sync sends the token the
// previous one returned (delta), accumulating changes in the cache.
func TestSyncDelta_usesAndAdvancesToken(t *testing.T) {
	defer swapSyncSeams()()
	var sawTokens []string
	syncFn = func(in items.SyncInput) (items.SyncOutput, error) {
		sawTokens = append(sawTokens, in.SyncToken)
		n := len(sawTokens)
		return items.SyncOutput{
			Items:     items.EncryptedItems{{UUID: fmt.Sprintf("u%d", n), ContentType: "Note"}},
			SyncToken: fmt.Sprintf("tok%d", n),
		}, nil
	}
	c := &Client{cache: newVaultCache()}
	if err := c.syncDelta(); err != nil {
		t.Fatal(err)
	}
	if err := c.syncDelta(); err != nil {
		t.Fatal(err)
	}
	if len(sawTokens) != 2 {
		t.Fatalf("want 2 syncs, got %d", len(sawTokens))
	}
	if sawTokens[0] != "" {
		t.Errorf("first sync must be full (empty token), got %q", sawTokens[0])
	}
	if sawTokens[1] != "tok1" {
		t.Errorf("second sync must send the first returned token tok1 (delta), got %q", sawTokens[1])
	}
	if got := len(c.cache.snapshot()); got != 2 {
		t.Errorf("cache should accumulate both items, got %d", got)
	}
}
