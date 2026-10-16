package snclient

import (
	"sync"

	"github.com/jonhadfield/gosn-v2/items"
)

// vaultCache holds the item set as ciphertext, keyed by uuid, plus the Standard Notes
// sync token. It lets snclient pull only CHANGES after the first full sync: the first
// sync (empty token) returns the whole vault; later syncs return only items changed
// since the token. The cache stores ciphertext, not plaintext, so the proven
// decrypt-on-read path (DecryptAndParse / DecryptItem) is unchanged — only the network
// pull shrinks. In-memory per process; never persisted, so decrypted content stays off
// disk (the privacy posture).
type vaultCache struct {
	mu    sync.Mutex
	token string
	items map[string]items.EncryptedItem
}

func newVaultCache() *vaultCache {
	return &vaultCache{items: map[string]items.EncryptedItem{}}
}

// apply merges a sync response's items into the cache and advances the token. It is
// called only after a successful sync, so the token and the item set move together.
func (vc *vaultCache) apply(syncItems items.EncryptedItems, newToken string) {
	vc.mu.Lock()
	defer vc.mu.Unlock()
	mergeInto(vc.items, syncItems)
	vc.token = newToken
}

// currentToken returns the sync token to send on the next sync (empty => full sync).
func (vc *vaultCache) currentToken() string {
	vc.mu.Lock()
	defer vc.mu.Unlock()
	return vc.token
}

// snapshot returns a copy of the cached ciphertext for decrypt-on-read.
func (vc *vaultCache) snapshot() items.EncryptedItems {
	vc.mu.Lock()
	defer vc.mu.Unlock()
	out := make(items.EncryptedItems, 0, len(vc.items))
	for _, e := range vc.items {
		out = append(out, e)
	}
	return out
}

// get returns the cached ciphertext for one uuid.
func (vc *vaultCache) get(uuid string) (items.EncryptedItem, bool) {
	vc.mu.Lock()
	defer vc.mu.Unlock()
	e, ok := vc.items[uuid]
	return e, ok
}

// mergeInto applies a delta to the item map: a Deleted tombstone removes its uuid; any
// other item is upserted. The delta reflects the newest server state for each uuid it
// names (gosn de-dupes newest within a response), so last-write-wins is correct.
func mergeInto(m map[string]items.EncryptedItem, delta items.EncryptedItems) {
	for _, e := range delta {
		if e.Deleted {
			delete(m, e.UUID)
			continue
		}
		m[e.UUID] = e
	}
}
