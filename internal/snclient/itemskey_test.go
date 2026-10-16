package snclient

// Internal tests for ensureItemsKey (unexported), the one non-mechanical part of
// Fetch/Push: a fresh account has no items key until a client makes one.

import (
	"strings"
	"testing"
	"time"

	"github.com/jonhadfield/gosn-v2/common"
	"github.com/jonhadfield/gosn-v2/items"
	"github.com/smirnov-labs/standard-notes-mcp/internal/testsupport"
)

func signInInternal(t *testing.T, email, pw string) *Client {
	t.Helper()
	c, err := SignIn(Config{Server: testsupport.TestServer}, email, pw,
		func(string) (string, error) { return "", nil })
	if err != nil {
		t.Fatalf("sign in: %v", err)
	}
	return c
}

func newTestNote(t *testing.T, title, text string) *items.Note {
	t.Helper()
	n, err := items.NewNote(title, text, nil)
	if err != nil {
		t.Fatalf("NewNote: %v", err)
	}
	n.Content.SetUpdateTime(time.Now().UTC())
	return &n
}

// liveItemsKeyUUIDs does a full pull on c's session and returns the uuids of the
// non-deleted SN|ItemsKey items the server holds for the account.
func liveItemsKeyUUIDs(t *testing.T, c *Client) []string {
	t.Helper()
	out, err := items.Sync(items.SyncInput{Session: c.sess})
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	var ids []string
	for _, it := range out.Items {
		if it.ContentType == common.SNItemTypeItemsKey && !it.Deleted {
			ids = append(ids, it.UUID)
		}
	}
	return ids
}

func TestEnsureItemsKeyFreshAccountMakesOneKeyOnce(t *testing.T) {
	email, pw := testsupport.NewAccount(t)
	c := signInInternal(t, email, pw)

	// Premise of the whole bootstrap: a pulled fresh account still has no key.
	if _, err := items.Sync(items.SyncInput{Session: c.sess}); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if c.hasDefaultItemsKey() || len(c.sess.ItemsKeys) != 0 {
		t.Fatal("premise broken: fresh account already has an items key")
	}

	if err := c.ensureItemsKey(); err != nil {
		t.Fatalf("ensureItemsKey: %v", err)
	}
	k := c.sess.DefaultItemsKey
	if !c.hasDefaultItemsKey() || !k.Default || k.Version != "004" || len(k.ItemsKey) != 64 {
		t.Fatalf("bad default key: uuid=%q default=%t version=%q keyLen=%d", k.UUID, k.Default, k.Version, len(k.ItemsKey))
	}
	if ids := liveItemsKeyUUIDs(t, c); len(ids) != 1 || ids[0] != k.UUID {
		t.Fatalf("server should hold exactly the new key %s, got %v", k.UUID, ids)
	}

	// A second call must be a no-op: no second key, same default.
	if err := c.ensureItemsKey(); err != nil {
		t.Fatalf("second ensureItemsKey: %v", err)
	}
	if c.sess.DefaultItemsKey.UUID != k.UUID {
		t.Fatalf("default key changed from %s to %s", k.UUID, c.sess.DefaultItemsKey.UUID)
	}
	if ids := liveItemsKeyUUIDs(t, c); len(ids) != 1 {
		t.Fatalf("second call minted another key: %v", ids)
	}
}

// A real account always has a key. A new session on an account that already has
// one must adopt it, write nothing, and read what the first session wrote.
func TestEnsureItemsKeyIsNoOpWhenAccountHasKey(t *testing.T) {
	email, pw := testsupport.NewAccount(t)
	a := signInInternal(t, email, pw)
	noteA, err := a.SeedNote(t, "Shopping", "milk, eggs")
	if err != nil {
		t.Fatalf("seed a: %v", err)
	}
	keyA := a.sess.DefaultItemsKey.UUID

	b := signInInternal(t, email, pw) // clean session: nothing in memory
	if b.hasDefaultItemsKey() {
		t.Fatal("new session should not hold a key before its first sync")
	}
	if err := b.ensureItemsKey(); err != nil {
		t.Fatalf("b ensureItemsKey: %v", err)
	}
	if b.sess.DefaultItemsKey.UUID != keyA {
		t.Fatalf("b did not adopt the existing key: want %s, got %s", keyA, b.sess.DefaultItemsKey.UUID)
	}
	if ids := liveItemsKeyUUIDs(t, b); len(ids) != 1 {
		t.Fatalf("no-op path created a key: %v", ids)
	}

	// The stored key decrypts from a clean session (master key -> items key -> note).
	got, err := b.FetchOne(noteA)
	if err != nil || got == nil {
		t.Fatalf("b FetchOne: note=%v err=%v", got, err)
	}
	if got.Title != "Shopping" || got.Text != "milk, eggs" {
		t.Fatalf("b decrypted %q / %q", got.Title, got.Text)
	}

	// And the other direction: a note b encrypts with the adopted key reads back in a.
	noteB, err := b.SeedNote(t, "From B", "written by the second session")
	if err != nil {
		t.Fatalf("seed b: %v", err)
	}
	back, err := a.FetchOne(noteB)
	if err != nil || back == nil || back.Text != "written by the second session" {
		t.Fatalf("a FetchOne of b's note: %v err=%v", back, err)
	}
}

// If the server holds live items keys the session cannot decrypt (here: a wrong
// master key), ensureItemsKey must refuse. Making another default key on top
// would re-key a real account, and a key wrapped with the wrong master key is
// one nobody could ever decrypt.
func TestEnsureItemsKeyRefusesToRekeyAccountItCannotDecrypt(t *testing.T) {
	email, pw := testsupport.NewAccount(t)
	a := signInInternal(t, email, pw)
	if _, err := a.SeedNote(t, "Keep", "me"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	b := signInInternal(t, email, pw)
	b.sess.MasterKey = strings.Repeat("00", 32) // cannot unwrap the stored key
	if err := b.ensureItemsKey(); err == nil {
		t.Fatal("expected ensureItemsKey to refuse, got nil")
	}
	if ids := liveItemsKeyUUIDs(t, a); len(ids) != 1 {
		t.Fatalf("guard failed: account now holds %d items keys: %v", len(ids), ids)
	}

	// Push runs the same guard: it refuses, and it pushes nothing.
	rejected := newTestNote(t, "Rejected", "must not reach the server")
	_, err := b.Push(items.Items{rejected})
	if err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("Push should fail with the refusal, got: %v", err)
	}
	if ids := liveItemsKeyUUIDs(t, a); len(ids) != 1 {
		t.Fatalf("Push re-keyed the account: %v", ids)
	}
	if got, err := a.FetchOne(rejected.GetUUID()); err != nil || got != nil {
		t.Fatalf("rejected note reached the server: %v err=%v", got, err)
	}
}

// Push is the write path. It must work on a fresh account with no prior Fetch,
// which is how the write engine uses it.
func TestPushBootstrapsItemsKeyOnFreshAccount(t *testing.T) {
	email, pw := testsupport.NewAccount(t)
	c := signInInternal(t, email, pw)

	first := newTestNote(t, "First", "pushed with no prior fetch")
	if _, err := c.Push(items.Items{first}); err != nil {
		t.Fatalf("Push on a fresh account: %v", err)
	}
	key := c.sess.DefaultItemsKey.UUID
	if key == "" {
		t.Fatal("Push left the session without a default items key")
	}
	got, err := c.FetchOne(first.GetUUID())
	if err != nil || got == nil || got.Title != "First" || got.Text != "pushed with no prior fetch" {
		t.Fatalf("read back: %v err=%v", got, err)
	}

	// A second Push reuses the key.
	second := newTestNote(t, "Second", "reuses the key")
	if _, err := c.Push(items.Items{second}); err != nil {
		t.Fatalf("second Push: %v", err)
	}
	if c.sess.DefaultItemsKey.UUID != key {
		t.Fatalf("default key changed from %s to %s", key, c.sess.DefaultItemsKey.UUID)
	}
	if ids := liveItemsKeyUUIDs(t, c); len(ids) != 1 || ids[0] != key {
		t.Fatalf("server should hold exactly key %s, got %v", key, ids)
	}
}

// On a real account the bootstrap in Push is a no-op beyond one sync: a clean
// session adopts the account's key and adds none.
func TestPushOnCleanSessionAdoptsExistingKey(t *testing.T) {
	email, pw := testsupport.NewAccount(t)
	a := signInInternal(t, email, pw)
	if _, err := a.SeedNote(t, "Seed", "gives the account its key"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	keyA := a.sess.DefaultItemsKey.UUID

	b := signInInternal(t, email, pw) // clean session: no key in memory, no Fetch
	n := newTestNote(t, "FromB", "b pushes first, with no fetch")
	if _, err := b.Push(items.Items{n}); err != nil {
		t.Fatalf("b Push: %v", err)
	}
	if b.sess.DefaultItemsKey.UUID != keyA {
		t.Fatalf("b did not adopt the existing key: want %s, got %s", keyA, b.sess.DefaultItemsKey.UUID)
	}
	if ids := liveItemsKeyUUIDs(t, b); len(ids) != 1 {
		t.Fatalf("Push minted a key on an account that had one: %v", ids)
	}
	back, err := a.FetchOne(n.GetUUID())
	if err != nil || back == nil || back.Text != "b pushes first, with no fetch" {
		t.Fatalf("a FetchOne of b's note: %v err=%v", back, err)
	}
}
