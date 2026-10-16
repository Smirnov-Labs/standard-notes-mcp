package snclient

import (
	"errors"
	"fmt"
	"time"

	"github.com/jonhadfield/gosn-v2/common"
	"github.com/jonhadfield/gosn-v2/items"
	"github.com/jonhadfield/gosn-v2/session"
)

type NoteView struct {
	UUID, Title, Text, NoteType, EditorIdentifier string
	// CreatedAt is the item's creation timestamp as the server stores it (an ISO
	// 8601 string, e.g. "2024-03-15T10:30:00.000000Z"). Used to place a note by date.
	CreatedAt string
	Trashed   bool
	raw       *items.Note
}
type TagView struct {
	UUID, Title string
	NoteUUIDs   []string
	raw         *items.Tag
}

// Fetch does an always-live sync (items.Sync hits the network every call) and
// returns decrypted notes and tags.
func (c *Client) Fetch() ([]*NoteView, []*TagView, error) {
	if err := c.syncDelta(); err != nil {
		return nil, nil, err
	}
	parsed, err := c.cache.snapshot().DecryptAndParse(c.sess)
	if err != nil {
		return nil, nil, err
	}
	var notes []*NoteView
	var tags []*TagView
	for _, it := range parsed {
		switch v := it.(type) {
		case *items.Note:
			notes = append(notes, toNoteView(v))
		case *items.Tag:
			var ids []string
			for _, r := range v.Content.GetNoteReferences() {
				ids = append(ids, r.UUID)
			}
			tags = append(tags, &TagView{UUID: v.GetUUID(), Title: v.Content.GetTitle(), NoteUUIDs: ids, raw: v})
		}
	}
	return notes, tags, nil
}

// syncDelta syncs only the changes since the cache's token (a full sync on the first
// call, when the token is empty), merges them into the cache, and advances the token.
// Callers decrypt-on-read from the cache afterward. gosn adopts any items-keys in the
// response into the session during the sync, so decryption keeps working across deltas.
func (c *Client) syncDelta() error {
	out, err := clientSync(items.SyncInput{Session: c.sess, SyncToken: c.cache.currentToken()})
	if err != nil {
		return err
	}
	c.cache.apply(out.Items, out.SyncToken)
	return nil
}

func (c *Client) FetchOne(uuid string) (*NoteView, error) {
	notes, _, err := c.Fetch()
	if err != nil {
		return nil, err
	}
	for _, n := range notes {
		if n.UUID == uuid {
			return n, nil
		}
	}
	return nil, nil
}

func toNoteView(n *items.Note) *NoteView {
	// Read the field, not GetTrashed(): that getter returns *Trashed and panics
	// when the note has no "trashed" key, which is every note never trashed.
	trashed := false
	if t := n.Content.Trashed; t != nil {
		trashed = *t
	}
	return &NoteView{
		UUID: n.GetUUID(), Title: n.Content.GetTitle(), Text: n.Content.GetText(),
		NoteType: n.Content.NoteType, EditorIdentifier: n.Content.EditorIdentifier,
		CreatedAt: n.GetCreatedAt(),
		Trashed:   trashed, raw: n,
	}
}

// Push encrypts with the default items key and syncs. If the session has no
// default key yet, Push calls ensureItemsKey first. That adopts the key of a
// real account after one sync, or makes the first key on a fresh account. Once
// the session holds a key, Push adds no work.
func (c *Client) Push(toPush items.Items) (items.SyncOutput, error) {
	if !c.hasDefaultItemsKey() {
		if err := c.ensureItemsKey(); err != nil {
			return items.SyncOutput{}, err
		}
	}
	enc, err := toPush.Encrypt(c.sess, c.sess.DefaultItemsKey)
	if err != nil {
		return items.SyncOutput{}, err
	}
	// Push BARE (no sync token). Sending a token changes the server's conflict
	// handling so a stale push no longer mints the copy the engine's stray-halt
	// detects — see writeengine's stale/duplicate tests. The cache stays correct
	// anyway: the read before each write (FetchRawOne -> syncDelta) refreshes it.
	return clientSync(items.SyncInput{Session: c.sess, Items: enc})
}

// hasDefaultItemsKey reports whether the session can encrypt: Items.Encrypt
// needs the key's uuid (items_key_id) and its key material.
func (c *Client) hasDefaultItemsKey() bool {
	k := c.sess.DefaultItemsKey
	return k.UUID != "" && k.ItemsKey != ""
}

// ensureItemsKey makes sure the session has a usable DefaultItemsKey, creating
// and pushing one if the account has none. A freshly registered account has no
// items key: gosn-v2's Register does not make one (the official apps do, during
// setup), so nothing can be encrypted until one exists. Push calls this whenever
// the session has no default key. On a real account, which always has a key,
// this is a no-op: one read-only sync, no write.
//
// Create sequence, from the gosn-v2 sources:
//
//  1. items.Sync (pull). processSessionItemsKeysInSavedItems adopts any
//     existing key as sess.DefaultItemsKey / sess.ItemsKeys.
//  2. items.CreateItemsKey: random 256-bit key, uuid, created_at(+_timestamp).
//     Its content defaults to version 004 and isDefault true.
//  3. items.EncryptItemsKey(key, sess, new=true): the key is encrypted under a
//     one-off item key, and that item key under sess.MasterKey (an items key is
//     the one item type wrapped by the root key, not by another items key). The
//     authenticated data carries the account key params. new=true leaves
//     updated_at empty; Sync drops any pushed SN|ItemsKey that has one.
//  4. items.Sync (push). The server echoes the key in SavedItems and Sync
//     decrypts it with the master key and adopts it as the session default.
//
// Two guards keep this from corrupting an account. The server must hold NO live
// items key before we create one: if it holds some the session failed to adopt,
// we stop rather than re-key a real account. And after the push, the key must
// come back as saved and be the session default, so a note is never encrypted
// with a key the server does not hold.
func (c *Client) ensureItemsKey() error {
	pulled, err := clientSync(items.SyncInput{Session: c.sess})
	if err != nil {
		return fmt.Errorf("ensure items key: sync: %w", err)
	}
	if c.hasDefaultItemsKey() {
		return nil
	}
	for _, it := range pulled.Items {
		if it.ContentType == common.SNItemTypeItemsKey && !it.Deleted {
			return errors.New("ensure items key: account has items keys but the session could not adopt one; refusing to create another")
		}
	}

	ik, err := items.CreateItemsKey()
	if err != nil {
		return fmt.Errorf("ensure items key: create: %w", err)
	}
	enc, err := items.EncryptItemsKey(session.SessionItemsKey{
		UUID:               ik.UUID,
		ItemsKey:           ik.ItemsKey,
		Version:            ik.Content.Version,
		Default:            true,
		CreatedAt:          ik.CreatedAt,
		CreatedAtTimestamp: ik.CreatedAtTimestamp,
	}, c.sess, true)
	if err != nil {
		return fmt.Errorf("ensure items key: encrypt: %w", err)
	}

	pushed, err := clientSync(items.SyncInput{Session: c.sess, Items: items.EncryptedItems{enc}})
	if err != nil {
		return fmt.Errorf("ensure items key: push: %w", err)
	}
	saved := false
	for _, it := range pushed.SavedItems {
		if it.UUID == ik.UUID {
			saved = true
		}
	}
	if !saved || c.sess.DefaultItemsKey.UUID != ik.UUID {
		return fmt.Errorf("ensure items key: server did not accept new items key %s (saved=%t, conflicts=%d)",
			ik.UUID, saved, len(pushed.Conflicts))
	}
	return nil
}

// SeedNote is a TEST-ONLY helper: create a note with a known title/body. Push
// makes the account's first items key when it has none. The first parameter is
// the narrow interface that *testing.T satisfies, so this package does not
// import testing.
func (c *Client) SeedNote(t interface{ Helper() }, title, text string) (string, error) {
	t.Helper()
	n, err := items.NewNote(title, text, nil)
	if err != nil {
		return "", err
	}
	n.Content.SetUpdateTime(time.Now().UTC())
	if _, err := c.Push(items.Items{&n}); err != nil {
		return "", err
	}
	return n.GetUUID(), nil
}
