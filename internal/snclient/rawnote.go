package snclient

// The surgical write path, for notes and for tags. gosn-v2's typed path loses
// fields: it decrypts into a fixed struct (unknown keys are dropped), and it
// encrypts that struct again. This file works on the raw decrypted JSON instead.
// A mutation changes the keys it names and client_updated_at. Every other value
// keeps its exact bytes, so a key it does not know, such as one a future app adds,
// survives. The encrypt and push steps do not look at the item type, so a note
// and a tag use the same ones. Only the fetch checks the type.

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jonhadfield/gosn-v2/auth"
	"github.com/jonhadfield/gosn-v2/common"
	"github.com/jonhadfield/gosn-v2/crypto"
	"github.com/jonhadfield/gosn-v2/items"
	"github.com/jonhadfield/gosn-v2/session"
)

// snAppDataKey is the appData domain that holds client_updated_at.
const snAppDataKey = "org.standardnotes.sn"

var (
	// ErrNoteNotFound means the server holds no live note with that uuid.
	ErrNoteNotFound = errors.New("note not found")

	// ErrTagNotFound means the server holds no live tag with that uuid.
	ErrTagNotFound = errors.New("tag not found")

	// ErrPushNotSaved means a push returned without an error, but the server did
	// not save the item. See RequireSaved.
	ErrPushNotSaved = errors.New("server did not save the pushed item")
)

// RawNote is the content of a note or a tag as the server holds it, decrypted but
// not parsed. A mutation of it can not drop a key that it never reads.
type RawNote struct {
	UUID string
	di   items.DecryptedItem // di.Content is the raw JSON text
}

// Content returns the raw decrypted JSON text of the item.
func (r *RawNote) Content() string { return r.di.Content }

// FetchRawOne syncs live and returns the note's raw content. It returns an error,
// never a nil note, for a uuid that is missing, deleted, or not a note. A nil note
// would panic in the caller, and a tag that went through a note mutation would
// get a text key. See fetchRaw.
func (c *Client) FetchRawOne(uuid string) (*RawNote, error) {
	return c.fetchRaw(uuid, common.SNItemTypeNote, ErrNoteNotFound)
}

// FetchRawTag is FetchRawOne for a tag. It returns an error, never a nil tag, for
// a uuid that is missing, deleted, or not a tag. A note that went through a tag
// mutation would get a reference list that it never had. The RawNote that it
// returns goes through EncryptMutated and PushEncrypted like a note does.
func (c *Client) FetchRawTag(uuid string) (*RawNote, error) {
	return c.fetchRaw(uuid, common.SNItemTypeTag, ErrTagNotFound)
}

// fetchRaw syncs live and returns the raw content of the item with this uuid. The
// sync output already holds the ciphertext of every item. fetchRaw decrypts the
// one it wants with DecryptItem, which returns the JSON text before any typed
// parse. It refuses an item that is deleted, an item that is not of content type
// want, and a uuid that no item has. For a deleted item and for a missing uuid it
// wraps notFound, so a caller can tell them apart from a wrong type.
func (c *Client) fetchRaw(uuid, want string, notFound error) (*RawNote, error) {
	if err := c.syncDelta(); err != nil {
		return nil, err
	}
	e, ok := c.cache.get(uuid)
	if !ok {
		// Not in the cache: it never existed, or a delete tombstone dropped it on
		// merge. Either way, not found (still wraps notFound, as before).
		return nil, fmt.Errorf("%w: %s", notFound, uuid)
	}
	if e.ContentType != want {
		return nil, fmt.Errorf("item %s is a %s, not a %s", uuid, e.ContentType, want)
	}
	di, err := items.DecryptItem(e, c.sess, c.sess.ItemsKeys)
	if err != nil {
		return nil, fmt.Errorf("decrypt %s %s: %w", strings.ToLower(want), uuid, err)
	}
	return &RawNote{UUID: uuid, di: di}, nil
}

// EncryptMutated applies mutate to the item's content, as a map of raw JSON
// values, then sets appData[org.standardnotes.sn].client_updated_at to now, and
// returns the item encrypted under the session's default items key. It does not
// push, and it does not change r: r stays as it was fetched.
//
// The item keeps the updated_at_timestamp that the fetch saw. The server compares
// it, and rejects a write that is based on a version that is no longer current.
func (c *Client) EncryptMutated(r *RawNote, mutate func(content map[string]json.RawMessage) error) (items.EncryptedItem, error) {
	if r == nil {
		return items.EncryptedItem{}, errors.New("encrypt mutated: no item")
	}
	content, err := mutateContent(r.di.Content, mutate, time.Now().UTC())
	if err != nil {
		return items.EncryptedItem{}, fmt.Errorf("item %s: %w", r.UUID, err)
	}
	di := r.di
	di.Content = content
	return encryptRawContent(di, c.sess.DefaultItemsKey, c.sess)
}

// PushEncrypted pushes items that are already encrypted. It mirrors Push but does
// not encrypt, so the content that EncryptMutated made is the content that lands.
// Like Push, it returns without an error when the server rejects an item as
// stale: see RequireSaved.
//
// It refuses an item whose envelope is marked deleted. That flag removes an item
// for good. The engine's only delete is the reversible trashed flag in the content.
func (c *Client) PushEncrypted(e items.EncryptedItems) (items.SyncOutput, error) {
	for _, it := range e {
		if it.Deleted {
			return items.SyncOutput{}, fmt.Errorf("push encrypted: item %s is marked deleted, and this layer never deletes", it.UUID)
		}
	}
	// Push BARE (no sync token): a token changes the server's conflict handling so a
	// stale push no longer mints the copy the engine detects. The cache refreshes on
	// the next read's syncDelta.
	return clientSync(items.SyncInput{Session: c.sess, Items: e})
}

// RequireSaved returns ErrPushNotSaved unless out lists uuid as saved. When the
// server rejects a push as stale, gosn-v2 returns no error. It keeps the server's
// version and saves ours as a copy under a new uuid. Only the absence of uuid
// from SavedItems shows that our write did not land. Other items in SavedItems,
// such as that copy, do not count: look for the uuid, not for a count.
// Every caller of PushEncrypted must check its push with this function.
func RequireSaved(out items.SyncOutput, uuid string) error {
	for _, it := range out.SavedItems {
		if it.UUID == uuid {
			return nil
		}
	}
	return fmt.Errorf("%w: %s (saved=%d unsaved=%d conflicts=%d)",
		ErrPushNotSaved, uuid, len(out.SavedItems), len(out.Unsaved), len(out.Conflicts))
}

// EditNoteText changes the text of a note and nothing else but client_updated_at.
// It is the template for an engine mutation: fetch fresh, encrypt the one change,
// push, and check that the push was saved. The engine also compares snapshots
// before and after, to find a conflict copy that a rejected push leaves behind.
func (c *Client) EditNoteText(uuid, newText string) error {
	r, err := c.FetchRawOne(uuid)
	if err != nil {
		return err
	}
	enc, err := c.EncryptMutated(r, textMutation(newText))
	if err != nil {
		return err
	}
	out, err := c.PushEncrypted(items.EncryptedItems{enc})
	if err != nil {
		return err
	}
	return RequireSaved(out, uuid)
}

// SetKey returns a mutation for EncryptMutated that sets one top-level key of the
// item to v and changes no other key. It writes v as the official apps write JSON:
// see jsonValue. A key that the item does not have is added. The engine builds its
// note edits from it: a text, a title, and the trashed flag. It builds the title
// change and the trash of a tag from it too.
func SetKey(key string, v any) func(map[string]json.RawMessage) error {
	return func(m map[string]json.RawMessage) error {
		raw, err := jsonValue(v)
		if err != nil {
			return err
		}
		m[key] = raw
		return nil
	}
}

// textMutation is a mutation that sets the text key and no other.
func textMutation(newText string) func(map[string]json.RawMessage) error {
	return SetKey("text", newText)
}

// SeedRawNote is a TEST-ONLY helper: create a note whose content is exactly raw.
// A test uses it to make a note with fields that gosn-v2 does not model. The
// first parameter is the narrow interface that *testing.T satisfies.
func (c *Client) SeedRawNote(t interface{ Helper() }, raw string) (string, error) {
	t.Helper()
	return c.seedRaw(raw, common.SNItemTypeNote)
}

// SeedRawTag is SeedRawNote for a tag: a TEST-ONLY helper that creates a tag whose
// content is exactly raw. A test uses it to make a tag with fields that gosn-v2
// does not model.
func (c *Client) SeedRawTag(t interface{ Helper() }, raw string) (string, error) {
	t.Helper()
	return c.seedRaw(raw, common.SNItemTypeTag)
}

// seedRaw creates an item of the given content type whose content is exactly raw,
// and returns its uuid. It makes the account's first items key when there is none.
func (c *Client) seedRaw(raw, contentType string) (string, error) {
	if !c.hasDefaultItemsKey() {
		if err := c.ensureItemsKey(); err != nil {
			return "", err
		}
	}
	now := time.Now().UTC()
	di := items.DecryptedItem{
		UUID: items.GenUUID(), ContentType: contentType, Content: raw,
		CreatedAt: now.Format(common.TimeLayout), CreatedAtTimestamp: now.UnixMicro(),
	}
	enc, err := encryptRawContent(di, c.sess.DefaultItemsKey, c.sess)
	if err != nil {
		return "", err
	}
	out, err := c.PushEncrypted(items.EncryptedItems{enc})
	if err != nil {
		return "", err
	}
	if err := RequireSaved(out, di.UUID); err != nil {
		return "", err
	}
	return di.UUID, nil
}

// mutateContent applies mutate to the top-level keys of a JSON object, sets
// client_updated_at, and returns the new JSON text.
func mutateContent(raw string, mutate func(map[string]json.RawMessage) error, now time.Time) (string, error) {
	m, err := decodeObject([]byte(raw))
	if err != nil {
		return "", fmt.Errorf("content is not a JSON object: %w", err)
	}
	if err := mutate(m); err != nil {
		return "", err
	}
	if err := setClientUpdatedAt(m, now); err != nil {
		return "", err
	}
	out, err := encodeObject(m)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// setClientUpdatedAt sets appData[org.standardnotes.sn].client_updated_at in m,
// in the layout that gosn-v2's SetUpdateTime writes. Only the objects on the path
// to that key are rebuilt; the values beside it keep their bytes.
func setClientUpdatedAt(m map[string]json.RawMessage, now time.Time) error {
	appData, err := objectOrEmpty(m["appData"], "appData")
	if err != nil {
		return err
	}
	sn, err := objectOrEmpty(appData[snAppDataKey], "appData["+snAppDataKey+"]")
	if err != nil {
		return err
	}
	stamp, err := jsonValue(now.UTC().Format(common.TimeLayout))
	if err != nil {
		return err
	}
	sn["client_updated_at"] = stamp
	if appData[snAppDataKey], err = encodeObject(sn); err != nil {
		return err
	}
	if m["appData"], err = encodeObject(appData); err != nil {
		return err
	}
	return nil
}

// decodeObject splits a JSON object into its top-level raw values. A value that
// is not an object is an error. A JSON null is one: encoding/json decodes it to a
// nil map without an error, and a write to that map would panic.
func decodeObject(raw []byte) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errors.New("value is null")
	}
	return m, nil
}

// objectOrEmpty is decodeObject for a value that may be absent. An absent value or
// a JSON null holds no data, so each gives an empty object. Any other value that
// is not an object is an error, so that data of an unknown shape is never overwritten.
func objectOrEmpty(raw json.RawMessage, name string) (map[string]json.RawMessage, error) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return map[string]json.RawMessage{}, nil
	}
	m, err := decodeObject(raw)
	if err != nil {
		return nil, fmt.Errorf("%s is not a JSON object: %w", name, err)
	}
	return m, nil
}

// jsonValue encodes v as the official apps do. JavaScript's JSON.stringify leaves
// <, > and & as they are. encoding/json would write them as <, > and
// & unless the escaping is switched off.
func jsonValue(v any) (json.RawMessage, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// encodeObject writes m as one JSON object. It copies each value as it is. It does
// not parse or re-encode a value, so an untouched value keeps every byte, spaces
// and number forms included. It sorts the keys: the order of keys in a JSON
// object carries no meaning. It refuses a value that is not valid JSON, because
// it would otherwise write a note that no client can parse.
func encodeObject(m map[string]json.RawMessage) ([]byte, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range keys {
		if !json.Valid(m[k]) {
			return nil, fmt.Errorf("key %q does not hold valid JSON", k)
		}
		if i > 0 {
			b.WriteByte(',')
		}
		kb, err := jsonValue(k)
		if err != nil {
			return nil, err
		}
		b.Write(kb)
		b.WriteByte(':')
		b.Write(m[k])
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// encryptRawContent encrypts di.Content, byte for byte, as a protocol 004 item.
// It follows gosn-v2's items.EncryptItem, which encrypts a typed item, but it
// takes the JSON text and does not marshal anything. It differs in one way: the
// item key gets its own nonce, as in the official apps. EncryptItem reuses the
// content nonce. Each nonce is stored in its own protocol string, so both decrypt.
//
// It does not call gosn-v2's (DecryptedItem).Encrypt, though that also encrypts
// Content as it is. Encrypt makes the item key with GenerateItemKey(32). The
// argument counts hex characters, so that key has 16 bytes. gosn-v2 pads it with
// zeros when it decrypts, so gosn-v2 can read the item. The official apps need a
// 256-bit key (V004Algorithm.EncryptionKeyLength in standardnotes/app, checked
// 2026-10-05). Their XChaCha20 decrypt fails on a 16-byte key, and they then mark
// the item errorDecrypting. EncryptItem calls GenerateItemKey(64), and so does
// this function.
func encryptRawContent(di items.DecryptedItem, ik session.SessionItemsKey, s *session.Session) (items.EncryptedItem, error) {
	if err := checkItemsKey(ik); err != nil {
		return items.EncryptedItem{}, err
	}
	itemKey, err := crypto.GenerateItemKey(64)
	if err != nil {
		return items.EncryptedItem{}, err
	}
	authData := base64.StdEncoding.EncodeToString([]byte(auth.GenerateAuthData(di.ContentType, di.UUID, s.KeyParams)))

	contentNonce, err := newNonce()
	if err != nil {
		return items.EncryptedItem{}, err
	}
	encContent, err := crypto.EncryptString(di.Content, itemKey, contentNonce, authData, 32)
	if err != nil {
		return items.EncryptedItem{}, fmt.Errorf("encrypt content: %w", err)
	}
	keyNonce, err := newNonce()
	if err != nil {
		return items.EncryptedItem{}, err
	}
	encItemKey, err := crypto.EncryptString(itemKey, ik.ItemsKey, keyNonce, authData, 32)
	if err != nil {
		return items.EncryptedItem{}, fmt.Errorf("encrypt item key: %w", err)
	}

	enc := items.EncryptedItem{
		UUID:               di.UUID,
		ItemsKeyID:         ik.UUID,
		ContentType:        di.ContentType,
		Content:            fmt.Sprintf("%s:%s:%s:%s", common.DefaultSNVersion, contentNonce, encContent, authData),
		EncItemKey:         fmt.Sprintf("%s:%s:%s:%s", common.DefaultSNVersion, keyNonce, encItemKey, authData),
		CreatedAt:          di.CreatedAt,
		UpdatedAt:          di.UpdatedAt,
		CreatedAtTimestamp: di.CreatedAtTimestamp,
		UpdatedAtTimestamp: di.UpdatedAtTimestamp,
	}
	// A push replaces the good ciphertext on the server. So read the item back
	// first, and refuse to return one that is not what we mean to push.
	if err := verifyEncrypted(enc, ik, di.Content); err != nil {
		return items.EncryptedItem{}, err
	}
	return enc, nil
}

// checkItemsKey fails unless ik is a real items key: a uuid, and 64 hex chars.
// The crypto code turns a missing or short key into zero bytes and goes on, which
// would encrypt a note under an all-zero key. And verifyEncrypted would pass,
// because it opens the item with the same key. The errors do not show the key.
func checkItemsKey(ik session.SessionItemsKey) error {
	if ik.UUID == "" {
		return errors.New("items key has no uuid")
	}
	if raw, err := hex.DecodeString(ik.ItemsKey); err != nil || len(raw) != 32 {
		return errors.New("items key is not 64 hex chars")
	}
	return nil
}

// verifyEncrypted opens enc with ik and fails unless it yields want. It also
// fails unless the item key is 64 hex chars (32 bytes). gosn-v2's decrypt accepts
// a shorter key, so the length needs its own check. The errors name no content.
func verifyEncrypted(enc items.EncryptedItem, ik session.SessionItemsKey, want string) error {
	itemKey, err := items.DecryptEncryptedItemKey(enc, ik.ItemsKey)
	if err != nil {
		return fmt.Errorf("verify: open item key: %w", err)
	}
	if raw, err := hex.DecodeString(string(itemKey)); err != nil || len(raw) != 32 {
		return fmt.Errorf("verify: item key has %d hex chars, want 64 (a 32-byte key)", len(itemKey))
	}
	got, err := items.DecryptContent(enc, string(itemKey))
	if err != nil {
		return fmt.Errorf("verify: open content: %w", err)
	}
	if string(got) != want {
		return errors.New("verify: the item does not decrypt to the intended content")
	}
	return nil
}

// newNonce returns a random 24-byte nonce as 48 hex characters.
func newNonce() (string, error) {
	b, err := crypto.GenerateNonce()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
