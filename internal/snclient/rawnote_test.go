package snclient

// Tests for the surgical note write path: decrypt to the raw JSON, change ONE
// key, encrypt that exact JSON. The integration tests need the Docker SN server
// and skip cleanly without it (testsupport.NewAccount probes the server and
// honours SN_TEST_SERVER=off). The offline tests need nothing.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jonhadfield/gosn-v2/common"
	"github.com/jonhadfield/gosn-v2/items"
	"github.com/jonhadfield/gosn-v2/session"
	"github.com/smirnov-labs/standard-notes-mcp/internal/testsupport"
)

// richContent is a note that carries every kind of field gosn-v2's typed note
// model drops: top-level flags (protected, starred), flags inside the SN appData
// domain (archived, locked), a third-party appData domain, and an unknown key.
// spellcheck is modeled by gosn-v2; it is here because a mutation must keep it too.
const richContent = `{"title":"rich","text":"old body","references":[],` +
	`"protected":true,"starred":true,` +
	`"appData":{"org.standardnotes.sn":{"client_updated_at":"2020-01-01T00:00:00.000Z","archived":true,"locked":true},` +
	`"dev.example.editor":{"theme":"dark","fontSize":17}},` +
	`"spellcheck":false,"future_unknown_key":"must survive"}`

// objectOf decodes a JSON object into its top-level raw values.
func objectOf(t *testing.T, raw []byte) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		t.Fatalf("not a JSON object (%v): %s", err, raw)
	}
	return m
}

// fetchRawContent returns the raw decrypted content the server holds for a note.
func fetchRawContent(t *testing.T, c *Client, uuid string) string {
	t.Helper()
	r, err := c.FetchRawOne(uuid)
	if err != nil {
		t.Fatalf("FetchRawOne(%s): %v", uuid, err)
	}
	return r.Content()
}

// diffKeys compares two objects key by key on the raw bytes. changed holds keys
// whose bytes differ; added and removed hold keys that exist on one side only.
func diffKeys(before, after map[string]json.RawMessage) (changed, added, removed []string) {
	for k, b := range before {
		a, ok := after[k]
		switch {
		case !ok:
			removed = append(removed, k)
		case !bytes.Equal(a, b):
			changed = append(changed, k)
		}
	}
	for k := range after {
		if _, ok := before[k]; !ok {
			added = append(added, k)
		}
	}
	sort.Strings(changed)
	sort.Strings(added)
	sort.Strings(removed)
	return changed, added, removed
}

// show renders m[k] for a failure message. Go prints a missing RawMessage as
// null, which reads as a value, so say <missing> instead.
func show(m map[string]json.RawMessage, k string) string {
	v, ok := m[k]
	if !ok {
		return "<missing>"
	}
	return string(v)
}

// requireKeys fails unless got equals want. level names the object for the message.
func requireKeys(t *testing.T, level, what string, got, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("%s: %s keys = %v, want %v", level, what, got, want)
	}
}

// The preservation test. A text edit through the surgical path must change the
// text and client_updated_at, and nothing else. Every other field, modeled or
// not, known or not, must come back byte for byte.
func TestSurgicalTextEditPreservesEveryUnmodeledField(t *testing.T) {
	email, pw := testsupport.NewAccount(t)
	c := signInInternal(t, email, pw)

	uuid, err := c.SeedRawNote(t, richContent)
	if err != nil {
		t.Fatalf("seed rich note: %v", err)
	}
	// Premise: the server holds the rich content byte for byte as sent. Without
	// this, a later match could mean the seed was already damaged.
	if got := fetchRawContent(t, c, uuid); got != richContent {
		t.Fatalf("premise broken: seeded content did not round-trip\n got: %s\nwant: %s", got, richContent)
	}

	if err := c.EditNoteText(uuid, "new body"); err != nil {
		t.Fatalf("EditNoteText: %v", err)
	}

	before := objectOf(t, []byte(richContent))
	after := objectOf(t, []byte(fetchRawContent(t, c, uuid)))
	beforeApp, afterApp := objectOf(t, before["appData"]), objectOf(t, after["appData"])
	beforeSN := objectOf(t, beforeApp["org.standardnotes.sn"])
	afterSN := objectOf(t, afterApp["org.standardnotes.sn"])

	// The edit landed.
	if string(after["text"]) != `"new body"` {
		t.Errorf("text = %s, want \"new body\"", after["text"])
	}

	// client_updated_at changed, uses the layout gosn-v2's SetUpdateTime writes,
	// and is the current time.
	if bytes.Equal(beforeSN["client_updated_at"], afterSN["client_updated_at"]) {
		t.Errorf("client_updated_at did not change: %s", afterSN["client_updated_at"])
	}
	var stamp string
	if err := json.Unmarshal(afterSN["client_updated_at"], &stamp); err != nil {
		t.Fatalf("client_updated_at is not a JSON string: %s", afterSN["client_updated_at"])
	}
	at, err := time.Parse(common.TimeLayout, stamp)
	if err != nil {
		t.Fatalf("client_updated_at %q is not in layout %q: %v", stamp, common.TimeLayout, err)
	}
	if d := time.Since(at); d < -time.Minute || d > time.Minute {
		t.Errorf("client_updated_at %q is %v from now", stamp, d)
	}

	// Each field the brief names is byte-identical.
	for _, k := range []string{"protected", "starred", "spellcheck", "future_unknown_key"} {
		if !bytes.Equal(before[k], after[k]) {
			t.Errorf("top-level %q changed: %s -> %s", k, show(before, k), show(after, k))
		}
	}
	for _, k := range []string{"archived", "locked"} {
		if !bytes.Equal(beforeSN[k], afterSN[k]) {
			t.Errorf("appData[org.standardnotes.sn].%s changed: %s -> %s", k, show(beforeSN, k), show(afterSN, k))
		}
	}
	if !bytes.Equal(beforeApp["dev.example.editor"], afterApp["dev.example.editor"]) {
		t.Errorf("third-party appData changed: %s -> %s", show(beforeApp, "dev.example.editor"), show(afterApp, "dev.example.editor"))
	}

	// Whole-object check: at each of the three levels, exactly the intended key
	// changed, and nothing was added or removed. appData differs only because the
	// SN domain inside it does, and that domain differs only by client_updated_at.
	for _, lvl := range []struct {
		name          string
		before, after map[string]json.RawMessage
		changed       []string
	}{
		{"content", before, after, []string{"appData", "text"}},
		{"appData", beforeApp, afterApp, []string{"org.standardnotes.sn"}},
		{"appData[org.standardnotes.sn]", beforeSN, afterSN, []string{"client_updated_at"}},
	} {
		changed, added, removed := diffKeys(lvl.before, lvl.after)
		requireKeys(t, lvl.name, "changed", changed, lvl.changed)
		requireKeys(t, lvl.name, "added", added, nil)
		requireKeys(t, lvl.name, "removed", removed, nil)
	}

	// What the server stores opens under a strict 004 client: the item key is 64
	// hex chars (32 bytes), not the 32 chars that gosn-v2's DecryptedItem.Encrypt makes.
	enc := storedEncrypted(t, c, uuid)
	if enc.ItemsKeyID != c.sess.DefaultItemsKey.UUID {
		t.Fatalf("stored under items key %s, want the default %s", enc.ItemsKeyID, c.sess.DefaultItemsKey.UUID)
	}
	itemKey, err := items.DecryptEncryptedItemKey(enc, c.sess.DefaultItemsKey.ItemsKey)
	if err != nil {
		t.Fatalf("open stored item key: %v", err)
	}
	if raw, err := hex.DecodeString(string(itemKey)); err != nil || len(raw) != 32 {
		t.Errorf("stored item key is %d hex chars (err=%v), want 64", len(itemKey), err)
	}
}

// storedEncrypted returns the ciphertext envelope the server holds for a note.
func storedEncrypted(t *testing.T, c *Client, uuid string) items.EncryptedItem {
	t.Helper()
	out, err := items.Sync(items.SyncInput{Session: c.sess})
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	for _, e := range out.Items {
		if e.UUID == uuid {
			return e
		}
	}
	t.Fatalf("note %s not on the server", uuid)
	return items.EncryptedItem{}
}

// Control for the test above. The same rich note, edited through the typed path
// that Plan 1 built, loses the unmodeled fields: gosn-v2 parses into a fixed
// struct and writes that struct back. This is why the surgical path exists, and
// it shows the preservation test can fail. If gosn-v2 ever keeps these fields,
// this test fails: check whether the surgical path is still needed.
func TestTypedEditDropsUnmodeledFields(t *testing.T) {
	email, pw := testsupport.NewAccount(t)
	c := signInInternal(t, email, pw)

	uuid, err := c.SeedRawNote(t, richContent)
	if err != nil {
		t.Fatalf("seed rich note: %v", err)
	}
	nv, err := c.FetchOne(uuid)
	if err != nil || nv == nil {
		t.Fatalf("FetchOne: note=%v err=%v", nv, err)
	}
	if err := c.ApplyTextEdit(nv, "typed edit"); err != nil {
		t.Fatalf("ApplyTextEdit: %v", err)
	}

	after := objectOf(t, []byte(fetchRawContent(t, c, uuid)))
	for _, k := range []string{"protected", "starred", "future_unknown_key"} {
		if _, ok := after[k]; ok {
			t.Errorf("control: typed edit kept top-level %q", k)
		}
	}
	app := objectOf(t, after["appData"])
	if _, ok := app["dev.example.editor"]; ok {
		t.Error("control: typed edit kept the third-party appData domain")
	}
	sn := objectOf(t, app["org.standardnotes.sn"])
	for _, k := range []string{"archived", "locked"} {
		if _, ok := sn[k]; ok {
			t.Errorf("control: typed edit kept appData[org.standardnotes.sn].%s", k)
		}
	}
}

// offlineClient is a Client that holds an items key and nothing else: enough to
// encrypt and decrypt, with no server.
func offlineClient() (*Client, session.SessionItemsKey) {
	key := session.SessionItemsKey{
		UUID: items.GenUUID(), ItemsKey: strings.Repeat("0123456789abcdef", 4), Version: "004", Default: true,
	}
	return &Client{sess: &session.Session{DefaultItemsKey: key, ItemsKeys: []session.SessionItemsKey{key}}}, key
}

// rawNoteFor wraps content as a RawNote that was fetched with fixed envelope timestamps.
func rawNoteFor(content string) *RawNote {
	id := items.GenUUID()
	return &RawNote{UUID: id, di: items.DecryptedItem{
		UUID: id, ContentType: common.SNItemTypeNote, Content: content,
		CreatedAt: "2026-01-02T03:04:05.000000Z", UpdatedAt: "2026-02-03T04:05:06.123456Z",
		CreatedAtTimestamp: 1767323045000000, UpdatedAtTimestamp: 1770091506123456,
	}}
}

// setText is a mutation that changes only the text key.
func setText(v string) func(map[string]json.RawMessage) error {
	return func(m map[string]json.RawMessage) error {
		m["text"] = json.RawMessage(v)
		return nil
	}
}

// openOffline decrypts enc with the offline key, the way gosn-v2 does.
func openOffline(t *testing.T, c *Client, enc items.EncryptedItem) string {
	t.Helper()
	di, err := items.DecryptItem(enc, c.sess, c.sess.ItemsKeys)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	return di.Content
}

// awkwardContent holds values that a re-encoding through encoding/json would
// change although they mean the same thing: <, > and & (json.Marshal writes
// them as \u003c, \u003e, \u0026), spaces inside nested values, number forms
// (1.50, 1e3, a 20-digit integer, -0, a long fraction), escapes, raw non-ASCII,
// and keys that are not in sorted order.
const awkwardContent = `{"title":"Q&A <draft> caf\u00e9 \ud83d\ude00","text":"old",` +
	`"references":[ {"uuid":"11111111-1111-4111-8111-111111111111","content_type":"Note"} ],` +
	`"appData":{"org.standardnotes.sn":{"client_updated_at":"2020-01-01T00:00:00.000Z","pinned":true},` +
	`"dev.example.editor":{ "nums":[1.50, 1e3, 12345678901234567890, -0, 0.1000000000000000055511151231257827], "nested":{ "a" : null , "b":"x" } }},` +
	`"preview_plain":"<b>raw</b> & more","emoji":"\u2028 \ud83d\ude00 \u00e9 é 😀","zeta":{},"alpha":[]}`

// A mutation changes its target key and client_updated_at. Every other value
// keeps the exact bytes it had, including the ones a Go JSON encoder would rewrite.
func TestEncryptMutatedKeepsUntouchedValuesVerbatim(t *testing.T) {
	c, _ := offlineClient()
	r := rawNoteFor(awkwardContent)

	enc, err := c.EncryptMutated(r, setText(`"a < b & c"`))
	if err != nil {
		t.Fatalf("EncryptMutated: %v", err)
	}
	before := objectOf(t, []byte(awkwardContent))
	after := objectOf(t, []byte(openOffline(t, c, enc)))

	changed, added, removed := diffKeys(before, after)
	requireKeys(t, "content", "changed", changed, []string{"appData", "text"})
	requireKeys(t, "content", "added", added, nil)
	requireKeys(t, "content", "removed", removed, nil)

	// The new value is written as the official app writes it: no HTML escaping.
	if string(after["text"]) != `"a < b & c"` {
		t.Errorf("text = %s", after["text"])
	}

	beforeApp, afterApp := objectOf(t, before["appData"]), objectOf(t, after["appData"])
	changed, added, removed = diffKeys(beforeApp, afterApp)
	requireKeys(t, "appData", "changed", changed, []string{"org.standardnotes.sn"})
	requireKeys(t, "appData", "added", added, nil)
	requireKeys(t, "appData", "removed", removed, nil)

	changed, added, removed = diffKeys(objectOf(t, beforeApp["org.standardnotes.sn"]), objectOf(t, afterApp["org.standardnotes.sn"]))
	requireKeys(t, "appData[org.standardnotes.sn]", "changed", changed, []string{"client_updated_at"})
	requireKeys(t, "appData[org.standardnotes.sn]", "added", added, nil)
	requireKeys(t, "appData[org.standardnotes.sn]", "removed", removed, nil)
}

// The item key must be 64 hex chars (a 32-byte key). gosn-v2's own decrypt zero-pads
// a shorter key, so only a check of the length can tell. A strict 004 client, such
// as the official apps, can not open an item whose key is shorter.
func TestEncryptMutatedUsesFullLengthItemKey(t *testing.T) {
	c, key := offlineClient()
	r := rawNoteFor(`{"title":"t","text":"x"}`)

	enc, err := c.EncryptMutated(r, setText(`"y"`))
	if err != nil {
		t.Fatalf("EncryptMutated: %v", err)
	}

	itemKey, err := items.DecryptEncryptedItemKey(enc, key.ItemsKey)
	if err != nil {
		t.Fatalf("open item key: %v", err)
	}
	if raw, err := hex.DecodeString(string(itemKey)); err != nil || len(raw) != 32 {
		t.Errorf("item key is %d hex chars (err=%v), want 64", len(itemKey), err)
	}

	// Framing of 004 protocol strings: version:nonce:ciphertext:authdata, with a 24-byte nonce.
	var nonces []string
	for name, s := range map[string]string{"content": enc.Content, "enc_item_key": enc.EncItemKey} {
		parts := strings.Split(s, ":")
		if len(parts) != 4 || parts[0] != "004" || len(parts[1]) != 48 {
			t.Errorf("%s is not a 004 protocol string: %.60q", name, s)
			continue
		}
		nonces = append(nonces, parts[1])
	}
	if len(nonces) == 2 && nonces[0] == nonces[1] {
		t.Error("content and item key share one nonce")
	}

	// The envelope names the default key, keeps the server's version stamps, and is not a delete.
	if enc.UUID != r.UUID || enc.ContentType != common.SNItemTypeNote || enc.ItemsKeyID != key.UUID {
		t.Errorf("envelope: uuid=%s type=%s items_key_id=%s", enc.UUID, enc.ContentType, enc.ItemsKeyID)
	}
	if enc.CreatedAt != r.di.CreatedAt || enc.UpdatedAt != r.di.UpdatedAt ||
		enc.CreatedAtTimestamp != r.di.CreatedAtTimestamp || enc.UpdatedAtTimestamp != r.di.UpdatedAtTimestamp {
		t.Errorf("version stamps changed: %+v", enc)
	}
	if enc.Deleted {
		t.Error("encrypted item is marked deleted")
	}
}

// gosn-v2's DecryptedItem.Encrypt encrypts Content as it is, but it makes a 16-byte
// item key. gosn-v2 reads that back, so gosn-v2 can not see the fault. This test
// pins the fault, so that a gosn-v2 upgrade that fixes it shows up here. It also
// checks verifyEncrypted, which stops the surgical path from ever pushing an item
// that a strict client can not open, or that does not decrypt to the intended text.
func TestVerifyEncryptedRejectsWhatAStrictClientCannotOpen(t *testing.T) {
	c, key := offlineClient()
	di := rawNoteFor(`{"title":"t","text":"x"}`).di

	short, err := di.Encrypt(items.ItemsKey{UUID: key.UUID, ItemsKey: key.ItemsKey}, c.sess)
	if err != nil {
		t.Fatalf("gosn-v2 Encrypt: %v", err)
	}
	if got := openOffline(t, c, short); got != di.Content {
		t.Fatalf("gosn-v2 can not read back its own item: %q", got)
	}
	itemKey, err := items.DecryptEncryptedItemKey(short, key.ItemsKey)
	if err != nil {
		t.Fatalf("open item key: %v", err)
	}
	if len(itemKey) != 32 {
		t.Fatalf("gosn-v2 Encrypt now makes a %d-char item key (was 32). If it is 64, "+
			"encryptRawContent may call Encrypt again; keep verifyEncrypted either way", len(itemKey))
	}
	if err := verifyEncrypted(short, key, di.Content); err == nil {
		t.Error("verifyEncrypted accepted an item with a 16-byte item key")
	}

	good, err := encryptRawContent(di, key, c.sess)
	if err != nil {
		t.Fatalf("encryptRawContent: %v", err)
	}
	if err := verifyEncrypted(good, key, di.Content); err != nil {
		t.Errorf("verifyEncrypted rejected a good item: %v", err)
	}
	if err := verifyEncrypted(good, key, di.Content+" "); err == nil {
		t.Error("verifyEncrypted accepted content that differs from the intended text")
	}
	other := key
	other.ItemsKey = strings.Repeat("fedcba9876543210", 4)
	if err := verifyEncrypted(good, other, di.Content); err == nil {
		t.Error("verifyEncrypted accepted an item that the key does not open")
	}
}

// A write built from a stale read must not overwrite a newer version on the
// server. The envelope carries the updated_at_timestamp that the read saw, and the
// server compares it. gosn-v2 reports no error for the rejected push: it keeps the
// server's version and saves our item as a new conflict copy under a new uuid. (The
// engine finds that copy by its snapshot diff.) The push returns without error, so
// the caller must check that its item was saved. RequireSaved does that.
func TestStaleSurgicalPushDoesNotOverwriteNewerVersion(t *testing.T) {
	email, pw := testsupport.NewAccount(t)
	c := signInInternal(t, email, pw)
	uuid, err := c.SeedRawNote(t, richContent)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	stale, err := c.FetchRawOne(uuid) // a reader holds version 1
	if err != nil {
		t.Fatalf("FetchRawOne: %v", err)
	}
	if err := c.EditNoteText(uuid, "version 2"); err != nil { // another writer saves version 2
		t.Fatalf("EditNoteText: %v", err)
	}

	enc, err := c.EncryptMutated(stale, setText(`"stale write"`))
	if err != nil {
		t.Fatalf("EncryptMutated: %v", err)
	}
	out, err := c.PushEncrypted(items.EncryptedItems{enc})
	if err != nil {
		t.Fatalf("PushEncrypted: %v", err)
	}
	if err := RequireSaved(out, uuid); !errors.Is(err, ErrPushNotSaved) {
		t.Errorf("RequireSaved after a stale push = %v, want ErrPushNotSaved", err)
	}

	// Version 2 is still the live note, with every rich field intact.
	after := objectOf(t, []byte(fetchRawContent(t, c, uuid)))
	if string(after["text"]) != `"version 2"` {
		t.Errorf("text = %s, want \"version 2\": the stale push overwrote it", after["text"])
	}
	changed, added, removed := diffKeys(objectOf(t, []byte(richContent)), after)
	requireKeys(t, "content", "changed", changed, []string{"appData", "text"})
	requireKeys(t, "content", "added", added, nil)
	requireKeys(t, "content", "removed", removed, nil)
}

// FetchRawOne must say "not found" as an error, not as a nil note: a write path
// that gets nil would panic. It must also refuse an item that is not a note. A
// tag's uuid given to EditNoteText must not put a text key into the tag.
func TestFetchRawOneRejectsMissingAndNonNoteItems(t *testing.T) {
	email, pw := testsupport.NewAccount(t)
	c := signInInternal(t, email, pw)
	if _, err := c.SeedRawNote(t, richContent); err != nil { // also makes the account's items key
		t.Fatalf("seed: %v", err)
	}
	tag, err := c.NewTag("a tag")
	if err != nil {
		t.Fatalf("NewTag: %v", err)
	}
	if _, err := c.Push(c.RawTag(tag)); err != nil {
		t.Fatalf("push tag: %v", err)
	}

	if r, err := c.FetchRawOne(items.GenUUID()); r != nil || !errors.Is(err, ErrNoteNotFound) {
		t.Errorf("unknown uuid: note=%v err=%v, want nil and ErrNoteNotFound", r, err)
	}
	if r, err := c.FetchRawOne(tag.UUID); r != nil || err == nil || errors.Is(err, ErrNoteNotFound) {
		t.Errorf("tag uuid: note=%v err=%v, want nil and a not-a-note error", r, err)
	}
	if err := c.EditNoteText(tag.UUID, "text for a tag"); err == nil {
		t.Error("EditNoteText accepted a tag uuid")
	}
	di, err := items.DecryptItem(storedEncrypted(t, c, tag.UUID), c.sess, c.sess.ItemsKeys)
	if err != nil {
		t.Fatalf("decrypt tag: %v", err)
	}
	if _, has := objectOf(t, []byte(di.Content))["text"]; has {
		t.Errorf("the tag now has a text key: %s", di.Content)
	}
}

// EncryptMutated must refuse what it can not change safely, with an error and
// without a panic, and it must not encrypt under a key that is not a real key.
func TestEncryptMutatedFailsClosed(t *testing.T) {
	t.Run("content", func(t *testing.T) {
		c, _ := offlineClient()
		for name, content := range map[string]string{
			"null":                      `null`,
			"array":                     `[]`,
			"string":                    `"text"`,
			"empty":                     ``,
			"truncated":                 `{"text":`,
			"appData is a string":       `{"text":"x","appData":"oops"}`,
			"appData is an array":       `{"text":"x","appData":[]}`,
			"SN appData is a string":    `{"text":"x","appData":{"org.standardnotes.sn":"oops"}}`,
			"SN appData is a number":    `{"text":"x","appData":{"org.standardnotes.sn":7}}`,
			"SN appData is a bad array": `{"text":"x","appData":{"org.standardnotes.sn":[1,2]}}`,
		} {
			if _, err := c.EncryptMutated(rawNoteFor(content), setText(`"y"`)); err == nil {
				t.Errorf("%s: no error", name)
			}
		}
	})

	t.Run("null appData is treated as absent", func(t *testing.T) {
		c, _ := offlineClient()
		for name, content := range map[string]string{
			"appData null":    `{"text":"x","appData":null}`,
			"SN domain null":  `{"text":"x","appData":{"org.standardnotes.sn":null,"other":1}}`,
			"appData missing": `{"text":"x"}`,
		} {
			enc, err := c.EncryptMutated(rawNoteFor(content), setText(`"y"`))
			if err != nil {
				t.Errorf("%s: %v", name, err)
				continue
			}
			app := objectOf(t, objectOf(t, []byte(openOffline(t, c, enc)))["appData"])
			if _, ok := objectOf(t, app["org.standardnotes.sn"])["client_updated_at"]; !ok {
				t.Errorf("%s: no client_updated_at", name)
			}
		}
	})

	t.Run("mutation", func(t *testing.T) {
		c, _ := offlineClient()
		boom := errors.New("boom")
		if _, err := c.EncryptMutated(rawNoteFor(`{"text":"x"}`), func(map[string]json.RawMessage) error { return boom }); !errors.Is(err, boom) {
			t.Errorf("mutation error = %v, want boom", err)
		}
		for name, v := range map[string]json.RawMessage{"not JSON": json.RawMessage(`not json`), "nil": nil, "empty": json.RawMessage(``)} {
			if _, err := c.EncryptMutated(rawNoteFor(`{"text":"x"}`), func(m map[string]json.RawMessage) error {
				m["text"] = v
				return nil
			}); err == nil {
				t.Errorf("a mutation that sets %s was accepted", name)
			}
		}
	})

	t.Run("key", func(t *testing.T) {
		good, _ := offlineClient()
		if _, err := good.EncryptMutated(nil, setText(`"y"`)); err == nil {
			t.Error("nil note was accepted")
		}
		for name, key := range map[string]session.SessionItemsKey{
			"none":         {},
			"no items key": {UUID: items.GenUUID()},
			"no uuid":      {ItemsKey: strings.Repeat("ab", 32)},
			"short":        {UUID: items.GenUUID(), ItemsKey: "abcd"},
			"not hex":      {UUID: items.GenUUID(), ItemsKey: strings.Repeat("zz", 32)},
		} {
			c := &Client{sess: &session.Session{DefaultItemsKey: key}}
			if _, err := c.EncryptMutated(rawNoteFor(`{"text":"x"}`), setText(`"y"`)); err == nil {
				t.Errorf("key %q was accepted", name)
			}
		}
	})
}

// PushEncrypted is the one raw push. It refuses an item whose envelope says
// deleted: that flag removes the note for good, and the engine's only delete is
// the reversible trashed flag inside the content. It must refuse before any
// network call, so the offline client here has no server.
func TestPushEncryptedRefusesDeletedItems(t *testing.T) {
	c, _ := offlineClient()
	_, err := c.PushEncrypted(items.EncryptedItems{
		{UUID: items.GenUUID(), ContentType: common.SNItemTypeNote},
		{UUID: items.GenUUID(), ContentType: common.SNItemTypeNote, Deleted: true},
	})
	if err == nil || !strings.Contains(err.Error(), "deleted") {
		t.Errorf("PushEncrypted with a deleted item: err=%v, want a refusal that says deleted", err)
	}
}

// The text that an edit writes must read back as exactly the string given,
// whatever the string holds. It must also be written as the official apps write
// it: < > & stay as they are.
func TestTextMutationRoundTripsAnyString(t *testing.T) {
	c, _ := offlineClient()
	for name, text := range map[string]string{
		"empty":                    "",
		"plain":                    "new body",
		"quotes and backslashes":   `say "hi", a \ b, \\, \"`,
		"newlines":                 "a\nb\r\nc\n",
		"tabs and trailing spaces": "\tindented  \nend   ",
		"html characters":          "if a < b && c > d { return \"&amp;\" }",
		"unicode":                  "café 日本語 😀 עברית",
		"line separators":          "a\u2028b\u2029c",
		"control characters":       "bell\x07 esc\x1b unit\x1f nul\x00",
		"looks like json":          `{"text":"not a key"}`,
		"large":                    strings.Repeat("0123456789\n", 100000),
	} {
		enc, err := c.EncryptMutated(rawNoteFor(`{"title":"t","text":"old"}`), textMutation(text))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		var got string
		after := objectOf(t, []byte(openOffline(t, c, enc)))
		if err := json.Unmarshal(after["text"], &got); err != nil || got != text {
			t.Errorf("%s: text did not read back as given (err=%v, %d bytes in, %d out)", name, err, len(text), len(got))
		}
	}

	enc, err := c.EncryptMutated(rawNoteFor(`{"text":"old"}`), textMutation("a < b > c & d"))
	if err != nil {
		t.Fatalf("EncryptMutated: %v", err)
	}
	if raw := objectOf(t, []byte(openOffline(t, c, enc)))["text"]; string(raw) != `"a < b > c & d"` {
		t.Errorf("text was written as %s, want it unescaped", raw)
	}
}

// EncryptMutated must leave the note it is given as it was fetched. The engine
// may retry from the same fetched note, and the retry must not carry the first try.
func TestEncryptMutatedDoesNotChangeTheFetchedNote(t *testing.T) {
	c, _ := offlineClient()
	r := rawNoteFor(richContent)

	if _, err := c.EncryptMutated(r, textMutation("first try")); err != nil {
		t.Fatalf("EncryptMutated: %v", err)
	}
	if r.Content() != richContent {
		t.Fatalf("EncryptMutated changed the note it was given:\n%s", r.Content())
	}

	enc, err := c.EncryptMutated(r, func(map[string]json.RawMessage) error { return nil })
	if err != nil {
		t.Fatalf("second EncryptMutated: %v", err)
	}
	if got := objectOf(t, []byte(openOffline(t, c, enc)))["text"]; string(got) != `"old body"` {
		t.Errorf("a second encrypt from the same note carries the first edit: text = %s", got)
	}
}

// SetKey is the mutation that the engine uses for every note edit. It sets one
// top-level key. Nothing else changes but client_updated_at. It writes the value as
// the official apps write JSON: < > & stay as they are. A key that the note did not
// have is added.
func TestSetKeyChangesOneKeyAndWritesItLikeTheOfficialApps(t *testing.T) {
	c, _ := offlineClient()
	for name, tc := range map[string]struct {
		key   string
		value any
		want  string // the bytes that the key must hold in the note
	}{
		"title with markup": {"title", `Q&A <draft> "x"`, `"Q&A <draft> \"x\""`},
		"text with markup":  {"text", "a < b > c & d", `"a < b > c & d"`},
		"trashed true":      {"trashed", true, `true`},
		"trashed false":     {"trashed", false, `false`},
	} {
		enc, err := c.EncryptMutated(rawNoteFor(richContent), SetKey(tc.key, tc.value))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		before := objectOf(t, []byte(richContent))
		after := objectOf(t, []byte(openOffline(t, c, enc)))
		if got := show(after, tc.key); got != tc.want {
			t.Errorf("%s: %s = %s, want %s", name, tc.key, got, tc.want)
		}
		changed, added, removed := diffKeys(before, after)
		touched := append(changed, added...)
		sort.Strings(touched)
		requireKeys(t, name, "touched", touched, []string{"appData", tc.key})
		requireKeys(t, name, "removed", removed, nil)
	}
}
