package snclient

// Opt-in integration tests against a LIVE Standard Notes account. They are the
// cloud half of the write canary: token refresh and stale-push (conflict) safety,
// which the Docker suite and the MCP tools cannot drive on their own.
//
// They are SKIPPED unless SN_CLOUD_TEST=1, so normal `go test ./...` never runs
// them. To run:
//
//	SN_CLOUD_TEST=1 SN_SERVER=https://api.standardnotes.com \
//	  SN_EMAIL=.. SN_PASSWORD=.. go test ./internal/snclient -run TestCloud -v
//
// They touch a throwaway account: they seed a temp note, trash it afterward, and
// trash any conflict copy a stale push mints. They never permanent-delete.

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jonhadfield/gosn-v2/items"
	"github.com/jonhadfield/gosn-v2/session"
)

func requireCloud(t *testing.T) (server, email, password string) {
	t.Helper()
	if os.Getenv("SN_CLOUD_TEST") != "1" {
		t.Skip("set SN_CLOUD_TEST=1 and SN_SERVER/SN_EMAIL/SN_PASSWORD to run live cloud validation")
	}
	server, email, password = os.Getenv("SN_SERVER"), os.Getenv("SN_EMAIL"), os.Getenv("SN_PASSWORD")
	if server == "" || email == "" || password == "" {
		t.Fatal("SN_CLOUD_TEST=1 requires SN_SERVER, SN_EMAIL and SN_PASSWORD")
	}
	return server, email, password
}

func cloudSignIn(t *testing.T) *Client {
	t.Helper()
	server, email, password := requireCloud(t)
	c, err := SignIn(Config{Server: server}, email, password, func(string) (string, error) { return "", nil })
	if err != nil {
		t.Fatalf("sign in to %s: %v", server, err)
	}
	return c
}

func contentText(t *testing.T, r *RawNote) string {
	t.Helper()
	m, err := decodeObject([]byte(r.Content()))
	if err != nil {
		t.Fatalf("decode content of %s: %v", r.UUID, err)
	}
	var s string
	_ = json.Unmarshal(m["text"], &s)
	return s
}

// TestCloudRefreshDirect proves the production refresh exchange works against the
// live server: body tokens + cookies -> 200 with a new session, and the rotated
// tokens still authenticate a fetch.
func TestCloudRefreshDirect(t *testing.T) {
	c := cloudSignIn(t)
	if _, _, err := c.Fetch(); err != nil {
		t.Fatalf("fetch before refresh: %v", err)
	}
	oldAccess, oldExp := c.sess.AccessToken, c.sess.AccessExpiration

	// The point: our official-client-shaped refresh gets a complete 200 from the
	// cloud, where gosn-v2's token-less-body refresh gets a 400. The cloud returns
	// the SAME still-valid token rather than rotating one nowhere near expiry, so
	// success is "200 + complete session + the session still authenticates", not
	// "the token changed".
	if err := refreshCookieSession(c.sess); err != nil {
		t.Fatalf("refreshCookieSession against cloud (expected a 200): %v", err)
	}
	if c.sess.AccessToken == "" || c.sess.RefreshToken == "" || c.sess.AccessExpiration == 0 {
		t.Fatalf("refresh returned an incomplete session")
	}
	if _, _, err := c.Fetch(); err != nil {
		t.Fatalf("fetch AFTER refresh: %v", err)
	}
	rotated := c.sess.AccessToken != oldAccess
	validDays := time.Until(time.UnixMilli(c.sess.AccessExpiration)).Hours() / 24
	t.Logf("refresh OK: 200 + complete session + post-refresh fetch works; token rotated=%v; access token valid ~%.1f days (exp %d->%d)",
		rotated, validDays, oldExp, c.sess.AccessExpiration)
}

// TestCloudRefreshViaGuard proves the Guard auto-refreshes before a call when the
// access token is within the 10-minute threshold of expiry — the production flow
// that keeps a long run alive.
func TestCloudRefreshViaGuard(t *testing.T) {
	c := cloudSignIn(t)
	g := NewGuard(c, "") // "" => no keyring persistence

	// Spy on the refresh seam to prove the guard invokes it, then delegate to the
	// real production refresh.
	called := 0
	g.refresh = func(s *session.Session) error {
		called++
		return refreshCookieSession(s)
	}

	// Make the guard believe the token is about to expire (inside the 10m threshold).
	c.sess.AccessExpiration = time.Now().Add(5 * time.Minute).UnixMilli()

	var fetched int
	err := g.Do(func(cl *Client) error {
		notes, _, err := cl.Fetch()
		fetched = len(notes)
		return err
	})
	if err != nil {
		t.Fatalf("guard.Do (expected refresh then fetch): %v", err)
	}
	if called != 1 {
		t.Errorf("guard invoked refresh %d times, want 1 (needsRefresh should have fired)", called)
	}
	if _, _, err := c.Fetch(); err != nil {
		t.Fatalf("fetch after guard refresh: %v", err)
	}
	t.Logf("guard auto-refresh OK: needsRefresh fired, refresh invoked %dx, fetched %d notes; session still valid", called, fetched)
}

// TestCloudStalePushCaught proves a push built on a stale version does NOT
// overwrite the server's newer version, and that RequireSaved reports it. This is
// the primitive the write engine's stray-halt relies on.
func TestCloudStalePushCaught(t *testing.T) {
	c := cloudSignIn(t)

	// A rejected stale push does NOT overwrite the server version (asserted below),
	// but the server mints a conflict copy on a LATER sync — not in the push result
	// here, where conflicts=0. The write engine's snapshot-diff stray-halt catches
	// that during a real edit; this raw-layer test does not, so it sweeps any copy a
	// previous run left behind, by title.
	const canaryTitle = "stale-push canary"
	sweepByTitle(c, canaryTitle)

	uuid, err := c.SeedNote(t, canaryTitle, "v1 original")
	if err != nil {
		t.Fatalf("seed temp note: %v", err)
	}
	t.Cleanup(func() { trashBestEffort(c, uuid) })

	// Take a stale handle, then advance the server past it.
	stale, err := c.FetchRawOne(uuid)
	if err != nil {
		t.Fatalf("fetch stale handle: %v", err)
	}
	if err := c.EditNoteText(uuid, "v2 current (the server's truth)"); err != nil {
		t.Fatalf("advance to v2: %v", err)
	}

	// Push from the stale handle. The server must reject it as stale.
	enc, err := c.EncryptMutated(stale, textMutation("v_STALE must NOT win"))
	if err != nil {
		t.Fatalf("encrypt stale mutation: %v", err)
	}
	out, err := c.PushEncrypted(items.EncryptedItems{enc})
	if err != nil {
		t.Fatalf("push stale (expected nil err, not-saved): %v", err)
	}

	if err := RequireSaved(out, uuid); err == nil {
		t.Errorf("RequireSaved did NOT catch the stale push (saved=%d conflicts=%d unsaved=%d)",
			len(out.SavedItems), len(out.Conflicts), len(out.Unsaved))
	} else {
		t.Logf("stale push correctly reported not-saved: %v", err)
	}

	// Trash any conflict copy the stale push minted (a new uuid in SavedItems).
	for _, it := range out.SavedItems {
		if it.UUID != uuid {
			t.Logf("stale push minted a conflict copy %s; trashing it", it.UUID)
			trashBestEffort(c, it.UUID)
		}
	}

	// The server's live version must still be v2, never the stale write.
	cur, err := c.FetchRawOne(uuid)
	if err != nil {
		t.Fatalf("fetch current after stale push: %v", err)
	}
	text := contentText(t, cur)
	if strings.Contains(text, "STALE") {
		t.Errorf("DATA LOSS: the stale write overwrote the server version; text=%q", text)
	}
	if !strings.Contains(text, "v2 current") {
		t.Errorf("unexpected live text after stale push: %q", text)
	}
	t.Logf("server version intact: text=%q (conflicts=%d saved=%d unsaved=%d)",
		text, len(out.Conflicts), len(out.SavedItems), len(out.Unsaved))
}

// trashBestEffort sets the reversible trashed flag on an item. It never
// permanent-deletes, and it ignores errors: it is cleanup, not an assertion.
func trashBestEffort(c *Client, uuid string) {
	r, err := c.FetchRawOne(uuid)
	if err != nil {
		return
	}
	enc, err := c.EncryptMutated(r, SetKey("trashed", true))
	if err != nil {
		return
	}
	_, _ = c.PushEncrypted(items.EncryptedItems{enc})
}

// sweepByTitle trashes every note with this exact title, so a stale push's
// conflict copy from a previous run does not accumulate. Best effort; trashing an
// already-trashed note is harmless.
func sweepByTitle(c *Client, title string) {
	notes, _, err := c.Fetch()
	if err != nil {
		return
	}
	for _, n := range notes {
		if n.Title == title {
			trashBestEffort(c, n.UUID)
		}
	}
}
