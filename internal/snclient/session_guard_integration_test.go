package snclient

// Live tests for Guard. They need the Docker SN server and skip cleanly without
// it (testsupport.NewAccount probes the server, and honours SN_TEST_SERVER=off).
// They sit in their own file so session_guard_test.go stays free of the server.

import (
	"testing"
	"time"

	"github.com/jonhadfield/gosn-v2/session"
	"github.com/smirnov-labs/standard-notes-mcp/internal/testsupport"
)

// requireHealthySession fails the test unless c holds a complete session that is
// far from both expiries. A test then knows that the near-expiry value it forces
// is the only reason for the Guard to refresh.
func requireHealthySession(t *testing.T, c *Client) {
	t.Helper()
	if c.sess.AccessToken == "" || needsRefresh(c.sess.AccessExpiration, time.Now()) ||
		time.Until(time.UnixMilli(c.sess.RefreshExpiration)) < 24*time.Hour {
		t.Fatalf("premise broken: fresh session is not healthy: tokenSet=%t accessExp=%d refreshExp=%d",
			c.sess.AccessToken != "", c.sess.AccessExpiration, c.sess.RefreshExpiration)
	}
}

// The unit tests pin the expiry decision and the failure handling. This test
// pins what the Guard is for: a session whose token is inside the refresh window
// is refreshed BEFORE the sync, so gosn-v2 never reaches its os.Exit on a 498.
// It runs the DEFAULT refresh, refreshCookieSession, against the Docker server:
// it is the only test that proves the production refresh works on a real server.
func TestGuardRefreshesNearExpiryTokenBeforeSync(t *testing.T) {
	email, pw := testsupport.NewAccount(t)
	c := signInInternal(t, email, pw)
	noteID, err := c.SeedNote(t, "Guarded read", "read through a refreshed session")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Premise: a fresh session is far from both expiries, so the near-expiry
	// forced below is the only reason for the Guard to refresh.
	requireHealthySession(t, c)

	// Force the access token inside the refresh window. The server's token is
	// untouched and still valid, so no 401 or 498 can trigger gosn-v2's own
	// refresh: only the Guard's clock check can move the expiry off this value.
	forced := time.Now().Add(5 * time.Minute).UnixMilli()
	c.sess.AccessExpiration = forced

	// Run a real fetch under the Guard. Record the session as fn starts: the
	// refresh must already have happened, not be a side effect of the sync.
	var seen struct {
		token string
		exp   int64
	}
	var got *NoteView
	g := NewGuard(c, "") // the default refresh: nothing injected
	err = g.Do(func(cl *Client) error {
		seen.token, seen.exp = cl.sess.AccessToken, cl.sess.AccessExpiration
		var ferr error
		got, ferr = cl.FetchOne(noteID)
		return ferr
	})
	if err != nil {
		t.Fatalf("Guard.Do on a near-expiry session: %v", err)
	}

	// Token lifetime is server-controlled: assert the expiry moved off the forced
	// value and is set, not what it moved to.
	if seen.token == "" {
		t.Fatal("no access token when the sync started")
	}
	if seen.exp == 0 || seen.exp == forced {
		t.Fatalf("access expiration when the sync started is %d (forced %d): token was not refreshed before the sync", seen.exp, forced)
	}
	if c.sess.AccessToken == "" || c.sess.AccessExpiration == 0 || c.sess.AccessExpiration == forced {
		t.Fatalf("session after Do is not refreshed: tokenSet=%t accessExp=%d (forced %d)",
			c.sess.AccessToken != "", c.sess.AccessExpiration, forced)
	}
	// The refreshed session must work: the sync decrypted the seeded note.
	if got == nil || got.Title != "Guarded read" || got.Text != "read through a refreshed session" {
		t.Fatalf("fetch under the Guard did not return the seeded note: %+v", got)
	}
}

// TestGuardFailsClosedWithoutBlankingSession is the live proof that a rejected
// refresh fails closed: no os.Exit, no fn, no corrupted session. It injects
// gosn-v2's own (*session.Session).Refresh, which is no longer the default. For
// a cookie session that refresh sends only {"api"} in the body, and the Docker
// server answers 400 "Please provide all required parameters." gosn-v2 does not
// check the status: it returns nil, and writes the empty answer over the
// session's tokens, expiries, FilesServerUrl and ReadOnlyAccess. The Guard must
// then:
//   - return an error, so no caller carries on with a dead session;
//   - not run fn, so no sync can reach gosn-v2's os.Exit on an expired token;
//   - put the old session back, so the live credentials are not corrupted.
//
// The final fetch checks the last point: the session still works.
func TestGuardFailsClosedWithoutBlankingSession(t *testing.T) {
	email, pw := testsupport.NewAccount(t)
	c := signInInternal(t, email, pw)
	noteID, err := c.SeedNote(t, "Fail closed", "survives a rejected refresh")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	requireHealthySession(t, c)

	// Force the access token inside the refresh window. Give the two fields that
	// gosn-v2's Refresh also writes values that no server answer repeats: the
	// 400 body carries the same filesServerUrl that the sign-in did, and
	// ReadOnlyAccess is false either way, so without these the check below could
	// not tell a restore from a coincidence. Then save the session.
	c.sess.AccessExpiration = time.Now().Add(5 * time.Minute).UnixMilli()
	c.sess.FilesServerUrl = "http://files.sentinel.invalid"
	c.sess.ReadOnlyAccess = true
	before := credsOf(c.sess)

	g := NewGuard(c, "")
	g.refresh = func(s *session.Session) error { return s.Refresh() } // gosn-v2's own refresh
	ran := false
	err = g.Do(func(*Client) error { ran = true; return nil })

	if err == nil {
		t.Fatal("Do returned nil: the server accepted gosn-v2's refresh, so this test no longer exercises a rejected refresh")
	}
	if ran {
		t.Fatal("fn ran although the refresh failed")
	}
	// Reaching this line proves the process did not exit.
	if changed := before.changed(credsOf(c.sess)); len(changed) > 0 {
		t.Fatalf("the rejected refresh left the session changed, fields: %v", changed)
	}

	// The session is intact, so it must still work. Move the forced expiry out of
	// the refresh window, so the next Do goes straight to fn.
	c.sess.AccessExpiration = time.Now().Add(72 * time.Hour).UnixMilli()
	var got *NoteView
	err = g.Do(func(cl *Client) error {
		var ferr error
		got, ferr = cl.FetchOne(noteID)
		return ferr
	})
	if err != nil {
		t.Fatalf("Guard.Do after a rejected refresh: %v", err)
	}
	if got == nil || got.Title != "Fail closed" || got.Text != "survives a rejected refresh" {
		t.Fatalf("fetch after a rejected refresh did not return the seeded note: %+v", got)
	}
}
