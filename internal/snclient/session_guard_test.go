package snclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonhadfield/gosn-v2/session"
	"github.com/zalando/go-keyring"
)

func TestNeedsRefreshUsesMillisAndThreshold(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	// AccessExpiration is unix MILLISECONDS. 5 min ahead is within the 10-min threshold → refresh.
	soon := now.Add(5 * time.Minute).UnixMilli()
	if !needsRefresh(soon, now) {
		t.Fatal("token expiring in 5m (< 10m threshold) must need refresh")
	}
	// 30 min ahead → no refresh.
	later := now.Add(30 * time.Minute).UnixMilli()
	if needsRefresh(later, now) {
		t.Fatal("token 30m out must not need refresh")
	}
	// already expired → refresh.
	if !needsRefresh(now.Add(-time.Minute).UnixMilli(), now) {
		t.Fatal("expired token must need refresh")
	}
}

// Guard's other job is that one caller at a time runs inside Do. The session
// here is far from expiry, so ensureFreshLocked never refreshes and the test
// needs no network. The fn of each caller marks when it is inside: if two are
// ever inside at once, the lock did not hold.
func TestGuardSerializesConcurrentAccess(t *testing.T) {
	farFutureMillis := time.Now().Add(72 * time.Hour).UnixMilli()
	c := &Client{sess: &session.Session{
		AccessToken:       "x",
		AccessExpiration:  farFutureMillis,
		RefreshExpiration: farFutureMillis,
	}}
	g := NewGuard(c, "")

	const callers = 50
	var (
		inside     atomic.Int32 // callers inside fn right now
		ran        atomic.Int32 // callers whose fn ran at all
		overlapped atomic.Bool  // set if a second caller got in while one was inside
		wg         sync.WaitGroup
	)
	errs := make([]error, callers) // one slot per caller: no shared writes
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = g.Do(func(*Client) error {
				ran.Add(1)
				if inside.Add(1) > 1 {
					overlapped.Store(true)
				}
				time.Sleep(time.Microsecond) // stay inside long enough for a second caller to arrive
				inside.Add(-1)
				return nil
			})
		}()
	}
	wg.Wait()

	if overlapped.Load() {
		t.Fatal("more than one caller was inside Do at the same time: the session is not serialized")
	}
	for i, err := range errs {
		if err != nil {
			t.Fatalf("Do #%d returned %v, want nil", i, err)
		}
	}
	if got := ran.Load(); got != callers {
		t.Fatalf("fn ran %d times, want %d", got, callers)
	}
}

// creds is every session field that a refresh can write: the six token fields,
// and the two that gosn-v2's Refresh also assigns. Tests compare these and list
// the fields that differ by name, so token values never reach a test log.
type creds struct {
	accessToken, refreshToken           string
	accessExpiration, refreshExpiration int64
	accessCookie, refreshCookie         string
	filesServerURL                      string
	readOnlyAccess                      bool
}

func credsOf(s *session.Session) creds {
	return creds{
		accessToken: s.AccessToken, refreshToken: s.RefreshToken,
		accessExpiration: s.AccessExpiration, refreshExpiration: s.RefreshExpiration,
		accessCookie: s.AccessTokenCookie, refreshCookie: s.RefreshTokenCookie,
		filesServerURL: s.FilesServerUrl, readOnlyAccess: s.ReadOnlyAccess,
	}
}

// changed names the fields that differ between a and b.
func (a creds) changed(b creds) []string {
	var names []string
	for _, f := range []struct {
		name string
		same bool
	}{
		{"AccessToken", a.accessToken == b.accessToken},
		{"RefreshToken", a.refreshToken == b.refreshToken},
		{"AccessExpiration", a.accessExpiration == b.accessExpiration},
		{"RefreshExpiration", a.refreshExpiration == b.refreshExpiration},
		{"AccessTokenCookie", a.accessCookie == b.accessCookie},
		{"RefreshTokenCookie", a.refreshCookie == b.refreshCookie},
		{"FilesServerUrl", a.filesServerURL == b.filesServerURL},
		{"ReadOnlyAccess", a.readOnlyAccess == b.readOnlyAccess},
	} {
		if !f.same {
			names = append(names, f.name)
		}
	}
	return names
}

// nearExpirySession is a hand-made session whose access token is inside the
// refresh window and whose refresh token is far from expiry, so the Guard must
// try a refresh. FilesServerUrl and ReadOnlyAccess start non-zero, so a refresh
// that blanks them is visible. Server is a dead local address: a test that
// forgets to inject a refresh fails at once with connection refused, and never
// reaches a real server.
func nearExpirySession() *session.Session {
	return &session.Session{
		Server:             "http://127.0.0.1:1",
		FilesServerUrl:     "http://files.old.invalid",
		ReadOnlyAccess:     true,
		AccessToken:        "access-old",
		RefreshToken:       "refresh-old",
		AccessExpiration:   time.Now().Add(5 * time.Minute).UnixMilli(),
		RefreshExpiration:  time.Now().Add(72 * time.Hour).UnixMilli(),
		AccessTokenCookie:  "access_token_x=old",
		RefreshTokenCookie: "refresh_token_x=old",
	}
}

// A refresh that fails must leave the session as it was. gosn-v2's Refresh
// blanks the tokens when the server rejects the request, and still returns nil,
// so the Guard checks the session as well as the error. The refresh seam lets
// this run with no server. The live test in session_guard_integration_test.go
// does the same against gosn-v2's own Refresh.
func TestGuardRestoresSessionWhenRefreshFails(t *testing.T) {
	errRejected := errors.New("server said no")
	cases := []struct {
		name    string
		refresh func(s *session.Session) error
		wantErr error // the error Do must wrap; nil when the refresh itself returns nil
	}{
		{
			name: "refresh returns an error after it wrote to every field",
			refresh: func(s *session.Session) error {
				s.AccessToken, s.RefreshToken = "half-written", "half-written"
				s.AccessExpiration, s.RefreshExpiration = 1, 1
				s.AccessTokenCookie, s.RefreshTokenCookie = "access_token_x=half-written", "refresh_token_x=half-written"
				s.FilesServerUrl, s.ReadOnlyAccess = "http://files.half-written.invalid", false
				return errRejected
			},
			wantErr: errRejected,
		},
		{
			name: "refresh returns nil but blanked the session, as gosn-v2 does on a 400",
			refresh: func(s *session.Session) error {
				s.AccessToken, s.RefreshToken = "", ""
				s.AccessExpiration, s.RefreshExpiration = 0, 0
				s.FilesServerUrl, s.ReadOnlyAccess = "", false
				return nil
			},
		},
		{
			name: "refresh returns nil with the access token blank",
			refresh: func(s *session.Session) error {
				s.AccessToken = ""
				return nil
			},
		},
		{
			name: "refresh returns nil with the access expiration zero",
			refresh: func(s *session.Session) error {
				s.AccessExpiration = 0
				return nil
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := nearExpirySession()
			before := credsOf(s)
			g := NewGuard(&Client{sess: s}, "")
			g.refresh = tc.refresh

			ran := false
			err := g.Do(func(*Client) error { ran = true; return nil })

			if err == nil {
				t.Fatal("Do returned nil after a failed refresh")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("Do returned %q, which does not wrap the refresh error", err)
			}
			if ran {
				t.Fatal("fn ran after a failed refresh")
			}
			if changed := before.changed(credsOf(s)); len(changed) > 0 {
				t.Fatalf("a failed refresh left the session changed, fields: %v", changed)
			}
		})
	}
}

// A refresh that works must stick: fn runs against the refreshed session, and
// the next call, now far from expiry, does not refresh again.
func TestGuardKeepsRefreshedSession(t *testing.T) {
	farFutureMillis := time.Now().Add(72 * time.Hour).UnixMilli()
	want := creds{
		accessToken: "access-new", refreshToken: "refresh-new",
		accessExpiration: farFutureMillis, refreshExpiration: farFutureMillis,
		accessCookie: "access_token_x=new", refreshCookie: "refresh_token_x=new",
		filesServerURL: "http://files.new.invalid", readOnlyAccess: false,
	}
	s := nearExpirySession()
	g := NewGuard(&Client{sess: s}, "")
	refreshes := 0
	g.refresh = func(s *session.Session) error {
		refreshes++
		s.AccessToken, s.RefreshToken = want.accessToken, want.refreshToken
		s.AccessExpiration, s.RefreshExpiration = want.accessExpiration, want.refreshExpiration
		s.AccessTokenCookie, s.RefreshTokenCookie = want.accessCookie, want.refreshCookie
		s.FilesServerUrl, s.ReadOnlyAccess = want.filesServerURL, want.readOnlyAccess
		return nil
	}

	var seenByFn creds
	if err := g.Do(func(c *Client) error { seenByFn = credsOf(c.sess); return nil }); err != nil {
		t.Fatalf("Do on a near-expiry session: %v", err)
	}
	if err := g.Do(func(*Client) error { return nil }); err != nil {
		t.Fatalf("second Do: %v", err)
	}

	if changed := want.changed(seenByFn); len(changed) > 0 {
		t.Fatalf("fn did not see the refreshed session, fields differ: %v", changed)
	}
	if changed := want.changed(credsOf(s)); len(changed) > 0 {
		t.Fatalf("the refreshed session did not stick, fields differ: %v", changed)
	}
	if refreshes != 1 {
		t.Fatalf("refresh ran %d times over two calls, want 1", refreshes)
	}
}

// Persisting after a refresh is best effort: the refresh has already worked in
// memory, so a keyring failure must not turn it into an error. The keyring
// provider is a process-wide global with no reset, and other tests in this
// binary use the real keyring. So the test runs itself again in a child
// process, where it can replace the provider freely.
func TestGuardPersistAfterRefreshIsBestEffort(t *testing.T) {
	const childEnv = "SN_GUARD_PERSIST_CHILD"
	if os.Getenv(childEnv) == "" {
		exe, err := os.Executable()
		if err != nil {
			t.Fatalf("os.Executable: %v", err)
		}
		cmd := exec.Command(exe, "-test.run=^"+t.Name()+"$", "-test.v", "-test.count=1")
		cmd.Env = append(os.Environ(), childEnv+"=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("child process failed: %v\n%s", err, out)
		}
		// A run that matched no test also exits 0. Insist on seeing the pass.
		if !strings.Contains(string(out), "--- PASS: "+t.Name()) {
			t.Fatalf("child process did not run the test:\n%s", out)
		}
		return
	}

	const ref = "persist-test-ref"
	rotate := func(s *session.Session) error {
		s.AccessToken = "access-new"
		s.AccessExpiration = time.Now().Add(72 * time.Hour).UnixMilli()
		return nil
	}

	// A working keyring receives the refreshed tokens.
	keyring.MockInit()
	s := nearExpirySession()
	g := NewGuard(&Client{sess: s}, ref)
	g.refresh = rotate
	if err := g.Do(func(*Client) error { return nil }); err != nil {
		t.Fatalf("Do with a working keyring: %v", err)
	}
	raw, err := keyring.Get(keyringService, ref)
	if err != nil {
		t.Fatalf("the refreshed session was not persisted: %v", err)
	}
	var stored blob
	if err := json.Unmarshal([]byte(raw), &stored); err != nil {
		t.Fatalf("stored session is not readable: %v", err)
	}
	if stored.AccessToken != "access-new" {
		t.Fatal("the keyring holds the access token from before the refresh")
	}

	// A failing keyring is logged, and the session stays refreshed and usable.
	keyring.MockInitWithError(errors.New("keychain locked"))
	var logs bytes.Buffer
	log.SetOutput(&logs)
	s = nearExpirySession()
	g = NewGuard(&Client{sess: s}, ref)
	g.refresh = rotate
	ran := false
	err = g.Do(func(*Client) error { ran = true; return nil })
	if err != nil {
		t.Fatalf("a keyring failure failed a refresh that had worked: %v", err)
	}
	if !ran {
		t.Fatal("fn did not run after a refresh that had worked")
	}
	if s.AccessToken != "access-new" {
		t.Fatal("a keyring failure rolled back a refresh that had worked")
	}
	if !strings.Contains(logs.String(), "persist after refresh failed: keychain locked") {
		t.Fatalf("the keyring failure was not logged, log output: %q", logs.String())
	}
}
