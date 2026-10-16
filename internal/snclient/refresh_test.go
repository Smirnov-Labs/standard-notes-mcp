package snclient

// Offline tests for refreshCookieSession, run against a fake of the stock
// server's refresh endpoint. The live test in session_guard_integration_test.go
// proves the same refresh on the real Docker server. These run anywhere.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jonhadfield/gosn-v2/common"
	"github.com/jonhadfield/gosn-v2/session"
)

// stockRejection is what the stock server answers when a refresh request breaks
// its contract.
const stockRejection = `{"meta":{"auth":{},"server":{}},"data":{"error":{"message":"Please provide all required parameters."}}}`

const (
	newAccessCookie  = "access_token_u1=cookie-new-a"
	newRefreshCookie = "refresh_token_u1=cookie-new-r"
)

// fakeRefreshServer imitates the part of the stock server's refresh endpoint
// that this client depends on: both tokens in the JSON body, both token cookies,
// and the client-version headers. A request that breaks that contract gets the
// stock 400 and is listed in violations, which every test checks. A request that
// keeps it gets whatever respond writes.
type fakeRefreshServer struct {
	*httptest.Server
	mu         sync.Mutex
	violations []string
}

func newFakeRefreshServer(t *testing.T, s *session.Session, respond func(w http.ResponseWriter)) *fakeRefreshServer {
	t.Helper()
	f := &fakeRefreshServer{}
	// What the server expects for this session: its two tokens and its cookies.
	access, refresh := s.AccessToken, s.RefreshToken
	cookies := map[string]string{}
	for _, pair := range []string{s.AccessTokenCookie, s.RefreshTokenCookie} {
		name, value, _ := strings.Cut(pair, "=")
		cookies[name] = value
	}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var bad []string
		if r.Method != http.MethodPost || r.URL.Path != common.AuthRefreshPath {
			bad = append(bad, "request is "+r.Method+" "+r.URL.Path)
		}
		if r.Header.Get(common.HeaderContentType) != common.SNAPIContentType {
			bad = append(bad, "Content-Type is not JSON")
		}
		if r.Header.Get("X-SNJS-Version") == "" || r.Header.Get("X-Application-Version") == "" {
			bad = append(bad, "client-version headers are missing")
		}
		var body struct {
			API          string `json:"api"`
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			bad = append(bad, "body is not JSON")
		}
		if body.API != common.APIVersion {
			bad = append(bad, "body api version is wrong")
		}
		if body.AccessToken != access || body.RefreshToken != refresh {
			bad = append(bad, "body does not carry both tokens")
		}
		for name, value := range cookies {
			if c, err := r.Cookie(name); err != nil || c.Value != value {
				bad = append(bad, "cookie "+name+" is missing or wrong")
			}
		}
		if len(bad) > 0 {
			f.mu.Lock()
			f.violations = append(f.violations, bad...)
			f.mu.Unlock()
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(stockRejection))
			return
		}
		respond(w)
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeRefreshServer) requireNoViolations(t *testing.T) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.violations) > 0 {
		t.Fatalf("the request broke the server's contract: %v", f.violations)
	}
}

// answer makes the fake server reply with the given status, body and cookies.
func answer(status int, body string, setCookies ...string) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		for _, c := range setCookies {
			w.Header().Add("Set-Cookie", c+"; Path=/; HttpOnly; SameSite=Lax")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

// sessionBody is a refresh answer that carries the given session fields.
func sessionBody(access, refresh string, accessExp, refreshExp int64) string {
	return fmt.Sprintf(`{"meta":{"auth":{},"server":{}},"data":{"session":{"access_token":%q,"refresh_token":%q,"access_expiration":%d,"refresh_expiration":%d}}}`,
		access, refresh, accessExp, refreshExp)
}

// cookieSession is a session as the official client holds one: two tokens and
// two token cookies. Callers set Server to the fake server's URL.
func cookieSession() *session.Session {
	return &session.Session{
		AccessToken:        "access-old",
		RefreshToken:       "refresh-old",
		AccessExpiration:   1000,
		RefreshExpiration:  2000,
		AccessTokenCookie:  "access_token_u1=cookie-old-a",
		RefreshTokenCookie: "refresh_token_u1=cookie-old-r",
		FilesServerUrl:     "http://files.old.invalid",
		ReadOnlyAccess:     true,
	}
}

func TestRefreshCookieSessionRotatesTokensExpiriesAndCookies(t *testing.T) {
	s := cookieSession()
	f := newFakeRefreshServer(t, s, answer(http.StatusOK,
		sessionBody("access-new", "refresh-new", 3000, 4000),
		"session_id=not-a-token-cookie", newAccessCookie, newRefreshCookie))
	s.Server = f.URL

	if err := refreshCookieSession(s); err != nil {
		t.Fatalf("refreshCookieSession: %v", err)
	}
	f.requireNoViolations(t)

	// FilesServerUrl and ReadOnlyAccess are not part of what this refresh reads,
	// so they stay as they were. The unrelated cookie is not adopted.
	want := creds{
		accessToken: "access-new", refreshToken: "refresh-new",
		accessExpiration: 3000, refreshExpiration: 4000,
		accessCookie: newAccessCookie, refreshCookie: newRefreshCookie,
		filesServerURL: "http://files.old.invalid", readOnlyAccess: true,
	}
	if changed := want.changed(credsOf(s)); len(changed) > 0 {
		t.Fatalf("session after a good refresh differs from the server's answer, fields: %v", changed)
	}
}

// The refresh writes to the session only after it holds a complete 200. Every
// other outcome returns an error and leaves all eight fields as they were.
func TestRefreshCookieSessionLeavesSessionAloneOnFailure(t *testing.T) {
	cases := []struct {
		name    string
		respond func(w http.ResponseWriter)
	}{
		{
			"server answers 400 with its rejection",
			answer(http.StatusBadRequest, stockRejection),
		},
		{
			"server answers 500 with a complete session in the body",
			answer(http.StatusInternalServerError, sessionBody("access-new", "refresh-new", 3000, 4000), newAccessCookie, newRefreshCookie),
		},
		{
			"200 without an access token",
			answer(http.StatusOK, sessionBody("", "refresh-new", 3000, 4000), newAccessCookie, newRefreshCookie),
		},
		{
			"200 without a refresh token",
			answer(http.StatusOK, sessionBody("access-new", "", 3000, 4000), newAccessCookie, newRefreshCookie),
		},
		{
			"200 with access expiration zero",
			answer(http.StatusOK, sessionBody("access-new", "refresh-new", 0, 4000), newAccessCookie, newRefreshCookie),
		},
		{
			"200 with refresh expiration zero",
			answer(http.StatusOK, sessionBody("access-new", "refresh-new", 3000, 0), newAccessCookie, newRefreshCookie),
		},
		{
			"200 with a body that is not JSON",
			answer(http.StatusOK, "<html>bad gateway</html>", newAccessCookie, newRefreshCookie),
		},
		{
			"200 with an empty body",
			answer(http.StatusOK, "", newAccessCookie, newRefreshCookie),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := cookieSession()
			f := newFakeRefreshServer(t, s, tc.respond)
			s.Server = f.URL
			before := credsOf(s)

			if err := refreshCookieSession(s); err == nil {
				t.Fatal("refreshCookieSession returned nil")
			}
			f.requireNoViolations(t)
			if changed := before.changed(credsOf(s)); len(changed) > 0 {
				t.Fatalf("a failed refresh left the session changed, fields: %v", changed)
			}
		})
	}
}

func TestRefreshCookieSessionLeavesSessionAloneWhenServerIsDown(t *testing.T) {
	s := cookieSession()
	f := newFakeRefreshServer(t, s, answer(http.StatusOK, sessionBody("access-new", "refresh-new", 3000, 4000)))
	s.Server = f.URL
	f.Close() // from here on, connections to the address are refused
	before := credsOf(s)

	if err := refreshCookieSession(s); err == nil {
		t.Fatal("refreshCookieSession returned nil with the server down")
	}
	if changed := before.changed(credsOf(s)); len(changed) > 0 {
		t.Fatalf("a failed refresh left the session changed, fields: %v", changed)
	}
}

// A session with no server URL must fail here. gosn-v2's own Refresh would
// fall back to the real cloud server in that case.
func TestRefreshCookieSessionNeedsAServerURL(t *testing.T) {
	s := cookieSession()
	before := credsOf(s)

	if err := refreshCookieSession(s); err == nil || !strings.Contains(err.Error(), "no server URL") {
		t.Fatalf("refreshCookieSession returned %v, want an error about the missing server URL", err)
	}
	if changed := before.changed(credsOf(s)); len(changed) > 0 {
		t.Fatalf("a failed refresh left the session changed, fields: %v", changed)
	}
}

// A cookie that the answer does not rotate must keep its old value. Blanking it
// would leave a session that cannot authenticate.
func TestRefreshCookieSessionKeepsCookiesTheAnswerDoesNotSet(t *testing.T) {
	s := cookieSession()
	f := newFakeRefreshServer(t, s, answer(http.StatusOK,
		sessionBody("access-new", "refresh-new", 3000, 4000), newAccessCookie)) // no refresh cookie
	s.Server = f.URL

	if err := refreshCookieSession(s); err != nil {
		t.Fatalf("refreshCookieSession: %v", err)
	}
	f.requireNoViolations(t)

	want := creds{
		accessToken: "access-new", refreshToken: "refresh-new",
		accessExpiration: 3000, refreshExpiration: 4000,
		accessCookie: newAccessCookie, refreshCookie: "refresh_token_u1=cookie-old-r",
		filesServerURL: "http://files.old.invalid", readOnlyAccess: true,
	}
	if changed := want.changed(credsOf(s)); len(changed) > 0 {
		t.Fatalf("session after the refresh differs from what the answer sets, fields: %v", changed)
	}
}

// countingTransport counts the requests that pass through it.
type countingTransport struct {
	next http.RoundTripper
	n    *atomic.Int32
}

func (c countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.n.Add(1)
	return c.next.RoundTrip(r)
}

// A session that has its own HTTP client (SignIn and Restore give every session
// one) must send the refresh through it, not through a client of the refresh's own.
func TestRefreshCookieSessionUsesTheSessionHTTPClient(t *testing.T) {
	t.Setenv("HTTP_PROXY", "") // gosn-v2's client sends even loopback requests through a set proxy
	s := cookieSession()
	f := newFakeRefreshServer(t, s, answer(http.StatusOK, sessionBody("access-new", "refresh-new", 3000, 4000)))
	s.Server = f.URL

	hc := common.NewHTTPClient()
	hc.RetryMax = 0
	var carried atomic.Int32
	hc.HTTPClient.Transport = countingTransport{next: hc.HTTPClient.Transport, n: &carried}
	s.HTTPClient = hc

	if err := refreshCookieSession(s); err != nil {
		t.Fatalf("refreshCookieSession: %v", err)
	}
	f.requireNoViolations(t)
	if got := carried.Load(); got != 1 {
		t.Fatalf("the session's HTTP client carried %d requests, want 1", got)
	}
	if s.AccessToken != "access-new" {
		t.Fatal("the refresh did not update the session")
	}
}
