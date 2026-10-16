package snclient

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/jonhadfield/gosn-v2/session"
)

// refreshThreshold mirrors gosn-v2 session.RefreshSessionThreshold (10m).
const refreshThreshold = 10 * time.Minute

// needsRefresh reports whether an access token (unix MILLISECONDS) is within the
// threshold of expiry (or past it), as of now.
func needsRefresh(accessExpirationMillis int64, now time.Time) bool {
	expiry := time.UnixMilli(accessExpirationMillis)
	return now.After(expiry.Add(-refreshThreshold)) || now.Equal(expiry.Add(-refreshThreshold))
}

// Guard serializes ALL access to one Client's session and refreshes the token
// BEFORE each sync, so gosn-v2 never reaches its uncatchable os.Exit on a 498
// expired-token sync and Sync's in-place field mutations never race.
type Guard struct {
	mu  sync.Mutex
	cl  *Client
	ref string // keyring ref, for re-persist after a token refresh
	// refresh performs the token refresh. It defaults to refreshCookieSession,
	// which follows the official app's refresh request. Tests inject another
	// refresh to drive a failure: gosn-v2's (*session.Session).Refresh sends no
	// tokens in the body, so the stock server rejects it.
	refresh func(s *session.Session) error
}

// NewGuard wraps cl. keyringRef names the keyring entry that is re-persisted
// after a token refresh; "" turns persistence off. Persisting is best effort: a
// keyring failure is logged, and does not fail the refresh.
func NewGuard(cl *Client, keyringRef string) *Guard {
	return &Guard{
		cl:      cl,
		ref:     keyringRef,
		refresh: refreshCookieSession,
	}
}

// Do runs fn with the session lock held and the token freshened first. Every
// read tool (and, in Plan 2b, every write Commit) runs inside Do, so there is
// never concurrent session access. fn must not call Do on the same Guard: the
// lock is not reentrant, so that would deadlock. If the refresh fails, Do
// returns the error without running fn, and the session is as it was before.
func (g *Guard) Do(fn func(c *Client) error) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.ensureFreshLocked(); err != nil {
		return err
	}
	return fn(g.cl)
}

// ensureFreshLocked: caller holds g.mu. Refresh proactively; never react to 498.
//
// A failed refresh must leave the session as it was. The default refresh writes
// only after a complete 200, but this does not rely on that: gosn-v2's Refresh,
// for one, does not check the HTTP status. When the server rejects the request,
// it returns nil after it has copied the empty answer over the session. So
// everything a refresh can write is saved first, and put back on any failure:
// an error from the refresh, or a session it left incomplete.
func (g *Guard) ensureFreshLocked() error {
	s := g.cl.sess
	now := time.Now().UTC()
	if now.After(time.UnixMilli(s.RefreshExpiration)) {
		return fmt.Errorf("refresh token expired; full re-authentication required")
	}
	if !needsRefresh(s.AccessExpiration, now) {
		return nil
	}
	saved := saveTokens(s)
	err := g.refresh(s)
	if err != nil || s.AccessToken == "" || s.AccessExpiration == 0 {
		saved.restore(s)
		if err != nil {
			return fmt.Errorf("refresh: %w", err)
		}
		return fmt.Errorf("refresh returned an incomplete session; previous session restored")
	}
	if g.ref != "" {
		// Best effort. The refresh already worked in memory, so the session is
		// usable: persisting only matters for surviving a restart.
		if err := g.cl.Persist(g.ref); err != nil { // re-persist rotated tokens
			log.Printf("sn-mcp: persist after refresh failed: %v", err)
		}
	}
	return nil
}

// tokenState is every session field that gosn-v2's (*session.Session).Refresh
// writes: the two tokens, the two expiries and the two cookies, plus
// FilesServerUrl and ReadOnlyAccess. A failed refresh restores all of them, so
// it is a true rollback.
type tokenState struct {
	accessToken, refreshToken             string
	accessExpiration, refreshExpiration   int64
	accessTokenCookie, refreshTokenCookie string
	filesServerUrl                        string
	readOnlyAccess                        bool
}

func saveTokens(s *session.Session) tokenState {
	return tokenState{
		accessToken:        s.AccessToken,
		refreshToken:       s.RefreshToken,
		accessExpiration:   s.AccessExpiration,
		refreshExpiration:  s.RefreshExpiration,
		accessTokenCookie:  s.AccessTokenCookie,
		refreshTokenCookie: s.RefreshTokenCookie,
		filesServerUrl:     s.FilesServerUrl,
		readOnlyAccess:     s.ReadOnlyAccess,
	}
}

func (t tokenState) restore(s *session.Session) {
	s.AccessToken, s.RefreshToken = t.accessToken, t.refreshToken
	s.AccessExpiration, s.RefreshExpiration = t.accessExpiration, t.refreshExpiration
	s.AccessTokenCookie, s.RefreshTokenCookie = t.accessTokenCookie, t.refreshTokenCookie
	s.FilesServerUrl, s.ReadOnlyAccess = t.filesServerUrl, t.readOnlyAccess
}
