package snclient

import (
	"encoding/json"
	"errors"
	"os"

	"github.com/jonhadfield/gosn-v2/auth"
	"github.com/jonhadfield/gosn-v2/common"
	"github.com/jonhadfield/gosn-v2/session"
	"github.com/zalando/go-keyring"
)

const keyringService = "standard-notes-mcp"

// ErrVerifyFailed means a read-after-write check did not match the intended change.
var ErrVerifyFailed = errors.New("read-after-write verification failed")

type Config struct{ Server string }

// EnvServer returns the SN server URL from SN_SERVER, or the local default.
func EnvServer() string {
	if s := os.Getenv("SN_SERVER"); s != "" {
		return s
	}
	return "http://localhost:3000"
}

type Client struct {
	sess *session.Session
	// cache holds the item set as ciphertext + the sync token, so syncs after the
	// first pull only CHANGES instead of the whole vault. In-memory per process.
	cache *vaultCache
}

// Authenticated reports whether the session carries the material needed to make
// authenticated calls. On this server Token is empty; auth rides on AccessToken.
func (c *Client) Authenticated() bool {
	return c.sess != nil && c.sess.AccessToken != "" && c.sess.MasterKey != ""
}

// SignIn authenticates (004). mfa is called with the echoed TokenName when a
// 2FA code is required; return the code.
func SignIn(cfg Config, email, password string, mfa func(prompt string) (string, error)) (*Client, error) {
	hc := common.NewHTTPClient()
	in := auth.SignInInput{HTTPClient: hc, Email: email, Password: password, APIServer: cfg.Server}
	so, err := auth.SignIn(in)
	if err != nil {
		return nil, err
	}
	if so.TokenName != "" {
		code, mErr := mfa(so.TokenName)
		if mErr != nil {
			return nil, mErr
		}
		in.TokenName, in.TokenVal = so.TokenName, code
		if so, err = auth.SignIn(in); err != nil {
			return nil, err
		}
	}
	sess := &session.Session{
		HTTPClient:         hc,
		Server:             cfg.Server,
		FilesServerUrl:     so.Session.FilesServerUrl,
		MasterKey:          so.Session.MasterKey,
		KeyParams:          so.KeyParams,
		AccessToken:        so.Session.AccessToken,
		RefreshToken:       so.Session.RefreshToken,
		AccessExpiration:   so.Session.AccessExpiration,
		RefreshExpiration:  so.Session.RefreshExpiration,
		AccessTokenCookie:  so.Session.AccessTokenCookie,
		RefreshTokenCookie: so.Session.RefreshTokenCookie,
		PasswordNonce:      so.Session.PasswordNonce,
	}
	return &Client{sess: sess, cache: newVaultCache()}, nil
}

// blob is the minimal persisted set. ItemsKeys are intentionally omitted —
// gosn-v2 refetches them on the first Sync.
type blob struct {
	Server, MasterKey, AccessToken, RefreshToken, PasswordNonce string
	AccessTokenCookie, RefreshTokenCookie                       string
	AccessExp, RefreshExp                                       int64
	KeyParams                                                   json.RawMessage
}

func (c *Client) Persist(ref string) error {
	kp, _ := json.Marshal(c.sess.KeyParams)
	b, _ := json.Marshal(blob{
		Server: c.sess.Server, MasterKey: c.sess.MasterKey,
		AccessToken: c.sess.AccessToken, RefreshToken: c.sess.RefreshToken,
		PasswordNonce:     c.sess.PasswordNonce,
		AccessTokenCookie: c.sess.AccessTokenCookie, RefreshTokenCookie: c.sess.RefreshTokenCookie,
		AccessExp: c.sess.AccessExpiration, RefreshExp: c.sess.RefreshExpiration, KeyParams: kp,
	})
	return keyring.Set(keyringService, ref, string(b))
}

func Restore(cfg Config, ref string) (*Client, error) {
	raw, err := keyring.Get(keyringService, ref)
	if err != nil {
		return nil, err
	}
	var b blob
	if err := json.Unmarshal([]byte(raw), &b); err != nil {
		return nil, err
	}
	sess := &session.Session{
		HTTPClient: common.NewHTTPClient(), Server: cfg.Server,
		MasterKey: b.MasterKey, AccessToken: b.AccessToken, RefreshToken: b.RefreshToken,
		PasswordNonce:     b.PasswordNonce,
		AccessTokenCookie: b.AccessTokenCookie, RefreshTokenCookie: b.RefreshTokenCookie,
		AccessExpiration: b.AccessExp, RefreshExpiration: b.RefreshExp,
	}
	_ = json.Unmarshal(b.KeyParams, &sess.KeyParams)
	return &Client{sess: sess, cache: newVaultCache()}, nil
}

// ForgetSession removes a persisted session (used for test cleanup and logout).
func ForgetSession(ref string) error { return keyring.Delete(keyringService, ref) }
