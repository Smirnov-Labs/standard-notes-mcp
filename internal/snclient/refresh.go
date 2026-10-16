package snclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jonhadfield/gosn-v2/common"
	"github.com/jonhadfield/gosn-v2/session"
)

const (
	refreshTimeout   = 15 * time.Second // for the client used when the session has none
	maxRefreshAnswer = 1 << 20          // the answer is a small JSON object: cap the read
)

// refreshCookieSession is the default refresh of Guard. It follows the refresh
// request of the official Standard Notes app (standardnotes/app, HttpService.ts
// and FetchRequestHandler.ts, checked 2026-10-05): both tokens in the JSON body,
// both token cookies (the app's fetch uses credentials: 'include'), and the
// client-version headers. It sends no Authorization header, and the Docker
// server answers it with 200 without one.
//
// gosn-v2's (*session.Session).Refresh does not follow that request. For every
// session type it posts a body of only {"api"}. The stock server checks for
// access_token and refresh_token in the body first, and answers 400 "Please
// provide all required parameters." Refresh does not check the status, so it
// returns nil and overwrites the session with the empty answer.
//
// The refresh writes to the session only after it holds a complete 200. A
// failure of any kind returns an error and leaves the session as it was. On
// success the tokens and expiries come from the answer, and the cookies from its
// Set-Cookie headers. A cookie that the answer does not set keeps its old value.
// The refresh does not touch FilesServerUrl or ReadOnlyAccess.
func refreshCookieSession(s *session.Session) error {
	if s.Server == "" {
		return errors.New("session has no server URL")
	}
	body, err := json.Marshal(map[string]string{
		"api":           common.APIVersion,
		"access_token":  s.AccessToken,
		"refresh_token": s.RefreshToken,
	})
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, s.Server+common.AuthRefreshPath, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set(common.HeaderContentType, common.SNAPIContentType)
	common.SetStandardClientHeaders(req.Header)
	var cookies []string
	for _, c := range []string{s.AccessTokenCookie, s.RefreshTokenCookie} {
		if c != "" {
			cookies = append(cookies, c)
		}
	}
	if len(cookies) > 0 {
		req.Header.Set("Cookie", strings.Join(cookies, "; "))
	}

	client := &http.Client{Timeout: refreshTimeout}
	if s.HTTPClient != nil {
		client = s.HTTPClient.StandardClient() // keeps the session's transport, retries and cookie jar
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return rejection(resp)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxRefreshAnswer))
	if err != nil {
		return fmt.Errorf("read answer: %w", err)
	}
	var answer struct {
		Data struct {
			Session struct {
				AccessToken       string `json:"access_token"`
				RefreshToken      string `json:"refresh_token"`
				AccessExpiration  int64  `json:"access_expiration"`
				RefreshExpiration int64  `json:"refresh_expiration"`
			} `json:"session"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &answer); err != nil {
		return fmt.Errorf("decode answer: %w", err)
	}
	n := answer.Data.Session
	if n.AccessToken == "" || n.RefreshToken == "" || n.AccessExpiration == 0 || n.RefreshExpiration == 0 {
		return errors.New("200 answer holds an incomplete session")
	}
	accessCookie, refreshCookie := tokenCookies(resp.Header.Values("Set-Cookie"))

	// The answer is complete. Only now does the session change.
	s.AccessToken, s.RefreshToken = n.AccessToken, n.RefreshToken
	s.AccessExpiration, s.RefreshExpiration = n.AccessExpiration, n.RefreshExpiration
	if accessCookie != "" {
		s.AccessTokenCookie = accessCookie
	}
	if refreshCookie != "" {
		s.RefreshTokenCookie = refreshCookie
	}
	return nil
}

// rejection describes a non-200 answer: the status, and the server's own message
// when the body carries one.
func rejection(resp *http.Response) error {
	var e struct {
		Data struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		} `json:"data"`
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if json.Unmarshal(b, &e) == nil && e.Data.Error.Message != "" {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, e.Data.Error.Message)
	}
	return fmt.Errorf("HTTP %d", resp.StatusCode)
}

// tokenCookies returns the name=value pair of the access and refresh token
// cookies that a response sets, and "" for one that it does not set.
func tokenCookies(setCookie []string) (access, refresh string) {
	for _, h := range setCookie {
		pair, _, _ := strings.Cut(h, ";")
		pair = strings.TrimSpace(pair)
		switch {
		case strings.HasPrefix(pair, "access_token_"):
			access = pair
		case strings.HasPrefix(pair, "refresh_token_"):
			refresh = pair
		}
	}
	return access, refresh
}
