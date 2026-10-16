package testsupport

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jonhadfield/gosn-v2/auth"
	"github.com/jonhadfield/gosn-v2/common"
)

const TestServer = "http://localhost:3000"

// NewAccount registers a fresh throwaway 004 account on the Docker server and
// returns its credentials. It skips the test if the server is unreachable or
// unhealthy. It fails the test if the server is healthy but registration
// fails, so a broken server or harness cannot hide behind a skip.
func NewAccount(t *testing.T) (email, password string) {
	t.Helper()
	if os.Getenv("SN_TEST_SERVER") == "off" {
		t.Skip("SN_TEST_SERVER=off")
	}
	if err := probeServer(); err != nil {
		t.Skipf("SN server unreachable at %s; start ops/docker (%v)", TestServer, err)
	}
	email = "t" + randHex(8) + "@local.test"
	password = "pw-" + randHex(12)
	hc := common.NewHTTPClient()
	// Register is a method on RegisterInput and returns (token, err). It makes
	// its own pw nonce and always registers version 004, so PWNonce, Version,
	// Origination and Created are ignored and left unset.
	_, err := auth.RegisterInput{
		Client: hc, Email: email, Password: password, APIServer: TestServer,
	}.Register()
	if err != nil {
		t.Fatalf("register failed against a reachable server: %v", err)
	}
	return email, password
}

// probeServer returns nil when GET /healthcheck answers 200 "OK" within 2s.
// A stopped server fails at once (connection refused) and a hung one after 2s,
// far sooner than the ~21s that Register spends retrying a dead server.
func probeServer() error {
	c := &http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get(TestServer + "/healthcheck")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != "OK" {
		return fmt.Errorf("GET /healthcheck: status %d, body %q", resp.StatusCode, body)
	}
	return nil
}

// randHex returns n random hex characters. It uses crypto/rand, not a
// time-seeded math/rand: parallel tests start within the same clock tick
// (the macOS clock is microsecond-resolution), would draw the same "random"
// email, and the second Register would fail as a duplicate.
func randHex(n int) string {
	b := make([]byte, (n+1)/2)
	_, _ = rand.Read(b) // never returns an error since Go 1.24
	return hex.EncodeToString(b)[:n]
}
