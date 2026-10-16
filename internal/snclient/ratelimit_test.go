package snclient

import (
	"errors"
	"testing"
	"time"

	"github.com/jonhadfield/gosn-v2/items"
)

// swapSyncSeams installs fast, deterministic test seams (no real waits) and returns a
// restore func.
func swapSyncSeams() func() {
	origFn, origWaits, origSleep := syncFn, syncRetryWaits, syncSleep
	syncRetryWaits = []time.Duration{0, 0, 0}
	syncSleep = func(time.Duration) {}
	return func() { syncFn, syncRetryWaits, syncSleep = origFn, origWaits, origSleep }
}

func TestIsTransientSyncErr(t *testing.T) {
	cases := []struct {
		msg  string
		want bool
	}{
		{"sync | sync returned unhandled error: unexpected status code: 429", true},
		{"sync returned unhandled error: unexpected status code: 503", true},
		{"unexpected status code: 500", false},
		{"invalid session", false},
		{"", false},
	}
	for _, c := range cases {
		var err error
		if c.msg != "" {
			err = errors.New(c.msg)
		}
		if got := isTransientSyncErr(err); got != c.want {
			t.Errorf("isTransientSyncErr(%q) = %v, want %v", c.msg, got, c.want)
		}
	}
}

func TestClientSync_retriesRetrieveThenSucceeds(t *testing.T) {
	defer swapSyncSeams()()
	calls := 0
	syncFn = func(items.SyncInput) (items.SyncOutput, error) {
		calls++
		if calls < 3 {
			return items.SyncOutput{}, errors.New("unexpected status code: 429")
		}
		return items.SyncOutput{SyncToken: "ok"}, nil
	}
	out, err := clientSync(items.SyncInput{})
	if err != nil {
		t.Fatalf("want success after retries, got %v", err)
	}
	if out.SyncToken != "ok" {
		t.Errorf("want advanced token, got %q", out.SyncToken)
	}
	if calls != 3 {
		t.Errorf("want 3 calls, got %d", calls)
	}
}

func TestClientSync_givesUpAfterSchedule(t *testing.T) {
	defer swapSyncSeams()()
	calls := 0
	syncFn = func(items.SyncInput) (items.SyncOutput, error) {
		calls++
		return items.SyncOutput{}, errors.New("unexpected status code: 429")
	}
	if _, err := clientSync(items.SyncInput{}); err == nil {
		t.Fatal("want error after exhausting retries")
	}
	if want := len(syncRetryWaits) + 1; calls != want {
		t.Errorf("want %d attempts, got %d", want, calls)
	}
}

func TestClientSync_doesNotRetryPush(t *testing.T) {
	defer swapSyncSeams()()
	calls := 0
	syncFn = func(items.SyncInput) (items.SyncOutput, error) {
		calls++
		return items.SyncOutput{}, errors.New("unexpected status code: 429")
	}
	// A push (Items present) must fail fast — never blindly re-pushed (never-lose-data).
	if _, err := clientSync(items.SyncInput{Items: make(items.EncryptedItems, 1)}); err == nil {
		t.Fatal("want error")
	}
	if calls != 1 {
		t.Errorf("push must not retry; want 1 call, got %d", calls)
	}
}

func TestClientSync_doesNotRetryNonTransient(t *testing.T) {
	defer swapSyncSeams()()
	calls := 0
	syncFn = func(items.SyncInput) (items.SyncOutput, error) {
		calls++
		return items.SyncOutput{}, errors.New("invalid session")
	}
	if _, err := clientSync(items.SyncInput{}); err == nil {
		t.Fatal("want error")
	}
	if calls != 1 {
		t.Errorf("non-transient must not retry; want 1 call, got %d", calls)
	}
}
