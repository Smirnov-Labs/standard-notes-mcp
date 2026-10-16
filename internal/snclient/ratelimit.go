package snclient

import (
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/jonhadfield/gosn-v2/items"
)

// syncFn is the sync entry point, seam-ed so tests can stub it.
var syncFn = items.Sync

// syncRetryWaits is the backoff schedule for a retryable retrieve. A var so tests can
// shrink it. The 429 Standard Notes returns is a bandwidth quota that needs a longer
// cooldown than gosn-v2's internal ~23s; the total here stays well under the Guard's
// ~10-minute refresh threshold so a backoff can't strand a session.
var syncRetryWaits = []time.Duration{15 * time.Second, 30 * time.Second, 60 * time.Second}

// syncSleep is time.Sleep, seam-ed for tests.
var syncSleep = time.Sleep

// clientSync wraps items.Sync with polite backoff on transient 429/503 errors. It
// retries ONLY pure retrieves (no Items to push): a push that fails is returned to
// the caller, whose reconcile-before-retry path decides what to do, so a write is
// never blindly re-pushed (never-lose-data). gosn-v2 does not surface Retry-After, so
// the schedule is a fixed, jittered best effort.
func clientSync(input items.SyncInput) (items.SyncOutput, error) {
	isPush := len(input.Items) > 0
	for attempt := 0; ; attempt++ {
		out, err := syncFn(input)
		if err == nil || isPush || !isTransientSyncErr(err) || attempt >= len(syncRetryWaits) {
			return out, err
		}
		wait := syncRetryWaits[attempt]
		if wait > 0 {
			wait += time.Duration(rand.Int63n(int64(wait)/2 + 1)) // up to +50% jitter
		}
		fmt.Fprintf(os.Stderr, "snclient: sync rate-limited (%s); backing off %s, retry %d/%d\n",
			transientStatus(err), wait.Round(time.Second), attempt+1, len(syncRetryWaits))
		syncSleep(wait)
	}
}

// isTransientSyncErr reports whether a sync error is a transient 429/503 worth
// retrying. gosn-v2 surfaces these only as a status-code substring in the message.
func isTransientSyncErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "unexpected status code: 429") ||
		strings.Contains(s, "unexpected status code: 503")
}

func transientStatus(err error) string {
	if err != nil && strings.Contains(err.Error(), "429") {
		return "429 Too Many Requests"
	}
	return "503 Service Unavailable"
}
