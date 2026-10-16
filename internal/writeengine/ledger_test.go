package writeengine_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	we "github.com/smirnov-labs/standard-notes-mcp/internal/writeengine"
)

// appendRaw adds raw bytes to the ledger file, the way a crash can leave a
// partial record.
func appendRaw(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(s); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLedgerRoundTripAndResume(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	l, err := we.OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := l.Record("op1", "create", "uuid-1", we.StateIntended); err != nil {
		t.Fatal(err)
	}
	if err := l.Record("op1", "create", "uuid-1", we.StateAcked); err != nil {
		t.Fatal(err)
	}

	l2, err := we.OpenLedger(path) // reopen = resume
	if err != nil {
		t.Fatal(err)
	}
	if got := l2.LastState("op1"); got != we.StateAcked {
		t.Fatalf("resume lost state: %q", got)
	}
	if got := l2.LastState("missing"); got != "" {
		t.Fatalf("unknown op should be empty, got %q", got)
	}
}

func TestLedgerLatestStateWinsAndResumeAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	l, err := we.OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}

	// Two interleaved ops: the latest Record wins per op, and ops stay independent.
	steps := []struct{ op, kind, uuid, state string }{
		{"op1", "create", "uuid-1", we.StateIntended},
		{"op2", "edit", "uuid-2", we.StateIntended},
		{"op1", "create", "uuid-1", we.StateAcked},
		{"op1", "create", "uuid-1", we.StateVerified},
	}
	for _, s := range steps {
		if err := l.Record(s.op, s.kind, s.uuid, s.state); err != nil {
			t.Fatal(err)
		}
	}
	if got := l.LastState("op1"); got != we.StateVerified {
		t.Fatalf("op1: the later Record must win, got %q", got)
	}
	if got := l.LastState("op2"); got != we.StateIntended {
		t.Fatalf("op1 clobbered op2, got %q", got)
	}

	// Resume, then keep writing: reopen must append, not truncate.
	l2, err := we.OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := l2.Record("op2", "edit", "uuid-2", we.StateAcked); err != nil {
		t.Fatal(err)
	}

	l3, err := we.OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := l3.LastState("op1"); got != we.StateVerified {
		t.Fatalf("op1 lost after resume+append: %q", got)
	}
	if got := l3.LastState("op2"); got != we.StateAcked {
		t.Fatalf("op2 append after resume was not replayed: %q", got)
	}
}

func TestLedgerResumeAfterTornFinalLine(t *testing.T) {
	cases := []struct {
		name    string
		tail    string // what a crashed Record left at the end of the file
		wantOp2 string // state replay reports for the torn record
	}{
		{"partial record", `{"OpID":"op2","Kind":"cre`, ""},
		{"whole record missing its newline", `{"OpID":"op2","Kind":"create","UUID":"uuid-2","State":"intended"}`, we.StateIntended},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ledger.jsonl")
			l, err := we.OpenLedger(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := l.Record("op1", "create", "uuid-1", we.StateAcked); err != nil {
				t.Fatal(err)
			}
			appendRaw(t, path, tc.tail) // crash mid-Record: the tail has no newline

			l2, err := we.OpenLedger(path) // resume after the crash
			if err != nil {
				t.Fatal(err)
			}
			if got := l2.LastState("op1"); got != we.StateAcked {
				t.Fatalf("op1 lost on resume: %q", got)
			}
			if got := l2.LastState("op2"); got != tc.wantOp2 {
				t.Fatalf("torn op2 after resume: want %q, got %q", tc.wantOp2, got)
			}

			// The first record written after the crash must survive the next resume.
			if err := l2.Record("op3", "create", "uuid-3", we.StateIntended); err != nil {
				t.Fatal(err)
			}
			l3, err := we.OpenLedger(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := l3.LastState("op3"); got != we.StateIntended {
				t.Fatalf("record written after a torn tail was lost on resume: %q", got)
			}
			if got := l3.LastState("op2"); got != tc.wantOp2 {
				t.Fatalf("torn op2 changed after the next record: want %q, got %q", tc.wantOp2, got)
			}
			if got := l3.LastState("op1"); got != we.StateAcked {
				t.Fatalf("op1 lost after the next record: %q", got)
			}
		})
	}
}

func TestLedgerReplayLongLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	l, err := we.OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}

	// A record past bufio.Scanner's 64 KiB default must replay, and so must the records after it.
	if err := l.Record("op1", "create", strings.Repeat("x", 70<<10), we.StateAcked); err != nil {
		t.Fatal(err)
	}
	if err := l.Record("op2", "create", "uuid-2", we.StateIntended); err != nil {
		t.Fatal(err)
	}
	l2, err := we.OpenLedger(path)
	if err != nil {
		t.Fatalf("replay of a 70 KiB record failed: %v", err)
	}
	if got := l2.LastState("op1"); got != we.StateAcked {
		t.Fatalf("70 KiB record lost on resume: %q", got)
	}
	if got := l2.LastState("op2"); got != we.StateIntended {
		t.Fatalf("record after a 70 KiB record lost on resume: %q", got)
	}

	// A line past the hard cap must fail loudly. A quiet stop drops every record after it.
	appendRaw(t, path, strings.Repeat("x", 2<<20)+"\n")
	if _, err := we.OpenLedger(path); err == nil {
		t.Fatal("OpenLedger must return an error for a line over the cap, got nil")
	}
}
