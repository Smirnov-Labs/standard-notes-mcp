package writeengine

import (
	"bufio"
	"encoding/json"
	"os"
	"sync"
)

const (
	StateIntended = "intended"
	StateAcked    = "acked"
	StateVerified = "verified"
)

type entry struct {
	OpID, Kind, UUID, State string
}

// Ledger is an append-only, fsync'd record of write operations and their state
// transitions (intended -> acked -> verified). Reopening replays the file so a
// crashed run can resume without re-applying completed ops.
type Ledger struct {
	mu   sync.Mutex
	f    *os.File
	last map[string]string // opID -> last state
}

// OpenLedger opens the ledger at path, creates it if needed, and replays it.
// Replay skips lines that are not valid JSON. If a crash left the last line
// without a trailing newline, OpenLedger adds the newline. The next Record
// then starts on a line of its own. A line over 1 MiB, or a read error
// during replay, makes OpenLedger return an error. Replay reads the whole
// file or fails.
func OpenLedger(path string) (*Ledger, error) {
	l := &Ledger{last: map[string]string{}}
	if f, err := os.Open(path); err == nil { // replay existing
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20) // accept lines up to 1 MiB
		for sc.Scan() {
			var e entry
			if json.Unmarshal(sc.Bytes(), &e) == nil {
				l.last[e.OpID] = e.State
			}
		}
		if err := sc.Err(); err != nil { // too long or unreadable: do not replay a partial file
			f.Close()
			return nil, err
		}
		f.Close()
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	if err := endTornLine(f); err != nil {
		f.Close()
		return nil, err
	}
	l.f = f
	return l, nil
}

// endTornLine writes a newline if the file is not empty and does not end in
// one. A crash in the middle of Record can leave such a tail. Without the
// newline, the next Record joins that tail and corrupts both records.
func endTornLine(f *os.File) error {
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if st.Size() == 0 {
		return nil
	}
	var last [1]byte
	if _, err := f.ReadAt(last[:], st.Size()-1); err != nil {
		return err
	}
	if last[0] == '\n' {
		return nil
	}
	if _, err := f.Write([]byte{'\n'}); err != nil {
		return err
	}
	return f.Sync()
}

func (l *Ledger) Record(opID, kind, uuid, state string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, _ := json.Marshal(entry{opID, kind, uuid, state})
	if _, err := l.f.Write(append(b, '\n')); err != nil {
		return err
	}
	if err := l.f.Sync(); err != nil {
		return err
	}
	l.last[opID] = state
	return nil
}

func (l *Ledger) LastState(opID string) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.last[opID]
}
