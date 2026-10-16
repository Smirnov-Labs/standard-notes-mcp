package gate

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
)

// Note is the gate's minimal view of a note.
type Note struct{ UUID, Title, Text, Kind string }

// Verdict is a classification result. Reasons name the signals that fired, such
// as "scanner" or "kind:authentication". They never hold note content.
type Verdict struct {
	Sensitive bool
	Reasons   []string
}

// stubLabel is the only text a stub shows in place of a note.
const stubLabel = "[sensitive — withheld]"

// A gated tool returns a Stubbed for a sensitive note, and nothing else. It is an
// opaque handle with NO title, body, or snippet. The type has two fields and no
// room for note content. Stub takes only a uuid. The literal below stops the
// build if a third field appears. Add a field only after a privacy review.
type Stubbed struct {
	UUID  string
	Label string // always stubLabel
}

var _ = Stubbed{"", ""}

// Stub returns the stub for the note with this uuid. It takes no title, body or
// snippet, so it cannot copy one.
func Stub(uuid string) Stubbed { return Stubbed{UUID: uuid, Label: stubLabel} }

type jevProber interface {
	SensitiveProbability(noteText string) (float64, error)
}

// Gate decides whether a note is sensitive. Make one with New. Classify is safe
// for concurrent use when the prober is.
type Gate struct {
	jev       jevProber
	threshold float64

	// cache holds one verdict for each distinct note content. mu guards it. The key
	// is a digest of the content. The cache holds no note text. An edit to a note
	// changes the key.
	mu    sync.Mutex
	cache map[[sha256.Size]byte]Verdict
}

// New returns a gate. A note is sensitive when jev gives it a probability of
// threshold or more.
func New(jev jevProber, threshold float64) *Gate {
	return &Gate{jev: jev, threshold: threshold, cache: make(map[[sha256.Size]byte]Verdict)}
}

// forcedSensitiveKinds are always sensitive regardless of content.
var forcedSensitiveKinds = map[string]bool{"authentication": true, "credential": true}

// reasonJevError is the reason on a verdict that jev could not answer.
const reasonJevError = "jev-error-fail-closed"

// Classify unions three signals: a forced note kind, the deterministic scanner,
// and a jev probability at or over the threshold. It errs toward sensitive, the
// safe direction. A jev failure counts as sensitive (fail closed). So does a jev
// answer that is not a probability from 0 to 1.
//
// Classify caches each verdict by the content of the note's title, text and kind.
// An edit changes the content, so Classify rules on an edited note again. It does
// not cache a verdict that came from a jev failure, because jev can recover.
func (g *Gate) Classify(n Note) Verdict {
	key := contentKey(n)

	g.mu.Lock()
	v, ok := g.cache[key]
	g.mu.Unlock()
	if ok {
		return v.clone()
	}

	v, cacheable := g.classify(n)
	if cacheable {
		g.mu.Lock()
		g.cache[key] = v.clone()
		g.mu.Unlock()
	}
	return v
}

// classify runs the three signals in order. The second result says whether the
// verdict is safe to cache.
func (g *Gate) classify(n Note) (Verdict, bool) {
	// The match ignores case and padding. A kind spelled "Authentication" is still
	// an authentication note.
	if kind := strings.ToLower(strings.TrimSpace(n.Kind)); forcedSensitiveKinds[kind] {
		return Verdict{Sensitive: true, Reasons: []string{"kind:" + kind}}, true
	}
	text := n.Title + "\n" + n.Text
	if r := Scan(text); r.Sensitive {
		return Verdict{Sensitive: true, Reasons: append([]string{"scanner"}, r.Reasons...)}, true
	}
	// A blank note has nothing to leak, and the scanner has cleared it. Skip jev.
	// nimble answers a blank note with a 400, and the gate reads a jev failure as
	// sensitive.
	if strings.TrimSpace(text) == "" {
		return Verdict{}, true
	}
	p, err := g.maxProbability(text)
	if err != nil {
		return Verdict{Sensitive: true, Reasons: []string{reasonJevError}}, false
	}
	// This is !(p < threshold), not p >= threshold. With a NaN threshold, the first
	// form reads sensitive. The second reads safe, because every comparison with
	// NaN is false.
	if !(p < g.threshold) {
		return Verdict{Sensitive: true, Reasons: []string{"jev"}}, true
	}
	return Verdict{}, true
}

var (
	errNoProber       = errors.New("gate: no jev prober")
	errNotProbability = errors.New("gate: jev answer is not a probability from 0 to 1")
)

// probe asks jev about one piece of text. The answer must be a probability.
// Every comparison with NaN is false. A loop that keeps the largest score with >
// skips a NaN, and p >= threshold reads it as safe. So a NaN is an error here.
func (g *Gate) probe(text string) (float64, error) {
	if g.jev == nil {
		return 0, errNoProber
	}
	p, err := g.jev.SensitiveProbability(text)
	if err != nil {
		return 0, err
	}
	if !(p >= 0 && p <= 1) {
		return 0, errNotProbability
	}
	return p, nil
}

// maxProbability asks jev about each window of text and returns the highest
// probability. If any window fails, it returns an error, and the caller reads
// that as sensitive. The scanner has already read the whole text. It catches a
// structured secret anywhere in it, with no help from the windows.
func (g *Gate) maxProbability(text string) (float64, error) {
	var top float64
	for _, w := range windows(text) {
		// A window can hold only whitespace when the note does not. nimble rejects
		// it, and it holds nothing to leak.
		if strings.TrimSpace(w) == "" {
			continue
		}
		p, err := g.probe(w)
		if err != nil {
			return 0, err
		}
		top = max(top, p)
	}
	return top, nil
}

const (
	// chunkSize is the most bytes the gate sends to jev in one call. nimble rejects
	// a note over 8194 tokens (about 35 KB) and a request body over 64 KiB. 24000
	// bytes stays well under both for ordinary text.
	chunkSize = 24000
	// chunkOverlap is the number of bytes that two neighbouring windows share. Any
	// run of this many bytes or fewer lies whole inside one window. A secret that
	// crosses a window edge is not cut in two.
	chunkOverlap = 2000
)

// windows splits text into byte windows of at most chunkSize bytes. Each window
// starts chunkSize-chunkOverlap bytes after the one before it. Text that fits in
// one window comes back whole. A window edge can fall inside a UTF-8 character.
// json.Marshal turns the cut bytes into U+FFFD, and the overlap covers the edge.
func windows(text string) []string {
	var out []string
	for start := 0; ; start += chunkSize - chunkOverlap {
		if end := start + chunkSize; end < len(text) {
			out = append(out, text[start:end])
		} else {
			return append(out, text[start:])
		}
	}
}

// contentKey is the cache key for a note: a SHA-256 digest of the three fields
// that decide a verdict. Each field has its length in front of it. Two different
// notes then never feed the same bytes to the hash. A NUL byte as a separator
// does not give that guarantee, because a title or a body can hold a NUL.
func contentKey(n Note) [sha256.Size]byte {
	h := sha256.New()
	var size [8]byte
	for _, field := range [...]string{n.Title, n.Text, n.Kind} {
		binary.BigEndian.PutUint64(size[:], uint64(len(field)))
		h.Write(size[:])
		io.WriteString(h, field)
	}
	var key [sha256.Size]byte
	h.Sum(key[:0])
	return key
}

// clone returns a copy of v that shares no memory with it. A caller that changes
// the Reasons it got then cannot change the cache.
func (v Verdict) clone() Verdict {
	v.Reasons = slices.Clone(v.Reasons)
	return v
}
