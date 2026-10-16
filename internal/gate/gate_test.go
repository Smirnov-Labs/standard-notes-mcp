package gate

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
)

type fakeJev struct{ p float64 }

func (f fakeJev) SensitiveProbability(string) (float64, error) { return f.p, nil }

// spyJev is a fake prober that counts and measures its calls. reply gives the
// answer to each call. The call number starts at 1.
type spyJev struct {
	mu    sync.Mutex
	sizes []int // the byte length of the text in each call
	reply func(call int, text string) (float64, error)
}

func (s *spyJev) SensitiveProbability(text string) (float64, error) {
	s.mu.Lock()
	s.sizes = append(s.sizes, len(text))
	call := len(s.sizes)
	s.mu.Unlock()
	return s.reply(call, text)
}

func (s *spyJev) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sizes)
}

// longest is the most bytes any call got.
func (s *spyJev) longest() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Max(append([]int{0}, s.sizes...))
}

// answers returns a spy that gives every call the probability p.
func answers(p float64) *spyJev {
	return &spyJev{reply: func(int, string) (float64, error) { return p, nil }}
}

// fails returns a spy whose every call fails.
func fails() *spyJev {
	return &spyJev{reply: func(int, string) (float64, error) { return 0, errors.New("jev down") }}
}

// awsKey is the example key from the AWS documentation. The constant joins two
// parts, so this file holds no literal that a secret scanner flags. It is not live.
const awsKey = "AKIA" + "IOSFODNN7EXAMPLE"

// benignNote is a note that the scanner leaves alone.
var benignNote = Note{UUID: "n-benign", Title: "groceries", Text: "buy milk and eggs", Kind: "note"}

// requireVerdict fails unless v has the given sensitivity and exactly these reasons.
func requireVerdict(t *testing.T, v Verdict, sensitive bool, reasons ...string) {
	t.Helper()
	if v.Sensitive != sensitive || !slices.Equal(v.Reasons, reasons) {
		t.Fatalf("got {Sensitive:%v Reasons:%q}, want {Sensitive:%v Reasons:%q}", v.Sensitive, v.Reasons, sensitive, reasons)
	}
}

func TestGateUnionAndStub(t *testing.T) {
	g := New(fakeJev{p: 0.0}, 0.5) // jev says not-sensitive...
	note := Note{UUID: "u1", Title: "keys", Text: awsKey, Kind: "note"}
	v := g.Classify(note)
	if !v.Sensitive { // ...but the deterministic scanner catches it
		t.Fatal("scanner-positive note must be sensitive regardless of jev")
	}
	if v.Reasons[0] != "scanner" || !slices.Contains(v.Reasons, "aws access key id") {
		t.Fatalf("scanner verdict must name the scanner and its rule, got %q", v.Reasons)
	}
	if !g.Classify(Note{UUID: "u2", Title: "x", Text: "y", Kind: "authentication"}).Sensitive {
		t.Fatal("authentication kind must be forced sensitive")
	}
	g2 := New(fakeJev{p: 0.9}, 0.5)
	v3 := g2.Classify(Note{UUID: "u3", Title: "diary", Text: "private", Kind: "note"})
	if !v3.Sensitive { // jev alone: the scanner has nothing to say about this note
		t.Fatal("jev over threshold must be sensitive")
	}
	requireVerdict(t, v3, true, "jev")

	// Negative control. Without it, a gate that flags every note passes this test.
	requireVerdict(t, g.Classify(benignNote), false)
}

func TestGateVerdictReasonsNeverHoldNoteContent(t *testing.T) {
	note := Note{UUID: "u1", Title: "TITLE-CANARY", Text: "BODY-CANARY " + awsKey, Kind: "note"}
	for _, v := range []Verdict{
		New(fakeJev{p: 0}, 0.5).Classify(note),
		New(fakeJev{p: 0}, 0.5).Classify(Note{Title: "TITLE-CANARY", Text: "BODY-CANARY", Kind: "authentication"}),
		New(fakeJev{p: 1}, 0.5).Classify(Note{Title: "TITLE-CANARY", Text: "BODY-CANARY", Kind: "note"}),
		New(fails(), 0.5).Classify(Note{Title: "TITLE-CANARY", Text: "BODY-CANARY", Kind: "note"}),
	} {
		if !v.Sensitive {
			t.Fatalf("setup: every one of these notes must be sensitive, got %+v", v)
		}
		for _, r := range v.Reasons {
			for _, leak := range []string{"CANARY", awsKey, "AKIA"} {
				if strings.Contains(r, leak) {
					t.Fatalf("reason %q holds note content %q", r, leak)
				}
			}
		}
	}
}

// Stubbed must never hold a title, a body or a snippet. gate.go has a literal that
// stops the build when someone adds a field. This test pins the field names and
// types.
func TestStubCarriesOnlyUUIDAndAFixedLabel(t *testing.T) {
	typ := reflect.TypeOf(Stubbed{})
	var names []string
	for i := range typ.NumField() {
		f := typ.Field(i)
		names = append(names, f.Name)
		if f.Type.Kind() != reflect.String || f.Anonymous || !f.IsExported() {
			t.Errorf("field %s must be a plain exported string, got %v", f.Name, f.Type)
		}
	}
	if !slices.Equal(names, []string{"UUID", "Label"}) {
		t.Fatalf("Stubbed must have exactly UUID and Label, got %v", names)
	}

	// Stub reads the uuid and nothing else. Whatever the note holds, the stub is the
	// uuid plus the fixed label.
	note := Note{UUID: "u1", Title: "TITLE-CANARY", Text: "BODY-CANARY", Kind: "authentication"}
	st := Stub(note.UUID)
	if st != (Stubbed{UUID: "u1", Label: "[sensitive — withheld]"}) {
		t.Fatalf("stub must be the uuid and the fixed label, got %+v", st)
	}
	if shown := fmt.Sprintf("%+v %#v", st, st); strings.Contains(shown, "CANARY") {
		t.Fatalf("stub shows note content: %s", shown)
	}
	for _, uuid := range []string{"", "a-b-c", "u2"} {
		if got := Stub(uuid); got.UUID != uuid || got.Label != "[sensitive — withheld]" {
			t.Fatalf("Stub(%q) = %+v", uuid, got)
		}
	}
}

func TestGateForcedKinds(t *testing.T) {
	for _, kind := range []string{"authentication", "credential", "Authentication", " CREDENTIAL ", "\tauthentication\n"} {
		jev := answers(0) // jev says safe
		got := New(jev, 0.5).Classify(Note{UUID: "u", Title: "groceries", Text: "buy milk", Kind: kind})
		requireVerdict(t, got, true, "kind:"+strings.ToLower(strings.TrimSpace(kind)))
		if jev.calls() != 0 {
			t.Errorf("kind %q: a forced kind needs no jev call, got %d", kind, jev.calls())
		}
	}
	// The kind must match as a whole. A kind that merely holds a forced word is not forced.
	for _, kind := range []string{"note", "", "plain-text", "authenticator", "non-credential"} {
		requireVerdict(t, New(answers(0), 0.5).Classify(Note{Title: "groceries", Text: "buy milk", Kind: kind}), false)
	}
}

func TestGateThresholdIsInclusive(t *testing.T) {
	for _, tc := range []struct {
		p    float64
		want bool
	}{{0, false}, {0.4999, false}, {0.5, true}, {0.5001, true}, {1, true}} {
		if got := New(fakeJev{p: tc.p}, 0.5).Classify(benignNote).Sensitive; got != tc.want {
			t.Errorf("p=%v, threshold 0.5: sensitive=%v, want %v", tc.p, got, tc.want)
		}
	}
}

func TestGateFailsClosedWhenJevFails(t *testing.T) {
	jev := fails()
	requireVerdict(t, New(jev, 0.5).Classify(benignNote), true, "jev-error-fail-closed")
	if jev.calls() != 1 { // the failing prober ran, so this is the error path
		t.Fatalf("setup: jev must have been asked once, got %d", jev.calls())
	}

	// Jev is not asked when an earlier signal has already decided.
	for _, tc := range []struct {
		name    string
		note    Note
		reasons []string
	}{
		{"scanner", Note{Title: "keys", Text: awsKey, Kind: "note"}, nil},
		{"forced kind", Note{Title: "x", Text: "y", Kind: "authentication"}, []string{"kind:authentication"}},
	} {
		jev := fails()
		v := New(jev, 0.5).Classify(tc.note)
		if !v.Sensitive || slices.Contains(v.Reasons, "jev-error-fail-closed") {
			t.Errorf("%s: want a %s verdict, got %+v", tc.name, tc.name, v)
		}
		if tc.reasons != nil && !slices.Equal(v.Reasons, tc.reasons) {
			t.Errorf("%s: reasons %q, want %q", tc.name, v.Reasons, tc.reasons)
		}
		if jev.calls() != 0 {
			t.Errorf("%s: jev must not be asked after the scanner or the kind decided, got %d calls", tc.name, jev.calls())
		}
	}
}

// The gate reads a jev answer that is not a probability as a failure. NaN is the
// case that matters. NaN is false in every comparison, so a plain "p >= threshold"
// reads it as "safe".
func TestGateFailsClosedOnAnAnswerThatIsNotAProbability(t *testing.T) {
	for _, p := range []float64{math.NaN(), -0.1, 1.0000001, math.Inf(1), math.Inf(-1)} {
		requireVerdict(t, New(fakeJev{p: p}, 0.5).Classify(benignNote), true, "jev-error-fail-closed")
	}
	// A threshold that is NaN must not turn the jev tier off.
	requireVerdict(t, New(fakeJev{p: 0.1}, math.NaN()).Classify(benignNote), true, "jev")
	// The ends of the range are valid answers.
	requireVerdict(t, New(fakeJev{p: 0}, 0.5).Classify(benignNote), false)
	requireVerdict(t, New(fakeJev{p: 1}, 0.5).Classify(benignNote), true, "jev")
}

func TestGateWithoutAProberFailsClosed(t *testing.T) {
	requireVerdict(t, New(nil, 0.5).Classify(benignNote), true, "jev-error-fail-closed")
	// The scanner and the kind still decide without a prober.
	requireVerdict(t, New(nil, 0.5).Classify(Note{Kind: "authentication"}), true, "kind:authentication")
}

func TestGateCachesTheVerdictByContent(t *testing.T) {
	jev := &spyJev{reply: func(_ int, text string) (float64, error) {
		if strings.Contains(text, "diary") {
			return 0.9, nil
		}
		return 0.1, nil
	}}
	g := New(jev, 0.5)
	note := Note{UUID: "u1", Title: "diary", Text: "private", Kind: "note"}

	first := g.Classify(note)
	second := g.Classify(note)
	requireVerdict(t, first, true, "jev")
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("a cached verdict must equal the first one: %+v vs %+v", first, second)
	}
	if jev.calls() != 1 {
		t.Fatalf("the same note twice must ask jev once, got %d calls", jev.calls())
	}

	// The verdict depends on content, not on identity. The same content under another uuid is a hit.
	g.Classify(Note{UUID: "u2", Title: "diary", Text: "private", Kind: "note"})
	if jev.calls() != 1 {
		t.Fatalf("the same content under another uuid must hit the cache, got %d calls", jev.calls())
	}

	// A change to any one field of the content is a miss.
	for _, changed := range []Note{
		{Title: "diary!", Text: "private", Kind: "note"},
		{Title: "diary", Text: "private!", Kind: "note"},
		{Title: "diary", Text: "private", Kind: "other"},
		// The same bytes with a NUL moved from one field to the other must not collide.
		{Title: "a\x00b", Text: "c", Kind: "note"},
		{Title: "a", Text: "b\x00c", Kind: "note"},
		// The same bytes split another way between title and text.
		{Title: "ab", Text: "c", Kind: "note"},
		{Title: "a", Text: "bc", Kind: "note"},
	} {
		before := jev.calls()
		g.Classify(changed)
		if jev.calls() != before+1 {
			t.Errorf("changed note %+v must be classified again", changed)
		}
	}
}

// An edit to a note must not meet a stale verdict, in either direction.
func TestGateEditInvalidatesTheVerdict(t *testing.T) {
	jev := &spyJev{reply: func(_ int, text string) (float64, error) {
		if strings.Contains(text, "diary") {
			return 0.9, nil
		}
		return 0.0, nil
	}}
	g := New(jev, 0.5)
	before := Note{UUID: "u1", Title: "t", Text: "my diary", Kind: "note"}
	after := Note{UUID: "u1", Title: "t", Text: "my groceries", Kind: "note"} // the same note, edited

	requireVerdict(t, g.Classify(before), true, "jev")
	requireVerdict(t, g.Classify(after), false)        // the edit made it safe: no stale "sensitive"
	requireVerdict(t, g.Classify(before), true, "jev") // and back: no stale "safe"
	if jev.calls() != 2 {
		t.Fatalf("each content must be classified once, got %d calls", jev.calls())
	}
}

// Jev can be down for a moment. The gate stubs the note for that call. It must
// not remember the failure, or the note stays stubbed after jev is back.
func TestGateDoesNotCacheAJevFailure(t *testing.T) {
	jev := &spyJev{reply: func(call int, _ string) (float64, error) {
		if call == 1 {
			return 0, errors.New("jev down")
		}
		return 0, nil
	}}
	g := New(jev, 0.5)
	requireVerdict(t, g.Classify(benignNote), true, "jev-error-fail-closed")
	requireVerdict(t, g.Classify(benignNote), false) // jev is back, and it clears the note
	requireVerdict(t, g.Classify(benignNote), false)
	if jev.calls() != 2 { // the third call is a cache hit
		t.Fatalf("want 2 jev calls (the failure, then the answer), got %d", jev.calls())
	}
}

// A caller that changes the Reasons it got must not change what the cache returns next.
func TestGateCacheHandsOutCopies(t *testing.T) {
	g := New(fakeJev{p: 0}, 0.5)
	note := Note{Title: "keys", Text: awsKey, Kind: "note"}

	computed := g.Classify(note) // a miss: the verdict was just made
	computed.Reasons[0] = "tampered"
	cached := g.Classify(note) // a hit
	if cached.Reasons[0] != "scanner" {
		t.Fatalf("a caller changed the cache through the first verdict: %q", cached.Reasons)
	}
	cached.Reasons[0] = "tampered"
	if again := g.Classify(note); again.Reasons[0] != "scanner" {
		t.Fatalf("a caller changed the cache through a cached verdict: %q", again.Reasons)
	}
}

func TestGateIsSafeForConcurrentUse(t *testing.T) {
	jev := answers(0)
	g := New(jev, 0.5)
	notes := make([]Note, 5)
	for i := range notes {
		notes[i] = Note{UUID: fmt.Sprint("u", i), Title: fmt.Sprint("note ", i), Text: "buy milk", Kind: "note"}
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 200 {
				if g.Classify(notes[i%len(notes)]).Sensitive {
					t.Error("a benign note came back sensitive")
				}
			}
		}()
	}
	wg.Wait()

	// The cache holds every note now.
	before := jev.calls()
	for _, n := range notes {
		g.Classify(n)
	}
	if jev.calls() != before {
		t.Fatalf("a second pass must be all cache hits, got %d new calls", jev.calls()-before)
	}
}

func TestGateSkipsJevForBlankNotes(t *testing.T) {
	for _, tc := range []struct {
		name string
		note Note
	}{
		{"nothing at all", Note{Kind: "note"}},
		{"spaces and a newline", Note{Title: "", Text: "  \n ", Kind: "note"}},
		{"tabs", Note{Title: "\t", Text: "\t\t", Kind: "note"}},
		{"unicode spaces", Note{Title: " ", Text: " 　\n", Kind: "note"}},
	} {
		// nimble answers a blank note with a 400, so a call stubs the note.
		jev := fails()
		requireVerdict(t, New(jev, 0.5).Classify(tc.note), false)
		if jev.calls() != 0 {
			t.Errorf("%s: a blank note must not be sent to jev, got %d calls", tc.name, jev.calls())
		}
	}

	// A blank note is never scored, so the threshold cannot flag it. At a threshold of
	// 0, a score of 0 otherwise counts as "at or over".
	jev0 := fails()
	requireVerdict(t, New(jev0, 0).Classify(Note{Text: " \n"}), false)
	if jev0.calls() != 0 {
		t.Errorf("a blank note must not be sent to jev at a threshold of 0, got %d calls", jev0.calls())
	}

	// A note is blank only when the title and the text are both blank.
	for _, n := range []Note{
		{Title: "groceries", Text: "  ", Kind: "note"},
		{Title: " ", Text: "buy milk", Kind: "note"},
	} {
		jev := answers(0)
		New(jev, 0.5).Classify(n)
		if jev.calls() != 1 {
			t.Errorf("note %+v has content and must go to jev, got %d calls", n, jev.calls())
		}
	}

	// A blank note of a forced kind is still sensitive. The kind runs first.
	jev := fails()
	requireVerdict(t, New(jev, 0.5).Classify(Note{Text: " ", Kind: "authentication"}), true, "kind:authentication")
	if jev.calls() != 0 {
		t.Errorf("a forced kind needs no jev call, got %d", jev.calls())
	}
}

// sentinel marks the spot in a long note that only jev can see. It is not a secret
// shape, so the scanner stays quiet on it.
const sentinel = "ZORBLAX-MARKER"

// filler returns n bytes of plain prose that the scanner leaves alone.
func filler(n int) string {
	return strings.Repeat("the quick brown fox jumps over the lazy dog\n", n/44+1)[:n]
}

// longNote returns a note with a combined title and text of total bytes. The title
// is empty, so the combined string is "\n" + text. If at is 1 or more, the sentinel
// overwrites the bytes of the combined string from offset at.
//
// The scanner must stay quiet on this text, or the test never reaches jev. Each
// test that uses it checks that: it expects exact reasons, or a count of jev calls.
func longNote(total, at int) Note {
	body := []byte(filler(total - 1))
	if at >= 1 {
		copy(body[at-1:], sentinel)
	}
	return Note{UUID: "long", Text: string(body), Kind: "note"}
}

// sentinelJev answers 0.99 for a text that holds the sentinel and 0 for any other.
// Like nimble, it fails a blank text.
func sentinelJev() *spyJev {
	return &spyJev{reply: func(_ int, text string) (float64, error) {
		if strings.TrimSpace(text) == "" {
			return 0, errors.New("400: blank state")
		}
		if strings.Contains(text, sentinel) {
			return 0.99, nil
		}
		return 0, nil
	}}
}

func TestGateScoresEveryWindowOfALongNote(t *testing.T) {
	const total = 60000
	step := chunkSize - chunkOverlap
	half := len(sentinel) / 2
	for _, tc := range []struct {
		name string
		at   int // where the sentinel starts in the combined title and text
	}{
		{"in the first window only", 100},
		{"in the middle", total / 2},
		{"in the last window only", total - len(sentinel) - 10},
		{"across the first window edge", chunkSize - half},
		{"ending on the first window edge", chunkSize - len(sentinel)},
		{"starting on the first window edge", chunkSize},
		{"across the second window edge", step + chunkSize - half},
	} {
		t.Run(tc.name, func(t *testing.T) {
			jev := sentinelJev()
			v := New(jev, 0.5).Classify(longNote(total, tc.at))
			requireVerdict(t, v, true, "jev") // the highest window score decides
			if jev.calls() < 2 {
				t.Errorf("a %d byte note must be split, got %d calls", total, jev.calls())
			}
			if jev.longest() > chunkSize {
				t.Errorf("a call got %d bytes, over the %d byte window", jev.longest(), chunkSize)
			}
		})
	}
}

func TestGateDoesNotStubALongBenignNote(t *testing.T) {
	jev := answers(0)
	requireVerdict(t, New(jev, 0.5).Classify(longNote(60000, -1)), false)
	if jev.calls() < 2 || jev.longest() > chunkSize {
		t.Fatalf("a 60000 byte note must go in windows of at most %d bytes, got %d calls, longest %d", chunkSize, jev.calls(), jev.longest())
	}
}

// If any window fails, the gate stubs the note, whatever the other windows said.
func TestGateFailsClosedWhenAnyWindowFails(t *testing.T) {
	for failOn := 1; failOn <= 3; failOn++ {
		jev := &spyJev{reply: func(call int, _ string) (float64, error) {
			if call == failOn {
				return 0, errors.New("jev down")
			}
			return 0, nil
		}}
		v := New(jev, 0.5).Classify(longNote(60000, -1))
		if !slices.Equal(v.Reasons, []string{"jev-error-fail-closed"}) || !v.Sensitive {
			t.Errorf("window %d fails: got %+v", failOn, v)
		}
		if jev.calls() < failOn {
			t.Errorf("window %d fails: jev was asked only %d times, so the failure was never reached", failOn, jev.calls())
		}
	}

	// A NaN from one window must not be lost in the maximum.
	for naNOn := 1; naNOn <= 3; naNOn++ {
		jev := &spyJev{reply: func(call int, _ string) (float64, error) {
			if call == naNOn {
				return math.NaN(), nil
			}
			return 0, nil
		}}
		requireVerdict(t, New(jev, 0.5).Classify(longNote(60000, -1)), true, "jev-error-fail-closed")
	}
}

// The scanner reads the whole note, not the windows. A structured secret deep in a
// long note is caught with no help from jev.
func TestGateScannerReadsTheWholeLongNote(t *testing.T) {
	body := []byte(filler(59999))
	copy(body[50000:], " "+awsKey+" ") // the key needs a word edge on each side to match
	jev := fails()
	v := New(jev, 0.5).Classify(Note{Text: string(body), Kind: "note"})
	if !v.Sensitive || v.Reasons[0] != "scanner" {
		t.Fatalf("want a scanner verdict, got %+v", v)
	}
	if jev.calls() != 0 {
		t.Fatalf("the scanner decided, so jev must not be asked, got %d calls", jev.calls())
	}
}

// A window of only whitespace holds nothing to leak, and nimble answers it with a
// 400. The gate does not stub the note for it.
func TestGateSkipsBlankWindowsOfALongNote(t *testing.T) {
	note := Note{UUID: "gappy", Text: "alpha" + strings.Repeat(" ", 3*chunkSize) + "omega", Kind: "note"}
	jev := sentinelJev() // fails any blank text it is sent
	requireVerdict(t, New(jev, 0.5).Classify(note), false)
	if jev.calls() != 2 { // the first and the last window have text. The two in between are blank.
		t.Fatalf("want 2 calls, for the two windows that have text, got %d", jev.calls())
	}
}

func TestGateSendsOneWindowOrTwoAtTheEdge(t *testing.T) {
	for _, tc := range []struct{ total, calls int }{{chunkSize - 1, 1}, {chunkSize, 1}, {chunkSize + 1, 2}} {
		jev := answers(0)
		New(jev, 0.5).Classify(longNote(tc.total, -1))
		if jev.calls() != tc.calls {
			t.Errorf("a %d byte note: got %d calls, want %d", tc.total, jev.calls(), tc.calls)
		}
	}
}

func TestWindowsOverlapAndCoverTheText(t *testing.T) {
	// Every 8 byte token is unique, so a window can be found in the text by value.
	var b strings.Builder
	for i := range 13000 {
		fmt.Fprintf(&b, "%07d,", i)
	}
	text := b.String() // 104000 bytes
	step := chunkSize - chunkOverlap

	got := windows(text)
	if len(got) < 3 {
		t.Fatalf("a %d byte text must make several windows, got %d", len(text), len(got))
	}
	for i, w := range got {
		start := strings.Index(text, w)
		if want := i * step; start != want {
			t.Fatalf("window %d starts at %d, want %d", i, start, want)
		}
		last := i == len(got)-1
		if last && start+len(w) != len(text) {
			t.Fatalf("the last window ends at %d, want the end of the text, %d", start+len(w), len(text))
		}
		if !last && len(w) != chunkSize {
			t.Fatalf("window %d has %d bytes, want %d", i, len(w), chunkSize)
		}
		if len(w) > chunkSize {
			t.Fatalf("window %d has %d bytes, over %d", i, len(w), chunkSize)
		}
	}

	// A text that fits comes back whole.
	for _, short := range []string{"", "x", strings.Repeat("y", chunkSize)} {
		if got := windows(short); len(got) != 1 || got[0] != short {
			t.Fatalf("a %d byte text must come back as one window, got %d windows", len(short), len(got))
		}
	}
}
