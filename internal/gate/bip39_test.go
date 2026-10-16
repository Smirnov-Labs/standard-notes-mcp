package gate

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
)

// A seed phrase is catastrophic to leak, because the words are the wallet's keys.
// A jev probe scored a bare 12-word phrase 0.04, and "Ledger seed" plus the words
// 0.145. Both sit under the 0.5 threshold, so the gate returned the note. Tier 0
// must catch a phrase without jev.
//
// Every phrase below is a public BIP-39 test vector or a phrase made for this
// file. None is anyone's wallet.

const seedReason = "bip39 seed phrase"

// zeroEntropy returns the BIP-39 phrase of n words that comes from all-zero
// entropy: n-1 words "abandon" and a last word that carries the checksum.
func zeroEntropy(n int, last string) string {
	return strings.Repeat("abandon ", n-1) + last
}

const (
	// A second public vector, from entropy 7f7f...7f.
	legalPhrase = "legal winner thank year wave sausage worth useful legal winner thank yellow"
	// A valid phrase with three-letter words (fog, toe, era) and an eight-letter
	// word (resemble). The wordlist has words of 3 to 8 letters, and this row
	// holds both limits.
	mixedLengthPhrase = "educate fog sunset evolve match secret begin toe resemble era fall keep"
)

func TestScanFlagsSeedPhrases(t *testing.T) {
	var numbered strings.Builder
	for i, w := range strings.Fields(legalPhrase) {
		numbered.WriteString(strconv.Itoa(i+1) + ". " + w + "\n")
	}
	legal := strings.Fields(legalPhrase)

	tests := []struct {
		name string
		text string
	}{
		{"12 words", zeroEntropy(12, "about")},
		{"15 words", zeroEntropy(15, "address")},
		{"18 words", zeroEntropy(18, "agent")},
		{"21 words", zeroEntropy(21, "admit")},
		{"24 words", zeroEntropy(24, "art")},
		{"another 12-word vector", legalPhrase},
		{"words of the shortest and longest length", mixedLengthPhrase},
		{"in a sentence", "my recovery words: " + legalPhrase + ". Keep them safe."},
		{"after a label", "Ledger seed\n" + legalPhrase},
		{"numbered lines", numbered.String()},
		{"upper case with commas", strings.ToUpper(strings.Join(legal, ", "))},
		// The gate joins a title and a body with a newline.
		{"split between title and body", strings.Join(legal[:6], " ") + "\n" + strings.Join(legal[6:], " ")},
		// Three wordlist words come first, so the real phrase starts at the fourth
		// word. Only the window that starts there has a valid checksum.
		{"after words that are also in the list", "pepper grape potato " + mixedLengthPhrase},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { requireRule(t, tc.text, seedReason) })
	}
}

// A run of wordlist words is not enough. The checksum must hold, the words must
// be in one unbroken run, and the run must not be the wordlist itself.
func TestScanIgnoresWordsThatAreNotASeedPhrase(t *testing.T) {
	tests := []struct {
		name string
		text string
	}{
		{"11 wordlist words", zeroEntropy(11, "about")},
		{"12 words, one not in the list", zeroEntropy(12, "xyzzy")},
		{"12 wordlist words with a broken checksum", zeroEntropy(12, "abandon")},
		// Each is a valid all-zero phrase with only its last checksum bit wrong:
		// "about" becomes "able", and "art" becomes "artefact".
		{"12 words with the last checksum bit flipped", zeroEntropy(12, "able")},
		{"24 words with the last checksum bit flipped", zeroEntropy(24, "artefact")},
		{"a valid phrase with its last word swapped", "legal winner thank year wave sausage worth useful legal winner thank above"},
		// 5 + 6 + 1 = 12 wordlist words, and they make a valid phrase if joined.
		// "xyzzy" sits in the middle and splits them into two short rows.
		{"a word outside the list splits a valid phrase", strings.Repeat("abandon ", 5) + "xyzzy " + strings.Repeat("abandon ", 6) + "about"},
		{"wordlist words that alternate with other words", strings.Repeat("abandon xyzzy ", 12)},
		// Fourteen everyday words that are all in the wordlist. None of the three
		// 12-word windows has a valid checksum.
		{"a shopping list of wordlist words", "pepper grape potato coffee banana orange milk lemon onion salt apple sugar honey tomato"},
		// Twelve words from the wordlist in order. The checksum happens to hold,
		// but a real phrase is never in alphabetical order.
		{"an excerpt of the wordlist in order", "aerobic affair afford afraid again age agent agree ahead aim air airport"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { requireNoRule(t, tc.text, seedReason) })
	}
}

func TestScanProseIsNotASeedPhrase(t *testing.T) {
	requireQuiet(t, "The meeting notes from Tuesday cover the roadmap for next quarter. "+
		"We agreed to ship the new onboarding flow first, then revisit pricing once the numbers are in. "+
		"Alice will draft the announcement, Bob owns the migration, and I will review the budget with "+
		"finance on Friday. Remember to buy milk and eggs on the way home, and book the dentist for early March.")
}

// canonicalWordlistSHA256 is the digest of bip-0039/english.txt in the
// bitcoin/bips repository. The detector is only as good as its list. One word out
// of place gives every real phrase the wrong checksum, and the detector then
// misses it without any error. So the digest is pinned.
const canonicalWordlistSHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"

func TestBip39WordlistIsTheCanonicalFile(t *testing.T) {
	sum := sha256.Sum256([]byte(bip39English))
	if got := hex.EncodeToString(sum[:]); got != canonicalWordlistSHA256 {
		t.Fatalf("bip39_english.txt has sha256 %s, want %s", got, canonicalWordlistSHA256)
	}
	words := strings.Fields(bip39English)
	if len(words) != 2048 || len(bip39Index) != 2048 {
		t.Fatalf("got %d words and %d index entries, want 2048 of each", len(words), len(bip39Index))
	}
	// A position is a word's index in the file. These four are fixed by the BIP.
	for word, want := range map[string]uint16{"abandon": 0, "about": 3, "art": 102, "zoo": 2047} {
		if got := bip39Index[word]; got != want {
			t.Fatalf("position of %q is %d, want %d", word, got, want)
		}
	}
	// wordPosition drops any token that is not 3 to 8 letters long before it looks
	// the token up. That is safe only while every word is 3 to 8 lower case letters.
	for _, w := range words {
		if len(w) < 3 || len(w) > 8 || strings.Trim(w, "abcdefghijklmnopqrstuvwxyz") != "" {
			t.Fatalf("word %q breaks the length and alphabet filter in wordPosition", w)
		}
	}
}

// The wordlist is in alphabetical order, so its stretches pass the checksum by
// chance, about 1 window in 16. A note that pastes the list holds no secret.
func TestScanIgnoresTheWordlistItself(t *testing.T) {
	words := strings.Fields(bip39English)
	requireNoRule(t, strings.Join(words, "\n"), seedReason)
	requireNoRule(t, strings.Join(words, " "), seedReason)
}

// Each valid length, checked without the tokenizer: the checksum of the all-zero
// entropy phrase holds, and a different last word breaks it.
func TestValidChecksum(t *testing.T) {
	for _, tc := range []struct {
		words int
		last  string
	}{{12, "about"}, {15, "address"}, {18, "agent"}, {21, "admit"}, {24, "art"}} {
		window := make([]uint16, tc.words) // all "abandon", position 0
		window[tc.words-1] = bip39Index[tc.last]
		if !validChecksum(window) {
			t.Fatalf("%d words ending in %q: the checksum must hold", tc.words, tc.last)
		}
		// Flip only the last bit of the last word, which is the last checksum bit.
		// A check that compares one bit too few would still pass this window.
		window[tc.words-1] = bip39Index[tc.last] ^ 1
		if validChecksum(window) {
			t.Fatalf("%d words with the last checksum bit flipped: the checksum must fail", tc.words)
		}
		window[tc.words-1] = bip39Index["zoo"]
		if validChecksum(window) {
			t.Fatalf("%d words ending in zoo: the checksum must fail", tc.words)
		}
	}
}

func TestWordPosition(t *testing.T) {
	for _, tc := range []struct {
		token string
		pos   uint16
		ok    bool
	}{
		{"abandon", 0, true},
		{"ABANDON", 0, true},
		{"Zoo", 2047, true},
		{"art", 102, true},
		{"ab", 0, false},        // two letters
		{"abandons", 0, false},  // eight letters, not in the list
		{"abandoned", 0, false}, // nine letters
		{"xyzzy", 0, false},
	} {
		pos, ok := wordPosition(tc.token)
		if ok != tc.ok || (ok && pos != tc.pos) {
			t.Fatalf("wordPosition(%q) = %d, %v; want %d, %v", tc.token, pos, ok, tc.pos, tc.ok)
		}
	}
}
