package gate

import (
	"crypto/sha256"
	_ "embed"
	"strings"
)

// bip39English is the BIP-39 English wordlist: 2048 words, one per line. The
// position of a word in the list is its 11-bit value. The file is bip-0039/english.txt
// from the bitcoin/bips repository (BIP-39 is licensed MIT). Its sha256 digest is
// 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda, and a test
// pins it. A list with one word out of place would give every phrase the wrong
// checksum and hide a real one, so do not edit the file.
//
//go:embed bip39_english.txt
var bip39English string

// bip39Index maps each word to its position in the list.
var bip39Index = func() map[string]uint16 {
	words := strings.Fields(bip39English)
	index := make(map[string]uint16, len(words))
	for i, w := range words {
		index[w] = uint16(i)
	}
	return index
}()

// seedLengths are the phrase lengths that BIP-39 allows. A phrase of n words holds
// n*11 bits: ENT bits of entropy, then ENT/32 bits of checksum.
var seedLengths = [...]int{12, 15, 18, 21, 24}

// hasSeedPhrase reports whether text holds a BIP-39 seed phrase. A phrase is 12,
// 15, 18, 21 or 24 wordlist words in a row, and its checksum must hold.
//
// A word is a maximal run of ASCII letters, in any case. Everything else
// separates words: spaces, newlines, commas, digits and punctuation. So "1.
// abandon 2. abandon" and "ABANDON, ABANDON" still read as a row of words. A
// token that is not in the wordlist ends the row. The search slides a window of
// each valid length over every row.
//
// The checksum keeps false positives rare. A row of 12 wordlist words that is not
// a phrase passes it 1 time in 16. The odds fall to 1 in 256 for 24 words. A real
// phrase always passes. A wallet will not accept a phrase that fails, so a row
// that fails is not a usable phrase and is not flagged.
//
// A phrase is flagged wherever it sits: after a label, inside a sentence, or
// split between a title and a body (the gate joins them with a newline).
func hasSeedPhrase(text string) bool {
	var row []uint16 // wordlist positions of the words in the current row
	for i := 0; i < len(text); {
		if !isLetter(text[i]) {
			i++
			continue
		}
		j := i + 1
		for j < len(text) && isLetter(text[j]) {
			j++
		}
		pos, ok := wordPosition(text[i:j])
		i = j
		if ok {
			row = append(row, pos)
			continue
		}
		if rowHoldsSeedPhrase(row) {
			return true
		}
		row = row[:0]
	}
	return rowHoldsSeedPhrase(row)
}

// isLetter reports whether c is an ASCII letter. Setting bit 5 folds an upper
// case letter onto its lower case form and moves no other byte into a-z.
func isLetter(c byte) bool {
	c |= 0x20
	return c >= 'a' && c <= 'z'
}

// wordPosition returns the position of token in the wordlist, ignoring case.
// token holds only ASCII letters.
func wordPosition(token string) (uint16, bool) {
	// Every word has 3 to 8 letters, so most tokens fail here, with no allocation.
	if len(token) < 3 || len(token) > 8 {
		return 0, false
	}
	var lower [8]byte
	for i := 0; i < len(token); i++ {
		lower[i] = token[i] | 0x20
	}
	pos, ok := bip39Index[string(lower[:len(token)])]
	return pos, ok
}

// rowHoldsSeedPhrase reports whether any window of a valid length in row is a
// seed phrase.
//
// It skips a window whose words are in strictly rising order. The wordlist is in
// that order, so a note that pastes the list, or a stretch of it, would pass the
// checksum by chance. About 1 window in 16 does. A real phrase is essentially
// never in alphabetical order, because a random 12-word phrase has 1 chance in
// 479 million of it.
func rowHoldsSeedPhrase(row []uint16) bool {
	for _, n := range seedLengths {
		for start := 0; start+n <= len(row); start++ {
			window := row[start : start+n]
			if !strictlyRising(window) && validChecksum(window) {
				return true
			}
		}
	}
	return false
}

// strictlyRising reports whether each position in w is greater than the one
// before it.
func strictlyRising(w []uint16) bool {
	for i := 1; i < len(w); i++ {
		if w[i] <= w[i-1] {
			return false
		}
	}
	return true
}

// validChecksum reports whether w, a window of 12, 15, 18, 21 or 24 wordlist
// positions, holds a valid BIP-39 checksum. The 11-bit positions, joined in order,
// are the entropy followed by the checksum. The checksum is the first
// len(w)*11/33 bits of the SHA-256 hash of the entropy.
func validChecksum(w []uint16) bool {
	var bits [33]byte // 24 words are 264 bits, which is 33 bytes
	for i, pos := range w {
		for b := 0; b < 11; b++ {
			if pos>>(10-b)&1 == 1 {
				at := i*11 + b
				bits[at/8] |= 0x80 >> (at % 8)
			}
		}
	}
	checkBits := len(w) * 11 / 33
	entropyBytes := (len(w)*11 - checkBits) / 8 // 16, 20, 24, 28 or 32
	// The entropy ends on a byte boundary, so the checksum is the top checkBits
	// bits of the next byte.
	sum := sha256.Sum256(bits[:entropyBytes])
	return sum[0]>>(8-checkBits) == bits[entropyBytes]>>(8-checkBits)
}
