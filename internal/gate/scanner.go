package gate

import (
	"math"
	"regexp"
	"strings"
)

// Result is the deterministic scan outcome.
type Result struct {
	Sensitive bool
	Reasons   []string
}

// rule is one named check. Scan reports name as a reason when match returns true.
type rule struct {
	name  string
	match func(text string) bool
}

// pattern builds a rule that fires when expr matches anywhere in the text.
func pattern(name, expr string) rule {
	return rule{name: name, match: regexp.MustCompile(expr).MatchString}
}

// rules are the tier-0 checks, in the order Scan reports them. They follow spec
// section 6.1: PEM private keys, AKIA keys, high-entropy tokens, Luhn-valid card
// numbers and password-manager export markers.
var rules = []rule{
	pattern("pem private key", `-----BEGIN [A-Z ]*PRIVATE KEY-----`),
	pattern("aws access key id", `\b(AKIA|ASIA)[0-9A-Z]{16}\b`),
	pattern("otp secret", `(?i)otpauth://|\botpauth\b|\btotp secrets?\b`),
	{"password-manager export", hasManagerExport},
	pattern("private key hint", `(?i)\bBEGIN (OPENSSH|PGP) PRIVATE KEY\b`),

	// Credentials with a documented shape. Each family has a named rule. The word
	// boundary keeps a prefix from matching inside a longer word, such as the "sk-"
	// in "disk-usage-monitoring-dashboard". The jwt rule has none. Its three dotted
	// segments make a false match unlikely, and a token can follow a word
	// character, as in "token_eyJ...".
	pattern("jwt", `eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}`),
	pattern("github token", `\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})`),
	pattern("slack token", `\bxox[baprs]-[A-Za-z0-9-]{10,}`),
	pattern("stripe key", `\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}`),
	pattern("openai-style key", `\bsk-[A-Za-z0-9_-]{20,}`),
	pattern("google api key", `\bAIza[A-Za-z0-9_-]{35}`),
	pattern("gitlab token", `\bglpat-[A-Za-z0-9_-]{20,}`),
	pattern("npm token", `\bnpm_[A-Za-z0-9]{36,}`),
	pattern("sendgrid key", `\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}`),

	// A URL with a user and a password in it. The user may be empty, as in
	// redis://:password@host. A URL with only a user (ssh://git@host) or only a
	// port (http://localhost:8080/) does not fire, because the rule needs a ":" and
	// then an "@" before the first "/".
	pattern("url with credentials", `://[^\s/@:]*:[^\s/@]+@[^\s/@]+`),

	// A keyword, a separator and a value of six or more characters on one line.
	// The keyword may sit inside a longer name (DB_PASSWORD, SECRET_KEY_BASE) and
	// may take a closing quote (a JSON key). "secret" also covers client_secret and
	// api_secret. A word that merely starts with a keyword ("secretary") has no
	// separator after the keyword, so it does not fire. A README that shows an
	// example such as PASSWORD=mypassword does fire. Tier 0 cannot tell an example
	// from a real value, and a miss is the worse mistake.
	pattern("secret assignment", `(?i)(?:password|passwd|secret(?: key)?|api[ _-]?key|access[ _-]?key|(?:access|api|auth|refresh)[ _-]?token|private[ _-]?key)(?:[_-][a-z0-9]+)*["']?[ \t]*(?:=>|:=|[:=])[ \t]*\S{6,}`),

	{"high-entropy token", hasHighEntropyToken},
	{"bip39 seed phrase", hasSeedPhrase},
	{"luhn-valid number", hasCardNumber},
}

// Scan reports whether text deterministically contains a secret. It errs toward
// flagging (high recall is the safe direction for the privacy gate).
func Scan(text string) Result {
	var r Result
	for _, rl := range rules {
		if rl.match(text) {
			r.Sensitive = true
			r.Reasons = append(r.Reasons, rl.name)
		}
	}
	return r
}

var (
	// managerName and exportContext match on their own. The order of the two words
	// and the newlines between them do not matter, and a note joins its title and
	// body with a newline.
	managerName   = regexp.MustCompile(`(?i)\b(?:1password|bitwarden|lastpass|keepass\w*|dashlane|proton ?pass)\b`)
	exportContext = regexp.MustCompile(`(?i)\b(?:export|back[ -]?up|vault)\w*`)
)

// hasManagerExport reports whether text names a password manager and also holds
// an export, backup or vault word. A manager named with none of those is a note
// about the manager, not a secret.
func hasManagerExport(text string) bool {
	return managerName.MatchString(text) && exportContext.MatchString(text)
}

// The generic token rule backs up the shaped rules above. It looks for a run of
// 32 or more token characters that mixes lowercase, uppercase and digits, and
// that looks random. A secret with no known shape fires. A hex digest, a UUID,
// a word, a slug and a plain identifier do not.
//
// The two thresholds come from a calibration on public text. On 8,017 README and
// documentation files the rule flagged about 0.4% of files. Nearly every hit was
// base64 key, certificate or JWT material. On random tokens of 32 to 64
// characters it fires 96% to 99.7% of the time.
const (
	// tokenMinBits is the least Shannon entropy, in bits per character. Random
	// base62 text of 40 characters averages 4.8. A CamelCase identifier scores 3.7
	// to 4.5.
	tokenMinBits = 4.2
	// tokenMinSwitching is the least share of neighbouring letters and digits that
	// change kind (lowercase, uppercase, digit). Random text switches about 62% of
	// the time. Identifiers and slugs switch 12% to 42%. Entropy alone cannot tell
	// the two apart at 32 characters, so this is the gate that rejects identifiers.
	tokenMinSwitching = 0.45
)

var (
	tokenRun = regexp.MustCompile(`[A-Za-z0-9+/_-]{32,}`)
	// dataURI and urlText are removed before the search. A random-looking run
	// inside a data: URI is an image. One inside a URL is usually an id or a
	// tracking token, such as a Drive id in "open?id=" or an fbclid, and a
	// 44-character id is statistically a random token. The shaped rules, the url
	// rule and the assignment rule still read the whole text, so "?api_key=..." or
	// "user:password@" in a URL fires. A bare token with no known shape in a query
	// string, such as "?token=...", does not.
	dataURI = regexp.MustCompile(`data:[A-Za-z0-9.+/-]*(?:;[A-Za-z0-9=.+/-]+)*,[A-Za-z0-9+/=_-]+`)
	urlText = regexp.MustCompile(`[A-Za-z]+://\S+`)
)

// hasHighEntropyToken reports whether text holds a run that looks like a random
// token.
func hasHighEntropyToken(text string) bool {
	text = dataURI.ReplaceAllString(text, " ")
	text = urlText.ReplaceAllString(text, " ")
	for _, run := range tokenRun.FindAllString(text, -1) {
		if looksRandom(run) {
			return true
		}
	}
	return false
}

// looksRandom applies the gates of the generic token rule to one run.
func looksRandom(run string) bool {
	var (
		counts                [256]int
		lower, upper, digit   bool
		prev, pairs, switches = -1, 0, 0
	)
	for i := 0; i < len(run); i++ {
		c := run[i]
		counts[c]++
		kind := -1
		switch {
		case c >= 'a' && c <= 'z':
			kind, lower = 0, true
		case c >= 'A' && c <= 'Z':
			kind, upper = 1, true
		case c >= '0' && c <= '9':
			kind, digit = 2, true
		}
		if kind < 0 {
			continue // + / - _ carry no case or digit signal
		}
		if prev >= 0 {
			pairs++
			if kind != prev {
				switches++
			}
		}
		prev = kind
	}
	if !lower || !upper || !digit {
		return false
	}
	if shannon(&counts, len(run)) < tokenMinBits {
		return false
	}
	return float64(switches) >= tokenMinSwitching*float64(pairs)
}

// shannon returns the entropy of a byte histogram, in bits per character.
func shannon(counts *[256]int, n int) float64 {
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / float64(n)
		h -= p * math.Log2(p)
	}
	return h
}

// cardRuns find candidate card numbers. Each regexp matches a whole run of
// digits and separators, and hasCardNumber then checks the digit count and the
// Luhn sum of the run.
//
// Spaces and dashes, the separators a card usually has, join groups freely.
// Tabs and dots join groups only in a pattern that looks like a card. A wider
// class that took tabs and dots anywhere would merge the digits next to a card
// into its run. A spreadsheet row ("Visa<TAB>4111 1111 1111 1111<TAB>12/26"), a
// numbered list item ("1. 4111 ...") and a card at the end of a sentence
// ("4111 ... 1111. 12 apples") would then fail the Luhn check and slip through.
// The first version of the rule flagged all three, so a wider class would be a
// regression.
//
// A run is maximal, so a card that is followed or preceded by more digits joined
// to it by a space or a dash (card plus expiry or CVV) forms one longer run, and
// the Luhn check can miss it. This is a known tier-0 limitation. A sliding window
// would fix it but would flag too many numeric ids, so the jev tier covers it.
var cardRuns = []*regexp.Regexp{
	// Spaces (any Unicode space, so a non-breaking space counts) or dashes.
	regexp.MustCompile(`[0-9][0-9\p{Zs}-]{11,}[0-9]`),
	// Three or more digit groups with a tab between each pair and nothing else.
	regexp.MustCompile(`[0-9]+(?:\t[0-9]+){2,}`),
	// A 4-digit group, then two or more groups of 4 to 7 digits, joined by dots.
	// This shape rules out a decimal number or a version string.
	regexp.MustCompile(`\b[0-9]{4}(?:\.[0-9]{4,7}){2,}\b`),
}

// hasCardNumber reports whether text holds a 13 to 19 digit number that passes
// the Luhn check.
func hasCardNumber(text string) bool {
	for _, re := range cardRuns {
		for _, m := range re.FindAllString(text, -1) {
			if d := digitsOf(m); len(d) >= 13 && len(d) <= 19 && luhnValid(d) {
				return true
			}
		}
	}
	return false
}

// digitsOf returns the ASCII digits of s and drops everything else.
func digitsOf(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, s)
}

// luhnValid reports whether digits pass the Luhn checksum. It returns false for
// any byte that is not an ASCII digit.
func luhnValid(digits string) bool {
	sum, alt := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i]) - '0'
		if d < 0 || d > 9 {
			return false
		}
		if alt {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}
