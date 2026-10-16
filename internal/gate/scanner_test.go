package gate

import (
	"slices"
	"strings"
	"testing"
)

func TestScanDetectsSecrets(t *testing.T) {
	hits := []string{
		"-----BEGIN RSA PRIVATE KEY-----\nMIIE...",
		"aws key AKIAIOSFODNN7EXAMPLE here",
		"card 4111 1111 1111 1111 on file", // Luhn-valid Visa test number
		"otpauth://totp/Acme:me?secret=JBSWY3DPEHPK3PXP",
	}
	for _, s := range hits {
		if !Scan(s).Sensitive {
			t.Fatalf("missed a secret in: %q", s)
		}
	}
	safe := []string{"buy milk and eggs", "meeting notes about the roadmap", "4111 1111 1111 1112"} // last fails Luhn
	for _, s := range safe {
		if Scan(s).Sensitive {
			t.Fatalf("false positive on: %q", s)
		}
	}
}

// A miss here can leak a secret to the orchestrator, so each rule needs a row
// that proves it fires, and each row names the rule that must fire. Without the
// reason check, a row could pass because some other rule matched the text.
func TestScanReportsTheRuleThatFired(t *testing.T) {
	tests := []struct {
		name   string
		text   string
		reason string
	}{
		{"aws key with the second prefix, ASIA", "temp creds ASIAIOSFODNN7EXAMPLE", "aws access key id"},
		{"pem key that is not RSA", "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEE...", "pem private key"},
		// PGP armor puts BLOCK after KEY, so the pem rule cannot match it. Only
		// the private-key-hint rule sees it.
		{"pgp private key block", "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQVYBF...", "private key hint"},
		// A hyphen follows "otpauth", so the otpauth:// branch cannot match. This
		// is the Google Authenticator export format. It carries the secrets of
		// every exported account.
		{"otpauth-migration export", "otpauth-migration://offline?data=CjEKCkhl", "otp secret"},
		{"totp secret named in words", "TOTP secret: JBSWY3DPEHPK3PXP", "otp secret"},
		{"password-manager export", "Bitwarden vault export, keep it safe", "password-manager export"},
		// The card rule covers 13 to 19 digits. These two rows sit on its edges.
		{"card with 13 digits", "4222222222222", "luhn-valid number"},
		{"card with 19 digits", "1234567890123456785", "luhn-valid number"},
		// 5 is the smallest digit whose double (10) needs the subtract-9 step of
		// the Luhn sum. This number doubles six 5s.
		{"mastercard test number", "5555 5555 5555 4444", "luhn-valid number"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Scan(tc.text)
			if !got.Sensitive {
				t.Fatalf("missed a secret in %q: want rule %q", tc.text, tc.reason)
			}
			if !slices.Contains(got.Reasons, tc.reason) {
				t.Fatalf("wrong rule for %q: want %q, got %v", tc.text, tc.reason, got.Reasons)
			}
		})
	}
}

// Near-misses of the card rule must stay quiet. The 16-digit row is in range,
// so only the Luhn check keeps it out. The rows marked "passes Luhn" are out of
// range, so only the 13 to 19 digit bound keeps them out. Tier 0 does not try to
// catch SSNs; the jev tier covers broader personal data.
func TestScanIgnoresNearMissesOfTheCardRule(t *testing.T) {
	tests := []struct {
		name string
		text string
	}{
		{"16 digits, fails Luhn", "order 1234567890123456"},
		{"9 digits, SSN-shaped, fails Luhn", "ssn 123 45 6789"},
		{"9 digits, SSN-shaped, passes Luhn", "ref 123 45 6782"},
		{"12 digits, passes Luhn", "acct 1234 5678 9015"},
		{"20 digits, passes Luhn", "acct 1234 5678 9012 3456 7894"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Scan(tc.text); got.Sensitive {
				t.Fatalf("false positive on %q: %v", tc.text, got.Reasons)
			}
		})
	}
}

// luhnValid is only ever called with digits, but its doc comment promises that
// any other byte makes it return false. A leading "&" is the sharp case: it sits
// below "0", so a check that tests only for a digit above "9" would count it as
// -10 and let the sum of an otherwise valid number still pass.
func TestLuhnValidRejectsNonDigits(t *testing.T) {
	if !luhnValid("4111111111111111") {
		t.Fatal("the control number must pass")
	}
	for _, s := range []string{"&4111111111111111", "4111 1111 1111 1111", "4111111111111111x", " 4111111111111111"} {
		if luhnValid(s) {
			t.Fatalf("luhnValid accepted %q", s)
		}
	}
}

// Scan lists every rule that fired, not only the first. The gate logs these
// reasons, and a note with a private key and a card number needs both.
func TestScanReportsEveryRuleThatFired(t *testing.T) {
	text := "-----BEGIN RSA PRIVATE KEY-----\naws AKIAIOSFODNN7EXAMPLE\ncard 4111 1111 1111 1111"
	got := Scan(text)
	for _, want := range []string{"pem private key", "aws access key id", "luhn-valid number"} {
		if !slices.Contains(got.Reasons, want) {
			t.Fatalf("reasons %v do not include %q", got.Reasons, want)
		}
	}
	if len(got.Reasons) != len(slices.Compact(slices.Sorted(slices.Values(got.Reasons)))) {
		t.Fatalf("a rule is listed more than once: %v", got.Reasons)
	}
}

// requireRule fails unless Scan flags text and names reason among its reasons.
func requireRule(t *testing.T, text, reason string) {
	t.Helper()
	got := Scan(text)
	if !got.Sensitive {
		t.Fatalf("missed a secret in %q: want rule %q", text, reason)
	}
	if !slices.Contains(got.Reasons, reason) {
		t.Fatalf("wrong rule for %q: want %q, got %v", text, reason, got.Reasons)
	}
}

// requireNoRule fails if Scan names reason for text. Other rules may still fire.
func requireNoRule(t *testing.T, text, reason string) {
	t.Helper()
	if slices.Contains(Scan(text).Reasons, reason) {
		t.Fatalf("rule %q fired on %q", reason, text)
	}
}

// requireQuiet fails if any rule flags text.
func requireQuiet(t *testing.T, text string) {
	t.Helper()
	if got := Scan(text); got.Sensitive {
		t.Fatalf("false positive on %q: %v", text, got.Reasons)
	}
}

// fillBase62 returns n characters of base62 text. A row can then name the exact
// length of a token and stay deterministic.
func fillBase62(n int) string {
	return strings.Repeat("aB3dE5gH7jK9mN1pQ", n)[:n]
}

// Spec section 6.1 puts "high-entropy tokens" in the tier-0 scanner. Real API
// keys, tokens and connection strings carry a fixed shape, so each family has its
// own named rule. A generic rule backs them up for tokens with no known shape.
//
// Fixtures that look like credentials are built from parts, so this file holds no
// literal that a secret scanner (push protection, for example) would flag. Every
// value is made up. None is a live credential.
func TestScanFlagsStructuredTokens(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + "." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ" + "." +
		"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	tests := []struct {
		name   string
		text   string
		reason string
	}{
		{"jwt", "Authorization: Bearer " + jwt, "jwt"},
		{"github classic token", "gh" + "p_" + "huG8GP38g4o5MNJAYKJ1UXXFWXLCpaNfhs0g", "github token"},
		{"github fine-grained token", "github" + "_pat_" + "Ca05RFRunzqw7wZyVGOeUv" + "_" + "fJIssDj4PTTKtb2TxxDBfz5LJF3hBGZW3M4Fz6Hq2AK7EGHZbKoXi0d9TH4", "github token"},
		{"slack bot token", "xo" + "xb-123456789012-1234567890123-" + "QgTNBEjE4o24hOSDRET79IqJ", "slack token"},
		{"stripe live key", "s" + "k_live_" + "zQtJZPGSEZ4zBms1racjP4M9", "stripe key"},
		{"stripe restricted test key", "r" + "k_test_" + "DZH7Fx6mqSFDGX0FZBJQ6c1s", "stripe key"},
		{"openai project key", "s" + "k-proj-" + "O6m4H5x29iI_Vmy0s5bla5kzFpfITtaO-rC8qLk1urN0XtzW", "openai-style key"},
		{"openai legacy key", "s" + "k-" + "a9gy4ed1wPw7X8bbGEuRtCu6hF8DKNZkjLHnBNvDMoRTeJzc", "openai-style key"},
		{"google api key", "AI" + "za" + "zwfg5y9cqBruxXI21kXNxSwH7_1K7wP94pJ", "google api key"},
		{"google api key inside a url query", "https://example.com/cb?key=" + "AI" + "za" + "zwfg5y9cqBruxXI21kXNxSwH7_1K7wP94pJ", "google api key"},
		{"gitlab token", "glp" + "at-" + "mBDal6Q0xdTuTBoJBLIq", "gitlab token"},
		{"npm token", "np" + "m_" + "gYqg9BkgRdWwUZlPOgGurL1es7ukqqeaA355", "npm token"},
		{"sendgrid key", "S" + "G." + "G1bhmEcNpmSO6eZOB72pVG" + "." + "XLTh3dKQLpM1OcRzhouppeqTMd2qT1XWE1CqxdYGsDc", "sendgrid key"},
		{"connection string with credentials", "postgres://admin:" + "s3cr3tP4ss@db.internal:5432/prod", "url with credentials"},
		{"connection string with an empty user", "redis://:" + "s3cr3tP4ss@cache:6379/0", "url with credentials"},
		{"connection string with an srv scheme", "mongodb+srv://app:" + "Pa55w0rd@cluster0.example.net/test", "url with credentials"},
		// A token with no known shape: 32 or more characters of token alphabet that
		// mix lowercase, uppercase and digits and look random.
		{"high-entropy token, 32 characters", "key Zx9QmT4vLkP2aWc8RbN6yHs1JdF3gUe7 saved", "high-entropy token"},
		{"high-entropy token, 40 characters", "Zx9QmT4vLkP2aWc8RbN6yHs1JdF3gUe7XoV5iBt0", "high-entropy token"},
		{"high-entropy token, base64url", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "high-entropy token"},
		{"high-entropy token, base64 with slash and plus", "qT7/xK2mPz9Lw4RbN8+vYc3HdJ6sFe1UaXo5Gi0V", "high-entropy token"},
		// These two sit just inside the calibrated thresholds: entropy 4.30 against
		// a floor of 4.2, and 18 of 39 neighbours switching kind against a floor of
		// 45%. The matching rows in TestScanGenericTokenIgnoresLookAlikes sit just
		// outside.
		{"high-entropy token, entropy just over the floor", "eY4uD4eH1xA3xS0nV5uL3sA2sS2oN3xZ2wN3nS0n", "high-entropy token"},
		{"high-entropy token, switching just over the floor", "471uL8k6BVQ0D53micw9Mavngzso24b7elqxyr18", "high-entropy token"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { requireRule(t, tc.text, tc.reason) })
	}
}

// Each family has a length floor, and the spelling letters inside a prefix
// matter too. A row on the floor must fire. A row one character short must not.
func TestScanTokenLengthFloors(t *testing.T) {
	floors := []struct {
		reason string
		prefix string
		floor  int
	}{
		{"github token", "gh" + "p_", 36},
		{"github token", "github" + "_pat_", 22},
		{"slack token", "xo" + "xb-", 10},
		{"stripe key", "s" + "k_live_", 16},
		{"openai-style key", "s" + "k-", 20},
		{"google api key", "AI" + "za", 35},
		{"gitlab token", "glp" + "at-", 20},
		{"npm token", "np" + "m_", 36},
	}
	for _, f := range floors {
		t.Run(f.prefix, func(t *testing.T) {
			requireRule(t, f.prefix+fillBase62(f.floor), f.reason)
			requireNoRule(t, f.prefix+fillBase62(f.floor-1), f.reason)
		})
	}

	t.Run("github prefix letters", func(t *testing.T) {
		for _, k := range "pousr" {
			requireRule(t, "gh"+string(k)+"_"+fillBase62(36), "github token")
		}
		requireNoRule(t, "gh"+"x_"+fillBase62(40), "github token")
	})
	t.Run("slack prefix letters", func(t *testing.T) {
		for _, k := range "baprs" {
			requireRule(t, "xox"+string(k)+"-"+fillBase62(10), "slack token")
		}
	})
	t.Run("stripe prefixes", func(t *testing.T) {
		for _, kind := range []string{"s" + "k", "r" + "k"} {
			for _, mode := range []string{"live", "test"} {
				requireRule(t, kind+"_"+mode+"_"+fillBase62(16), "stripe key")
			}
		}
		// A publishable key is meant to be public.
		requireNoRule(t, "p"+"k_live_"+fillBase62(24), "stripe key")
	})
	t.Run("sendgrid segments", func(t *testing.T) {
		requireRule(t, "S"+"G."+fillBase62(16)+"."+fillBase62(16), "sendgrid key")
		requireNoRule(t, "S"+"G."+fillBase62(15)+"."+fillBase62(16), "sendgrid key")
		requireNoRule(t, "S"+"G."+fillBase62(16)+"."+fillBase62(15), "sendgrid key")
	})
	t.Run("jwt segments", func(t *testing.T) {
		requireRule(t, "eyJ"+fillBase62(6)+"."+fillBase62(6)+"."+fillBase62(6), "jwt")
		requireNoRule(t, "eyJ"+fillBase62(5)+"."+fillBase62(6)+"."+fillBase62(6), "jwt")
		requireNoRule(t, "eyJ"+fillBase62(6)+"."+fillBase62(5)+"."+fillBase62(6), "jwt")
		requireNoRule(t, "eyJ"+fillBase62(6)+"."+fillBase62(6)+"."+fillBase62(5), "jwt")
	})
	t.Run("a key prefix inside a longer word", func(t *testing.T) {
		// The word boundary keeps a hyphenated word such as "disk-usage-..." out.
		requireNoRule(t, "di"+"sk-"+"usage-monitoring-dashboard-v2", "openai-style key")
	})
}

// A secret assignment is a keyword, then a separator, then a value of six or
// more characters on the same line. A note that only names the word does not
// fire, so "reset the api_key in settings" stays quiet.
func TestScanSecretAssignments(t *testing.T) {
	hits := []string{
		"password: hunter2xyz",
		"PASSWORD: Hunter2xyz",
		`"password": "hunter2xyz"`,
		"DB_PASSWORD=s3cr3tP4ss",
		"SECRET_KEY=django-insecure-abc123",
		"API Key: AbC123xyz789",
		"access_token=ya29.a0AfH6SMBxyz",
		`password := "hunter2xyz"`,
		`'password' => 'hunter2xyz'`,
		"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"Wi-Fi password: Guest2024!",
	}
	for _, s := range hits {
		t.Run(s, func(t *testing.T) { requireRule(t, s, "secret assignment") })
	}

	t.Run("each keyword", func(t *testing.T) {
		keywords := []string{
			"password", "passwd", "secret", "secret key", "api_key", "api-key", "api key", "apikey",
			"access_key", "access key", "auth_token", "api_token", "refresh_token", "access_token",
			"private_key", "private key",
		}
		for _, kw := range keywords {
			requireRule(t, kw+": hunter2xyz", "secret assignment")
		}
	})
	t.Run("each separator", func(t *testing.T) {
		for _, sep := range []string{":", "=", ": ", " = ", " := ", " => "} {
			requireRule(t, "password"+sep+"hunter2xyz", "secret assignment")
		}
	})
	t.Run("value length floor", func(t *testing.T) {
		requireRule(t, "password: abcdef", "secret assignment")
		requireNoRule(t, "password: abcde", "secret assignment")
	})
	t.Run("value on the next line", func(t *testing.T) {
		requireNoRule(t, "Password:\nRequirements for the new login", "secret assignment")
		requireNoRule(t, "password\n= abcdefghij", "secret assignment")
	})
}

// The first version of the rule required the manager name before "export" on one
// line. A note joins its title and body with a newline, and people write
// "export of my vault" as often as "vault export". Now the two words match on
// their own. A manager named with no export, backup or vault context is a note
// about the manager, not a secret.
func TestScanPasswordManagerExport(t *testing.T) {
	for _, s := range []string{
		"export of my 1Password vault",
		"Exported from Bitwarden",
		"1Password\n\nexport",
		"KeePassXC database export",
		"Title: Backup\nBody: LastPass",
	} {
		t.Run(s, func(t *testing.T) { requireRule(t, s, "password-manager export") })
	}
	t.Run("every manager name", func(t *testing.T) {
		names := []string{"1Password", "Bitwarden", "LastPass", "KeePass", "Dashlane", "ProtonPass", "Proton Pass"}
		for _, name := range names {
			requireRule(t, name+" export", "password-manager export")
		}
	})
	t.Run("every context word", func(t *testing.T) {
		for _, word := range []string{"export", "backup", "back up", "back-up", "vault"} {
			requireRule(t, "Bitwarden "+word, "password-manager export")
		}
	})
	t.Run("a name or a context word alone", func(t *testing.T) {
		requireNoRule(t, "I switched from LastPass to 1Password last year.", "password-manager export")
		requireNoRule(t, "export PATH=$HOME/bin:$PATH", "password-manager export")
		requireNoRule(t, "Back up the laptop before the trip.", "password-manager export")
	})
}

// The otp phrases are matched without regard to case, as the key-hint and
// password-manager rules already were.
func TestScanOtpRulesIgnoreCase(t *testing.T) {
	for _, s := range []string{
		"totp secret: JBSWY3DPEHPK3PXP",
		"TOTP Secret: JBSWY3DPEHPK3PXP",
		"TOTP secrets for the lab accounts",
		"OTPAUTH://totp/Acme:me?issuer=Acme",
		"OtpAuth-Migration://offline?data=CjEKCkhl",
	} {
		t.Run(s, func(t *testing.T) { requireRule(t, s, "otp secret") })
	}
}

// Cards written with non-breaking spaces, tabs or dots are found. Widening the
// separator set naively would merge the digits next to a card into its run and
// then miss the card. The last four rows held before and must keep holding.
// A card followed by more digits that a space or a dash joins to it (card plus
// expiry or CVV) still forms one longer run. Tier 0 does not try to split it,
// because a sliding window would flag too many numeric ids. The jev tier covers it.
func TestScanCardNumberSeparators(t *testing.T) {
	const card = "4111 1111 1111 1111"
	tests := []struct {
		name string
		text string
	}{
		{"non-breaking spaces", "4111 1111 1111 1111"},
		{"narrow no-break spaces", "4111 1111 1111 1111"},
		{"spaces and a no-break space", "4111 1111 1111 1111"},
		{"tabs", "4111\t1111\t1111\t1111"},
		{"dots", "4111.1111.1111.1111"},
		{"amex with dots", "3782.822463.10005"},
		{"amex with tabs", "3782\t822463\t10005"},
		{"spreadsheet row", "Visa\t" + card + "\t12/26\t123"},
		{"card then a tab and the expiry month", card + "\t12"},
		{"numbered list item", "1. " + card},
		{"card at the end of a sentence", "card " + card + ". 12 apples"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { requireRule(t, tc.text, "luhn-valid number") })
	}
}

// Each row passes every gate of the generic token rule but one (the identifier
// row misses two), so a row dies only if that gate is removed. The rule is
// deliberately conservative: hex-only and lowercase-only strings, identifiers and
// slugs do not fire.
func TestScanGenericTokenIgnoresLookAlikes(t *testing.T) {
	tests := []struct {
		name string
		text string
	}{
		{"31 characters, one under the floor", "Zx9QmT4vLkP2aWc8RbN6yHs1JdF3gUe"},
		{"no uppercase letter", "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0"},
		{"no digit", "aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmN"},
		{"no lowercase letter", "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0"},
		{"low entropy", "aB1aB1aB1aB1aB1aB1aB1aB1aB1aB1aB1aB1aB1aB1"},
		{"entropy just under the floor", "lN7bF6zZ1zK5iK2zF2dN1dA9uF2bA1uA9bL3lL9i"},
		{"switching just under the floor", "tz39msfbvyPX58kIEMZachRlrjpTgO61uwd02HQ7"},
		{"go benchmark name", "BenchmarkNinOptNonByteCustomTypeProtoMarshal-8"},
		{"identifier with digits", "TestSHA256HashesMatchAcrossPlatformsCorrectly"},
		{"title-case slug", "How-To-Build-A-Scalable-API-With-FastAPI-And-Docker-2024"},
		{"relative path", "Users/me/Documents/2026/Taxes/Receipts_Q3x9"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { requireQuiet(t, tc.text) })
	}
}

// Ordinary notes must not fire. Each row is something a real note holds that a
// careless rule would flag: hashes and ids, links, prose about passwords, a
// password manager named in passing.
func TestScanStaysQuietOnBenignText(t *testing.T) {
	// The payload is random base64, so it passes every gate of the generic token
	// rule. Only the data: URI context keeps it out.
	const imagePayload = "zwZWdfRLgxL+Z1bvxbT7WrKL8ozFiA2auK7Z7GtQbU4WWEOCV81K2LSnAwqRzZHb4gzQt8HQT0PMPSlWW0Sao/dgPuXJkBGrbwzrzx1vLXEvz4dncnNobfxl4K41gIlp9Qg3l0Ukw4YwrZsAtlYVh1d0szAOZAnV"
	tests := []struct {
		name string
		text string
	}{
		{"lowercase hex git sha", "commit 9fceb02d0ae598e95dc970b74767f19372d61af8 fixes the sync"},
		{"sha256 digest", "image sha256:3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b"},
		{"uuid", "id 550e8400-e29b-41d4-a716-446655440000"},
		{"base64 image in a data uri", "![logo](data:image/png;base64," + imagePayload + ")"},
		// A random-looking id in a link is not a secret. A Drive id is 44 characters
		// and a tracking id is longer, and both pass every gate of the generic token
		// rule, so only the URL context keeps them out. An id set between slashes
		// never fires, because the words around it dilute the run.
		{"google drive link with an id", "https://drive.google.com/open?id=1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms"},
		{"tracking id in a link", "https://example.com/post?fbclid=IwAR2Zx9QmT4vLkP2aWc8RbN6yHs1JdF3gUe7XoV5iBt0"},
		{"google docs link with the id in the path", "notes at https://docs.google.com/document/d/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms/edit"},
		{"prose about passwords", "Remember to rotate the password after the first login, and never reuse a password across sites."},
		{"api_key named without a value", "reset the api_key in settings"},
		{"plain https url", "see https://example.com/docs/getting-started?ref=nav#install for details"},
		{"url with a port", "health check at http://localhost:8080/health"},
		{"ssh url with a user only", "clone ssh://git@github.com/org/repo.git"},
		{"https url with a user and no password", "mail https://user@example.com/inbox"},
		{"url with a user and an empty password", "ftp://user:@example.com/"},
		{"password manager named in passing", "I switched from LastPass to 1Password last year."},
		{"shell export with no manager", "export PATH=$HOME/bin:$PATH"},
		{"word that starts with a keyword", "secretary: Johnson"},
		{"label that names a manager", "password manager: Bitwarden"},
		{"secret santa", "Secret Santa list for 2026"},
		{"plural label", "Passwords: use a manager for everything"},
		{"value under six characters", "password: abc12"},
		// Both numbers pass the Luhn check. The dot rule only accepts a card shape,
		// so a decimal or a version string with dots does not fire.
		{"decimal constant that passes Luhn", "e is 2.718281828459045"},
		{"go pre-release version that passes Luhn", "require example.com/m 1.1.1-0.20190913142402"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { requireQuiet(t, tc.text) })
	}
}
