//go:build windows && (amd64 || arm64)

package desktop

import (
	"strings"
	"testing"
)

// TestEscapeWQLLike is a regression test for a one-call denial of service.
// ProcessKill builds "Name LIKE '%<input>%'" and only quotes were escaped, so the
// LIKE metacharacters stayed live: name "_" matched every process with at least
// one character in its name -- Explorer, the EDR agent, this server itself.
func TestEscapeWQLLike(t *testing.T) {
	cases := []struct{ in, want string }{
		{"notepad", "notepad"},
		{"_", `\_`},          // matched any single character
		{"%", `\%`},          // matched anything at all
		{"[a-z]", `\[a-z\]`}, // character class
		{`a\b`, `a\\b`},      // the escape character itself
		{"it's", `it\'s`},    // quote, escaped the WQL way not by doubling
		{"^", `\^`},          // class negation
		{"", ""},
	}
	for _, tc := range cases {
		if got := escapeWQLLike(tc.in); got != tc.want {
			t.Errorf("escapeWQLLike(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestEscapeWQLLikeNeutralisesWildcardKill states the property in the terms that
// matter: after escaping, every surviving metacharacter is preceded by the escape
// character, so a wildcard-only input can no longer match everything.
func TestEscapeWQLLikeNeutralisesWildcardKill(t *testing.T) {
	const meta = "%_[]"
	const escapeChar = byte(92) // backslash
	for _, in := range []string{"_", "%", "%_%", "[a-z]", "____"} {
		escaped := escapeWQLLike(in)
		for i := 0; i < len(escaped); i++ {
			if !strings.ContainsRune(meta, rune(escaped[i])) {
				continue
			}
			if i == 0 || escaped[i-1] != escapeChar {
				t.Errorf("escapeWQLLike(%q) = %q leaves an unescaped %q", in, escaped, escaped[i])
			}
		}
	}
}
