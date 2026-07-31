package hostmatch

import (
	"net/netip"
	"strings"
	"testing"
)

// TestWildcardCoversApexAndEveryDepth pins the semantics an operator is
// promised: "*.example.com" is the whole zone, not one level of it.
func TestWildcardCoversApexAndEveryDepth(t *testing.T) {
	set, err := Compile([]string{"*.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{
		"example.com",
		"www.example.com",
		"a.b.example.com",
		"deep.nested.sub.example.com",
		"EXAMPLE.COM",
		"www.example.com.", // trailing dot is the same name
	} {
		if !set.Match(host) {
			t.Errorf("%q should match *.example.com", host)
		}
	}
}

// TestWildcardIsAnchoredAtALabelBoundary is the attack this matcher exists to
// refuse: a suffix comparison without the dot would admit every one of these.
func TestWildcardIsAnchoredAtALabelBoundary(t *testing.T) {
	set, err := Compile([]string{"*.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{
		"fakeexample.com",
		"notexample.com",
		"example.com.evil.test",
		"example.computer",
		"example.co",
		"",
	} {
		if set.Match(host) {
			t.Errorf("%q must not match *.example.com", host)
		}
	}
}

func TestExactPatternDoesNotAdmitSubdomains(t *testing.T) {
	set, err := Compile([]string{"login.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !set.Match("login.example.com") {
		t.Error("the exact host should match")
	}
	for _, host := range []string{"example.com", "evil.login.example.com", "xlogin.example.com"} {
		if set.Match(host) {
			t.Errorf("%q must not match the exact pattern login.example.com", host)
		}
	}
}

// TestInternationalizedNamesMatchInEitherForm covers a client sending Unicode
// against a punycode pattern and the reverse; both normalize to the same name.
func TestInternationalizedNamesMatchInEitherForm(t *testing.T) {
	unicode, err := Compile([]string{"bücher.example"})
	if err != nil {
		t.Fatal(err)
	}
	if !unicode.Match("xn--bcher-kva.example") {
		t.Error("a punycode request should match a Unicode pattern")
	}
	punycode, err := Compile([]string{"xn--bcher-kva.example"})
	if err != nil {
		t.Fatal(err)
	}
	if !punycode.Match("bücher.example") {
		t.Error("a Unicode request should match a punycode pattern")
	}
}

func TestIPLiteralsMatchCanonicallyAndOnlyByIPPatterns(t *testing.T) {
	set, err := Compile([]string{"203.0.113.7", "[2001:db8::1]", "*.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"203.0.113.7", "::ffff:203.0.113.7", "2001:db8::1", "[2001:db8::1]"} {
		if !set.Match(host) {
			t.Errorf("%q should match its IP pattern", host)
		}
	}
	if set.Match("203.0.113.8") {
		t.Error("a different address must not match")
	}
	// A wildcard names a DNS suffix; it can never describe an address.
	if set.Match("198.51.100.1") {
		t.Error("*.example.com must not admit an IP literal")
	}
}

func TestCompileRejectsPatternsThatWouldMislead(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		want    error
	}{
		{"", ErrEmptyPattern},
		{"*", ErrMatchEverything},
		{"*.*.example.com", ErrBadWildcard},
		{"exa*ple.com", ErrBadWildcard},
		{"sub.*.example.com", ErrBadWildcard},
		{"https://example.com", ErrNotAHostname},
		{"example.com/path", ErrNotAHostname},
		{"user@example.com", ErrNotAHostname},
		{"example.com:443", ErrNotAHostname},
		{"exa mple.com", ErrNotAHostname},
	} {
		_, err := Compile([]string{tc.pattern})
		if err == nil {
			t.Errorf("%q should be rejected", tc.pattern)
			continue
		}
		if !strings.Contains(err.Error(), tc.want.Error()) {
			t.Errorf("%q rejected as %v, want %v", tc.pattern, err, tc.want)
		}
	}
}

// TestCompileReportsEveryBadPatternAtOnce mirrors the policy package's
// collect-all-problems behaviour.
func TestCompileReportsEveryBadPatternAtOnce(t *testing.T) {
	_, err := Compile([]string{"good.example.com", "*", "bad/pattern"})
	if err == nil {
		t.Fatal("expected a rejection")
	}
	if !strings.Contains(err.Error(), `"*"`) || !strings.Contains(err.Error(), "bad/pattern") {
		t.Errorf("both bad patterns should be named: %v", err)
	}
}

func TestZeroSetMatchesNothing(t *testing.T) {
	var set *Set
	if set.Match("example.com") {
		t.Error("a nil set must admit nothing")
	}
	if set.Len() != 0 || set.Patterns() != nil {
		t.Error("a nil set reports no patterns")
	}
}

func TestEmptyAllowlistMatchesNothing(t *testing.T) {
	set, err := Compile(nil)
	if err != nil {
		t.Fatal(err)
	}
	if set.Match("example.com") {
		t.Error("an empty allowlist must admit nothing")
	}
}

func TestForbiddenAddrCoversTheSpecialRanges(t *testing.T) {
	for _, tc := range []struct {
		addr      string
		forbidden bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"::ffff:127.0.0.1", true}, // the unmap case
		{"10.0.0.1", true},
		{"::ffff:10.0.0.1", true},
		{"192.168.1.1", true},
		{"172.16.0.1", true},
		{"169.254.169.254", true}, // cloud metadata
		{"fe80::1", true},
		{"fc00::1", true},
		{"100.64.0.1", true},
		{"224.0.0.1", true},
		{"255.255.255.255", true},
		{"0.0.0.0", true},
		{"::", true},
		{"93.184.216.34", false},
		{"2606:2800:220:1:248:1893:25c8:1946", false},
	} {
		addr := netip.MustParseAddr(tc.addr)
		reason, forbidden := ForbiddenAddr(addr, false)
		if forbidden != tc.forbidden {
			t.Errorf("ForbiddenAddr(%s) = %v (%q), want %v", tc.addr, forbidden, reason, tc.forbidden)
		}
		if forbidden && reason == "" {
			t.Errorf("ForbiddenAddr(%s) refused without saying why", tc.addr)
		}
	}
}

// TestAllowPrivateNetworksKeepsTheSpecialAddressesForbidden checks that opting
// into intranet targets does not also open loopback and link-local.
func TestAllowPrivateNetworksKeepsTheSpecialAddressesForbidden(t *testing.T) {
	if _, forbidden := ForbiddenAddr(netip.MustParseAddr("10.0.0.1"), true); forbidden {
		t.Error("allow_private_networks should permit RFC1918")
	}
	for _, addr := range []string{"127.0.0.1", "169.254.169.254", "::1", "224.0.0.1"} {
		if _, forbidden := ForbiddenAddr(netip.MustParseAddr(addr), true); !forbidden {
			t.Errorf("%s must stay forbidden even with allow_private_networks", addr)
		}
	}
}

func TestPatternsAreReportedForRefusalMessages(t *testing.T) {
	set, err := Compile([]string{"*.zebra.example", "alpha.example"})
	if err != nil {
		t.Fatal(err)
	}
	got := set.Patterns()
	if len(got) != 2 || got[0] != "*.zebra.example" || got[1] != "alpha.example" {
		t.Errorf("patterns should come back sorted, got %v", got)
	}
	if set.Len() != 2 {
		t.Errorf("Len() = %d, want 2", set.Len())
	}
}
