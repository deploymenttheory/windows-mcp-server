package hostmatch

import (
	"net/netip"
	"testing"
)

// FuzzCompileAndMatch drives the two functions on the security boundary with
// attacker-influenced input: Compile parses operator text, Match runs against a
// hostname the far side may choose. The property under test is robustness — no
// panic, no hang — because a crash on a crafted allowlist entry or a crafted host
// is itself a denial of service on the thing the allowlist protects.
func FuzzCompileAndMatch(f *testing.F) {
	seeds := []struct{ pattern, host string }{
		{"example.com", "example.com"},
		{"example.com", "www.example.com"},
		{"*.example.com", "example.com"},
		{"*.example.com", "a.b.example.com"},
		{"*.example.com", "fakeexample.com"},
		{"*", "anything"},
		{"", ""},
		{"192.168.1.1", "192.168.1.1"},
		{"[2001:db8::1]", "2001:db8::1"},
		{"München.de", "xn--mnchen-3ya.de"},
		{"EXAMPLE.com.", "example.com"},
		{"host:8080", "host"},
		{"a/b", "a"},
		{"user@host", "host"},
	}
	for _, s := range seeds {
		f.Add(s.pattern, s.host)
	}

	f.Fuzz(func(t *testing.T, pattern, host string) {
		set, err := Compile([]string{pattern})
		if err != nil {
			// A rejected pattern is a valid outcome; the point is that it did not
			// panic. Nothing compiled to match against.
			return
		}
		// Must not panic on any host, and must return without hanging.
		got := set.Match(host)

		// Determinism: the same host decides the same way twice.
		if set.Match(host) != got {
			t.Fatalf("Match(%q) is not deterministic for pattern %q", host, pattern)
		}

		// The zero Set admits nothing, whatever the host — the safe direction a
		// failed compile must degrade to.
		if (&Set{}).Match(host) {
			t.Fatalf("the zero Set must match nothing, matched %q", host)
		}
	})
}

// FuzzForbiddenAddr fuzzes the post-resolution SSRF check: it classifies a
// resolved address, and must never panic on any address shape.
func FuzzForbiddenAddr(f *testing.F) {
	for _, s := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "8.8.8.8", "::1", "fe80::1", ""} {
		f.Add(s, false)
		f.Add(s, true)
	}
	f.Fuzz(func(t *testing.T, addr string, allowPrivate bool) {
		a, err := netip.ParseAddr(addr)
		if err != nil {
			return
		}
		// No panic, and a forbidden address always carries a reason. Note the
		// classes that survive allow_private_networks are the special ones --
		// loopback, link-local, multicast, unspecified -- not CGNAT, which sits
		// below the early return with RFC1918 because an operator allowing private
		// networks may legitimately be on carrier-grade NAT space.
		reason, forbidden := ForbiddenAddr(a, allowPrivate)
		if forbidden && reason == "" {
			t.Fatalf("ForbiddenAddr(%q) forbade with no reason", addr)
		}
	})
}
