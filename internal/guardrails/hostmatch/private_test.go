package hostmatch

import (
	"net/netip"
	"testing"
)

// TestIPv6TransitionAddressesAreForbidden closes three ways of writing an IPv4
// destination as IPv6 that netip's predicates do not see through.
//
// Unmap only handles ::ffff:0:0/96, so 64:ff9b::a00:1 (NAT64 to 10.0.0.1),
// 2002:0a00:0001:: (6to4 to 10.0.0.1) and ::7f00:1 (IPv4-compatible loopback)
// all passed every check -- and each reaches the embedded address on a host with
// the matching transition mechanism configured.
func TestIPv6TransitionAddressesAreForbidden(t *testing.T) {
	forbidden := []string{
		"64:ff9b::a00:1",     // NAT64 -> 10.0.0.1
		"64:ff9b::7f00:1",    // NAT64 -> 127.0.0.1
		"64:ff9b::a9fe:a9fe", // NAT64 -> 169.254.169.254, the metadata endpoint
		"2002:a00:1::",       // 6to4 -> 10.0.0.1
		"::7f00:1",           // IPv4-compatible -> 127.0.0.1
	}
	for _, s := range forbidden {
		addr := netip.MustParseAddr(s)
		if reason, bad := ForbiddenAddr(addr, false); !bad {
			t.Errorf("%s reaches a forbidden IPv4 destination but was allowed (reason %q)", s, reason)
		}
	}

	// A public IPv6 address must still be allowed, including one that merely looks
	// similar to a transition prefix.
	for _, s := range []string{"2001:4860:4860::8888", "2606:4700:4700::1111"} {
		if reason, bad := ForbiddenAddr(netip.MustParseAddr(s), false); bad {
			t.Errorf("%s is a public address but was refused as %q", s, reason)
		}
	}
}

// TestIANASpecialIPv4BlocksAreForbidden covers the non-routable IPv4 space that
// no predicate caught: 0.0.0.0/8 beyond the unspecified address, IETF protocol
// assignments, benchmarking space, and reserved space.
func TestIANASpecialIPv4BlocksAreForbidden(t *testing.T) {
	for _, s := range []string{"0.1.2.3", "192.0.0.1", "198.18.0.1", "240.0.0.1"} {
		if reason, bad := ForbiddenAddr(netip.MustParseAddr(s), false); !bad {
			t.Errorf("%s is not a public destination but was allowed (reason %q)", s, reason)
		}
	}
}
