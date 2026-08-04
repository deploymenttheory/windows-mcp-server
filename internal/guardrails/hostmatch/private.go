package hostmatch

import "net/netip"

// cgnat is RFC 6598 carrier-grade NAT space. netip has no predicate for it, and
// it is routable-looking address space an operator does not mean to expose.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// IPv6 transition prefixes that embed an IPv4 destination. See embeddedIPv4.
var (
	nat64          = netip.MustParsePrefix("64:ff9b::/96")
	sixToFour      = netip.MustParsePrefix("2002::/16")
	ipv4Compatible = netip.MustParsePrefix("::/96")
)

// specialIPv4 are IANA special-purpose blocks that are not public destinations:
// "this host on this network" (which includes 0.0.0.0/8 beyond the unspecified
// address itself), IETF protocol assignments, benchmarking, and reserved space.
var specialIPv4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// ForbiddenAddr reports whether an address is one the proxy must never dial,
// and why.
//
// This is the check that makes an allowlist meaningful. Without it, an allowed
// name whose DNS answer points at 127.0.0.1, 169.254.169.254 or an internal
// 10.x host turns the proxy into a way to reach the very things it exists to
// keep the workload away from. It runs on the *resolved* addresses, after the
// name has been allowed, which is what closes the DNS-rebinding path.
//
// The reason is returned for the refusal message: "that name resolves to a
// loopback address" is something an operator can act on, where a bare denial is
// not.
func ForbiddenAddr(addr netip.Addr, allowPrivate bool) (reason string, forbidden bool) {
	// An IPv4-mapped IPv6 address is the same host as its IPv4 form, so unmap
	// before testing or ::ffff:10.0.0.1 slips past every predicate below.
	addr = addr.Unmap()

	// Three more ways to write an IPv4 destination as IPv6, none of which netip's
	// predicates see through. Each reaches the embedded address on a host with the
	// matching transition mechanism configured, so 64:ff9b::a00:1 is 10.0.0.1 and
	// ::7f00:1 is 127.0.0.1 -- addresses every check below is written to refuse.
	if embedded, ok := embeddedIPv4(addr); ok {
		if reason, forbidden := ForbiddenAddr(embedded, allowPrivate); forbidden {
			return reason + " reached through an IPv6 transition address", true
		}
	}

	switch {
	case !addr.IsValid():
		return "not a valid address", true
	case addr.IsUnspecified():
		return "the unspecified address", true
	case addr.IsLoopback():
		return "a loopback address", true
	case addr.IsLinkLocalUnicast(), addr.IsLinkLocalMulticast():
		// Covers 169.254.0.0/16, and with it the 169.254.169.254 cloud metadata
		// endpoint, and fe80::/10.
		return "a link-local address", true
	case addr.IsMulticast():
		return "a multicast address", true
	case addr.IsInterfaceLocalMulticast():
		return "an interface-local multicast address", true
	case addr.Is4() && addr.As4() == [4]byte{255, 255, 255, 255}:
		return "the broadcast address", true
	}

	// The remaining classes are private rather than special, so an operator who
	// deliberately proxies to an intranet host can permit them.
	if allowPrivate {
		return "", false
	}
	switch {
	case addr.IsPrivate():
		// RFC 1918 for IPv4, and fc00::/7 unique-local for IPv6.
		return "a private address", true
	case addr.Is4() && cgnat.Contains(addr):
		return "a carrier-grade NAT address", true
	case addr.Is4() && ianaSpecial(addr):
		return "an IANA special-purpose address", true
	}
	return "", false
}

// embeddedIPv4 extracts the IPv4 address carried inside an IPv6 transition
// address, if there is one.
//
// netip.Addr.Unmap only handles ::ffff:0:0/96. These three carry an IPv4
// destination too, and are reachable wherever the corresponding mechanism is
// configured:
//
//	64:ff9b::/96   NAT64 (RFC 6052) — the standard prefix a NAT64 gateway
//	               translates, so 64:ff9b::a00:1 reaches 10.0.0.1
//	2002::/16      6to4 (RFC 3056) — the address is in bytes 2..5
//	::/96          IPv4-compatible (deprecated) — ::7f00:1 is 127.0.0.1, and
//	               netip treats only ::1 as loopback
func embeddedIPv4(addr netip.Addr) (netip.Addr, bool) {
	if !addr.Is6() || addr.Is4In6() {
		return netip.Addr{}, false
	}
	b := addr.As16()
	switch {
	case nat64.Contains(addr):
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case sixToFour.Contains(addr):
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	case ipv4Compatible.Contains(addr) && addr != netip.IPv6Unspecified():
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	}
	return netip.Addr{}, false
}

// ianaSpecial covers the IPv4 blocks that are not routable public destinations
// and were not caught by any predicate above.
func ianaSpecial(addr netip.Addr) bool {
	for _, p := range specialIPv4 {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
