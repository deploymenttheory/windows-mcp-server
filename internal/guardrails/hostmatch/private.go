package hostmatch

import "net/netip"

// cgnat is RFC 6598 carrier-grade NAT space. netip has no predicate for it, and
// it is routable-looking address space an operator does not mean to expose.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

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
	}
	return "", false
}
