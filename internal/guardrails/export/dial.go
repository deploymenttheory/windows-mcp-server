package export

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/hostmatch"
)

// dialTimeout bounds one connection attempt. The overall upload is bounded by the
// caller's context; this is only so a black-holed address does not consume the
// whole budget on its own.
const dialTimeout = 10 * time.Second

// newHTTPClient builds the one client every backend in this package uses.
//
// Proxy is nil deliberately, the same choice the egress proxy makes for its own
// transport (internal/guardrails/egress/proxy.go): honouring HTTP_PROXY here
// would send the bundle — and, for a signed URL, its credential — to whatever a
// per-user environment variable named, past the address vetting below. The
// device's own egress proxy is not usable from this path either: it is stopped by
// its own defer before the audit-close defer that seals and ships.
func newHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           dialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          4,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

// dialContext resolves, vets and dials in one step, so the address that is
// checked is the address that is connected to.
//
// This is the same shape as pkg/windows/scrape.go's scrapeDialContext and uses
// the same predicate, hostmatch.ForbiddenAddr — the one the egress proxy uses.
// The reason it is needed here is that an export destination is operator-supplied
// text, and for a signed URL it arrives entirely from the environment. A name
// answering with a loopback, RFC1918 or link-local address would mean the bundle
// (and the signature in the URL) goes somewhere on or beside this machine, which
// is not an export at all — and 169.254.169.254 is the cloud metadata endpoint
// this package's no-ambient-credentials rule exists to keep out of reach.
//
// Because the dial goes to the vetted netip.Addr rather than back to the name,
// there is no second resolution to disagree with the first. It runs on every
// connection the client opens, so a redirect hop is covered by construction.
func dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("cannot parse destination %q: %w", addr, err)
	}

	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve export destination: %w", err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%w: %q resolves to no addresses", ErrForbiddenAddr, host)
	}

	// Every answer must be acceptable, not merely one of them. Dialling the first
	// public address in a set that also contains a private one would let a name
	// answering with both reach the private one on a retry.
	for _, a := range addrs {
		if reason, forbidden := hostmatch.ForbiddenAddr(a, false); forbidden {
			return nil, fmt.Errorf("%w: %q resolves to %s (%s)", ErrForbiddenAddr, host, a, reason)
		}
	}

	dialer := &net.Dialer{Timeout: dialTimeout}
	var lastErr error
	for _, a := range addrs {
		conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(a.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}
	return nil, fmt.Errorf("dial export destination: %w", lastErr)
}

// vetHost refuses a destination whose host is an address literal this server will
// not dial. A name cannot be settled here — whatever it resolves to now, it is the
// resolution at dial time that decides where the bytes go, which is what
// dialContext is for — but a literal can, and refusing it at construction gives
// the operator the reason while they are still watching.
func vetHost(host string) error {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return nil
	}
	if reason, forbidden := hostmatch.ForbiddenAddr(addr, false); forbidden {
		return fmt.Errorf("%w: %s is %s", ErrForbiddenAddr, host, reason)
	}
	return nil
}
