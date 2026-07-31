// Package egress is the device egress proxy: a loopback forward proxy that
// admits only the domains an operator declared, and the OS actuation that stops
// the named workloads going around it.
//
// The decision is deliberately small and lives entirely here. A CONNECT request
// carries its target in cleartext and a plain-HTTP proxy request carries it in
// the request-target, so the allowlist is enforced on the name the client asked
// for, with no interception, no certificate authority and no decryption.
//
// Two orderings in this package are load-bearing, and both are the opposite of
// what a naive implementation does:
//
//   - The allowlist is checked BEFORE the name is resolved. A refused host must
//     not generate a DNS query, or the refusal itself becomes the covert channel.
//   - The forbidden-address check runs on the RESOLVED addresses, after the name
//     was allowed, and the dial goes to the vetted address rather than the name.
//     That is what stops an allowed name whose answer points at loopback, an
//     intranet host, or the cloud metadata endpoint.
//
// The OS side sits behind Enforcer so the whole package is testable with fakes
// on any platform.
package egress

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/hostmatch"
)

// Errors returned when a Config could not produce a usable proxy.
var (
	ErrEmptyAllowlist = errors.New("egress proxy: the allowlist is empty")
	ErrNotLoopback    = errors.New("egress proxy: the listen address is not loopback")
	ErrBadListenAddr  = errors.New("egress proxy: the listen address is not host:port")
)

// Config is everything the service needs, resolved from the policy document.
type Config struct {
	Listen       string
	Allow        *hostmatch.Set
	AllowPorts   []int
	AllowPrivate bool
	// AuthToken, when set, must be presented as Proxy-Authorization by every
	// client. It arrives from the environment, never from the policy document.
	AuthToken string
	// Enforcement names the tier in force ("proxy-only", "scoped", "global"),
	// for the status snapshot and the audit record.
	Enforcement string
	Logger      *slog.Logger

	// Resolve and Dial are injectable so the request path is testable without a
	// network. Nil means the real resolver and dialer.
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	Dial    func(ctx context.Context, addr string) (net.Conn, error)
}

// Service owns the listener and the counters for one session.
type Service struct {
	cfg    Config
	proxy  *proxy
	srv    *http.Server
	addr   string
	stop   sync.Once
	closed chan struct{}
}

// Start binds the proxy and serves until Stop. The listener is loopback-only,
// re-checked here rather than trusted from validation, so no future caller can
// route around it.
func Start(ctx context.Context, cfg Config) (*Service, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if err := requireLoopback(cfg.Listen); err != nil {
		return nil, err
	}
	if cfg.Allow == nil || cfg.Allow.Len() == 0 {
		// Starting with an allowlist that admits nothing would present a proxy
		// that refuses every request, which reads as a broken network rather
		// than a policy. Validation rejects this; this is the belt.
		return nil, ErrEmptyAllowlist
	}

	svc := &Service{cfg: cfg, closed: make(chan struct{})}
	svc.proxy = newProxy(cfg)

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("egress proxy listen %s: %w", cfg.Listen, err)
	}
	svc.addr = ln.Addr().String()
	// ReadHeaderTimeout bounds a client that opens a connection and never
	// finishes a request. There is deliberately no write or idle timeout: a
	// CONNECT tunnel is long-lived by nature and the dial timeout bounds setup.
	svc.srv = &http.Server{Handler: svc.proxy, ReadHeaderTimeout: 10 * time.Second}

	go func() {
		if err := svc.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			cfg.Logger.Warn("egress proxy stopped", "error", err)
		}
		close(svc.closed)
	}()
	cfg.Logger.Info("egress proxy listening",
		"addr", svc.addr, "patterns", cfg.Allow.Len(), "enforcement", cfg.Enforcement)
	return svc, nil
}

// Addr is the bound address, which may differ from the configured one when the
// policy asked for port 0.
func (s *Service) Addr() string { return s.addr }

// Stop closes the listener. It is safe to call more than once, because the
// normal-exit defer and the kill path both reach it.
func (s *Service) Stop() {
	s.stop.Do(func() {
		if s.srv != nil {
			_ = s.srv.Close()
			<-s.closed
		}
		s.cfg.Logger.Info("egress proxy stopped", "counters", s.Counters())
	})
}

// Counters reports the running totals for the status snapshot and the periodic
// audit summary.
func (s *Service) Counters() Counters { return s.proxy.counters.snapshot() }

// DeniedHosts returns the distinct hosts refused this session, bounded, for the
// audit summary.
func (s *Service) DeniedHosts() []string { return s.proxy.counters.deniedHosts() }

// requireLoopback refuses any address the network could reach.
//
// The check lives here, next to the bind, rather than only in policy
// validation, so that no future caller can construct a Config by hand and get a
// proxy the rest of the network can use. This server's transport is stdio for
// the same reason.
func requireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%w: %q", ErrBadListenAddr, addr)
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return fmt.Errorf("%w: %q is not an IP address or localhost", ErrBadListenAddr, host)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("%w: refusing to bind %q", ErrNotLoopback, addr)
	}
	return nil
}
