package egress

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/hostmatch"
)

// Timeouts for the outbound leg. The tunnel itself is deliberately unbounded —
// a TLS session through a CONNECT proxy is long-lived by design.
const (
	resolveTimeout  = 5 * time.Second
	dialTimeout     = 10 * time.Second
	responseTimeout = 30 * time.Second
)

// hopByHopHeaders are stripped in both directions. They describe the connection
// the client has with the proxy, not the request, so forwarding them would
// corrupt the upstream connection. The list is RFC 9110 section 7.6.1 plus
// Proxy-Connection, which is not in any RFC but is still sent in the wild.
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// ErrBadTarget is returned when a request names something that is not a
// resolvable destination at all, before any policy question is reached.
var ErrBadTarget = errors.New("not a valid proxy target")

// target is a vetted destination: the name the client asked for and the address
// the proxy will actually dial.
type target struct {
	host string
	port int
	addr netip.Addr
}

func (t target) dialAddr() string { return net.JoinHostPort(t.addr.String(), strconv.Itoa(t.port)) }

// refusal is a decision to say no, carrying the message the client sees. The
// text is written for whoever reads it — an operator or the model driving the
// session — so it names the host, the reason and the fix.
type refusal struct {
	status  int
	message string
	host    string
}

type proxy struct {
	cfg       Config
	counters  *counters
	logger    *slog.Logger
	transport *http.Transport
}

func newProxy(cfg Config) *proxy {
	p := &proxy{cfg: cfg, counters: newCounters(), logger: cfg.Logger}
	// The transport never consults the environment or a proxy of its own, and
	// its DialContext ignores the address net/http computed from the URL: the
	// vetted address decided in checkTarget is the only one dialled.
	p.transport = &http.Transport{
		Proxy:                 nil,
		ResponseHeaderTimeout: responseTimeout,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConnsPerHost:   4,
	}
	return p
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !p.authorized(r) {
		p.counters.deniedAuth.Add(1)
		// Bearer, because that is the scheme this proxy actually accepts and the one
		// docs/egress.md tells clients to send. It advertised Basic while comparing
		// the raw token, so a client that followed the challenge and encoded its
		// credential per RFC 7617 could never authenticate. Basic is still accepted
		// (see authorized) for a client configured to send it regardless.
		w.Header().Set("Proxy-Authenticate", `Bearer realm="windows-mcp-egress"`)
		http.Error(w, "egress policy: this proxy requires a Proxy-Authorization credential.",
			http.StatusProxyAuthRequired)
		return
	}
	if r.Method == http.MethodConnect {
		p.serveConnect(w, r)
		return
	}
	p.serveHTTP(w, r)
}

// authorized compares in constant time so a wrong token cannot be discovered by
// timing. An empty configured token means no authentication is required.
//
// Three accepted forms. "Bearer <token>" is what the challenge advertises and
// what the documentation shows. "Basic <base64>" is decoded per RFC 7617 and
// either half of userid:password may carry the token, because a client told only
// "the proxy needs a credential" will often put it in one or the other. A bare
// value with no scheme is accepted too: it worked before this function knew about
// Basic, and breaking it would be a gratuitous change to a running deployment.
func (p *proxy) authorized(r *http.Request) bool {
	if p.cfg.AuthToken == "" {
		return true
	}
	got := strings.TrimSpace(r.Header.Get("Proxy-Authorization"))

	if rest, ok := cutSchemePrefix(got, "Basic "); ok {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rest))
		if err != nil {
			return false
		}
		userid, password, found := strings.Cut(string(decoded), ":")
		if !found {
			return p.tokenEquals(string(decoded))
		}
		// Both halves are compared, and neither short-circuits the other, so the
		// answer takes the same work either way.
		return p.tokenEquals(userid) || p.tokenEquals(password)
	}
	if rest, ok := cutSchemePrefix(got, "Bearer "); ok {
		return p.tokenEquals(strings.TrimSpace(rest))
	}
	return p.tokenEquals(got)
}

func (p *proxy) tokenEquals(candidate string) bool {
	return subtle.ConstantTimeCompare([]byte(candidate), []byte(p.cfg.AuthToken)) == 1
}

// cutSchemePrefix strips an auth-scheme prefix case-insensitively, since RFC 9110
// makes the scheme token case-insensitive and clients vary.
func cutSchemePrefix(header, scheme string) (rest string, ok bool) {
	if len(header) < len(scheme) {
		return "", false
	}
	if !strings.EqualFold(header[:len(scheme)], scheme) {
		return "", false
	}
	return header[len(scheme):], true
}

// serveConnect tunnels a CONNECT once the authority has been vetted.
func (p *proxy) serveConnect(w http.ResponseWriter, r *http.Request) {
	host, port, err := splitTarget(r.Host, 443)
	if err != nil {
		p.refuse(w, refusal{
			status:  http.StatusBadRequest,
			message: fmt.Sprintf("egress policy: %q is not a valid CONNECT target.", r.Host),
		})
		p.counters.failed.Add(1)
		return
	}
	tgt, ref := p.checkTarget(r.Context(), host, port)
	if ref != nil {
		p.refuse(w, *ref)
		return
	}

	upstream, err := p.dial(r.Context(), tgt)
	if err != nil {
		p.counters.failed.Add(1)
		p.logger.Warn("egress proxy could not reach an allowed host",
			"host", tgt.host, "addr", tgt.dialAddr(), "error", err)
		http.Error(w, fmt.Sprintf("egress policy: %q is allowed but could not be reached: %v", tgt.host, err),
			http.StatusBadGateway)
		return
	}
	defer func() { _ = upstream.Close() }()

	client, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		p.counters.failed.Add(1)
		http.Error(w, "egress policy: this connection cannot be tunnelled.", http.StatusInternalServerError)
		return
	}
	defer func() { _ = client.Close() }()

	// Whatever the client pipelined after the CONNECT line is already in the
	// hijacked reader, not on the socket. A client that writes its TLS ClientHello
	// in the same segment as the request — most of them, under load — lost it
	// here, and the tunnel then hung waiting for a handshake that had already been
	// read. Hand it upstream before wiring the two ends together.
	if brw != nil && brw.Reader.Buffered() > 0 {
		if _, err := io.CopyN(upstream, brw, int64(brw.Reader.Buffered())); err != nil {
			p.counters.failed.Add(1)
			return
		}
	}

	// Counted at the decision rather than after the tunnel closes: the question
	// the counter answers is how many connections policy admitted, and a
	// long-lived tunnel would otherwise go unreported for its whole life.
	p.counters.allowed.Add(1)
	p.logger.Debug("egress allow", "method", "CONNECT", "host", tgt.host, "addr", tgt.dialAddr())

	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		p.counters.failed.Add(1)
		return
	}
	tunnel(client, upstream)
}

// tunnel copies in both directions until either side finishes, propagating the
// half-close so a peer that has finished sending is not left waiting.
func tunnel(client, upstream net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, client)
		closeWrite(upstream)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, upstream)
		closeWrite(client)
		done <- struct{}{}
	}()
	<-done
	<-done
}

func closeWrite(c net.Conn) {
	type writeCloser interface{ CloseWrite() error }
	if wc, ok := c.(writeCloser); ok {
		_ = wc.CloseWrite()
		return
	}
	_ = c.Close()
}

// serveHTTP forwards a plain-HTTP proxy request, which arrives in absolute
// form: "GET http://host/path HTTP/1.1".
func (p *proxy) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if !r.URL.IsAbs() {
		p.counters.failed.Add(1)
		p.refuse(w, refusal{
			status:  http.StatusBadRequest,
			message: "egress policy: this is a forward proxy. Send an absolute URI, or CONNECT for TLS.",
		})
		return
	}
	// There is no Host-header-versus-request-target check here because there is
	// no ambiguity left to check: net/http resolves an absolute-form request by
	// taking the authority from the request-target, and this handler vets that
	// same value and forwards it. The host policy decided on is the host the
	// upstream is asked for, which is the property a smuggling check would be
	// protecting.
	defaultPort := 80
	if strings.EqualFold(r.URL.Scheme, "https") {
		defaultPort = 443
	}
	host, port, err := splitTarget(r.URL.Host, defaultPort)
	if err != nil {
		p.counters.failed.Add(1)
		p.refuse(w, refusal{
			status:  http.StatusBadRequest,
			message: fmt.Sprintf("egress policy: %q is not a valid target.", r.URL.Host),
		})
		return
	}
	tgt, ref := p.checkTarget(r.Context(), host, port)
	if ref != nil {
		p.refuse(w, *ref)
		return
	}

	outbound := r.Clone(r.Context())
	outbound.RequestURI = ""
	stripHopByHop(outbound.Header)
	outbound.Header.Set("Via", "1.1 windows-mcp-egress")

	// Pin this request to the vetted address: the transport dials what we
	// resolved and approved, never a fresh lookup of the name.
	transport := p.transport.Clone()
	transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return p.dial(ctx, tgt)
	}

	// The clone carries its own connection pool, and a dropped Transport keeps its
	// idle sockets and read-loop goroutine alive for IdleConnTimeout (90s) —
	// nothing finalizes one. At N requests a second that is ~90N sockets held for
	// no reason.
	defer transport.CloseIdleConnections()

	resp, err := transport.RoundTrip(outbound)
	if err != nil {
		p.counters.failed.Add(1)
		p.logger.Warn("egress proxy could not reach an allowed host",
			"host", tgt.host, "addr", tgt.dialAddr(), "error", err)
		http.Error(w, fmt.Sprintf("egress policy: %q is allowed but could not be reached: %v", tgt.host, err),
			http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	stripHopByHop(resp.Header)
	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)

	p.counters.allowed.Add(1)
	p.logger.Debug("egress allow", "method", r.Method, "host", tgt.host, "addr", tgt.dialAddr())
}

// checkTarget is the whole decision, in the order that makes it meaningful.
//
// The allowlist is consulted before anything leaves the machine, so a refused
// host produces no DNS query — the refusal must not itself be an outbound
// signal. Only then is the name resolved, and every answer is re-checked
// against the forbidden ranges before one is chosen to dial, because an allowed
// name that resolves to loopback or an intranet address is exactly the bypass
// this proxy exists to prevent.
// defaultAllowPorts mirrors policy.DefaultEgressPorts. It is duplicated rather
// than imported because egress must not depend on policy — the proxy's request
// path is deliberately pure Go with no document schema behind it.
var defaultAllowPorts = []int{443, 80}

func (p *proxy) checkTarget(ctx context.Context, host string, port int) (target, *refusal) {
	// An empty AllowPorts is treated as the default set, never as "any port".
	// policy.Parse defaults it for a document, but egress.Start has an explicit
	// belt for an empty allowlist and had none for empty ports — so a Config built
	// in code, which is exactly the case that belt exists for, produced a generic
	// TCP relay to any port on an allowed host: 445 for SMB and NTLM coercion, 22,
	// 3389.
	allowed := p.cfg.AllowPorts
	if len(allowed) == 0 {
		allowed = defaultAllowPorts
	}
	if !slices.Contains(allowed, port) {
		p.counters.deniedPort.Add(1)
		p.logger.Info("egress deny", "reason", "port", "host", host, "port", port)
		return target{}, &refusal{status: http.StatusForbidden, host: host, message: fmt.Sprintf(
			"egress policy: port %d is not allowed. Allowed ports: %s. "+
				"Add it to egress.allow_ports in the policy document to permit it.",
			port, joinInts(allowed))}
	}

	// An IP literal never gets a name lookup, and is judged on the address the
	// client asked for.
	if addr, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		if !p.cfg.Allow.Match(host) {
			return target{}, p.denyHost(host)
		}
		if reason, forbidden := hostmatch.ForbiddenAddr(addr, p.cfg.AllowPrivate); forbidden {
			return target{}, p.denyAddress(host, addr, reason)
		}
		return target{host: host, port: port, addr: addr.Unmap()}, nil
	}

	if !p.cfg.Allow.Match(host) {
		return target{}, p.denyHost(host)
	}

	addrs, err := p.resolve(ctx, host)
	if err != nil {
		p.counters.failed.Add(1)
		p.logger.Warn("egress proxy could not resolve an allowed host", "host", host, "error", err)
		return target{}, &refusal{status: http.StatusBadGateway, host: host, message: fmt.Sprintf(
			"egress policy: %q is allowed but could not be resolved: %v", host, err)}
	}

	var lastReason string
	for _, addr := range addrs {
		reason, forbidden := hostmatch.ForbiddenAddr(addr, p.cfg.AllowPrivate)
		if forbidden {
			lastReason = reason
			continue
		}
		return target{host: host, port: port, addr: addr.Unmap()}, nil
	}
	if lastReason == "" {
		lastReason = "no usable address"
	}
	return target{}, p.denyAddress(host, netip.Addr{}, lastReason)
}

func (p *proxy) denyHost(host string) *refusal {
	p.counters.deniedHost.Add(1)
	p.counters.noteDenied(host)
	p.logger.Info("egress deny", "reason", "host", "host", host)
	return &refusal{status: http.StatusForbidden, host: host, message: fmt.Sprintf(
		"egress policy: %q is not an allowed destination. Allowed patterns: %s. "+
			"Add it to egress.allow in the policy document to permit it.",
		host, strings.Join(p.cfg.Allow.Patterns(), ", "))}
}

func (p *proxy) denyAddress(host string, addr netip.Addr, reason string) *refusal {
	p.counters.deniedAddress.Add(1)
	p.counters.noteDenied(host)
	p.logger.Info("egress deny", "reason", "address", "host", host, "addr", addr.String(), "why", reason)
	return &refusal{status: http.StatusForbidden, host: host, message: fmt.Sprintf(
		"egress policy: %q is an allowed name but resolves to %s, which this proxy will not dial. "+
			"Set egress.allow_private_networks if reaching it is intended.",
		host, reason)}
}

func (p *proxy) refuse(w http.ResponseWriter, ref refusal) {
	http.Error(w, ref.message, ref.status)
}

func (p *proxy) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	if p.cfg.Resolve != nil {
		return p.cfg.Resolve(ctx, host)
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	return addrs, nil
}

func (p *proxy) dial(ctx context.Context, tgt target) (net.Conn, error) {
	if p.cfg.Dial != nil {
		return p.cfg.Dial(ctx, tgt.dialAddr())
	}
	dialer := &net.Dialer{Timeout: dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", tgt.dialAddr())
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", tgt.dialAddr(), err)
	}
	return conn, nil
}

// splitTarget accepts "host", "host:port" and "[v6]:port", supplying the
// scheme's default when no port is written.
func splitTarget(authority string, defaultPort int) (host string, port int, err error) {
	authority = strings.TrimSpace(authority)
	if authority == "" {
		return "", 0, fmt.Errorf("%w: empty authority", ErrBadTarget)
	}
	h, p, splitErr := net.SplitHostPort(authority)
	if splitErr != nil {
		// No port present. A bare IPv6 literal also lands here.
		return strings.Trim(authority, "[]"), defaultPort, nil
	}
	parsed, convErr := strconv.Atoi(p)
	if convErr != nil || parsed < 1 || parsed > 65535 {
		return "", 0, fmt.Errorf("%w: %q is not a port", ErrBadTarget, p)
	}
	return strings.Trim(h, "[]"), parsed, nil
}

// stripHopByHop removes the standard hop-by-hop headers plus anything the
// Connection header names, which is the extension mechanism for the same idea.
func stripHopByHop(h http.Header) {
	for _, name := range strings.Split(h.Get("Connection"), ",") {
		if name = strings.TrimSpace(name); name != "" {
			h.Del(name)
		}
	}
	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
}

func joinInts(values []int) string {
	parts := make([]string, 0, len(values))
	for _, v := range values {
		parts = append(parts, strconv.Itoa(v))
	}
	return strings.Join(parts, ", ")
}
