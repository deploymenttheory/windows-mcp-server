package egress

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/hostmatch"
)

// harness is a running proxy plus the record of what its resolver and dialer
// were asked to do. Those counts are the point of most of these tests: a
// refusal that still resolved or still dialled has leaked.
type harness struct {
	svc      *Service
	resolves atomic.Int64
	dials    atomic.Int64
	dialed   atomic.Value // string: the address actually dialled
	upstream *httptest.Server
}

func newHarness(t *testing.T, allow []string, mutate func(*Config)) *harness {
	t.Helper()
	set, err := hostmatch.Compile(allow)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{}
	h.upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Upstream-Saw-Proxy-Auth", r.Header.Get("Proxy-Authorization"))
		w.Header().Set("X-Upstream-Saw-Via", r.Header.Get("Via"))
		_, _ = io.WriteString(w, "upstream ok")
	}))
	t.Cleanup(h.upstream.Close)

	upstreamAddr := h.upstream.Listener.Addr().String()
	cfg := Config{
		Listen:      "127.0.0.1:0",
		Allow:       set,
		AllowPorts:  []int{443, 80},
		Enforcement: "proxy-only",
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Resolve: func(_ context.Context, _ string) ([]netip.Addr, error) {
			h.resolves.Add(1)
			// A public address, so the forbidden-address check passes and the
			// dial is what the test observes.
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		},
		Dial: func(ctx context.Context, addr string) (net.Conn, error) {
			h.dials.Add(1)
			h.dialed.Store(addr)
			// Every allowed dial lands on the local upstream, whatever address
			// the proxy vetted, so the forwarding path can be exercised.
			var d net.Dialer
			return d.DialContext(ctx, "tcp", upstreamAddr)
		},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	svc, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Stop)
	h.svc = svc
	return h
}

// do sends one request through the proxy over a fresh connection and returns
// the response. Raw net.Dial rather than an http.Client, because CONNECT needs
// the connection left alone afterwards.
func (h *harness) do(t *testing.T, request string) *http.Response {
	t.Helper()
	conn, err := net.Dial("tcp", h.svc.Addr())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func connectRequest(authority string) string {
	return "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\n\r\n"
}

func bodyOf(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestDeniedHostIsRefusedWithoutResolvingIt is the leak test, and the reason
// checkTarget consults the allowlist before the resolver. A refusal that still
// emitted a DNS query would turn every blocked request into an outbound signal.
func TestDeniedHostIsRefusedWithoutResolvingIt(t *testing.T) {
	h := newHarness(t, []string{"*.allowed.example"}, nil)

	resp := h.do(t, connectRequest("tracker.denied.example:443"))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if got := h.resolves.Load(); got != 0 {
		t.Errorf("a denied host was resolved %d times; it must never leave the machine", got)
	}
	if got := h.dials.Load(); got != 0 {
		t.Errorf("a denied host was dialled %d times", got)
	}
	body := bodyOf(t, resp)
	if !strings.Contains(body, "tracker.denied.example") || !strings.Contains(body, "*.allowed.example") {
		t.Errorf("the refusal should name the host and the allowed patterns, got %q", body)
	}
	if !strings.Contains(body, "egress.allow") {
		t.Errorf("the refusal should say how to permit it, got %q", body)
	}
}

func TestAllowedHostIsTunnelled(t *testing.T) {
	h := newHarness(t, []string{"*.allowed.example"}, nil)

	resp := h.do(t, connectRequest("api.allowed.example:443"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", resp.StatusCode, bodyOf(t, resp))
	}
	if h.resolves.Load() != 1 || h.dials.Load() != 1 {
		t.Errorf("expected one resolve and one dial, got %d and %d", h.resolves.Load(), h.dials.Load())
	}
	// The dial must target the vetted address, never the name.
	if got, _ := h.dialed.Load().(string); got != "93.184.216.34:443" {
		t.Errorf("dialled %q, want the vetted address 93.184.216.34:443", got)
	}
	if c := h.svc.Counters(); c.Allowed != 1 {
		t.Errorf("allowed counter = %d, want 1", c.Allowed)
	}
}

// TestAllowedNameResolvingToAForbiddenAddressIsRefused covers the rebinding
// case: the name is on the list, the answer is not something we will dial.
func TestAllowedNameResolvingToAForbiddenAddressIsRefused(t *testing.T) {
	for _, tc := range []struct{ name, addr, want string }{
		{"loopback", "127.0.0.1", "loopback"},
		{"private", "10.0.0.1", "private"},
		{"metadata", "169.254.169.254", "link-local"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, []string{"*.allowed.example"}, func(c *Config) {
				c.Resolve = func(context.Context, string) ([]netip.Addr, error) {
					return []netip.Addr{netip.MustParseAddr(tc.addr)}, nil
				}
			})
			resp := h.do(t, connectRequest("api.allowed.example:443"))
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", resp.StatusCode)
			}
			if h.dials.Load() != 0 {
				t.Error("a forbidden address must not be dialled")
			}
			if body := bodyOf(t, resp); !strings.Contains(body, tc.want) {
				t.Errorf("refusal should say why, got %q", body)
			}
		})
	}
}

// TestAllowPrivateNetworksPermitsIntranetTargets is the escape hatch for an
// allowlist that names internal hosts.
func TestAllowPrivateNetworksPermitsIntranetTargets(t *testing.T) {
	h := newHarness(t, []string{"intranet.allowed.example"}, func(c *Config) {
		c.AllowPrivate = true
		c.Resolve = func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("10.1.2.3")}, nil
		}
	})
	resp := h.do(t, connectRequest("intranet.allowed.example:443"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", resp.StatusCode, bodyOf(t, resp))
	}
	// Loopback stays forbidden even here.
	h2 := newHarness(t, []string{"intranet.allowed.example"}, func(c *Config) {
		c.AllowPrivate = true
		c.Resolve = func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
	})
	if resp := h2.do(t, connectRequest("intranet.allowed.example:443")); resp.StatusCode != http.StatusForbidden {
		t.Errorf("loopback must stay forbidden, got %d", resp.StatusCode)
	}
}

// TestForbiddenAddressesAreSkippedWhenAnotherAnswerIsUsable checks that a
// mixed DNS answer picks the usable address rather than refusing outright.
func TestForbiddenAddressesAreSkippedWhenAnotherAnswerIsUsable(t *testing.T) {
	h := newHarness(t, []string{"api.allowed.example"}, func(c *Config) {
		c.Resolve = func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{
				netip.MustParseAddr("127.0.0.1"),
				netip.MustParseAddr("93.184.216.34"),
			}, nil
		}
	})
	resp := h.do(t, connectRequest("api.allowed.example:443"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got, _ := h.dialed.Load().(string); got != "93.184.216.34:443" {
		t.Errorf("dialled %q, want the usable address", got)
	}
}

func TestPortNotAllowedIsRefusedWithoutResolving(t *testing.T) {
	h := newHarness(t, []string{"*.allowed.example"}, nil)

	resp := h.do(t, connectRequest("api.allowed.example:22"))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if h.resolves.Load() != 0 {
		t.Error("a refused port must not trigger a lookup")
	}
	if body := bodyOf(t, resp); !strings.Contains(body, "port 22") ||
		!strings.Contains(body, "egress.allow_ports") {
		t.Errorf("refusal should name the port and the fix, got %q", body)
	}
}

// TestIPLiteralTargetsAreJudgedAsAddresses covers a client that skips DNS.
func TestIPLiteralTargetsAreJudgedAsAddresses(t *testing.T) {
	h := newHarness(t, []string{"93.184.216.34"}, nil)

	if resp := h.do(t, connectRequest("93.184.216.34:443")); resp.StatusCode != http.StatusOK {
		t.Errorf("an allowlisted IP literal should be admitted, got %d", resp.StatusCode)
	}
	if h.resolves.Load() != 0 {
		t.Error("an IP literal must not be resolved")
	}
	if resp := h.do(t, connectRequest("198.51.100.9:443")); resp.StatusCode != http.StatusForbidden {
		t.Errorf("an IP outside the allowlist should be refused, got %d", resp.StatusCode)
	}
	// Even allowlisted, a forbidden range is never dialled.
	h2 := newHarness(t, []string{"127.0.0.1"}, nil)
	if resp := h2.do(t, connectRequest("127.0.0.1:443")); resp.StatusCode != http.StatusForbidden {
		t.Errorf("a loopback literal must be refused however it is listed, got %d", resp.StatusCode)
	}
}

func TestPlainHTTPForwardingStripsHopByHopHeaders(t *testing.T) {
	h := newHarness(t, []string{"api.allowed.example"}, nil)

	resp := h.do(t, "GET http://api.allowed.example/thing HTTP/1.1\r\n"+
		"Host: api.allowed.example\r\n"+
		"Proxy-Connection: keep-alive\r\n"+
		"Connection: X-Custom-Hop\r\n"+
		"X-Custom-Hop: should-not-survive\r\n"+
		"X-Kept: yes\r\n\r\n")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", resp.StatusCode, bodyOf(t, resp))
	}
	// The upstream must not have seen the credential or the hop-by-hop headers.
	if got := resp.Header.Get("X-Upstream-Saw-Proxy-Auth"); got != "" {
		t.Errorf("Proxy-Authorization reached the upstream: %q", got)
	}
	if got := resp.Header.Get("X-Upstream-Saw-Via"); got != "1.1 windows-mcp-egress" {
		t.Errorf("Via = %q, want the proxy's own", got)
	}
	// And the response's own hop-by-hop headers must not be relayed back.
	if got := resp.Header.Get("Connection"); strings.Contains(got, "keep-alive") {
		t.Errorf("the upstream's Connection header was relayed: %q", got)
	}
	if body := bodyOf(t, resp); body != "upstream ok" {
		t.Errorf("body = %q", body)
	}
}

func TestPlainHTTPDeniedHostIsRefused(t *testing.T) {
	h := newHarness(t, []string{"api.allowed.example"}, nil)

	resp := h.do(t, "GET http://denied.example/thing HTTP/1.1\r\nHost: denied.example\r\n\r\n")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if h.resolves.Load() != 0 || h.dials.Load() != 0 {
		t.Error("a denied plain-HTTP target must not be resolved or dialled")
	}
}

// TestDisagreeingHostHeaderCannotWidenTheDecision pins the property a
// request-smuggling check would protect: when the Host header names a different
// host from the request-target, the host that is vetted and the host that is
// dialled are the same one. net/http resolves the ambiguity in favour of the
// request-target, so a header naming a denied host cannot admit it, and a header
// naming an allowed host cannot launder a denied target.
func TestDisagreeingHostHeaderCannotWidenTheDecision(t *testing.T) {
	h := newHarness(t, []string{"api.allowed.example"}, nil)

	// Denied target, allowed host header: still refused.
	resp := h.do(t, "GET http://denied.example/thing HTTP/1.1\r\nHost: api.allowed.example\r\n\r\n")
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 — the request-target decides", resp.StatusCode)
	}
	if h.dials.Load() != 0 {
		t.Error("a denied target must not be forwarded whatever the Host header says")
	}
}

func TestOriginFormRequestIsRejected(t *testing.T) {
	h := newHarness(t, []string{"api.allowed.example"}, nil)

	resp := h.do(t, "GET /thing HTTP/1.1\r\nHost: api.allowed.example\r\n\r\n")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if body := bodyOf(t, resp); !strings.Contains(body, "forward proxy") {
		t.Errorf("the refusal should explain what the proxy expects, got %q", body)
	}
}

func TestProxyAuthorizationIsRequiredWhenConfigured(t *testing.T) {
	h := newHarness(t, []string{"api.allowed.example"}, func(c *Config) { c.AuthToken = "s3cret" })

	resp := h.do(t, connectRequest("api.allowed.example:443"))
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", resp.StatusCode)
	}
	if resp.Header.Get("Proxy-Authenticate") == "" {
		t.Error("a 407 must carry Proxy-Authenticate")
	}
	if h.resolves.Load() != 0 {
		t.Error("an unauthenticated request must not reach the resolver")
	}

	authed := h.do(t, "CONNECT api.allowed.example:443 HTTP/1.1\r\n"+
		"Host: api.allowed.example:443\r\nProxy-Authorization: Bearer s3cret\r\n\r\n")
	if authed.StatusCode != http.StatusOK {
		t.Errorf("the correct credential should be admitted, got %d", authed.StatusCode)
	}
}

func TestStartRefusesANonLoopbackAddress(t *testing.T) {
	set, err := hostmatch.Compile([]string{"example.com"})
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range []string{"0.0.0.0:8181", "192.168.1.5:8181", "[::]:8181"} {
		_, err := Start(context.Background(), Config{Listen: addr, Allow: set})
		if err == nil {
			t.Errorf("Start(%q) should refuse to bind off-loopback", addr)
		}
	}
}

func TestStartRefusesAnEmptyAllowlist(t *testing.T) {
	set, err := hostmatch.Compile(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Start(context.Background(), Config{Listen: "127.0.0.1:0", Allow: set}); err == nil {
		t.Error("a proxy that can admit nothing should not start")
	}
}

func TestStopIsIdempotent(t *testing.T) {
	h := newHarness(t, []string{"api.allowed.example"}, nil)
	h.svc.Stop()
	h.svc.Stop() // the normal-exit defer and the kill path both reach this
}

// TestDeniedHostTrackingIsBounded stops a host-rotating client from driving the
// length of the audit chain.
func TestDeniedHostTrackingIsBounded(t *testing.T) {
	c := newCounters()
	firsts := 0
	for i := range maxTrackedDeniedHosts * 3 {
		if c.noteDenied(string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".example") {
			firsts++
		}
	}
	if firsts > maxTrackedDeniedHosts {
		t.Errorf("recorded %d distinct hosts, cap is %d", firsts, maxTrackedDeniedHosts)
	}
	if len(c.deniedHosts()) > maxTrackedDeniedHosts {
		t.Errorf("table grew past the cap: %d", len(c.deniedHosts()))
	}
}

func TestCountersSeparateTheReasonsForRefusal(t *testing.T) {
	h := newHarness(t, []string{"api.allowed.example"}, nil)
	h.do(t, connectRequest("denied.example:443"))
	h.do(t, connectRequest("api.allowed.example:22"))
	h.do(t, connectRequest("api.allowed.example:443"))

	c := h.svc.Counters()
	if c.DeniedHost != 1 || c.DeniedPort != 1 || c.Allowed != 1 {
		t.Errorf("counters = %+v; want one host denial, one port denial, one allow", c)
	}
	if c.Denied() != 2 {
		t.Errorf("Denied() = %d, want 2", c.Denied())
	}
}

// TestEmptyAllowPortsIsNotAnyPort pins the port gate against a Config built in
// code rather than parsed from a document.
//
// checkTarget enforced ports only when AllowPorts was non-empty. policy.Parse
// defaults it for a document, so documents were safe -- but egress.Start has an
// explicit belt for an empty *allowlist* and had none for empty *ports*, and a
// hand-built Config is exactly the case that belt exists for. The result was a
// generic TCP relay to any port on an allowed host: 445 for SMB and NTLM
// coercion, 22, 3389.
func TestEmptyAllowPortsIsNotAnyPort(t *testing.T) {
	set, err := hostmatch.Compile([]string{"allowed.example"})
	if err != nil {
		t.Fatal(err)
	}
	p := &proxy{
		cfg: Config{
			Allow: set, // AllowPorts deliberately unset
			Resolve: func(context.Context, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
			},
		},
		counters: &counters{},
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	for _, port := range []int{445, 22, 3389, 8080} {
		if _, refused := p.checkTarget(context.Background(), "allowed.example", port); refused == nil {
			t.Errorf("port %d must not be reachable when no ports were configured", port)
		}
	}
	// The defaults must still work, or an empty config would deny everything.
	for _, port := range []int{443, 80} {
		if _, refused := p.checkTarget(context.Background(), "allowed.example", port); refused != nil {
			t.Errorf("port %d is a default and should be allowed, got %q", port, refused.message)
		}
	}
}
