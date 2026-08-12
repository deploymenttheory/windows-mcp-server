//go:build windows && (amd64 || arm64)

package windows

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestValidateScrapeURL(t *testing.T) {
	bad := []string{
		"ftp://example.com",  // wrong scheme
		"http://localhost/x", // localhost
		"http://127.0.0.1/x", // loopback
		"file:///etc/passwd", // wrong scheme
		"not a url",          // unparseable/host-less
	}
	for _, u := range bad {
		if err := validateScrapeURL(u, false); err == nil {
			t.Errorf("validateScrapeURL(%q) should have failed", u)
		}
	}
	// A public host should pass validation (requires DNS; skip if offline).
	if err := validateScrapeURL("https://example.com", false); err != nil {
		t.Skipf("public URL validation skipped (offline?): %v", err)
	}
}

// TestScrapeEnforceHTTPS covers the Enforce HTTPS setting on the Scrape path: off
// it is permissive as before, on it refuses plaintext regardless of scheme case.
// The scheme checks are ordered before DNS resolution, so these need no network.
func TestScrapeEnforceHTTPS(t *testing.T) {
	plaintext := []string{
		"http://example.com/page",
		"HTTP://example.com/page",  // upper case must not bypass
		"HtTp://example.com/page",  // mixed case must not bypass
		"http://example.com:8080/", // non-default port is still plaintext
	}
	for _, u := range plaintext {
		err := validateScrapeURL(u, true)
		if err == nil {
			t.Errorf("validateScrapeURL(%q, enforce) should be blocked", u)
			continue
		}
		if !errors.Is(err, ErrPlaintextHTTP) {
			t.Errorf("validateScrapeURL(%q, enforce) = %v; want ErrPlaintextHTTP", u, err)
		}
		// The message has to tell the model what to do instead.
		if !strings.Contains(err.Error(), "https://") {
			t.Errorf("blocked message should suggest https, got %q", err)
		}
	}

	// With the setting off, plaintext is allowed through the scheme gate. Use a
	// loopback host so the later SSRF check fails for its own reason, proving the
	// HTTPS gate did not fire.
	if err := validateScrapeURL("http://127.0.0.1/x", false); errors.Is(err, ErrPlaintextHTTP) {
		t.Error("plaintext must not be blocked when Enforce HTTPS is off")
	}

	// A non-http scheme is still rejected by the pre-existing scheme check rather
	// than by Enforce HTTPS.
	if err := validateScrapeURL("ftp://example.com", true); err == nil {
		t.Error("ftp should still be rejected")
	} else if errors.Is(err, ErrPlaintextHTTP) {
		t.Errorf("ftp should fail the scheme check, not the HTTPS gate: %v", err)
	}
}

// TestURLSchemeIfURL pins the App-launch discriminator: ordinary app names must
// not be mistaken for URLs, and URL-shaped values must be recognized whatever
// their scheme case.
func TestURLSchemeIfURL(t *testing.T) {
	for _, tc := range []struct {
		in     string
		scheme string
		ok     bool
	}{
		{"http://example.com", "http", true},
		{"HTTPS://example.com", "https", true},
		{"  http://example.com  ", "http", true}, // trimmed
		{"notepad", "", false},
		{"msedge", "", false},
		{"C:\\Windows\\notepad.exe", "", false},
		{"ftp://example.com", "", false},
		{"", "", false},
		{"example.com", "", false}, // no scheme: not a navigation
	} {
		scheme, ok := urlSchemeIfURL(tc.in)
		if ok != tc.ok || scheme != tc.scheme {
			t.Errorf("urlSchemeIfURL(%q) = (%q,%t); want (%q,%t)", tc.in, scheme, ok, tc.scheme, tc.ok)
		}
	}
}

func TestExtractText(t *testing.T) {
	htmlDoc := `<html><head><style>.x{color:red}</style><title>T</title></head>
	<body><h1>Hello</h1><script>var x=1;</script><p>World  of   text</p></body></html>`
	got, err := extractText(strings.NewReader(htmlDoc))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "Hello") || !strings.Contains(got, "World of text") {
		t.Errorf("expected visible text, got %q", got)
	}
	if strings.Contains(got, "color:red") || strings.Contains(got, "var x=1") {
		t.Errorf("script/style content leaked into text: %q", got)
	}
}

// permissiveDial connects without vetting the address, so a test can use an
// httptest server on loopback -- which the real dialer refuses, by design and by
// the test below. Everything except the address check is still exercised.
func permissiveDial(ctx context.Context, network, addr string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, addr)
}

// TestScrapeDialerRefusesTheAddressesItResolves is the regression test for the
// DNS-rebinding half of the SSRF class.
//
// The address check used to run in validateScrapeURL over a net.LookupIP whose
// answers were then discarded; http.Client resolved the name again at connect, so
// a short-TTL name could answer publicly for the check and with a loopback or
// RFC1918 address for the fetch. The check now happens in the dialer and the
// connection goes to the vetted address, so there is no second resolution.
//
// The NAT64 case is the one the hand-rolled predicate missed entirely: To4()
// returns nil for 64:ff9b::a9fe:a9fe, so IsLinkLocalUnicast never saw the
// 169.254.169.254 inside it.
func TestScrapeDialerRefusesTheAddressesItResolves(t *testing.T) {
	for _, addr := range []string{
		"127.0.0.1:80",            // loopback
		"10.0.0.1:80",             // RFC1918
		"169.254.169.254:80",      // link-local, the cloud metadata endpoint
		"100.64.0.1:80",           // CGNAT -- missed by the old IsPrivate check
		"[::ffff:127.0.0.1]:80",   // IPv4-mapped loopback
		"[64:ff9b::a9fe:a9fe]:80", // NAT64-embedded link-local
		"[::7f00:1]:80",           // ::/96-embedded loopback
	} {
		if _, err := scrapeDialContext(context.Background(), "tcp", addr); err == nil {
			t.Errorf("scrapeDialContext(%q) connected; it must refuse the address", addr)
		}
	}
}

// TestScrapeRefusesAddressLiteralsUpFront: a literal needs no resolution, so it
// is settled in validateScrapeURL with a message naming the reason.
func TestScrapeRefusesAddressLiteralsUpFront(t *testing.T) {
	for _, u := range []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://100.64.0.1/",
		"http://[64:ff9b::a9fe:a9fe]/",
	} {
		if err := validateScrapeURL(u, false); err == nil {
			t.Errorf("validateScrapeURL(%q) should have failed", u)
		}
	}
}

// TestRedirectsAreRevalidated is a regression test for a full SSRF and
// Enforce-HTTPS bypass: only the URL the model supplied was validated, and Go's
// default CheckRedirect then followed any 302 without a second look. An
// attacker-controlled host could redirect to a link-local or RFC1918 address --
// 169.254.169.254 being the obvious one -- and the body came back to the model.
//
// The address half of that is now the dialer's job (see above), which covers
// redirect hops by construction. What CheckRedirect still owns is the scheme: a
// 302 from https to plaintext http is a policy question no dialer can see, so
// that is what this exercises, with a permissive dialer so the hop is reached.
func TestRedirectsAreRevalidated(t *testing.T) {
	var target string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, target, http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("<html><body>should never be read</body></html>"))
	}))
	defer srv.Close()
	target = srv.URL + "/private"

	// enforceHTTPS on, and the httptest server speaks plaintext, so the hop is
	// refused by the per-hop scheme check.
	_, err := fetchReadableText(context.Background(), srv.URL+"/redirect", true, permissiveDial, "")
	if err == nil {
		t.Fatal("a redirect to a refused target must not be followed")
	}
	if !strings.Contains(err.Error(), "refused a redirect") {
		t.Errorf("the refusal should name the redirect as the cause, got: %v", err)
	}
}

// TestRedirectChainIsBounded keeps a validated-but-endless chain from spinning.
//
// Exercised against checkScrapeRedirect directly. Driving it with a real loop is
// no longer possible hermetically: every local fixture is a loopback address, and
// the hop is refused for that reason on the first redirect, so a live test would
// pass without the cap existing at all.
func TestRedirectChainIsBounded(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.com/next", nil)
	if err != nil {
		t.Fatal(err)
	}

	// One hop short of the cap: allowed on scheme grounds.
	via := make([]*http.Request, maxScrapeRedirects-1)
	if err := checkScrapeRedirect(req, via, false); err != nil {
		t.Errorf("hop %d should be allowed, got: %v", len(via), err)
	}

	// At the cap: refused, and it says why.
	via = make([]*http.Request, maxScrapeRedirects)
	err = checkScrapeRedirect(req, via, false)
	if err == nil {
		t.Fatal("an unbounded redirect chain must terminate with an error")
	}
	if !strings.Contains(err.Error(), "stopped after") {
		t.Errorf("the chain should end at the redirect cap, got: %v", err)
	}
}

// TestScrapeRoutesThroughTheEgressProxy pins the Phase-6 governance: with a
// provisioned egress proxy, the fetch goes to the proxy (an absolute-URI
// proxy request), not to the target — the server's own reaching-out is
// governed by the same allowlist as everything else's. The proxy hop uses a
// plain dialer, because the vetting dialer would rightly refuse its loopback
// address; destination vetting becomes the proxy's job.
func TestScrapeRoutesThroughTheEgressProxy(t *testing.T) {
	var sawProxyRequest atomic.Bool
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A proxied plain-HTTP request carries the absolute URI in the
		// request target; a direct fetch would carry only the path.
		if r.URL.IsAbs() && r.URL.Host == "scrape-target.example.com" {
			sawProxyRequest.Store(true)
		}
		_, _ = w.Write([]byte("<html><body>proxied body</body></html>"))
	}))
	defer proxy.Close()

	text, err := fetchReadableText(context.Background(),
		"http://scrape-target.example.com/page", false, nil, proxy.Listener.Addr().String())
	if err != nil {
		t.Fatalf("fetch via proxy: %v", err)
	}
	if !sawProxyRequest.Load() {
		t.Fatal("the fetch did not route through the egress proxy")
	}
	if !strings.Contains(text, "proxied body") {
		t.Fatalf("proxied body not returned: %q", text)
	}
}
