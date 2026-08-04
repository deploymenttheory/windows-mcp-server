//go:build windows && (amd64 || arm64)

package windows

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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

// TestRedirectsAreRevalidated is a regression test for a full SSRF and
// Enforce-HTTPS bypass: only the URL the model supplied was validated, and Go's
// default CheckRedirect then followed any 302 without a second look. An
// attacker-controlled host could redirect to a link-local or RFC1918 address --
// 169.254.169.254 being the obvious one -- and the body came back to the model.
func TestRedirectsAreRevalidated(t *testing.T) {
	// The redirect target resolves to loopback, which validateScrapeURL refuses.
	// Using the real server's own address keeps the test hermetic: no outbound
	// request is made, and the refusal happens before any connection to it.
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

	_, err := fetchReadableText(context.Background(), srv.URL+"/redirect", false)
	if err == nil {
		t.Fatal("a redirect to a non-public address must be refused, not followed")
	}
	if !strings.Contains(err.Error(), "refused a redirect") {
		t.Errorf("the refusal should name the redirect as the cause, got: %v", err)
	}
}

// TestRedirectChainIsBounded keeps a validated-but-endless chain from spinning.
func TestRedirectChainIsBounded(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/next", http.StatusFound)
	}))
	defer srv.Close()

	if _, err := fetchReadableText(context.Background(), srv.URL, false); err == nil {
		t.Fatal("an unbounded redirect chain must terminate with an error")
	}
}
