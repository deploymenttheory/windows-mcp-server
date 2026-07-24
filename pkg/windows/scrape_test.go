//go:build windows && (amd64 || arm64)

package windows

import (
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
		if err := validateScrapeURL(u); err == nil {
			t.Errorf("validateScrapeURL(%q) should have failed", u)
		}
	}
	// A public host should pass validation (requires DNS; skip if offline).
	if err := validateScrapeURL("https://example.com"); err != nil {
		t.Skipf("public URL validation skipped (offline?): %v", err)
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
