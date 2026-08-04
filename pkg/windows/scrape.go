//go:build windows && (amd64 || arm64)

package windows

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/net/html"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/hostmatch"
	"github.com/deploymenttheory/windows-mcp-server/pkg/inventory"
)

const scrapeMaxBytes = 4 << 20 // 4 MiB response cap

// maxScrapeChars bounds what one call returns to the model.
const maxScrapeChars = 50000

// Scrape fetches a web page and extracts its readable text.
func Scrape() inventory.ServerTool {
	openWorld := true
	return NewToolFromHandler(
		ToolsetWeb,
		mcp.Tool{
			Name:        "Scrape",
			Description: "Fetch a public web page over HTTP(S) and return its readable text content (scripts, styles, and markup removed). Use for reading documentation or article content.",
			Annotations: &mcp.ToolAnnotations{
				Title:         "Scrape web page",
				ReadOnlyHint:  true,
				OpenWorldHint: &openWorld,
			},
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"url":       {Type: "string", Description: "The http(s) URL to fetch."},
					"max_chars": {Type: "integer", Description: "Maximum characters of text to return (default 8000)."},
				},
				Required: []string{"url"},
			},
		},
		func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args, err := ArgsMap(req)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			rawURL, err := RequiredString(args, "url")
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			maxChars, err := OptionalInt(args, "max_chars", 8000)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			// Floor and ceiling. Without an upper bound a single call could put the
			// whole 4 MiB body cap into the model's context.
			maxChars = clampInt(maxChars, 100, maxScrapeChars)

			if err := validateScrapeURL(rawURL, deps.EnforceHTTPS()); err != nil {
				return NewToolResultErrorFromErr("invalid URL", err), nil
			}

			text, err := fetchReadableText(ctx, rawURL, deps.EnforceHTTPS(), nil)
			if err != nil {
				return NewToolResultErrorFromErr("scrape failed", err), nil
			}
			if len(text) > maxChars {
				text = text[:maxChars] + "\n\n[truncated]"
			}
			return NewToolResultTextf("Content of %s:\n\n%s", rawURL, text), nil
		},
	)
}

// validateScrapeURL enforces http(s) and applies the Enforce HTTPS setting.
//
// It deliberately does NOT decide the address question. That check used to live
// here, over a net.LookupIP whose answers were then thrown away -- http.Client
// resolved the name a second time at connect, so an attacker-controlled name
// could answer publicly for the check and with 127.0.0.1 or an RFC1918 address
// for the fetch. Nothing a scheme-and-name check does can close that window; the
// address has to be vetted by whoever dials it. See scrapeDialContext.
func validateScrapeURL(rawURL string, enforceHTTPS bool) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	// Compare case-insensitively: url.Parse keeps the caller's case, and
	// "HTTP://host" is a valid equivalent URL.
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return fmt.Errorf("only http and https are allowed")
	}
	if err := enforceHTTPSScheme(u, enforceHTTPS); err != nil {
		return err
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("missing host")
	}
	if strings.EqualFold(host, "localhost") {
		return fmt.Errorf("localhost is not allowed")
	}
	// An address literal needs no resolution, so it can be settled here and
	// refused with a message that names the reason. A name cannot: whatever it
	// resolves to now, it is the resolution at dial time that decides where the
	// connection goes, which is why scrapeDialContext exists.
	if addr, err := netip.ParseAddr(host); err == nil {
		if reason, forbidden := hostmatch.ForbiddenAddr(addr, false); forbidden {
			return fmt.Errorf("%s is not allowed: %s", host, reason)
		}
	}
	return nil
}

// scrapeDialContext resolves, vets and dials in one step, so the address that is
// checked is the address that is connected to.
//
// Two things this fixes. The address predicate is now hostmatch.ForbiddenAddr,
// the same one the egress proxy uses: the hand-rolled test it replaces
// (IsLoopback/IsPrivate/IsLinkLocalUnicast/IsUnspecified) missed CGNAT 100.64/10,
// the IANA special-purpose ranges, and IPv4 embedded in IPv6 via NAT64, 6to4 and
// ::/96 -- so 64:ff9b::a9fe:a9fe reached link-local 169.254.169.254 past all four
// predicates. And because the dial goes to the vetted netip.Addr rather than back
// to the name, there is no second resolution to disagree with the first.
//
// This runs on every connection the client opens, so redirect hops are covered by
// construction rather than by remembering to re-check them.
func scrapeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("cannot parse target %q: %w", addr, err)
	}

	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve host: %w", err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("host resolves to no addresses")
	}

	// Every answer must be acceptable, not merely one of them. Dialling the first
	// public address in a set that also contains a private one would let a name
	// answering with both reach the private one on a retry.
	for _, a := range addrs {
		if reason, forbidden := hostmatch.ForbiddenAddr(a, false); forbidden {
			return nil, fmt.Errorf("host resolves to %s (%s)", a, reason)
		}
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var lastErr error
	for _, a := range addrs {
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(a.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// maxScrapeRedirects bounds the redirect chain. Go's default is 10; the lower
// cap is here because every hop is re-validated, and a long chain of validated
// hops is still a long chain.
const maxScrapeRedirects = 5

// checkScrapeRedirect is the per-hop policy: the chain cap, then the scheme and
// Enforce HTTPS checks against the new target.
//
// A named function rather than a closure so the cap can be tested for what it is.
// Left inline, the only way to reach it was a real redirect loop, and every local
// fixture is a loopback address the dialer now refuses on the first hop -- so the
// chain terminated for the right reason at the wrong place and the cap went
// untested.
func checkScrapeRedirect(r *http.Request, via []*http.Request, enforceHTTPS bool) error {
	if len(via) >= maxScrapeRedirects {
		return fmt.Errorf("stopped after %d redirects", maxScrapeRedirects)
	}
	if err := validateScrapeURL(r.URL.String(), enforceHTTPS); err != nil {
		return fmt.Errorf("refused a redirect to %s: %w", r.URL.Redacted(), err)
	}
	return nil
}

// fetchReadableText fetches the URL and extracts visible text.
//
// Every redirect hop is re-validated. Validating only the URL the model supplied
// was a full bypass of both the SSRF guard and Enforce HTTPS: an attacker-controlled
// host answered 302 to http://169.254.169.254/... or an RFC1918 address, Go's
// default CheckRedirect followed it without a second look, and the body came back
// to the model.
// dial selects how connections are made. Production passes nil, which means
// scrapeDialContext -- the vetting dialer. It is a parameter rather than a
// package-level variable that tests reassign, so the production call site can be
// read and confirmed strict without tracing what else might have rebound it: there
// is exactly one caller passing nil, in Scrape's handler above.
//
// Tests pass a permissive dialer because httptest servers bind loopback, which
// the real one refuses -- correctly, and that refusal is itself pinned by
// TestScrapeDialerRefusesTheAddressesItResolves.
func fetchReadableText(
	ctx context.Context,
	rawURL string,
	enforceHTTPS bool,
	dial func(context.Context, string, string) (net.Conn, error),
) (string, error) {
	if dial == nil {
		dial = scrapeDialContext
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "windows-mcp-server/scrape")

	client := &http.Client{
		Timeout: 20 * time.Second,
		// Not http.DefaultTransport: this one vets the address it dials. The
		// scheme and Enforce HTTPS checks below still run per hop, because a
		// redirect to a plaintext or non-http scheme is a policy question the
		// dialer cannot see.
		Transport: &http.Transport{
			DialContext:           dial,
			Proxy:                 http.ProxyFromEnvironment,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
		},
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			return checkScrapeRedirect(r, via, enforceHTTPS)
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return extractText(io.LimitReader(resp.Body, scrapeMaxBytes))
}

// extractText walks the HTML, collecting visible text and skipping script/style.
func extractText(r io.Reader) (string, error) {
	tokenizer := html.NewTokenizer(r)
	var b strings.Builder
	skip := 0
	for {
		switch tokenizer.Next() {
		case html.ErrorToken:
			if err := tokenizer.Err(); err != nil && err != io.EOF {
				return "", err
			}
			return collapseWhitespace(b.String()), nil
		case html.StartTagToken:
			name, _ := tokenizer.TagName()
			switch string(name) {
			case "script", "style", "noscript", "svg":
				skip++
			}
		case html.EndTagToken:
			name, _ := tokenizer.TagName()
			switch string(name) {
			case "script", "style", "noscript", "svg":
				if skip > 0 {
					skip--
				}
			}
		case html.TextToken:
			if skip == 0 {
				b.Write(tokenizer.Text())
				b.WriteByte(' ')
			}
		}
	}
}

// collapseWhitespace normalizes runs of whitespace and blank lines.
func collapseWhitespace(s string) string {
	lines := strings.Split(s, "\n")
	var out []string
	for _, ln := range lines {
		if f := strings.Join(strings.Fields(ln), " "); f != "" {
			out = append(out, f)
		}
	}
	return strings.Join(out, "\n")
}
