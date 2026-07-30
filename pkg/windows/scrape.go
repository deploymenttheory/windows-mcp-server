//go:build windows && (amd64 || arm64)

package windows

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/net/html"

	"github.com/deploymenttheory/windows-mcp-server/pkg/inventory"
)

const scrapeMaxBytes = 4 << 20 // 4 MiB response cap

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
			if maxChars < 100 {
				maxChars = 100
			}

			if err := validateScrapeURL(rawURL, deps.EnforceHTTPS()); err != nil {
				return NewToolResultErrorFromErr("invalid URL", err), nil
			}

			text, err := fetchReadableText(ctx, rawURL)
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

// validateScrapeURL enforces http(s), applies the Enforce HTTPS setting, and
// blocks obvious SSRF targets (loopback, private, and link-local addresses).
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
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("cannot resolve host: %w", err)
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return fmt.Errorf("host resolves to a non-public address")
		}
	}
	return nil
}

// fetchReadableText fetches the URL and extracts visible text.
func fetchReadableText(ctx context.Context, rawURL string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "windows-mcp-server/scrape")

	client := &http.Client{Timeout: 20 * time.Second}
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
