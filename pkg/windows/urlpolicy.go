//go:build windows && (amd64 || arm64)

package windows

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ErrPlaintextHTTP is returned when Enforce HTTPS is on and a plaintext http://
// target is requested.
var ErrPlaintextHTTP = errors.New("plaintext http:// is blocked by Enforce HTTPS")

// enforceHTTPSScheme rejects a plaintext http:// URL when Enforce HTTPS is on.
//
// The scheme is compared case-insensitively because url.Parse preserves the case
// the caller wrote and "HTTP://example.com" is a valid, equivalent URL — a
// case-sensitive check would be trivially bypassable.
//
// The message is written for the model rather than the operator: it says what to
// do next (retry over https) so the agent can self-correct instead of retrying
// the same blocked call.
func enforceHTTPSScheme(u *url.URL, enforceHTTPS bool) error {
	if !enforceHTTPS {
		return nil
	}
	if strings.EqualFold(u.Scheme, "http") {
		return fmt.Errorf("%w: retry with https://%s%s, or ask the operator to start the server "+
			"without --enforce-https if this site genuinely has no HTTPS endpoint",
			ErrPlaintextHTTP, u.Host, u.Path)
	}
	return nil
}

// urlSchemeIfURL reports the lower-cased scheme when s is a URL with an explicit
// http or https scheme, and ok=false otherwise.
//
// It exists because tools accept values that are *usually* not URLs — App's
// "name" is normally something like "notepad" — but which Windows will happily
// treat as one. `Start-Process http://example.com` opens the default browser, so
// a URL-shaped app name is a navigation, and Enforce HTTPS has to see it.
func urlSchemeIfURL(s string) (scheme string, ok bool) {
	s = strings.TrimSpace(s)
	// Require an explicit scheme separator: a bare "notepad" must not be treated
	// as a URL, and url.Parse would happily accept it as a path.
	if !strings.Contains(s, "://") {
		return "", false
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", false
	}
	switch lower := strings.ToLower(u.Scheme); lower {
	case "http", "https":
		return lower, true
	default:
		return "", false
	}
}
