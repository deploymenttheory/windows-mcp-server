// Package hostmatch compiles an operator's egress allowlist and decides whether
// a requested host is on it.
//
// It is a leaf: the policy package calls Compile during validation so a
// malformed pattern fails at load rather than at the first connection, and the
// egress proxy calls Match on every request. Nothing here touches the network or
// the OS, so the whole decision is testable on any platform.
//
// The wildcard form is "*.example.com", and it matches the apex as well as every
// depth below it — example.com, www.example.com and a.b.example.com. That is
// what an operator writing an egress allowlist almost always means. Matching is
// anchored at a label boundary, so fakeexample.com is never a match.
package hostmatch

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"golang.org/x/net/idna"
)

// Errors reported by Compile. They are distinct values so a caller can explain
// which shape of pattern was rejected.
var (
	ErrEmptyPattern    = errors.New("empty pattern")
	ErrMatchEverything = errors.New(`"*" would allow every host, which defeats the allowlist`)
	ErrBadWildcard     = errors.New(`wildcard must be a single leading label, as in "*.example.com"`)
	ErrNotAHostname    = errors.New("pattern must be a bare hostname or IP address")
	ErrBadLabel        = errors.New("hostname label is empty or not encodable")
	// ErrInvalidAllowlist wraps the collected pattern problems, so a caller can
	// test for "the allowlist is bad" without matching on the rendered list.
	ErrInvalidAllowlist = errors.New("invalid egress allowlist")
)

// Set is a compiled allowlist. The zero value matches nothing, which is the
// safe direction: a Set that failed to compile never admits a host.
type Set struct {
	patterns []string // as written, for error messages the operator can act on
	exact    map[string]bool
	suffixes []string     // wildcard bodies: "*.example.com" is stored as "example.com"
	addrs    []netip.Addr // IP literals, compared canonically rather than as text
}

// Compile turns operator-written patterns into a Set, reporting every bad
// pattern at once rather than only the first — an operator fixing a list one
// error per run gives up before the list is right.
func Compile(patterns []string) (*Set, error) {
	set := &Set{exact: map[string]bool{}}
	var problems []string

	for _, raw := range patterns {
		pattern := strings.TrimSpace(raw)
		set.patterns = append(set.patterns, pattern)

		if err := set.add(pattern); err != nil {
			problems = append(problems, fmt.Sprintf("%q: %v", raw, err))
		}
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrInvalidAllowlist, strings.Join(problems, "; "))
	}
	return set, nil
}

func (s *Set) add(pattern string) error {
	if pattern == "" {
		return ErrEmptyPattern
	}
	if pattern == "*" {
		return ErrMatchEverything
	}
	if err := rejectNonHostname(pattern); err != nil {
		return err
	}

	if body, isWildcard := strings.CutPrefix(pattern, "*."); isWildcard {
		if strings.Contains(body, "*") {
			return ErrBadWildcard
		}
		host, err := normalizeHost(body)
		if err != nil {
			return err
		}
		s.suffixes = append(s.suffixes, host)
		return nil
	}
	if strings.Contains(pattern, "*") {
		return ErrBadWildcard
	}

	// An IP literal is stored as an address, so 127.0.0.1 and ::ffff:7f00:1 are
	// recognised as the same host however the client writes them.
	if addr, err := netip.ParseAddr(strings.Trim(pattern, "[]")); err == nil {
		s.addrs = append(s.addrs, addr.Unmap())
		return nil
	}
	host, err := normalizeHost(pattern)
	if err != nil {
		return err
	}
	s.exact[host] = true
	return nil
}

// rejectNonHostname refuses the shapes that mean the operator wrote something
// other than a host: a URL, a host:port, a path, or credentials. Silently
// ignoring the extra part would admit a broader or narrower set than the text
// suggests.
func rejectNonHostname(pattern string) error {
	switch {
	case strings.Contains(pattern, "://"):
		return fmt.Errorf("%w: drop the scheme", ErrNotAHostname)
	case strings.Contains(pattern, "/"):
		return fmt.Errorf("%w: drop the path", ErrNotAHostname)
	case strings.Contains(pattern, "@"):
		return fmt.Errorf("%w: drop the userinfo", ErrNotAHostname)
	case strings.ContainsAny(pattern, " \t\r\n"):
		return fmt.Errorf("%w: it contains whitespace", ErrNotAHostname)
	case strings.HasPrefix(pattern, "["):
		// A bracketed IPv6 literal is fine; a bracketed anything-else is not.
		if _, err := netip.ParseAddr(strings.Trim(pattern, "[]")); err != nil {
			return fmt.Errorf("%w: %q is not an IPv6 address", ErrNotAHostname, pattern)
		}
	case strings.Contains(pattern, ":"):
		// Unbracketed colons are either a port or a bare IPv6 literal.
		if _, err := netip.ParseAddr(pattern); err != nil {
			return fmt.Errorf("%w: drop the port", ErrNotAHostname)
		}
	}
	return nil
}

// normalizeHost lowercases, strips one trailing dot and converts to punycode, so
// a pattern and a request written in different forms of the same name compare
// equal. idna.Lookup is the profile for names being resolved, which is what
// these are.
func normalizeHost(host string) (string, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return "", ErrEmptyPattern
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrBadLabel, err)
	}
	return ascii, nil
}

// Match reports whether host is on the allowlist. The host comes off the wire —
// a CONNECT authority or a Host header — so it is normalized the same way the
// patterns were before anything is compared.
func (s *Set) Match(host string) bool {
	if s == nil {
		return false
	}
	trimmed := strings.Trim(strings.TrimSpace(host), "[]")
	if addr, err := netip.ParseAddr(trimmed); err == nil {
		// A wildcard names a DNS suffix and can never describe an address, so an
		// IP literal is matched only by an IP literal.
		return slices.Contains(s.addrs, addr.Unmap())
	}

	name, err := normalizeHost(host)
	if err != nil {
		return false
	}
	if s.exact[name] {
		return true
	}
	for _, suffix := range s.suffixes {
		// The leading dot is the label anchor: it is what stops "*.example.com"
		// from matching "fakeexample.com".
		if name == suffix || strings.HasSuffix(name, "."+suffix) {
			return true
		}
	}
	return false
}

// Len reports how many patterns compiled, for the status snapshot.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.patterns)
}

// Patterns returns the allowlist as written, sorted, for the refusal message. An
// operator reading "this host is not allowed" needs to see what is.
func (s *Set) Patterns() []string {
	if s == nil {
		return nil
	}
	out := slices.Clone(s.patterns)
	sort.Strings(out)
	return out
}
