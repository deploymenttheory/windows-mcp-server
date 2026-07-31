//go:build windows && (amd64 || arm64)

package winmcp

import (
	"context"
	"encoding/json"
	"testing"
)

// TestCacheHintsDescribeThisServer checks the SEP-2549 caching hints on the wire.
//
// The SDK defaults every cacheable result to cacheScope "public" with ttlMs 0.
// That is structurally conformant but untrue here: "public" invites a shared
// intermediary to cache one caller's answer and serve it to another, and this
// server's manifest depends on the persona and toolsets the session was started
// with. The values are set deliberately; this test is what stops an SDK upgrade
// silently restoring the defaults.
func TestCacheHintsDescribeThisServer(t *testing.T) {
	surface, err := CaptureSurface(context.Background(), Config{Toolsets: []string{"all"}})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		payload json.RawMessage
	}{
		{"tools/list", surface.ToolsListResult},
		{"handshake", surface.HandshakeResult},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.payload) == 0 {
				t.Skip("nothing captured for this revision")
			}
			var env struct {
				TTLMs      *int    `json:"ttlMs"`
				CacheScope *string `json:"cacheScope"`
			}
			if err := json.Unmarshal(tc.payload, &env); err != nil {
				t.Fatal(err)
			}
			// Both fields are required on a cacheable result, so a missing one is a
			// conformance failure and not merely a lost hint.
			if env.TTLMs == nil || env.CacheScope == nil {
				t.Fatalf("%s must carry both ttlMs and cacheScope: %s", tc.name, tc.payload)
			}
			if *env.CacheScope != cacheScopePrivate {
				t.Errorf("cacheScope = %q, want %q — the manifest is specific to this "+
					"session's persona and toolsets", *env.CacheScope, cacheScopePrivate)
			}
			if want := int(manifestTTL.Milliseconds()); *env.TTLMs != want {
				t.Errorf("ttlMs = %d, want %d", *env.TTLMs, want)
			}
		})
	}
}
