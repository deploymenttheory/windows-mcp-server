//go:build windows && (amd64 || arm64)

package winmcp

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/windows-mcp-server/internal/mcpspec"
)

func schemaDir() string { return filepath.Join("..", "..", "schema") }

// TestServedSurfaceValidatesAgainstTheNewestRevision is the offline pre-flight.
//
// The authority on conformance is the official suite, run from the compliance
// workflow against the loopback HTTP host. This is deliberately something
// smaller: a pass/fail check that every wire object this server serves validates
// against the newest vendored schema, so `go test` still catches a broken tool
// schema on a machine with no Node installed. It reports no score — the score it
// replaced was self-marked, which is the whole reason the suite is now run.
func TestServedSurfaceValidatesAgainstTheNewestRevision(t *testing.T) {
	m, err := mcpspec.LoadManifest(schemaDir())
	if err != nil {
		t.Fatal(err)
	}
	spec, err := mcpspec.Load(schemaDir(), m.Newest())
	if err != nil {
		t.Fatal(err)
	}
	surface, err := CaptureSurface(context.Background(), Config{Toolsets: []string{"all"}})
	if err != nil {
		t.Fatal(err)
	}
	if surface.NegotiatedVersion != m.Newest() {
		t.Errorf("session negotiated %q but the newest vendored revision is %q; the "+
			"pre-flight would be validating against the wrong shape",
			surface.NegotiatedVersion, m.Newest())
	}

	t.Run("every tool", func(t *testing.T) {
		var payload struct {
			Tools []json.RawMessage `json:"tools"`
		}
		if err := json.Unmarshal(surface.ToolsListResult, &payload); err != nil {
			t.Fatal(err)
		}
		if len(payload.Tools) == 0 {
			t.Fatal("no tools served")
		}
		for _, raw := range payload.Tools {
			var named struct {
				Name string `json:"name"`
			}
			_ = json.Unmarshal(raw, &named)
			if err := spec.ValidateJSON("Tool", raw); err != nil {
				t.Errorf("tool %q does not validate: %v", named.Name, err)
			}
		}
	})

	t.Run("tools/list result", func(t *testing.T) {
		if err := spec.ValidateJSON("ListToolsResult", surface.ToolsListResult); err != nil {
			t.Errorf("tools/list result does not validate: %v", err)
		}
	})

	t.Run("capabilities", func(t *testing.T) {
		if len(surface.Capabilities) == 0 {
			t.Fatal("no capabilities captured")
		}
		if err := spec.ValidateJSON("ServerCapabilities", surface.Capabilities); err != nil {
			t.Errorf("server capabilities do not validate: %v", err)
		}
	})

	t.Run("handshake", func(t *testing.T) {
		def, ok := spec.FirstPresent("DiscoverResult", "InitializeResult")
		if !ok {
			t.Skipf("revision %s defines neither handshake result", m.Newest())
		}
		if err := spec.ValidateJSON(def, surface.HandshakeResult); err != nil {
			t.Errorf("handshake does not validate against %s: %v\ncaptured: %s",
				def, err, surface.HandshakeResult)
		}
	})
}

// TestCaptureRecordsTheWireNotTheSDKView is the regression guard for a bug this
// capture used to have.
//
// It reported the handshake from ClientSession.InitializeResult(), which on
// 2026-07-28 is a *synthesized legacy view*: the real exchange is server/discover,
// whose result must carry resultType, cacheScope, ttlMs and supportedVersions.
// Validating the synthesized view made a conformant server look non-conformant.
func TestCaptureRecordsTheWireNotTheSDKView(t *testing.T) {
	surface, err := CaptureSurface(context.Background(), Config{Toolsets: []string{"all"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(surface.HandshakeResult) == 0 {
		t.Fatal("no handshake result captured")
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(surface.HandshakeResult, &got); err != nil {
		t.Fatal(err)
	}
	if _, isDiscover := got["supportedVersions"]; !isDiscover {
		t.Skip("this revision negotiates initialize, not server/discover")
	}
	for _, field := range []string{"resultType", "cacheScope", "ttlMs", "supportedVersions"} {
		if _, ok := got[field]; !ok {
			t.Errorf("captured handshake is missing %q — looks like the normalized "+
				"InitializeResult rather than the wire DiscoverResult", field)
		}
	}
}
