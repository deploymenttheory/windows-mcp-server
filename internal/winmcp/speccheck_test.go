//go:build windows && (amd64 || arm64)

package winmcp

import (
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"testing"

	"github.com/deploymenttheory/windows-mcp-server/internal/mcpspec"
)

func schemaDir() string { return filepath.Join("..", "..", "schema") }

// TestCaptureSurfaceHandshakeConforms is the regression guard for the harness bug
// this replaced.
//
// CaptureSurface used to report the handshake from ClientSession.InitializeResult(),
// which on protocol 2026-07-28 is a *synthesized legacy view*: the real wire
// exchange is server/discover, whose result must carry resultType, cacheScope,
// ttlMs and supportedVersions. Validating the synthesized view made a conformant
// server look non-conformant. The fix records the actual frames; this test fails
// if anyone reverts to the normalized accessor.
func TestCaptureSurfaceHandshakeConforms(t *testing.T) {
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
	if len(surface.HandshakeResult) == 0 {
		t.Fatal("no handshake result captured")
	}

	def, ok := spec.FirstPresent("InitializeResult", "DiscoverResult")
	if !ok {
		t.Fatalf("revision %s defines neither handshake result", m.Newest())
	}
	if err := spec.ValidateJSON(def, surface.HandshakeResult); err != nil {
		t.Errorf("captured handshake does not validate against %s: %v\ncaptured: %s",
			def, err, surface.HandshakeResult)
	}

	// The captured object must be the wire result, not the normalized view: on the
	// newest revision it carries fields InitializeResult does not have.
	if def == "DiscoverResult" {
		var got map[string]json.RawMessage
		if err := json.Unmarshal(surface.HandshakeResult, &got); err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{"resultType", "cacheScope", "ttlMs", "supportedVersions"} {
			if _, ok := got[field]; !ok {
				t.Errorf("captured handshake is missing %q — looks like the normalized "+
					"InitializeResult rather than the wire DiscoverResult", field)
			}
		}
	}
}

// TestCaptureSurfaceConformsFully asserts the whole captured surface scores 100 on
// conformance against the newest revision, with no findings.
func TestCaptureSurfaceConformsFully(t *testing.T) {
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
	surface.Manifest = m

	rep := mcpspec.Evaluate(spec, surface)
	if rep.ConformanceScore != 100 {
		t.Errorf("conformance = %d, want 100", rep.ConformanceScore)
		for _, f := range rep.Findings {
			t.Errorf("  finding: %s/%s: %s", f.Dimension, f.Subject, f.Problem)
		}
	}
}

// TestAlwaysServedMethodsCounted guards the second harness false negative: these
// are in the SDK's dispatch table with no capability gate, so deriving the method
// surface from declared capabilities alone under-reports them.
func TestAlwaysServedMethodsCounted(t *testing.T) {
	got := implementedMethods(nil)
	for _, want := range alwaysServedMethods {
		if !slices.Contains(got, want) {
			t.Errorf("implementedMethods must always include %q, got %v", want, got)
		}
	}
	// Capability-gated methods must not appear without their capability.
	withTools := implementedMethods([]string{"tools"})
	if !slices.Contains(withTools, "tools/call") {
		t.Errorf("declaring tools should imply tools/call, got %v", withTools)
	}
	if slices.Contains(withTools, "prompts/list") {
		t.Errorf("prompts/list must not be reported without the prompts capability: %v", withTools)
	}
}
