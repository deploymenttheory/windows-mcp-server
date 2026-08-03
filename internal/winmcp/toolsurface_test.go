//go:build windows && (amd64 || arm64)

package winmcp

import (
	"context"
	"strings"
	"testing"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/policy"
	"github.com/deploymenttheory/windows-mcp-server/pkg/windows"
)

// TestGuardrailToolsAlwaysServed pins that GuardrailStatus and Kill survive
// --exclude-tools: they are registered outside the inventory, so no inventory
// filter can remove them. The assertion is against the real served tools/list.
func TestGuardrailToolsAlwaysServed(t *testing.T) {
	surface, err := CaptureSurface(context.Background(), Config{
		ExcludeTools: []string{"GuardrailStatus", "Kill"},
	})
	if err != nil {
		t.Fatalf("CaptureSurface: %v", err)
	}
	served := string(surface.ToolsListResult)
	for _, name := range []string{"GuardrailStatus", "Kill"} {
		if !strings.Contains(served, `"`+name+`"`) {
			t.Errorf("%s must be served despite --exclude-tools; tools/list did not contain it", name)
		}
	}
}

// TestGuardrailToolsAbsentFromPolicyIndex documents the deliberate exemption: the
// policy tool index is built from the inventory, which does not contain the
// guardrail tools, so a rule matching annotation:destructive does not cover Kill.
// Denying the agent's own stop lever under bad posture would suppress a safety
// action; Kill routes to StopGracefully unless the policy arms containment.
func TestGuardrailToolsAbsentFromPolicyIndex(t *testing.T) {
	inv, _, err := buildInventory(Config{Toolsets: []string{"all"}}, false)
	if err != nil {
		t.Fatalf("buildInventory: %v", err)
	}
	idx := newToolIndex(context.Background(), inv)

	for _, name := range []string{"GuardrailStatus", "Kill"} {
		if _, ok := idx.Lookup(name); ok {
			t.Errorf("%s should be absent from the policy tool index (it belongs to no toolset)", name)
		}
	}
	// A normal tool is present, so the index is not simply empty.
	if _, ok := idx.Lookup("Snapshot"); !ok {
		t.Error("a normal tool (Snapshot) should be in the policy tool index")
	}
}

func TestToolsOutsidePersona(t *testing.T) {
	// first-line-support carries shell/diagnostics but not filesystem or web.
	inv, _, err := buildInventory(Config{Persona: "first-line-support"}, false)
	if err != nil {
		t.Fatalf("buildInventory: %v", err)
	}
	enabled := inv.EnabledToolsets()

	// FileSystem (filesystem toolset) is outside the persona; PowerShell (shell) is in.
	if out := toolsOutsidePersona([]string{"FileSystem"}, enabled); len(out) != 1 || out[0] != "FileSystem" {
		t.Errorf("FileSystem should be flagged as outside first-line-support, got %v", out)
	}
	if out := toolsOutsidePersona([]string{"PowerShell"}, enabled); len(out) != 0 {
		t.Errorf("PowerShell is within first-line-support and should not be flagged, got %v", out)
	}
	// Always-served tools belong to no toolset and are never flagged.
	if out := toolsOutsidePersona([]string{"Kill"}, enabled); len(out) != 0 {
		t.Errorf("Kill belongs to no toolset and must not be flagged, got %v", out)
	}
}

func TestProtectedPathsCoverGuardrailFiles(t *testing.T) {
	cfg := Config{
		PolicyConfig:    `C:\policy.json`,
		CredentialsFile: `C:\secrets\creds.json`,
	}
	dp := &policy.Policy{Transparency: policy.TransparencyPolicy{AuditSink: `C:\ProgramData\windows-mcp\audit\`}}

	deps := windows.NewBaseDeps(nil, nil, nil).WithProtectedPaths(protectedPaths(cfg, dp))

	for _, tc := range []struct {
		name       string
		path       string
		write      bool
		wantDenied bool
	}{
		{"read credentials denied", `C:\secrets\creds.json`, false, true},
		{"write credentials denied", `C:\secrets\creds.json`, true, true},
		{"read policy allowed", `C:\policy.json`, false, false},
		{"write policy denied", `C:\policy.json`, true, true},
		{"read audit allowed", `C:\ProgramData\windows-mcp\audit\session-x.audit.jsonl`, false, false},
		{"write audit file denied", `C:\ProgramData\windows-mcp\audit\session-x.audit.jsonl`, true, true},
		{"write audit manifest denied", `C:\ProgramData\windows-mcp\audit\audit-manifest.jsonl`, true, true},
		{"unrelated file allowed", `C:\Users\me\Desktop\notes.txt`, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, denied := deps.ProtectedPathViolation(tc.path, tc.write)
			if denied != tc.wantDenied {
				t.Errorf("ProtectedPathViolation(%q, write=%v) denied=%v, want %v", tc.path, tc.write, denied, tc.wantDenied)
			}
		})
	}
}
