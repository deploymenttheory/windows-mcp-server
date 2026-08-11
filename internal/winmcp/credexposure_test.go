//go:build windows && (amd64 || arm64)

package winmcp

import (
	"reflect"
	"testing"

	"github.com/deploymenttheory/agentweave-harness/guardrails/policy"
	"github.com/deploymenttheory/windows-mcp-server/pkg/inventory"
	"github.com/deploymenttheory/windows-mcp-server/pkg/windows"
)

func TestSplitCredentialExposure(t *testing.T) {
	shell := windows.ToolsetShell
	fs := windows.ToolsetFilesystem
	screen := windows.ToolsetScreen
	creds := windows.ToolsetCredentials

	for _, tc := range []struct {
		name                   string
		enabled                []inventory.ToolsetMetadata
		ack                    policy.StringSet
		wantUnacked, wantAcked []string
	}{
		{"shell unacknowledged refuses", []inventory.ToolsetMetadata{screen, shell, creds}, nil, []string{"shell"}, nil},
		{"filesystem unacknowledged refuses", []inventory.ToolsetMetadata{fs, creds}, nil, []string{"filesystem"}, nil},
		{"shell acknowledged proceeds", []inventory.ToolsetMetadata{shell, creds}, policy.StringSet{"shell"}, nil, []string{"shell"}},
		{"only shell acked, filesystem still refuses", []inventory.ToolsetMetadata{shell, fs, creds}, policy.StringSet{"shell"}, []string{"filesystem"}, []string{"shell"}},
		{"no risky toolset served", []inventory.ToolsetMetadata{screen, creds}, nil, nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			unacked, acked := splitCredentialExposure(tc.enabled, tc.ack, false)
			if !reflect.DeepEqual(unacked, tc.wantUnacked) {
				t.Errorf("unacknowledged = %v, want %v", unacked, tc.wantUnacked)
			}
			if !reflect.DeepEqual(acked, tc.wantAcked) {
				t.Errorf("acknowledged = %v, want %v", acked, tc.wantAcked)
			}
		})
	}
}

// TestFirstLineSupportWithCredentialsRefusesByDefault exercises the whole
// persona -> toolset -> exposure path: first-line-support carries shell, so a
// --credentials-file must refuse it unless the policy acknowledges shell.
func TestFirstLineSupportWithCredentialsRefusesByDefault(t *testing.T) {
	cfg := Config{Persona: "first-line-support", CredentialsFile: `C:\creds.json`}
	inv, _, err := buildInventory(cfg, false)
	if err != nil {
		t.Fatalf("buildInventory: %v", err)
	}

	unacked, _ := splitCredentialExposure(inv.EnabledToolsets(), nil, false)
	if len(unacked) != 1 || unacked[0] != "shell" {
		t.Fatalf("first-line-support + credentials should expose shell, got %v", unacked)
	}

	unacked2, acked2 := splitCredentialExposure(inv.EnabledToolsets(), policy.StringSet{"shell"}, false)
	if len(unacked2) != 0 {
		t.Errorf("acknowledging shell should clear the refusal, got %v", unacked2)
	}
	if len(acked2) != 1 || acked2[0] != "shell" {
		t.Errorf("acknowledged = %v, want [shell]", acked2)
	}
}

// TestBusinessUserWithCredentialsIsFine confirms the check does not fire for a
// persona that carries neither shell nor filesystem.
// TestUnmaskedTargetsWidenTheExposureSet pins the one case where a perception
// toolset becomes a credential-disclosure surface.
//
// Screen and interaction are safe while injection requires a destination that
// reports itself as masked: the agent picks where the keystrokes go, but not
// somewhere it can read them back. A credential declaring allow_unmasked_target
// gives that up, and the startup check has to notice.
func TestUnmaskedTargetsWidenTheExposureSet(t *testing.T) {
	inv, _, err := buildInventory(Config{Persona: "business-user"}, false)
	if err != nil {
		t.Fatal(err)
	}
	enabled := inv.EnabledToolsets()

	if unacked, _ := splitCredentialExposure(enabled, nil, false); len(unacked) != 0 {
		t.Errorf("with masked destinations enforced, business-user is not an exposure; got %v", unacked)
	}
	unacked, _ := splitCredentialExposure(enabled, nil, true)
	if len(unacked) == 0 {
		t.Error("a credential opting out of the masked-destination check makes the perception " +
			"toolsets a way to read the secret back; startup must not pass silently")
	}
}

func TestBusinessUserWithCredentialsIsFine(t *testing.T) {
	cfg := Config{Persona: "business-user", CredentialsFile: `C:\creds.json`}
	inv, _, err := buildInventory(cfg, false)
	if err != nil {
		t.Fatalf("buildInventory: %v", err)
	}
	if unacked, _ := splitCredentialExposure(inv.EnabledToolsets(), nil, false); len(unacked) != 0 {
		t.Errorf("business-user exposes no risky toolset, got %v", unacked)
	}
}
