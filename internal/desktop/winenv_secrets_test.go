//go:build windows && (amd64 || arm64)

package desktop

import (
	"strings"
	"testing"
)

// TestServerOwnVarsAreWithheldFromChildren is a regression test for a real
// disclosure: powerShellEnv merged every host variable into the child
// environment, so one "Get-ChildItem Env:" from the PowerShell tool returned the
// audit-chain HMAC key and a tenant-wide Entra client secret to the model.
func TestServerOwnVarsAreWithheldFromChildren(t *testing.T) {
	secrets := map[string]string{
		"WINDOWS_MCP_AUDIT_KEY":           "audit-key-value",
		"WINDOWS_MCP_GRAPH_CLIENT_SECRET": "entra-secret-value",
		"WINDOWS_MCP_APPROVAL_KEY":        "approval-key-value",
		"windows_mcp_lowercase_check":     "case-insensitive-value",
	}
	for k, v := range secrets {
		t.Setenv(k, v)
	}
	// A variable that is genuinely the user's must still reach the child.
	t.Setenv("WMCP_TEST_USER_VAR", "user-value")

	env, _, _ := buildWindowsEnv()
	joined := strings.Join(env, "\n")

	for name, value := range secrets {
		if strings.Contains(joined, value) {
			t.Errorf("%s leaked its value into the child environment", name)
		}
	}
	if !strings.Contains(joined, "user-value") {
		t.Error("a host-provided variable that is not this server's was dropped; " +
			"the merge must only withhold WINDOWS_MCP_*")
	}
}

// TestIsServerOwnVar pins the prefix rule, including the case-insensitivity
// Windows environment names require.
func TestIsServerOwnVar(t *testing.T) {
	own := []string{
		"WINDOWS_MCP_AUDIT_KEY",
		"windows_mcp_audit_key",
		"Windows_Mcp_Anything",
		"WINDOWS_MCP_",
	}
	notOwn := []string{
		"PATH",
		"WINDOWS_MC",
		"MY_WINDOWS_MCP_KEY", // prefix rule is anchored, not a substring match
		"",
	}
	for _, name := range own {
		if !isServerOwnVar(name) {
			t.Errorf("isServerOwnVar(%q) = false, want true", name)
		}
	}
	for _, name := range notOwn {
		if isServerOwnVar(name) {
			t.Errorf("isServerOwnVar(%q) = true, want false", name)
		}
	}
}
