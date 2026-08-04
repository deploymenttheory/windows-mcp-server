//go:build windows && (amd64 || arm64)

package winmcp

import (
	"os"
	"path/filepath"
	"testing"
)

// TestAuditKeyIsGeneratedAndReused pins keyed-by-default.
//
// An unkeyed chain is tamper-evident, not unforgeable: anyone able to write the
// file could edit an entry and recompute every hash after it, and VerifyChain
// reported it clean. Keying was opt-in via an environment variable nobody sets,
// which also meant the keyed path -- including the manifest MACs -- was the one
// least exercised.
func TestAuditKeyIsGeneratedAndReused(t *testing.T) {
	dir := t.TempDir() + string(os.PathSeparator) // trailing separator marks a directory destination
	t.Setenv("WINDOWS_MCP_AUDIT_KEY", "")

	first := resolveAuditKey(dir, nil)
	if len(first) == 0 {
		t.Fatal("a file destination must get a key by default")
	}
	second := resolveAuditKey(dir, nil)
	if string(first) != string(second) {
		t.Error("the key must persist across starts, or chains from different sessions " +
			"cannot be verified together")
	}
	if _, err := os.Stat(filepath.Join(dir, auditKeyFile)); err != nil {
		t.Errorf("the key should be persisted beside the audit directory: %v", err)
	}
}

// TestOperatorKeyWins keeps the out-of-band key authoritative. A key stored next
// to the log is readable by anyone who can rewrite the log, so an operator
// supplying one through the environment must not be overridden by a generated file.
func TestOperatorKeyWins(t *testing.T) {
	dir := t.TempDir() + string(os.PathSeparator)
	t.Setenv("WINDOWS_MCP_AUDIT_KEY", "operator-supplied")

	if got := string(resolveAuditKey(dir, nil)); got != "operator-supplied" {
		t.Errorf("resolveAuditKey = %q, want the operator's key", got)
	}
	if _, err := os.Stat(filepath.Join(dir, auditKeyFile)); err == nil {
		t.Error("no key file should be written when the operator supplied one")
	}
}

// TestStderrDestinationGetsNoKey: there is no file to protect and nowhere beside
// it to keep a key.
func TestStderrDestinationGetsNoKey(t *testing.T) {
	t.Setenv("WINDOWS_MCP_AUDIT_KEY", "")
	for _, dest := range []string{"", "stderr"} {
		if key := resolveAuditKey(dest, nil); len(key) != 0 {
			t.Errorf("destination %q should get no key, got %d bytes", dest, len(key))
		}
	}
}
