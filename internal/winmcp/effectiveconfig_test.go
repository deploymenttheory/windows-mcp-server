//go:build windows && (amd64 || arm64)

package winmcp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/agentweave-harness/guardrails/policy"
	"github.com/deploymenttheory/agentweave-harness/wire"

	"github.com/deploymenttheory/windows-mcp-server/pkg/windows"
)

// TestEffectiveConfigEnablesEnforceHTTPS pins the narrowing direction that
// must work: a harness whose composed policy demands HTTPS binds this server's
// URL-shaped tools even when the local config never asked for it.
func TestEffectiveConfigEnablesEnforceHTTPS(t *testing.T) {
	cfg := Config{}
	deps := windows.NewBaseDeps(nil, nil, nil).WithEnforceHTTPS(enforceHTTPS(cfg))

	applyEffectiveConfig(wire.EffectiveConfig{EnforceHTTPS: true},
		&cfg, &policy.Policy{}, deps, func(string) {}, discardLogger())

	if !deps.EnforceHTTPS() {
		t.Fatal("ack's enforce_https did not reach the tool dependencies")
	}
	if !cfg.EnforceHTTPS {
		t.Fatal("ack's enforce_https did not reach cfg (guardrailEnv reads it from there)")
	}
}

// TestEffectiveConfigNeverRelaxes pins the other direction: an ack with the
// protection off must not switch off a protection the local policy set. A
// harness that could relax local protections would be a way around the
// reviewed document.
func TestEffectiveConfigNeverRelaxes(t *testing.T) {
	cfg := Config{EnforceHTTPS: true}
	deps := windows.NewBaseDeps(nil, nil, nil).WithEnforceHTTPS(enforceHTTPS(cfg))

	applyEffectiveConfig(wire.EffectiveConfig{EnforceHTTPS: false},
		&cfg, &policy.Policy{}, deps, func(string) {}, discardLogger())

	if !deps.EnforceHTTPS() || !cfg.EnforceHTTPS {
		t.Fatal("an ack with enforce_https off relaxed the locally-configured protection")
	}
}

// TestEffectiveConfigAddsProtectedPaths pins that harness-declared paths are
// refused in both directions — the wire carries no reason, so the server
// cannot tell a tamper-target from a secret and guesses neither — and that the
// locally-derived protections survive the extension.
func TestEffectiveConfigAddsProtectedPaths(t *testing.T) {
	local := filepath.Join(t.TempDir(), "creds.json")
	if err := os.WriteFile(local, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{CredentialsFile: local}
	dp := &policy.Policy{}
	deps := windows.NewBaseDeps(nil, nil, nil).WithProtectedPaths(protectedPaths(cfg, dp))

	harnessPath := filepath.Join(t.TempDir(), "harness-audit.jsonl")
	applyEffectiveConfig(wire.EffectiveConfig{ProtectedPaths: []string{harnessPath}},
		&cfg, dp, deps, func(string) {}, discardLogger())

	for _, write := range []bool{false, true} {
		if _, denied := deps.ProtectedPathViolation(harnessPath, write); !denied {
			t.Fatalf("harness-declared path not protected (write=%v)", write)
		}
	}
	if _, denied := deps.ProtectedPathViolation(local, false); !denied {
		t.Fatal("extending with harness paths dropped the local credentials-file protection")
	}
}

// TestEffectiveConfigBanner pins that the banner request actuates exactly when
// asked.
func TestEffectiveConfigBanner(t *testing.T) {
	var shown []string
	record := func(msg string) { shown = append(shown, msg) }

	cfg := Config{}
	deps := windows.NewBaseDeps(nil, nil, nil)
	applyEffectiveConfig(wire.EffectiveConfig{}, &cfg, &policy.Policy{}, deps, record, discardLogger())
	if len(shown) != 0 {
		t.Fatalf("banner shown without being asked: %q", shown)
	}
	applyEffectiveConfig(wire.EffectiveConfig{Banner: true}, &cfg, &policy.Policy{}, deps, record, discardLogger())
	if len(shown) != 1 {
		t.Fatalf("banner requested but shown %d times", len(shown))
	}
}
