//go:build windows && (amd64 || arm64)

package winmcp

import (
	"strings"
	"testing"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails"
)

func TestEffectiveModeEnforceImpliedByPreflight(t *testing.T) {
	if m := effectiveMode(Config{}); m != guardrails.ModeOff {
		t.Errorf("bare config → off, got %s", m)
	}
	if m := effectiveMode(Config{Security: true}); m != guardrails.ModeEnforce {
		t.Errorf("--security → enforce, got %s", m)
	}
	if m := effectiveMode(Config{WithMDM: true}); m != guardrails.ModeEnforce {
		t.Errorf("a pre-flight check → enforce, got %s", m)
	}
	if m := effectiveMode(Config{IsNotAdmin: true}); m != guardrails.ModeEnforce {
		t.Errorf("is-not-admin → enforce, got %s", m)
	}
	// Explicit audit is respected (not downgraded).
	if m := effectiveMode(Config{Guardrails: "audit"}); m != guardrails.ModeAudit {
		t.Errorf("explicit audit respected, got %s", m)
	}
}

func TestPreflightExtrasMapping(t *testing.T) {
	got := preflightExtras(Config{
		WithMDM:             true,
		WithUserContext:     true,
		IsNotAdmin:          true,
		WithLoggedOnAccount: `^svc-\d+$`,
		Guardrail:           []string{"secure-boot"},
	})
	joined := strings.Join(got, ",")
	for _, want := range []string{"secure-boot", "mdm-enrolled", "run-context", "not-admin", `logged-on-account=^svc-\d+$`} {
		if !strings.Contains(joined, want) {
			t.Errorf("preflightExtras missing %q (have %s)", want, joined)
		}
	}
}

func TestKillActionConfigDefaultIsolate(t *testing.T) {
	kc := killActionConfig(Config{KillActionIsolate: true})
	if !kc.Isolate || kc.Shutdown || kc.KillProcs || kc.Lock {
		t.Errorf("default kill action should be isolate-only, got %+v", kc)
	}
}
