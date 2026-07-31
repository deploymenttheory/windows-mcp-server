package policy

import (
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/signals"

	"path/filepath"
	"testing"
)

// TestShippedExamplePoliciesValidate keeps the migration targets honest.
//
// policy/examples/*.json are what operators are pointed at when the flag surface
// they used to configure is gone. An example that names a signal this build
// cannot evaluate, or that fails validation for any other reason, is worse than
// no example: it fails at the moment someone is already mid-migration.
//
// The registry here is the real one, so the test also catches the reverse
// direction — a signal renamed or dropped in providers.go or health.go without
// the examples being updated.
func TestShippedExamplePoliciesValidate(t *testing.T) {
	reg := signals.NewRegistry()
	signals.RegisterBuiltins(reg)
	signals.RegisterHealth(reg)
	known := reg.IDs()

	paths, err := filepath.Glob(filepath.Join("..", "..", "..", "policy", "examples", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no example policies found; the migration targets have gone missing")
	}

	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			policy, err := Load(path, known)
			if err != nil {
				t.Fatalf("shipped example does not validate: %v", err)
			}
			if len(policy.Rules) == 0 {
				t.Error("an example with no rules demonstrates nothing")
			}
			for i, r := range policy.Rules {
				if r.Name == "" {
					t.Errorf("rule #%d is unnamed; examples are read during incidents, "+
						"where a positional label is the wrong thing to be reading", i)
				}
			}
		})
	}
}

// TestAuditExampleRefusesNothing pins the property that makes audit.json the safe
// first step of a migration: it is the document an operator adopts before they
// trust the engine, so it must observe and nothing more.
func TestAuditExampleRefusesNothing(t *testing.T) {
	reg := signals.NewRegistry()
	signals.RegisterBuiltins(reg)
	signals.RegisterHealth(reg)

	policy, err := Load(filepath.Join("..", "..", "..", "policy", "examples", "audit.json"), reg.IDs())
	if err != nil {
		t.Fatal(err)
	}
	if policy.Mode != ModeAuditOnly {
		t.Fatalf("audit.json mode = %q, want %q", policy.Mode, ModeAuditOnly)
	}
	for _, r := range policy.Rules {
		if got := policy.Mode.clamp(r.OnFail); got >= SeverityDeny {
			t.Errorf("rule %q yields %v; audit.json must never refuse", r.Name, got)
		}
	}
	if a := policy.Kill.Actions; a.Isolate || a.Lock || a.Shutdown || len(a.KillProcs) > 0 {
		t.Errorf("audit.json configures containment: %+v", a)
	}
	// Nor may it alter the device's networking: an operator adopting audit.json
	// is asking to watch, not to have traffic start being dropped.
	if policy.Egress.Enabled {
		t.Error("audit.json enables the egress proxy; the observe-only example must not constrain traffic")
	}
}
