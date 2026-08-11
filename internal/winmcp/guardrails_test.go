//go:build windows && (amd64 || arm64)

package winmcp

import (
	"strings"
	"testing"

	"github.com/deploymenttheory/agentweave-harness/guardrails/audit"
	"github.com/deploymenttheory/agentweave-harness/guardrails/contain"
	"github.com/deploymenttheory/agentweave-harness/guardrails/policy"
)

// TestEnforceHTTPSResolution pins that the setting comes from Config, which
// RunStdio populates from the policy document. It is on Config rather than read
// from the policy at each call site because it has to reach the tool
// dependencies and the guardrail Env, neither of which carries a policy.
func TestEnforceHTTPSResolution(t *testing.T) {
	if enforceHTTPS(Config{}) {
		t.Error("enforceHTTPS must default off")
	}
	if !enforceHTTPS(Config{EnforceHTTPS: true}) {
		t.Error("enforceHTTPS must follow the policy-derived setting")
	}
}

// TestKillPolicyConfigMapsContainment checks the policy's containment actions
// reach the executor, and that a policy configuring none produces none.
func TestKillPolicyConfigMapsContainment(t *testing.T) {
	none := killPolicyConfig(&policy.Policy{})
	if none.Isolate || none.Lock || none.Shutdown || none.KillProcs {
		t.Errorf("a policy with no actions must contain nothing, got %+v", none)
	}

	full := killPolicyConfig(&policy.Policy{Kill: policy.KillPolicy{
		Actions: policy.KillActions{
			Isolate:   true,
			Lock:      true,
			KillProcs: []string{"evil.exe"},
		},
	}})
	if !full.Isolate || !full.Lock || !full.KillProcs || full.Shutdown {
		t.Errorf("containment actions did not map through: %+v", full)
	}
	if len(full.ProcNames) != 1 || full.ProcNames[0] != "evil.exe" {
		t.Errorf("process names did not map through: %+v", full.ProcNames)
	}
}

// TestGuardrailEnvCarriesEnforceHTTPS proves the setting actually reaches the
// guardrail checks, which is what lets remote-policy refuse a plaintext endpoint.
func TestGuardrailEnvCarriesEnforceHTTPS(t *testing.T) {
	if env := guardrailEnv(Config{EnforceHTTPS: true}, nil, nil); !env.EnforceHTTPS {
		t.Error("guardrailEnv must propagate EnforceHTTPS")
	}
	if env := guardrailEnv(Config{}, nil, nil); env.EnforceHTTPS {
		t.Error("guardrailEnv must not set EnforceHTTPS when off")
	}
}

// capturingDest records audit entries so the disarmed path can be inspected.
type capturingDest struct{ entries []audit.AuditEntry }

func (s *capturingDest) Write(e audit.AuditEntry) error {
	s.entries = append(s.entries, e)
	return nil
}
func (s *capturingDest) Flush() error { return nil }
func (s *capturingDest) Close() error { return nil }

func TestTripFuncArmedTripsTheSwitch(t *testing.T) {
	var reason string
	kill := contain.NewKillSwitch(func(r string) { reason = r })
	dest := &capturingDest{}

	trip := tripFunc("rugpull", true, kill, audit.NewAuditLog(dest), nil)
	trip("manifest drift")

	if tripped, _ := kill.Tripped(); !tripped {
		t.Error("armed trigger must trip the kill switch")
	}
	if reason != "manifest drift" {
		t.Errorf("trip reason = %q, want the caller's reason", reason)
	}
}

// TestTripFuncDisarmedAuditsWithoutContaining is the transparency guarantee: a
// disarmed trigger still lands in the hash-chained audit log (so the operator can
// see it fired) while containing nothing.
func TestTripFuncDisarmedAuditsWithoutContaining(t *testing.T) {
	var tripped bool
	kill := contain.NewKillSwitch(func(string) { tripped = true })
	dest := &capturingDest{}

	trip := tripFunc("posture-drift", false, kill, audit.NewAuditLog(dest), nil)
	trip("secure-boot=fail")

	if tripped {
		t.Error("disarmed trigger must not contain")
	}
	if got, _ := kill.Tripped(); got {
		t.Error("disarmed trigger must leave the kill switch untripped")
	}
	if len(dest.entries) != 1 {
		t.Fatalf("want 1 audit entry, got %d", len(dest.entries))
	}
	e := dest.entries[0]
	if e.Event != "killswitch.disarmed" {
		t.Errorf("event = %q, want killswitch.disarmed", e.Event)
	}
	payload := string(e.Payload)
	for _, want := range []string{"posture-drift", "secure-boot=fail"} {
		if !strings.Contains(payload, want) {
			t.Errorf("audit payload missing %q: %s", want, payload)
		}
	}
	if err := audit.VerifyChain(dest.entries); err != nil {
		t.Errorf("disarmed entries must keep the chain verifiable: %v", err)
	}
}

// TestTripFuncNilAuditIsSafe covers the tests-and-degraded path where no audit
// log is wired.
func TestTripFuncNilAuditIsSafe(t *testing.T) {
	kill := contain.NewKillSwitch(nil)
	tripFunc("sentinel", false, kill, nil, nil)("no audit configured")
	if tripped, _ := kill.Tripped(); tripped {
		t.Error("disarmed trigger must not trip even without an audit log")
	}
}
