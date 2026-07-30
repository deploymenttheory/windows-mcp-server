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

// capturingSink records audit entries so the disarmed path can be inspected.
type capturingSink struct{ entries []guardrails.AuditEntry }

func (s *capturingSink) Write(e guardrails.AuditEntry) error {
	s.entries = append(s.entries, e)
	return nil
}
func (s *capturingSink) Flush() error { return nil }
func (s *capturingSink) Close() error { return nil }

func TestTripFuncArmedTripsTheSwitch(t *testing.T) {
	var reason string
	kill := guardrails.NewKillSwitch(func(r string) { reason = r })
	sink := &capturingSink{}

	trip := tripFunc("rugpull", true, kill, guardrails.NewAuditLog(sink), nil)
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
	kill := guardrails.NewKillSwitch(func(string) { tripped = true })
	sink := &capturingSink{}

	trip := tripFunc("posture-drift", false, kill, guardrails.NewAuditLog(sink), nil)
	trip("secure-boot=fail")

	if tripped {
		t.Error("disarmed trigger must not contain")
	}
	if got, _ := kill.Tripped(); got {
		t.Error("disarmed trigger must leave the kill switch untripped")
	}
	if len(sink.entries) != 1 {
		t.Fatalf("want 1 audit entry, got %d", len(sink.entries))
	}
	e := sink.entries[0]
	if e.Event != "killswitch.disarmed" {
		t.Errorf("event = %q, want killswitch.disarmed", e.Event)
	}
	payload := string(e.Payload)
	for _, want := range []string{"posture-drift", "secure-boot=fail"} {
		if !strings.Contains(payload, want) {
			t.Errorf("audit payload missing %q: %s", want, payload)
		}
	}
	if err := guardrails.VerifyChain(sink.entries); err != nil {
		t.Errorf("disarmed entries must keep the chain verifiable: %v", err)
	}
}

// TestTripFuncNilAuditIsSafe covers the tests-and-degraded path where no audit
// log is wired.
func TestTripFuncNilAuditIsSafe(t *testing.T) {
	kill := guardrails.NewKillSwitch(nil)
	tripFunc("sentinel", false, kill, nil, nil)("no audit configured")
	if tripped, _ := kill.Tripped(); tripped {
		t.Error("disarmed trigger must not trip even without an audit log")
	}
}
