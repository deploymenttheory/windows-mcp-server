//go:build windows && (amd64 || arm64)

package winmcp

import (
	"context"
	"testing"

	"github.com/deploymenttheory/agentweave-harness/guardrails/audit"
	"github.com/deploymenttheory/agentweave-harness/guardrails/egress"
	"github.com/deploymenttheory/agentweave-harness/guardrails/policy"
)

// egressTestPolicy builds an enabled egress policy with no OS-enforcement
// demands, so the paths under test run unprivileged.
func egressTestPolicy() *policy.Policy {
	return &policy.Policy{
		Version: 1,
		Egress: policy.EgressPolicy{
			Enabled: true,
			Listen:  "127.0.0.1:0",
			Allow:   policy.StringSet{"api.example.com"},
		},
	}
}

// TestHarnessModeSkipsLocalProxyOnlyWhenPortAnnounced pins the Phase-6
// boundary: with no announced port the server runs its own listener exactly
// as before; with one announced it runs none and delegates — never both,
// never neither.
func TestHarnessModeSkipsLocalProxyOnlyWhenPortAnnounced(t *testing.T) {
	log := audit.NewAuditLog(nil)

	// No announcement: the local proxy starts (standalone behavior).
	svc, cleanup, _, err := provisionEgress(
		context.Background(), egressTestPolicy(), log, discardLogger(), harnessEgress{})
	if err != nil {
		t.Fatalf("standalone provisioning failed: %v", err)
	}
	if svc == nil {
		t.Fatal("no announced port, but the local proxy was not started")
	}
	cleanup()

	// Announced: no local listener; enforcement is delegated.
	svc, cleanup, suspend, err := provisionEgress(
		context.Background(), egressTestPolicy(), log, discardLogger(), harnessEgress{
			Port:       48123,
			Executable: `C:\hn\agentweave-harness.exe`,
		})
	if err != nil {
		t.Fatalf("delegated provisioning failed: %v", err)
	}
	if svc != nil {
		t.Fatal("port announced, but a local proxy was started anyway — two proxies, one session")
	}
	// The teardown pair must be callable in either order, like the local path's.
	suspend()
	cleanup()
}

// TestDelegatedEgressStillRefusesUnelevatedEnforcement pins that delegation
// does not weaken the refusal: a policy naming applications still needs
// elevation for the firewall work, whichever process serves the proxy.
func TestDelegatedEgressStillRefusesUnelevatedEnforcement(t *testing.T) {
	if (egress.WindowsEnforcer{}).Elevated() {
		t.Skip("running elevated; the refusal under test cannot fire")
	}
	pol := egressTestPolicy()
	pol.Egress.Applications = policy.StringSet{`C:\Tools\agent.exe`}

	_, _, _, err := provisionEgress(
		context.Background(), pol, audit.NewAuditLog(nil), discardLogger(), harnessEgress{Port: 48123})
	if err == nil {
		t.Fatal("unelevated server accepted an enforcement-demanding policy under delegation")
	}
}
