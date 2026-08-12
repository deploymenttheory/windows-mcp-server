//go:build windows && (amd64 || arm64)

package winmcp

import (
	"encoding/json"
	"log/slog"
	"sync/atomic"
	"testing"

	"github.com/deploymenttheory/agentweave-harness/guardrails/egress"
	"github.com/deploymenttheory/agentweave-harness/wire"
)

// fakeEnforcer records what the egress rungs asked the OS to do, without
// touching a firewall, so the rung logic is testable off an elevated host.
type fakeEnforcer struct {
	elevated    bool
	applied     *egress.EnforceSpec
	restoreRuns atomic.Int32
	suspended   atomic.Bool
	applyErr    error
}

func (f *fakeEnforcer) Elevated() bool { return f.elevated }

func (f *fakeEnforcer) Apply(spec egress.EnforceSpec) (func() error, error) {
	if f.applyErr != nil {
		return nil, f.applyErr
	}
	f.applied = &spec
	return func() error { f.restoreRuns.Add(1); return nil }, nil
}

func (f *fakeEnforcer) Recover() (int, error) { return 0, nil }
func (f *fakeEnforcer) Suspend() error        { f.suspended.Store(true); return nil }

func egressRungTable(t *testing.T, enf egress.Enforcer, holder *egressRestoreHolder) map[string]rungFunc {
	t.Helper()
	return buildRungs(rungPrimitives{
		Egress:        enf,
		EgressRestore: holder,
		Logger:        slog.New(slog.DiscardHandler),
	})
}

// TestEgressApplyRungActuatesAndStashesRestore pins the apply path: the rung
// hands the enforcer a spec pointed at the announced proxy port with the
// harness executable, and stashes the undo where the restore rung and the
// exit defer can reach it.
func TestEgressApplyRungActuatesAndStashesRestore(t *testing.T) {
	enf := &fakeEnforcer{elevated: true}
	holder := &egressRestoreHolder{}
	rungs := egressRungTable(t, enf, holder)

	params, _ := json.Marshal(wire.EgressApplyParams{
		ProxyPort:       48123,
		ProxyExecutable: `C:\hn\agentweave-harness.exe`,
		Applications:    []string{`C:\Tools\agent.exe`},
	})
	res := rungs[wire.RungEgressApply](params)
	if !res.OK {
		t.Fatalf("apply refused: %+v", res)
	}
	if enf.applied == nil || enf.applied.ProxyAddr != "127.0.0.1:48123" {
		t.Fatalf("spec not pointed at the announced port: %+v", enf.applied)
	}
	if enf.applied.ProxyExecutable != `C:\hn\agentweave-harness.exe` {
		t.Fatalf("harness executable not carried into the spec: %+v", enf.applied)
	}

	// The stashed restore runs exactly once across the explicit rung and the
	// exit defer.
	if r := rungs[wire.RungEgressRestore](nil); !r.OK {
		t.Fatalf("restore rung failed: %+v", r)
	}
	_ = holder.run() // the exit defer, after an explicit restore
	if got := enf.restoreRuns.Load(); got != 1 {
		t.Fatalf("restore ran %d times, want exactly 1", got)
	}
}

// TestEgressApplyRungRefusesUnelevatedFirewallTier pins that the firewall
// tiers still need elevation on the actuation path, mirroring the local
// path's refusal — a skip is reported, never faked.
func TestEgressApplyRungRefusesUnelevatedFirewallTier(t *testing.T) {
	enf := &fakeEnforcer{elevated: false}
	rungs := egressRungTable(t, enf, &egressRestoreHolder{})

	params, _ := json.Marshal(wire.EgressApplyParams{ProxyPort: 1, BlockAllOutbound: true})
	res := rungs[wire.RungEgressApply](params)
	if res.OK || res.SkippedReason != "not elevated" {
		t.Fatalf("unelevated global block was not refused: %+v", res)
	}
	if enf.applied != nil {
		t.Fatal("a refused apply still touched the enforcer")
	}
}

// TestEgressSuspendRung pins the containment hook.
func TestEgressSuspendRung(t *testing.T) {
	enf := &fakeEnforcer{elevated: true}
	rungs := egressRungTable(t, enf, &egressRestoreHolder{})
	if res := rungs[wire.RungEgressSuspend](nil); !res.OK {
		t.Fatalf("suspend refused: %+v", res)
	}
	if !enf.suspended.Load() {
		t.Fatal("suspend rung did not reach the enforcer")
	}
}
