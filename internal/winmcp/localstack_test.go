//go:build windows && (amd64 || arm64)

package winmcp

import (
	"context"
	"errors"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// namedMiddleware builds a middleware whose composed handler reports the given
// name, so a test can recover which layers receivingChain kept and their order.
// Function values are not comparable in Go; the name-carrying error is the
// identity.
func namedMiddleware(name string) mcp.Middleware {
	return func(mcp.MethodHandler) mcp.MethodHandler {
		return func(context.Context, string, mcp.Request) (mcp.Result, error) {
			return nil, errors.New(name)
		}
	}
}

// localStackInputs is the full seven-layer standalone stack, in RunStdio's
// order.
func localStackInputs() (auditMW, telemetryMW mcp.Middleware, rugpullMWs []mcp.Middleware, enforceMW mcp.Middleware) {
	return namedMiddleware("audit"),
		namedMiddleware("telemetry"),
		[]mcp.Middleware{
			namedMiddleware("rp-tool"),
			namedMiddleware("rp-prompt"),
			namedMiddleware("rp-resource"),
			namedMiddleware("rp-discover"),
		},
		namedMiddleware("enforce")
}

// chainNames maps an assembled chain back to its layer names.
func chainNames(t *testing.T, chain []mcp.Middleware) []string {
	t.Helper()
	names := make([]string, 0, len(chain))
	for _, mw := range chain {
		_, err := mw(nil)(context.Background(), "", nil)
		if err == nil {
			t.Fatal("chain contains a middleware not built by namedMiddleware")
		}
		names = append(names, err.Error())
	}
	return names
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestHarnessModeInstallsNoLocalEnforcement pins the shed: under an enforcing
// harness the local receiving chain is the audit layer alone — no local policy
// engine, rug-pull or telemetry runs against traffic the harness has already
// decided, audited and fingerprinted on the wire.
func TestHarnessModeInstallsNoLocalEnforcement(t *testing.T) {
	auditMW, telemetryMW, rugpullMWs, enforceMW := localStackInputs()
	got := chainNames(t, receivingChain(true, auditMW, telemetryMW, rugpullMWs, enforceMW))
	if !equalStrings(got, []string{"audit"}) {
		t.Fatalf("enforcing harness installed %v, want [audit] only", got)
	}
}

// TestHarnessModeStillAuditsLocally pins the other half of the two-chain
// model: shedding enforcement never sheds the local audit record. This host's
// chain is the account of what the process actually served, kept so the
// harness's account of the session is not the only one.
func TestHarnessModeStillAuditsLocally(t *testing.T) {
	auditMW, telemetryMW, rugpullMWs, enforceMW := localStackInputs()
	for _, enforcing := range []bool{true, false} {
		got := chainNames(t, receivingChain(enforcing, auditMW, telemetryMW, rugpullMWs, enforceMW))
		if len(got) == 0 || got[0] != "audit" {
			t.Fatalf("harnessEnforcing=%v: audit is not the outermost layer: %v", enforcing, got)
		}
	}
}

// TestObserveAckKeepsFullLocalStack pins that anything short of an enforce ack
// changes nothing: the full standalone stack runs, in the pinned order, with
// enforce innermost. An observe-mode harness records and fingerprints but
// refuses nothing, so the local stack must keep doing all of it.
func TestObserveAckKeepsFullLocalStack(t *testing.T) {
	auditMW, telemetryMW, rugpullMWs, enforceMW := localStackInputs()
	got := chainNames(t, receivingChain(false, auditMW, telemetryMW, rugpullMWs, enforceMW))
	want := []string{"audit", "telemetry", "rp-tool", "rp-prompt", "rp-resource", "rp-discover", "enforce"}
	if !equalStrings(got, want) {
		t.Fatalf("observe mode chain is %v, want %v", got, want)
	}
	// Telemetry is optional; its absence must not drop any other layer.
	got = chainNames(t, receivingChain(false, auditMW, nil, rugpullMWs, enforceMW))
	want = []string{"audit", "rp-tool", "rp-prompt", "rp-resource", "rp-discover", "enforce"}
	if !equalStrings(got, want) {
		t.Fatalf("observe mode chain without telemetry is %v, want %v", got, want)
	}
}
