//go:build windows && (amd64 || arm64)

package winmcp

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deploymenttheory/agentweave-harness/guardrails/signals"
	"github.com/deploymenttheory/agentweave-harness/wire"
)

// harnessEnd is the test's stand-in for the harness: it drives the far end of
// an in-memory pipe, completing the handshake and exchanging control messages.
type harnessEnd struct {
	r *wire.Reader
	w *wire.Writer
}

// newServantRig wires a servant to a fake harness over net.Pipe and completes
// the handshake with the given ack. It returns the servant, the harness end,
// and the servant's serve loop already running.
func newServantRig(t *testing.T, deps servantDeps, ack wire.HelloAck) (*harnessServant, *harnessEnd) {
	t.Helper()
	srvConn, harnConn := net.Pipe()
	harn := &harnessEnd{r: wire.NewReader(harnConn), w: wire.NewWriter(harnConn)}

	// The harness must answer hello with hello.ack concurrently, because the
	// pipe is unbuffered — connectServant blocks writing hello until the far
	// end reads it.
	helloCh := make(chan wire.Hello, 1)
	go func() {
		env, err := harn.r.Read()
		if err != nil {
			t.Errorf("harness reading hello: %v", err)
			return
		}
		var h wire.Hello
		_ = wire.Unmarshal(env, &h)
		helloCh <- h
		ackEnv, _ := wire.Marshal(wire.MaxProtocolVersion, wire.TypeHelloAck, "", "", ack)
		_ = harn.w.Write(ackEnv)
	}()

	if deps.Logger == nil {
		deps.Logger = slog.New(slog.DiscardHandler)
	}
	servant, _, err := connectServant(srvConn, "tok", "test", "stamp", deps)
	if err != nil {
		t.Fatalf("connectServant: %v", err)
	}
	<-helloCh

	t.Cleanup(func() { _ = servant.Close(); _ = harnConn.Close() })
	return servant, harn
}

func (h *harnessEnd) request(t *testing.T, typ, id string, payload any) {
	t.Helper()
	env, err := wire.Marshal(wire.MaxProtocolVersion, typ, id, "", payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.w.Write(env); err != nil {
		t.Fatal(err)
	}
}

func (h *harnessEnd) read(t *testing.T) wire.Envelope {
	t.Helper()
	env, err := h.r.Read()
	if err != nil {
		t.Fatalf("harness read: %v", err)
	}
	return env
}

// fakeRegistry builds a registry with one always-passing signal.
func fakeRegistry(id string, calls *atomic.Int32) *signals.Registry {
	reg := signals.NewRegistry()
	reg.Register(signals.Guardrail{
		ID: id,
		Check: func(_ context.Context, _ *signals.Env) signals.Result {
			if calls != nil {
				calls.Add(1)
			}
			return signals.Result{ID: id, Status: signals.Pass, Detail: "ok"}
		},
	})
	return reg
}

func baseDeps(reg *signals.Registry) servantDeps {
	return servantDeps{
		Registry: reg,
		EnvFn:    func() *signals.Env { return &signals.Env{} },
		Rungs:    map[string]rungFunc{},
		Alive:    func() bool { return true },
		Logger:   slog.New(slog.DiscardHandler),
	}
}

// TestServantHelloAdvertisesCapabilities pins that the servant declares the
// signals it can evaluate and the rungs it can execute, so the harness never
// has to guess and a policy needing more than is offered can refuse at
// handshake.
func TestServantHelloAdvertisesCapabilities(t *testing.T) {
	reg := fakeRegistry("tpm", nil)
	deps := baseDeps(reg)
	deps.Rungs = map[string]rungFunc{wire.RungBanner: func(json.RawMessage) wire.ActuateResult { return wire.ActuateResult{} }}
	deps.Elevated = true

	srvConn, harnConn := net.Pipe()
	defer func() { _ = harnConn.Close() }()
	helloCh := make(chan wire.Hello, 1)
	go func() {
		env, _ := wire.NewReader(harnConn).Read()
		var h wire.Hello
		_ = wire.Unmarshal(env, &h)
		helloCh <- h
		ackEnv, _ := wire.Marshal(1, wire.TypeHelloAck, "", "", wire.HelloAck{Mode: wire.ModeObserve})
		_ = wire.NewWriter(harnConn).Write(ackEnv)
	}()

	servant, _, err := connectServant(srvConn, "tok", "v1", "s1", deps)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = servant.Close() }()

	h := <-helloCh
	if h.Token != "tok" || h.ServerVersion != "v1" {
		t.Fatalf("hello identity = %+v", h)
	}
	if len(h.Capabilities.Signals) != 1 || h.Capabilities.Signals[0] != "tpm" {
		t.Fatalf("advertised signals = %v", h.Capabilities.Signals)
	}
	if len(h.Capabilities.Actuators) != 1 || h.Capabilities.Actuators[0] != wire.RungBanner {
		t.Fatalf("advertised actuators = %v", h.Capabilities.Actuators)
	}
	if !h.Capabilities.Elevated {
		t.Error("elevated not advertised")
	}
}

// TestServantSignalEvaluateUsesDeclaredIdsOnly pins that a requested id runs
// its registered check, while an id the registry does not carry is reported
// errored rather than dispatched anywhere — the channel cannot make this host
// compute anything but registered posture checks.
func TestServantSignalEvaluateUsesDeclaredIdsOnly(t *testing.T) {
	var calls atomic.Int32
	reg := fakeRegistry("tpm", &calls)
	servant, harn := newServantRig(t, baseDeps(reg), wire.HelloAck{Mode: wire.ModeObserve})
	go servant.serve(context.Background())

	harn.request(t, wire.TypeSignalEvaluate, "q1", wire.SignalEvaluate{IDs: []string{"tpm", "not-a-signal"}})

	env := harn.read(t)
	if env.Type != wire.TypeSignalResult || env.Re != "q1" {
		t.Fatalf("reply = %+v", env)
	}
	var res wire.SignalResult
	if err := wire.Unmarshal(env, &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Results) != 2 {
		t.Fatalf("want 2 results, got %d", len(res.Results))
	}
	var known, unknown signals.Result
	_ = json.Unmarshal(res.Results[0], &known)
	_ = json.Unmarshal(res.Results[1], &unknown)
	if known.Status != signals.Pass {
		t.Errorf("declared signal status = %v", known.Status)
	}
	if unknown.Status != signals.Error {
		t.Errorf("undeclared signal status = %v, want error", unknown.Status)
	}
	if calls.Load() != 1 {
		t.Errorf("check ran %d times, want 1 (only the declared id)", calls.Load())
	}
}

// TestServantNeverExposesRunShell pins that the control vocabulary has no
// generic execution verb. A servant compromise must not become remote code
// execution: signal evaluation is by declared id, actuation is a closed rung
// set, and neither the dispatch nor the rung table admits a shell/exec verb.
func TestServantNeverExposesRunShell(t *testing.T) {
	rungs := buildRungs(rungPrimitives{Logger: slog.New(slog.DiscardHandler)})
	for name := range rungs {
		switch name {
		case "shell", "exec", "run", "run_shell", "runshell", "command", "powershell":
			t.Fatalf("actuation table exposes an execution verb: %q", name)
		}
	}
	// The servant dispatch handles a fixed set of control types; assert an
	// exec-shaped request is refused as unknown, not run.
	servant, harn := newServantRig(t, baseDeps(fakeRegistry("tpm", nil)), wire.HelloAck{})
	go servant.serve(context.Background())

	harn.request(t, "shell", "x1", map[string]string{"command": "calc.exe"})
	env := harn.read(t)
	if env.Type != "error" || env.Re != "x1" {
		t.Fatalf("exec-shaped request not refused: %+v", env)
	}
}

// TestServantUnknownRungIsRefused pins that an actuation rung the server does
// not implement is refused and reported, never guessed at.
func TestServantUnknownRungIsRefused(t *testing.T) {
	deps := baseDeps(fakeRegistry("tpm", nil))
	servant, harn := newServantRig(t, deps, wire.HelloAck{})
	go servant.serve(context.Background())

	harn.request(t, wire.TypeActuate, "a1", wire.Actuate{Rung: "detonate"})
	env := harn.read(t)
	var res wire.ActuateResult
	if err := wire.Unmarshal(env, &res); err != nil {
		t.Fatal(err)
	}
	if res.OK || res.SkippedReason == "" {
		t.Fatalf("unknown rung not refused: %+v", res)
	}
}

// TestServantActuateRunsTheInjectedRung pins that a known rung executes its
// injected primitive and reports the result.
func TestServantActuateRunsTheInjectedRung(t *testing.T) {
	var ran atomic.Bool
	deps := baseDeps(fakeRegistry("tpm", nil))
	deps.Rungs = map[string]rungFunc{
		wire.RungSeal: func(json.RawMessage) wire.ActuateResult {
			ran.Store(true)
			return wire.ActuateResult{Rung: wire.RungSeal, OK: true}
		},
	}
	servant, harn := newServantRig(t, deps, wire.HelloAck{})
	go servant.serve(context.Background())

	harn.request(t, wire.TypeActuate, "a2", wire.Actuate{Rung: wire.RungSeal})
	env := harn.read(t)
	var res wire.ActuateResult
	_ = wire.Unmarshal(env, &res)
	if !res.OK || !ran.Load() {
		t.Fatalf("seal rung did not run: ran=%v res=%+v", ran.Load(), res)
	}
}

// TestChannelLossFiresOnLostOnce pins that a dropped channel fires the
// loss callback exactly once — the hook RunStdio wires to cancel the run
// context so credential cleanup and the rest of the LIFO teardown run.
func TestChannelLossFiresOnLostOnce(t *testing.T) {
	var count atomic.Int32
	fired := make(chan struct{}, 1)
	deps := baseDeps(fakeRegistry("tpm", nil))
	deps.OnLost = func(error) {
		count.Add(1)
		select {
		case fired <- struct{}{}:
		default:
		}
	}
	servant, harn := newServantRig(t, deps, wire.HelloAck{})
	go servant.serve(context.Background())

	// Drop the channel from the harness side.
	_ = harn.w // keep referenced
	servant.conn.Close()

	select {
	case <-fired:
	case <-time.After(2 * time.Second):
		t.Fatal("onLost never fired on channel loss")
	}
	// A second close must not fire it again.
	servant.fireLost(errors.New("again"))
	time.Sleep(20 * time.Millisecond)
	if count.Load() != 1 {
		t.Fatalf("onLost fired %d times, want 1", count.Load())
	}
}

// TestServantHeartbeatReportsDesktopLiveness pins that a heartbeat carries the
// engine-liveness bit — the one fact the harness cannot read off the MCP wire.
func TestServantHeartbeatReportsDesktopLiveness(t *testing.T) {
	var alive atomic.Bool
	alive.Store(true)
	deps := baseDeps(fakeRegistry("tpm", nil))
	deps.Alive = func() bool { return alive.Load() }
	servant, harn := newServantRig(t, deps, wire.HelloAck{})

	// net.Pipe is synchronous: the push blocks until the read, so they must run
	// concurrently — exactly as the two real processes do.
	pushErr := make(chan error, 1)
	go func() { pushErr <- servant.PushHeartbeat() }()
	env := harn.read(t)
	if err := <-pushErr; err != nil {
		t.Fatal(err)
	}
	if env.Type != wire.TypeHeartbeat {
		t.Fatalf("type = %q", env.Type)
	}
	var hb wire.Heartbeat
	_ = wire.Unmarshal(env, &hb)
	if !hb.DesktopAlive || hb.Seq != 1 {
		t.Fatalf("heartbeat = %+v", hb)
	}
}

// TestServantConfigUpdateIsToleratedNotFatal pins forward-compatibility: a
// config.update the server does not yet apply is accepted, and the serve loop
// keeps going.
func TestServantConfigUpdateIsToleratedNotFatal(t *testing.T) {
	deps := baseDeps(fakeRegistry("tpm", nil))
	servant, harn := newServantRig(t, deps, wire.HelloAck{})
	go servant.serve(context.Background())

	harn.request(t, wire.TypeConfigUpdate, "", wire.EffectiveConfig{Banner: true})
	// A subsequent signal.evaluate still gets answered.
	harn.request(t, wire.TypeSignalEvaluate, "q9", wire.SignalEvaluate{IDs: []string{"tpm"}})
	env := harn.read(t)
	if env.Type != wire.TypeSignalResult || env.Re != "q9" {
		t.Fatalf("serve loop did not survive config.update: %+v", env)
	}
}
