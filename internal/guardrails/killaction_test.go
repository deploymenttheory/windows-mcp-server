package guardrails

import (
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeActuator struct {
	elevated bool
	calls    []string
}

func (f *fakeActuator) Elevated() bool { return f.elevated }
func (f *fakeActuator) IsolateNetwork() (func() error, error) {
	f.calls = append(f.calls, "isolate")
	return func() error { f.calls = append(f.calls, "restore"); return nil }, nil
}

func (f *fakeActuator) KillProcesses(names []string) []error {
	f.calls = append(f.calls, "kill:"+strings.Join(names, ","))
	return nil
}
func (f *fakeActuator) LockWorkstation() error { f.calls = append(f.calls, "lock"); return nil }
func (f *fakeActuator) Shutdown(string, time.Duration) error {
	f.calls = append(f.calls, "shutdown")
	return nil
}
func (f *fakeActuator) IsAdmin() bool                 { return f.elevated }
func (f *fakeActuator) LoggedOnUser() (string, error) { return "tester", nil }

func newExec(cfg KillActionConfig, act SystemActuator, seq *[]string) *KillExecutor {
	return NewKillExecutor(KillExecutorDeps{
		Config: cfg, Actuator: act, Audit: NewAuditLog(&memSink{}),
		Banner:   func(string) { *seq = append(*seq, "banner") },
		Finalize: func() { *seq = append(*seq, "finalize") },
		Abort:    func(error) { *seq = append(*seq, "abort") },
	})
}

func TestKillDefaultIsolateAndAbortOnly(t *testing.T) {
	act := &fakeActuator{elevated: true}
	var seq []string
	e := newExec(DefaultKillActionConfig(), act, &seq)
	e.OnTrip("test")

	if !contains(seq, "banner") || !contains(seq, "finalize") || !contains(seq, "abort") {
		t.Errorf("banner/finalize/abort must always run: %v", seq)
	}
	if !contains(act.calls, "isolate") {
		t.Errorf("default must isolate: %v", act.calls)
	}
	if contains(act.calls, "shutdown") || containsPrefix(act.calls, "kill:") || contains(act.calls, "lock") {
		t.Errorf("default must NOT kill/lock/shutdown: %v", act.calls)
	}
}

func TestKillAllTiersOrder(t *testing.T) {
	act := &fakeActuator{elevated: true}
	var seq []string
	cfg := KillActionConfig{Isolate: true, KillProcs: true, Lock: true, Shutdown: true, ProcNames: []string{"evil.exe"}}
	e := newExec(cfg, act, &seq)
	e.OnTrip("all")

	// Actuator action order.
	want := []string{"isolate", "kill:evil.exe", "lock", "shutdown"}
	got := filterActs(act.calls)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("action order = %v, want %v", got, want)
	}
	// finalize must precede abort in the always-run sequence.
	if idx(seq, "finalize") > idx(seq, "abort") {
		t.Error("finalize must precede abort")
	}
}

func TestKillDegradesWhenNotElevated(t *testing.T) {
	act := &fakeActuator{elevated: false}
	var seq []string
	cfg := KillActionConfig{Isolate: true, KillProcs: true, Shutdown: true, ProcNames: []string{"x"}}
	e := newExec(cfg, act, &seq)
	e.OnTrip("degrade")

	if contains(act.calls, "isolate") || contains(act.calls, "shutdown") || containsPrefix(act.calls, "kill:") {
		t.Errorf("no elevated action should run unprivileged: %v", act.calls)
	}
	// But banner/finalize/abort still happen.
	if !contains(seq, "banner") || !contains(seq, "finalize") || !contains(seq, "abort") {
		t.Errorf("degraded trip must still banner/finalize/abort: %v", seq)
	}
}

func TestKillRestoreUndoesIsolation(t *testing.T) {
	act := &fakeActuator{elevated: true}
	var seq []string
	e := newExec(DefaultKillActionConfig(), act, &seq)
	e.OnTrip("x")
	if err := e.Restore(); err != nil {
		t.Fatal(err)
	}
	if !contains(act.calls, "restore") {
		t.Errorf("Restore must undo isolation: %v", act.calls)
	}
}

// TestStopGracefullyDoesNotContain covers the agent-facing Kill path: the session
// still ends, but no containment action runs and no security banner is raised —
// an agent cannot escalate "stop this session" into network isolation or a
// shutdown, even with every escalation configured.
func TestStopGracefullyDoesNotContain(t *testing.T) {
	act := &fakeActuator{elevated: true}
	var seq []string
	cfg := KillActionConfig{Isolate: true, KillProcs: true, Lock: true, Shutdown: true, ProcNames: []string{"x"}}
	e := newExec(cfg, act, &seq)
	e.StopGracefully("agent requested stop")

	if len(act.calls) != 0 {
		t.Errorf("graceful stop must not actuate containment: %v", act.calls)
	}
	if contains(seq, "banner") {
		t.Errorf("graceful stop must not raise the security banner: %v", seq)
	}
	if !contains(seq, "finalize") || !contains(seq, "abort") {
		t.Errorf("graceful stop must finalize the recording and abort: %v", seq)
	}
	if idx(seq, "finalize") > idx(seq, "abort") {
		t.Error("finalize must precede abort")
	}
}

// TestStopGracefullyCauseIsMatchable pins the cancel cause the server layer keys
// off to exit 0 on a requested stop rather than reporting a crash.
func TestStopGracefullyCauseIsMatchable(t *testing.T) {
	var cause error
	e := NewKillExecutor(KillExecutorDeps{
		Audit: NewAuditLog(&memSink{}),
		Abort: func(err error) { cause = err },
	})
	e.StopGracefully("journey complete")

	if !errors.Is(cause, ErrSessionStopped) {
		t.Errorf("cause = %v, want errors.Is(..., ErrSessionStopped)", cause)
	}
	if !strings.Contains(cause.Error(), "journey complete") {
		t.Errorf("cause must carry the reason, got %v", cause)
	}
}

// helpers
func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func containsPrefix(s []string, p string) bool {
	for _, x := range s {
		if strings.HasPrefix(x, p) {
			return true
		}
	}
	return false
}

func idx(s []string, v string) int {
	for i, x := range s {
		if x == v {
			return i
		}
	}
	return -1
}

func filterActs(calls []string) []string {
	var out []string
	for _, c := range calls {
		if c == "restore" {
			continue
		}
		out = append(out, c)
	}
	return out
}
