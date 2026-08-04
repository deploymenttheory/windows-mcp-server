package contain

import (
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/audit"
	"io"
	"log/slog"

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
func (f *fakeActuator) IsolateNetwork() (func() error, []string, error) {
	f.calls = append(f.calls, "isolate")
	return func() error { f.calls = append(f.calls, "restore"); return nil },
		[]string{"profile1=block", "profile2=block", "profile4=block"}, nil
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
		Config: cfg, Actuator: act, Audit: audit.NewAuditLog(&memDest{}),
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

// isolatingActuator reports isolation as having run while the OS says nothing
// changed -- the case that motivated recording a read-back at all.
type isolatingActuator struct{ observed []string }

func (isolatingActuator) Elevated() bool { return true }
func (a isolatingActuator) IsolateNetwork() (func() error, []string, error) {
	return func() error { return nil }, a.observed, nil
}
func (isolatingActuator) KillProcesses([]string) []error       { return nil }
func (isolatingActuator) LockWorkstation() error               { return nil }
func (isolatingActuator) Shutdown(string, time.Duration) error { return nil }

// TestIsolateRecordsWhatTheOSReportedBack keeps "isolate ran" and "isolate took
// effect" as separate claims in the chain.
//
// A Put that returns no error proves the call was accepted, not that anything
// changed. Live testing produced a trip audited killaction.done{isolate} on a run
// where the outbound default was never observed leaving Allow, and there was no
// way to tell a write that did not take hold from a measurement that had missed
// it -- because the record carried only the fact that the call was made.
func TestIsolateRecordsWhatTheOSReportedBack(t *testing.T) {
	for _, tc := range []struct {
		name     string
		observed []string
		want     string
	}{
		{"took effect", []string{"profile1=block", "profile2=block", "profile4=block"}, "profile1=block"},
		{"did not take effect", []string{"profile1=NOT-BLOCKED(1)"}, "NOT-BLOCKED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dest := &memDest{}
			e := NewKillExecutor(KillExecutorDeps{
				Config:   KillActionConfig{Isolate: true},
				Actuator: isolatingActuator{observed: tc.observed},
				Audit:    audit.NewAuditLog(dest),
				Banner:   func(string) {},
				Finalize: func() {},
				Abort:    func(error) {},
			})
			e.OnTrip("test")

			var payload string
			for _, entry := range dest.entries {
				if entry.Event == "killaction.done" {
					payload = string(entry.Payload)
				}
			}
			if payload == "" {
				t.Fatal("no killaction.done entry was recorded")
			}
			if !strings.Contains(payload, tc.want) {
				t.Errorf("the record must carry what the OS reported back; want %q in: %s",
					tc.want, payload)
			}
		})
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
		Audit: audit.NewAuditLog(&memDest{}),
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

// discardLogger keeps kill-ladder tests quiet: OnTrip logs at Error by design.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// panickingActuator fails the way a real one can: a COM fault or a nil
// dereference inside a Win32 call, part-way through the ladder.
type panickingActuator struct{ elevated bool }

func (p *panickingActuator) Elevated() bool { return p.elevated }
func (p *panickingActuator) IsolateNetwork() (func() error, []string, error) {
	panic("simulated COM fault during isolation")
}
func (p *panickingActuator) KillProcesses([]string) []error       { return nil }
func (p *panickingActuator) LockWorkstation() error               { return nil }
func (p *panickingActuator) Shutdown(string, time.Duration) error { return nil }

// TestKillLadderSurvivesAPanickingActuator pins the ALWAYS steps against a panic
// mid-ladder.
//
// OnTrip runs on the monitor or watchdog goroutine, so without a recover a panic
// took the process down without finalizing the recording or aborting the session
// -- losing exactly the forensic trail the ladder's ordering exists to protect.
// The existing coverage never injected a failing actuator, so this could not have
// been caught.
func TestKillLadderSurvivesAPanickingActuator(t *testing.T) {
	var finalized, aborted bool
	e := NewKillExecutor(KillExecutorDeps{
		Config:   KillActionConfig{Isolate: true},
		Actuator: &panickingActuator{elevated: true},
		Finalize: func() { finalized = true },
		Abort:    func(error) { aborted = true },
		Logger:   discardLogger(),
	})

	// Must not propagate: the caller is a monitor goroutine with nothing above it.
	e.OnTrip("test")

	if !finalized {
		t.Error("the recording must still be finalized after a panic in the ladder")
	}
	if !aborted {
		t.Error("the session must still be aborted after a panic in the ladder")
	}
}

// TestKillLadderToleratesANilAuditLog covers the one audit call that was not
// nil-guarded. KillExecutorDeps documents that any dependency may be nil, and
// AuditLog.Flush takes its mutex before checking anything, so a nil log panicked
// on the shutdown branch.
func TestKillLadderToleratesANilAuditLog(t *testing.T) {
	var aborted bool
	e := NewKillExecutor(KillExecutorDeps{
		Config:   KillActionConfig{Shutdown: true},
		Actuator: &fakeActuator{elevated: true},
		Abort:    func(error) { aborted = true },
		Logger:   discardLogger(),
	})

	e.OnTrip("test")

	if !aborted {
		t.Error("the session must still be aborted with no audit log configured")
	}
}
