package policy

import (
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/signals"

	"context"
	"strings"
	"testing"
	"time"
)

// fakeIndex is a stand-in for the served tool manifest.
type fakeIndex map[string]ToolFacts

func (f fakeIndex) Lookup(tool string) (ToolFacts, bool) {
	facts, ok := f[tool]
	return facts, ok
}

var testIndex = fakeIndex{
	"Snapshot":   {Toolset: "screen", ReadOnly: true},
	"PowerShell": {Toolset: "shell", Destructive: true},
	"Registry":   {Toolset: "system", Destructive: true},
	"Scrape":     {Toolset: "web", ReadOnly: true, OpenWorld: true},
}

// newTestEngine builds an engine over a policy and a set of signal outcomes.
func newTestEngine(t *testing.T, policyJSON string, outcomes map[string]signals.Status) (*Engine, *countingRegistry) {
	t.Helper()
	ids := make([]string, 0, len(outcomes))
	for id := range outcomes {
		ids = append(ids, id)
	}
	cr := newCountingRegistry(ids...)
	for id, status := range outcomes {
		cr.set(id, status)
	}
	p, err := Parse([]byte(policyJSON))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Validate(ids); err != nil {
		t.Fatalf("test policy is invalid: %v", err)
	}
	return NewEngine(p, cr.reg, testIndex, func() *signals.Env { return &signals.Env{} }), cr
}

const layeredPolicy = `{
  "version": 1,
  "mode": "enforce",
  "signals": {
    "run-context": { "ttl": "0s" },
    "bitlocker":   { "ttl": "60s" },
    "mdm-enrolled":{ "ttl": "60s" }
  },
  "rules": [
    { "name": "baseline",    "match": { "toolset": "*" },              "require": ["run-context"], "on_fail": "deny" },
    { "name": "destructive", "match": { "annotation": "destructive" }, "require": ["bitlocker"],   "on_fail": "deny" },
    { "name": "shell",       "match": { "tool": "PowerShell" },        "require": ["mdm-enrolled"],"on_fail": "kill" }
  ]
}`

// TestRuleMatchingScalesWithWhatTheCallCanDo is the point of per-tool rules: a
// screenshot must not be gated on the posture a shell command is gated on.
func TestRuleMatchingScalesWithWhatTheCallCanDo(t *testing.T) {
	e, _ := newTestEngine(t, layeredPolicy, map[string]signals.Status{
		"run-context": signals.Pass, "bitlocker": signals.Fail, "mdm-enrolled": signals.Pass,
	})
	ctx := context.Background()

	readOnly := e.Evaluate(ctx, e.SubjectForTool("tools/call", "Snapshot"))
	if !readOnly.Allowed() {
		t.Errorf("a read-only tool must not be gated on the destructive rule: %+v", readOnly)
	}
	destructive := e.Evaluate(ctx, e.SubjectForTool("tools/call", "Registry"))
	if destructive.Allowed() {
		t.Error("a destructive tool must be denied when its required signal fails")
	}
	if destructive.Severity != SeverityDeny {
		t.Errorf("severity = %v, want deny", destructive.Severity)
	}
}

// TestSeverityIsAttributedToTheMostSpecificRule pins the precedence rule. Both
// the baseline and the shell rule cover PowerShell; the failure of a signal only
// the shell rule requires must carry the shell rule's severity.
func TestSeverityIsAttributedToTheMostSpecificRule(t *testing.T) {
	e, _ := newTestEngine(t, layeredPolicy, map[string]signals.Status{
		"run-context": signals.Pass, "bitlocker": signals.Pass, "mdm-enrolled": signals.Fail,
	})
	v := e.Evaluate(context.Background(), e.SubjectForTool("tools/call", "PowerShell"))

	if v.Severity != SeverityKill {
		t.Fatalf("severity = %v, want kill (the tool-specific rule's on_fail)", v.Severity)
	}
	if len(v.Failures) != 1 || v.Failures[0].Signal != "mdm-enrolled" {
		t.Fatalf("failures = %+v", v.Failures)
	}
	if v.Failures[0].Rule != `rule "shell"` {
		t.Errorf("failure attributed to %q, want the shell rule", v.Failures[0].Rule)
	}
}

// TestRequirementsUnionAcrossMatchingRules: adding a rule must never remove a
// requirement another rule imposed.
func TestRequirementsUnionAcrossMatchingRules(t *testing.T) {
	e, _ := newTestEngine(t, layeredPolicy, map[string]signals.Status{
		"run-context": signals.Fail, "bitlocker": signals.Fail, "mdm-enrolled": signals.Fail,
	})
	v := e.Evaluate(context.Background(), e.SubjectForTool("tools/call", "PowerShell"))

	got := map[string]bool{}
	for _, f := range v.Failures {
		got[f.Signal] = true
	}
	for _, want := range []string{"run-context", "bitlocker", "mdm-enrolled"} {
		if !got[want] {
			t.Errorf("PowerShell must inherit %q from a broader rule; failures = %+v", want, v.Failures)
		}
	}
	// Highest severity wins across the failures.
	if v.Severity != SeverityKill {
		t.Errorf("severity = %v, want kill (the highest among the failures)", v.Severity)
	}
}

// TestAuditModeClampsButStillRecords is the safety property of the default.
func TestAuditModeClampsButStillRecords(t *testing.T) {
	auditPolicy := `{
	  "version": 1, "mode": "audit",
	  "signals": { "bitlocker": { "ttl": "0s" } },
	  "rules": [ { "name": "destructive", "match": { "annotation": "destructive" }, "require": ["bitlocker"], "on_fail": "kill" } ]
	}`
	e, cr := newTestEngine(t, auditPolicy, map[string]signals.Status{"bitlocker": signals.Fail})
	v := e.Evaluate(context.Background(), e.SubjectForTool("tools/call", "PowerShell"))

	if !v.Allowed() {
		t.Error("audit mode must never refuse a call")
	}
	if v.Severity != SeverityWarn {
		t.Errorf("severity = %v, want warn (kill clamped by audit mode)", v.Severity)
	}
	if v.Intended != SeverityKill {
		t.Errorf("intended = %v, want kill; audit mode must record what enforcing would have done", v.Intended)
	}
	if len(v.Failures) != 1 {
		t.Errorf("audit mode must still record the failure, got %+v", v.Failures)
	}
	if cr.calls("bitlocker") == 0 {
		t.Error("audit mode must still evaluate signals; skipping them would prove nothing")
	}
}

// TestPassingSignalsProduceNoFailures covers the green path.
func TestPassingSignalsProduceNoFailures(t *testing.T) {
	e, _ := newTestEngine(t, layeredPolicy, map[string]signals.Status{
		"run-context": signals.Pass, "bitlocker": signals.Pass, "mdm-enrolled": signals.Pass,
	})
	v := e.Evaluate(context.Background(), e.SubjectForTool("tools/call", "PowerShell"))
	if !v.Allowed() || v.Severity != SeverityAllow || len(v.Failures) != 0 {
		t.Errorf("a fully-passing device must yield a clean allow, got %+v", v)
	}
}

// TestSkippedSignalIsNotAFailure: signals.Skip means "not applicable here", which is how
// the existing checks report an absent probe. Treating it as a failure would
// deny every call on a device that simply lacks the hardware a check reads.
func TestSkippedSignalIsNotAFailure(t *testing.T) {
	e, _ := newTestEngine(t, layeredPolicy, map[string]signals.Status{
		"run-context": signals.Pass, "bitlocker": signals.Skip, "mdm-enrolled": signals.Pass,
	})
	v := e.Evaluate(context.Background(), e.SubjectForTool("tools/call", "Registry"))
	if !v.Allowed() {
		t.Errorf("a skipped signal must not deny: %+v", v.Failures)
	}
}

// TestErrorIsAFailure: a check that could not run has not proved anything, so it
// must not be treated as a pass.
func TestErrorIsAFailure(t *testing.T) {
	e, _ := newTestEngine(t, layeredPolicy, map[string]signals.Status{
		"run-context": signals.Error, "bitlocker": signals.Pass, "mdm-enrolled": signals.Pass,
	})
	v := e.Evaluate(context.Background(), e.SubjectForTool("tools/call", "Snapshot"))
	if v.Allowed() {
		t.Error("a signal that errored must not be treated as passing")
	}
}

// TestUnknownToolStillMatchesTheBaseline guards the fail-open hole: a tool the
// index cannot resolve must not escape every rule.
func TestUnknownToolStillMatchesTheBaseline(t *testing.T) {
	e, _ := newTestEngine(t, layeredPolicy, map[string]signals.Status{
		"run-context": signals.Fail, "bitlocker": signals.Pass, "mdm-enrolled": signals.Pass,
	})
	v := e.Evaluate(context.Background(), e.SubjectForTool("tools/call", "SomeToolAddedLater"))
	if v.Allowed() {
		t.Error("an unresolvable tool must still be covered by the toolset \"*\" baseline")
	}
}

// TestStartupScopeIsSeparateFromCallScope: startup rules must not fire on tool
// calls, and call rules must not fire at startup.
func TestStartupScopeIsSeparateFromCallScope(t *testing.T) {
	policy := `{
	  "version": 1, "mode": "enforce",
	  "signals": { "run-context": { "ttl": "0s" }, "bitlocker": { "ttl": "0s" } },
	  "rules": [
	    { "name": "admission", "match": { "scope": "startup" }, "require": ["run-context"], "on_fail": "deny" },
	    { "name": "calls",     "match": { "toolset": "*" },     "require": ["bitlocker"],   "on_fail": "deny" }
	  ]
	}`
	e, _ := newTestEngine(t, policy, map[string]signals.Status{"run-context": signals.Fail, "bitlocker": signals.Pass})
	ctx := context.Background()

	startup := e.Evaluate(ctx, StartupSubject())
	if startup.Allowed() {
		t.Error("a failing startup requirement must refuse admission")
	}
	call := e.Evaluate(ctx, e.SubjectForTool("tools/call", "Snapshot"))
	if !call.Allowed() {
		t.Errorf("a startup rule must not gate individual calls: %+v", call.Failures)
	}
}

// TestSelectorsWithinOneMatchAreAnded documents the combination semantics.
func TestSelectorsWithinOneMatchAreAnded(t *testing.T) {
	policy := `{
	  "version": 1, "mode": "enforce",
	  "signals": { "bitlocker": { "ttl": "0s" } },
	  "rules": [
	    { "name": "destructive-shell", "match": { "toolset": "shell", "annotation": "destructive" },
	      "require": ["bitlocker"], "on_fail": "deny" }
	  ]
	}`
	e, _ := newTestEngine(t, policy, map[string]signals.Status{"bitlocker": signals.Fail})
	ctx := context.Background()

	if v := e.Evaluate(ctx, e.SubjectForTool("tools/call", "PowerShell")); v.Allowed() {
		t.Error("PowerShell is in the shell toolset AND destructive, so the rule must cover it")
	}
	// signals.Registry is destructive but in a different toolset; Snapshot is in neither.
	if v := e.Evaluate(ctx, e.SubjectForTool("tools/call", "Registry")); !v.Allowed() {
		t.Error("Registry is destructive but not in the shell toolset, so an ANDed match must not cover it")
	}
	if v := e.Evaluate(ctx, e.SubjectForTool("tools/call", "Snapshot")); !v.Allowed() {
		t.Error("Snapshot matches neither selector")
	}
}

// TestRateLimitShareOneWindowPerLimit: alternating between two tools that match
// the same limit must not double the allowance.
func TestRateLimitShareOneWindowPerLimit(t *testing.T) {
	policy := `{
	  "version": 1, "mode": "enforce",
	  "signals": {},
	  "rules": [],
	  "rate_limits": [
	    { "name": "destructive-burst", "match": { "annotation": "destructive" },
	      "window": "10s", "max": 2, "on_exceed": "deny" }
	  ]
	}`
	e, _ := newTestEngine(t, policy, map[string]signals.Status{})
	ctx := context.Background()

	if v := e.Evaluate(ctx, e.SubjectForTool("tools/call", "PowerShell")); !v.Allowed() {
		t.Fatal("call 1 should pass")
	}
	if v := e.Evaluate(ctx, e.SubjectForTool("tools/call", "Registry")); !v.Allowed() {
		t.Fatal("call 2 should pass")
	}
	v := e.Evaluate(ctx, e.SubjectForTool("tools/call", "PowerShell"))
	if v.Allowed() {
		t.Error("call 3 exceeds a shared window; alternating tools must not evade the limit")
	}
	if len(v.Failures) != 1 || v.Failures[0].Signal != "rate-limit" {
		t.Errorf("failures = %+v, want a rate-limit failure", v.Failures)
	}
}

// TestRateLimitIgnoresUnmatchedTools: a read-only call must not consume the
// destructive allowance.
func TestRateLimitIgnoresUnmatchedTools(t *testing.T) {
	policy := `{
	  "version": 1, "mode": "enforce", "signals": {}, "rules": [],
	  "rate_limits": [
	    { "name": "destructive-burst", "match": { "annotation": "destructive" },
	      "window": "10s", "max": 1, "on_exceed": "deny" }
	  ]
	}`
	e, _ := newTestEngine(t, policy, map[string]signals.Status{})
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		if v := e.Evaluate(ctx, e.SubjectForTool("tools/call", "Snapshot")); !v.Allowed() {
			t.Fatalf("read-only call %d must not consume the destructive allowance", i)
		}
	}
	if v := e.Evaluate(ctx, e.SubjectForTool("tools/call", "PowerShell")); !v.Allowed() {
		t.Error("the first destructive call should still be within the limit")
	}
}

// TestExplainReportsCoverageWithoutEvaluating backs the explain subcommand: an
// operator asking "why" must not have to run device probes to find out.
func TestExplainReportsCoverageWithoutEvaluating(t *testing.T) {
	e, cr := newTestEngine(t, layeredPolicy, map[string]signals.Status{
		"run-context": signals.Pass, "bitlocker": signals.Pass, "mdm-enrolled": signals.Pass,
	})

	rules := e.Explain(e.SubjectForTool("tools/call", "PowerShell"))
	if len(rules) != 3 {
		t.Errorf("PowerShell should be covered by all three rules, got %d", len(rules))
	}
	rules = e.Explain(e.SubjectForTool("tools/call", "Snapshot"))
	if len(rules) != 1 || rules[0].Name != "baseline" {
		t.Errorf("Snapshot should be covered by the baseline only, got %+v", rules)
	}
	for _, id := range []string{"run-context", "bitlocker", "mdm-enrolled"} {
		if cr.calls(id) != 0 {
			t.Errorf("Explain evaluated %q; it must not touch the device", id)
		}
	}
}

// TestEvaluateReusesCachedSignals: the per-call cost is the reason for the cache,
// so assert the expensive signals are not re-read on every request.
func TestEvaluateReusesCachedSignals(t *testing.T) {
	e, cr := newTestEngine(t, layeredPolicy, map[string]signals.Status{
		"run-context": signals.Pass, "bitlocker": signals.Pass, "mdm-enrolled": signals.Pass,
	})
	ctx := context.Background()
	for i := 0; i < 20; i++ {
		e.Evaluate(ctx, e.SubjectForTool("tools/call", "PowerShell"))
	}
	if got := cr.calls("bitlocker"); got != 1 {
		t.Errorf("bitlocker evaluated %d times across 20 calls, want 1 (ttl 60s)", got)
	}
	if got := cr.calls("run-context"); got != 20 {
		t.Errorf("run-context evaluated %d times, want 20 (ttl 0 = live)", got)
	}
}

// TestVerdictReasonNamesSignalAndRule: the message reaches the model on a denial,
// so it has to say which control failed and which rule imposed it.
func TestVerdictReasonNamesSignalAndRule(t *testing.T) {
	e, _ := newTestEngine(t, layeredPolicy, map[string]signals.Status{
		"run-context": signals.Pass, "bitlocker": signals.Fail, "mdm-enrolled": signals.Pass,
	})
	v := e.Evaluate(context.Background(), e.SubjectForTool("tools/call", "Registry"))
	reason := v.Reason()
	if reason == "" {
		t.Fatal("a denial must carry a reason")
	}
	for _, want := range []string{"bitlocker", "destructive"} {
		if !strings.Contains(reason, want) {
			t.Errorf("reason %q does not mention %q", reason, want)
		}
	}
}

// TestRateLimitWindowSlides: entries older than the window must drop out, or a
// long session would eventually deny everything.
func TestRateLimitWindowSlides(t *testing.T) {
	limiter := newRateLimiter([]RateLimit{{
		Name: "burst", Match: Match{Annotation: StringSet{AnnotationDestructive}},
		Window: Duration(10 * time.Second), Max: 2, OnExceed: SeverityDeny,
	}})
	subj := Subject{Scope: ScopeCall, Facts: ToolFacts{Name: "PowerShell", Destructive: true}}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	for i := 0; i < 2; i++ {
		if _, _, ok := limiter.exceeded(subj, base); ok {
			t.Fatalf("call %d should be within the limit", i)
		}
	}
	if _, _, ok := limiter.exceeded(subj, base); !ok {
		t.Fatal("the third call in the window should exceed")
	}
	// Well past the window: the earlier hits have aged out.
	if _, _, ok := limiter.exceeded(subj, base.Add(time.Minute)); ok {
		t.Error("hits older than the window must not count")
	}
}

// TestSkippedRequiredSignalIsRecorded pins the other half of skip handling.
//
// A skipped signal must not deny (TestSkippedSignalIsNotAFailure), but it must
// not vanish either. Skip is produced when a may-run endpoint is unconfigured,
// when there is no DHA state, when no AIK is provisioned, and for any id no
// provider serves -- so a rule written on_fail: deny passed forever, recording
// nothing, on exactly the devices it was written for. An operator reading the
// chain in audit mode saw a clean run.
func TestSkippedRequiredSignalIsRecorded(t *testing.T) {
	e, _ := newTestEngine(t, layeredPolicy, map[string]signals.Status{
		"run-context": signals.Pass, "bitlocker": signals.Skip, "mdm-enrolled": signals.Pass,
	})
	v := e.Evaluate(context.Background(), e.SubjectForTool("tools/call", "Registry"))

	if !v.Allowed() {
		t.Fatalf("a skipped signal must still not deny: %+v", v.Failures)
	}
	var found bool
	for _, f := range v.Failures {
		if f.Signal == "bitlocker" {
			found = true
			if f.Severity != SeverityWarn {
				t.Errorf("a skipped required signal should be recorded at warn, got %v", f.Severity)
			}
		}
	}
	if !found {
		t.Error("a required signal that could not be evaluated must appear in the verdict; " +
			"silently satisfying the rule is how a control that is not in force reads as one that is")
	}
}

// TestWildcardToolSelectorIsBroadNotNarrow pins the precedence of {tool: "*"}.
//
// specificity ranked any non-empty tool selector 3, the narrowest tier, including
// the wildcard -- which matches every tool. So a later "and warn on everything
// else" rule written {tool: "*", on_fail: "warn"} won attribution over an earlier
// {tool: "PowerShell", on_fail: "deny"} and silently downgraded it. toolset: "*"
// already carried the demotion; tool did not, and nothing covered it.
func TestWildcardToolSelectorIsBroadNotNarrow(t *testing.T) {
	specific := Rule{Match: Match{Tool: StringSet{"PowerShell"}}}
	wildcard := Rule{Match: Match{Tool: StringSet{"*"}}}
	annotation := Rule{Match: Match{Annotation: StringSet{"destructive"}}}

	if specific.specificity() <= wildcard.specificity() {
		t.Error("a named tool must outrank a wildcard tool selector, " +
			"or a broad rule can downgrade the severity a specific one assigned")
	}
	if wildcard.specificity() >= annotation.specificity() {
		t.Error("a wildcard tool selector matches everything, so it must rank below " +
			"an annotation selector, not above it")
	}
}
