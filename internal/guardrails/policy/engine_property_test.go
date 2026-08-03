package policy_test

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"pgregory.net/rapid"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/policy"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/policy/policytest"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/signals"
)

// These tests generate random rule sets and device states and assert the
// invariants the engine documents on Evaluate. They are the kind that break
// silently under a refactor — a lost requirement, a specificity comparison flipped
// — which an example-based test would not necessarily catch.

var ctx = context.Background()

// The subject space: a fixed set of tools whose facts the index resolves. Rules
// select on these by name, toolset, or annotation.
var propTools = map[string]policy.ToolFacts{
	"Snapshot":   {Name: "Snapshot", Toolset: "screen", ReadOnly: true},
	"PowerShell": {Name: "PowerShell", Toolset: "shell", Destructive: true},
	"Registry":   {Name: "Registry", Toolset: "system", Destructive: true},
	"Scrape":     {Name: "Scrape", Toolset: "web", ReadOnly: true, OpenWorld: true},
}

var (
	propIndex   = policytest.StaticIndex(propTools)
	propSignals = []string{"s0", "s1", "s2", "s3"}
	propToolIDs = []string{"Snapshot", "PowerShell", "Registry", "Scrape"}
)

func drawTool(t *rapid.T, label string) string {
	return rapid.SampledFrom(propToolIDs).Draw(t, label)
}

func drawMatch(t *rapid.T, label string) policy.Match {
	switch rapid.SampledFrom([]string{"tool", "annotation", "toolset", "wildcard"}).Draw(t, label+"-kind") {
	case "tool":
		return policy.Match{Tool: policy.StringSet{drawTool(t, label+"-tool")}}
	case "annotation":
		a := rapid.SampledFrom([]string{"read-only", "destructive", "open-world"}).Draw(t, label+"-anno")
		return policy.Match{Annotation: policy.StringSet{a}}
	case "toolset":
		ts := rapid.SampledFrom([]string{"screen", "shell", "system", "web"}).Draw(t, label+"-ts")
		return policy.Match{Toolset: policy.StringSet{ts}}
	default:
		return policy.Match{Toolset: policy.StringSet{"*"}}
	}
}

func drawRule(t *rapid.T, i int) policy.Rule {
	return policy.Rule{
		Name:    fmt.Sprintf("r%d", i),
		Match:   drawMatch(t, fmt.Sprintf("rule%d", i)),
		Require: []string{rapid.SampledFrom(propSignals).Draw(t, fmt.Sprintf("rule%d-sig", i))},
		OnFail:  rapid.SampledFrom([]policy.Severity{policy.SeverityWarn, policy.SeverityDeny, policy.SeverityKill}).Draw(t, fmt.Sprintf("rule%d-sev", i)),
	}
}

func drawRules(t *rapid.T) []policy.Rule {
	n := rapid.IntRange(0, 8).Draw(t, "n-rules")
	rules := make([]policy.Rule, n)
	for i := range rules {
		rules[i] = drawRule(t, i)
	}
	return rules
}

func drawStates(t *rapid.T) map[string]signals.Status {
	m := make(map[string]signals.Status, len(propSignals))
	for _, s := range propSignals {
		if rapid.Bool().Draw(t, "pass-"+s) {
			m[s] = signals.Pass
		} else {
			m[s] = signals.Fail
		}
	}
	return m
}

func uniformStates(status signals.Status) map[string]signals.Status {
	m := make(map[string]signals.Status, len(propSignals))
	for _, s := range propSignals {
		m[s] = status
	}
	return m
}

// buildPolicy assembles a policy from generated rules. Every signal is declared at
// ttl 0 (live), so a state change is seen on the next evaluation.
func buildPolicy(mode policy.PolicyMode, rules []policy.Rule) *policy.Policy {
	sig := make(map[string]policy.SignalConfig, len(propSignals))
	for _, s := range propSignals {
		sig[s] = policy.SignalConfig{}
	}
	return &policy.Policy{Version: 1, Mode: mode, Signals: sig, Rules: rules}
}

func failingSignals(v policy.Verdict) map[string]bool {
	out := map[string]bool{}
	for _, f := range v.Failures {
		out[f.Signal] = true
	}
	return out
}

// --- local re-derivations of the documented rules, to check the engine against ---

func annotationsOf(f policy.ToolFacts) []string {
	var out []string
	if f.ReadOnly {
		out = append(out, "read-only")
	}
	if f.Destructive {
		out = append(out, "destructive")
	}
	if f.OpenWorld {
		out = append(out, "open-world")
	}
	return out
}

func matchesSubject(m policy.Match, f policy.ToolFacts) bool {
	if len(m.Tool) > 0 && !m.Tool.Contains(f.Name) {
		return false
	}
	if len(m.Toolset) > 0 && !m.Toolset.Contains(f.Toolset) {
		return false
	}
	if len(m.Annotation) > 0 {
		any := false
		for _, a := range annotationsOf(f) {
			if m.Annotation.Contains(a) {
				any = true
			}
		}
		if !any {
			return false
		}
	}
	return len(m.Tool) > 0 || len(m.Toolset) > 0 || len(m.Annotation) > 0
}

func specificityOf(m policy.Match) int {
	switch {
	case len(m.Tool) > 0:
		return 3
	case len(m.Annotation) > 0:
		return 2
	case len(m.Toolset) > 0 && !m.Toolset.Contains("*"):
		return 1
	default:
		return 0
	}
}

// expectedSeverity re-derives the documented attribution: the on_fail of the most
// specific matching rule requiring sig, ties broken by document order (last wins).
func expectedSeverity(rules []policy.Rule, f policy.ToolFacts, sig string) (policy.Severity, bool) {
	best := -1
	var sev policy.Severity
	found := false
	for _, r := range rules {
		if !slices.Contains(r.Require, sig) || !matchesSubject(r.Match, f) {
			continue
		}
		if sp := specificityOf(r.Match); sp >= best { // >= gives last-wins on ties
			best, sev, found = sp, r.OnFail, true
		}
	}
	return sev, found
}

// TestPropUnionMonotonic: adding a rule never drops a required signal. With every
// signal failing, the set of failing signals can only grow when a rule is added.
func TestPropUnionMonotonic(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		rules := drawRules(t)
		extra := drawRule(t, 99)
		tool := drawTool(t, "subject")

		e0 := policytest.NewEngine(buildPolicy(policy.ModeEnforcing, rules), propIndex, uniformStates(signals.Fail))
		withExtra := append(append([]policy.Rule{}, rules...), extra)
		e1 := policytest.NewEngine(buildPolicy(policy.ModeEnforcing, withExtra), propIndex, uniformStates(signals.Fail))

		s0 := failingSignals(e0.Evaluate(ctx, e0.SubjectForTool("tools/call", tool)))
		s1 := failingSignals(e1.Evaluate(ctx, e1.SubjectForTool("tools/call", tool)))
		for sig := range s0 {
			if !s1[sig] {
				t.Fatalf("adding a rule dropped required signal %q (rules=%+v extra=%+v)", sig, rules, extra)
			}
		}
	})
}

// TestPropSeverityAttribution: every failing signal takes the on_fail of the most
// specific matching rule requiring it, ties last-wins. Covers both the specificity
// order and the equal-specificity tiebreak.
func TestPropSeverityAttribution(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		rules := drawRules(t)
		tool := drawTool(t, "subject")
		facts := propTools[tool]

		e := policytest.NewEngine(buildPolicy(policy.ModeEnforcing, rules), propIndex, drawStates(t))
		v := e.Evaluate(ctx, e.SubjectForTool("tools/call", tool))

		for _, f := range v.Failures {
			if f.Signal == "rate-limit" {
				continue
			}
			want, ok := expectedSeverity(rules, facts, f.Signal)
			if !ok {
				t.Fatalf("engine attributed %q with no matching rule requiring it (rules=%+v)", f.Signal, rules)
			}
			if f.Severity != want {
				t.Fatalf("signal %q attributed %v, want %v (rules=%+v)", f.Signal, f.Severity, want, rules)
			}
		}
	})
}

// TestPropRecoveryRestoresService: a device whose signals recover is admitted on
// the next evaluation, with no restart and nothing latched.
func TestPropRecoveryRestoresService(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		rules := drawRules(t)
		tool := drawTool(t, "subject")

		st := uniformStates(signals.Fail)
		e := policytest.NewEngine(buildPolicy(policy.ModeEnforcing, rules), propIndex, st)
		subj := e.SubjectForTool("tools/call", tool)

		_ = e.Evaluate(ctx, subj) // may deny or kill

		for k := range st {
			st[k] = signals.Pass // the device recovers
		}
		v := e.Evaluate(ctx, subj)
		if !v.Allowed() {
			t.Fatalf("a recovered device must be admitted without a restart, got %v", v.Severity)
		}
		if len(v.Failures) != 0 {
			t.Fatalf("no failures expected after recovery, got %+v", v.Failures)
		}
	})
}

// TestPropAuditClampPreservesIntent: audit mode never exceeds Warn, and its
// Intended is exactly what enforce mode would have done — the record of what
// enforcing would refuse, which is the whole value of audit mode.
func TestPropAuditClampPreservesIntent(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		rules := drawRules(t)
		tool := drawTool(t, "subject")
		st := drawStates(t)

		eEnf := policytest.NewEngine(buildPolicy(policy.ModeEnforcing, rules), propIndex, st)
		eAud := policytest.NewEngine(buildPolicy(policy.ModeAuditOnly, rules), propIndex, st)
		vEnf := eEnf.Evaluate(ctx, eEnf.SubjectForTool("tools/call", tool))
		vAud := eAud.Evaluate(ctx, eAud.SubjectForTool("tools/call", tool))

		if vAud.Severity > policy.SeverityWarn {
			t.Fatalf("audit severity %v exceeds warn", vAud.Severity)
		}
		if vAud.Intended != vEnf.Severity {
			t.Fatalf("audit intended %v != enforce severity %v", vAud.Intended, vEnf.Severity)
		}
		if vAud.Intended != vEnf.Intended {
			t.Fatalf("intended differs between modes: audit %v vs enforce %v", vAud.Intended, vEnf.Intended)
		}
	})
}
