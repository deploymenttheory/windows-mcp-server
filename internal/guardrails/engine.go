package guardrails

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// ToolFacts are the properties a policy rule can select on. They come from the
// served manifest, so a rule written against them describes what a call can
// actually do rather than what its name suggests.
type ToolFacts struct {
	Name    string
	Toolset string
	// ReadOnly, Destructive and OpenWorld mirror the MCP tool annotations.
	ReadOnly    bool
	Destructive bool
	OpenWorld   bool
}

// annotations returns the annotation names this tool carries.
func (f ToolFacts) annotations() []string {
	var out []string
	if f.ReadOnly {
		out = append(out, AnnotationReadOnly)
	}
	if f.Destructive {
		out = append(out, AnnotationDestructive)
	}
	if f.OpenWorld {
		out = append(out, AnnotationOpenWorld)
	}
	return out
}

// ToolIndex resolves a tool name to the facts rules match on.
//
// It is an interface for the same reason SystemProbe and HealthProbe are: it
// keeps this package free of any dependency on the tool inventory, so the engine
// is unit-testable with a fake index and no Windows host. internal/winmcp
// supplies the adapter over the real manifest.
type ToolIndex interface {
	Lookup(tool string) (ToolFacts, bool)
}

// Subject is the thing a decision is about: one MCP request, or the process
// itself at startup.
type Subject struct {
	// Scope is ScopeCall or ScopeStartup.
	Scope string
	// Method is the MCP method, for audit and for subjects that are not tools.
	Method string
	// Facts describe the tool being called. For resources/read and prompts/get
	// they are synthesized (see SubjectForMethod) so those methods cannot route
	// around a rule that covers equivalent tools.
	Facts ToolFacts
}

// String renders the subject for audit records and explain output.
func (s Subject) String() string {
	if s.Scope == ScopeStartup {
		return "startup"
	}
	if s.Facts.Name != "" {
		return s.Method + " " + s.Facts.Name
	}
	return s.Method
}

// Failure is one requirement that did not hold, and what the policy says to do
// about it.
type Failure struct {
	// Signal is the guardrail id that failed.
	Signal string `json:"signal"`
	// Rule identifies the rule the requirement was attributed to.
	Rule string `json:"rule"`
	// Severity is that rule's on_fail, before mode clamping.
	Severity Severity `json:"severity"`
	Detail   string   `json:"detail,omitempty"`
}

// Verdict is the engine's decision about one subject.
type Verdict struct {
	Subject string `json:"subject"`
	// Severity is what will actually happen, after mode clamping.
	Severity Severity `json:"severity"`
	// Intended is what the policy asked for before the mode capped it. In audit
	// mode the two differ, and the difference is the whole value of audit mode:
	// it is the record of what enforcing would have done.
	Intended Severity   `json:"intended"`
	Mode     PolicyMode `json:"mode"`
	// Rules are the rules that matched, for attribution.
	Rules    []string  `json:"rules,omitempty"`
	Failures []Failure `json:"failures,omitempty"`
}

// Allowed reports whether the request may proceed.
func (v Verdict) Allowed() bool { return v.Severity < SeverityDeny }

// Reason renders the failures as a single human-readable string.
func (v Verdict) Reason() string {
	if len(v.Failures) == 0 {
		return ""
	}
	parts := make([]string, 0, len(v.Failures))
	for _, f := range v.Failures {
		part := f.Signal + " (" + f.Rule + ")"
		if f.Detail != "" {
			part += ": " + f.Detail
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, "; ")
}

// Engine is the policy decision point on the request path.
type Engine struct {
	policy *Policy
	cache  *signalCache
	index  ToolIndex
	args   map[string]string
	limits *rateLimiter
}

// NewEngine builds the engine. The policy must already have been validated
// against reg, which LoadPolicy does.
func NewEngine(policy *Policy, reg *Registry, index ToolIndex, env func() *Env) *Engine {
	return &Engine{
		policy: policy,
		cache:  newSignalCache(reg, policy, env),
		index:  index,
		args:   argsFrom(policy),
		limits: newRateLimiter(policy.RateLimits),
	}
}

// Policy returns the active policy.
func (e *Engine) Policy() *Policy { return e.policy }

// SetIndex supplies the tool index once the served manifest exists.
//
// The engine is built before the inventory because the startup admission
// decision has to be made first, and a denied startup must not have gone as far
// as assembling a tool surface. A startup subject has no tool to resolve, so the
// index is genuinely not needed until serving begins. Call this before the first
// request; after that the engine is read-only.
func (e *Engine) SetIndex(index ToolIndex) { e.index = index }

// Signals returns the current readings, for the status surface.
func (e *Engine) Signals() []Result { return e.cache.Snapshot() }

// Refresh re-evaluates expired signals. Register it as a monitor VerifyFunc.
func (e *Engine) Refresh(ctx context.Context) error { return e.cache.Refresh(ctx, e.args) }

// SubjectForTool builds a call subject from a tool name, resolving its facts
// through the index.
//
// A tool the index does not know still gets a subject, with only its name set.
// It therefore matches `toolset: "*"` rules and no narrower ones — which is the
// safe reading: an unrecognized tool should still be covered by the baseline,
// not exempted from everything.
func (e *Engine) SubjectForTool(method, tool string) Subject {
	facts := ToolFacts{Name: tool}
	if e.index != nil {
		if found, ok := e.index.Lookup(tool); ok {
			facts = found
			facts.Name = tool
		}
	}
	return Subject{Scope: ScopeCall, Method: method, Facts: facts}
}

// StartupSubject is the subject for the once-per-process admission decision.
func StartupSubject() Subject { return Subject{Scope: ScopeStartup, Method: "startup"} }

// Evaluate decides one subject.
//
// Rule precedence. Every rule whose match selects the subject contributes its
// requirements, so requirements are the union across matching rules — a
// requirement can never be lost by adding another rule. Severity is attributed
// per signal: each required signal takes the on_fail of the most *specific* rule
// that requires it, where specificity is tool > annotation > named toolset >
// toolset "*". Ties are broken by document order, last wins, so an author can
// override an earlier rule by restating it later at the same specificity.
//
// The verdict is the highest severity among the failures, then capped by the
// policy mode.
func (e *Engine) Evaluate(ctx context.Context, subj Subject) Verdict {
	v := Verdict{Subject: subj.String(), Mode: e.policy.Mode}

	// Attribute each required signal to the most specific rule requiring it.
	type attribution struct {
		rule        string
		severity    Severity
		specificity int
	}
	attributed := map[string]attribution{}
	for i, r := range e.policy.Rules {
		if !e.matches(r.Match, r.scope(), subj) {
			continue
		}
		label := ruleLabel(r.Name, i)
		v.Rules = append(v.Rules, label)
		for _, id := range r.Require {
			cur, seen := attributed[id]
			if seen && cur.specificity > r.specificity() {
				continue
			}
			attributed[id] = attribution{rule: label, severity: r.OnFail, specificity: r.specificity()}
		}
	}

	// Read the signals in a stable order so the audit record is reproducible.
	for _, id := range sortedKeys(attributed) {
		res := e.cache.Read(ctx, id, e.args)
		if res.Status != Fail && res.Status != Error {
			continue
		}
		a := attributed[id]
		v.Failures = append(v.Failures, Failure{
			Signal: id, Rule: a.rule, Severity: a.severity, Detail: res.Detail,
		})
		if a.severity > v.Intended {
			v.Intended = a.severity
		}
	}

	// Rate limits are evaluated after the signals: exceeding one is a property of
	// the request stream rather than of the device, but it lands in the same
	// verdict so a caller sees one decision rather than two.
	if sev, label, ok := e.limits.exceeded(subj, time.Now()); ok {
		v.Rules = append(v.Rules, label)
		v.Failures = append(v.Failures, Failure{
			Signal: "rate-limit", Rule: label, Severity: sev,
			Detail: "too many matching calls within the window",
		})
		if sev > v.Intended {
			v.Intended = sev
		}
	}

	v.Severity = e.policy.Mode.clamp(v.Intended)
	return v
}

// Explain reports which rules cover a subject and what they require, without
// evaluating any signal.
//
// This exists because a denial nobody can attribute is a denial that gets fixed
// by turning the engine off.
func (e *Engine) Explain(subj Subject) []Rule {
	var out []Rule
	for _, r := range e.policy.Rules {
		if e.matches(r.Match, r.scope(), subj) {
			out = append(out, r)
		}
	}
	return out
}

// matches reports whether a rule's match selects the subject.
//
// Selectors within one match are ANDed: a match naming both a toolset and an
// annotation covers only tools that are in that toolset *and* carry that
// annotation. Values within a single selector are ORed.
func (e *Engine) matches(m Match, scope string, subj Subject) bool {
	if scope != subj.Scope {
		return false
	}
	if subj.Scope == ScopeStartup {
		return true // a startup rule has no tool to select
	}
	if len(m.Tool) > 0 && !m.Tool.Contains(subj.Facts.Name) {
		return false
	}
	if len(m.Toolset) > 0 && !m.Toolset.Contains(subj.Facts.Toolset) {
		return false
	}
	if len(m.Annotation) > 0 && !matchesAnyAnnotation(m.Annotation, subj.Facts) {
		return false
	}
	// A call-scope match with no selector at all reaches here only if validation
	// was skipped; treat it as selecting nothing rather than everything.
	return len(m.Tool) > 0 || len(m.Toolset) > 0 || len(m.Annotation) > 0
}

func matchesAnyAnnotation(want StringSet, facts ToolFacts) bool {
	for _, have := range facts.annotations() {
		if want.Contains(have) {
			return true
		}
	}
	return false
}

// rateLimiter enforces the policy's rate limits over sliding windows.
//
// One window is kept per limit, not per tool: the limits describe how much of a
// *class* of action is acceptable, so alternating between two destructive tools
// must not double the allowance. This is the same reasoning that put tools/call
// and resources/read on a shared window in the previous implementation.
type rateLimiter struct {
	mu     sync.Mutex
	limits []RateLimit
	hits   [][]time.Time
}

func newRateLimiter(limits []RateLimit) *rateLimiter {
	return &rateLimiter{limits: limits, hits: make([][]time.Time, len(limits))}
}

// exceeded records a matching call and reports whether a limit is now exceeded.
func (r *rateLimiter) exceeded(subj Subject, now time.Time) (Severity, string, bool) {
	if r == nil || len(r.limits) == 0 || subj.Scope != ScopeCall {
		return SeverityAllow, "", false
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	var (
		worst    Severity
		label    string
		exceeded bool
	)
	for i, limit := range r.limits {
		if !matchesLimit(limit.Match, subj) {
			continue
		}
		cutoff := now.Add(-limit.Window.Std())
		kept := r.hits[i][:0]
		for _, t := range r.hits[i] {
			if t.After(cutoff) {
				kept = append(kept, t)
			}
		}
		kept = append(kept, now)
		r.hits[i] = kept
		if len(kept) > limit.Max && limit.OnExceed > worst {
			worst, label, exceeded = limit.OnExceed, ruleLabel(limit.Name, i), true
		}
	}
	return worst, label, exceeded
}

// matchesLimit mirrors Engine.matches for rate-limit matches, which are always
// call-scoped.
func matchesLimit(m Match, subj Subject) bool {
	if len(m.Tool) > 0 && !m.Tool.Contains(subj.Facts.Name) {
		return false
	}
	if len(m.Toolset) > 0 && !m.Toolset.Contains(subj.Facts.Toolset) {
		return false
	}
	if len(m.Annotation) > 0 && !matchesAnyAnnotation(m.Annotation, subj.Facts) {
		return false
	}
	return len(m.Tool) > 0 || len(m.Toolset) > 0 || len(m.Annotation) > 0
}

// DecisionFrom renders a verdict as the Decision document the status surface and
// audit chain already understand, so the policy engine reuses one shape rather
// than inventing a second.
func (e *Engine) DecisionFrom(v Verdict, device DeviceIdentity, rc RunContext) Decision {
	d := Decision{
		Device:     device,
		RunContext: rc,
		Mode:       string(e.policy.Mode),
		Admit:      v.Allowed(),
		Results:    e.cache.Snapshot(),
	}
	for _, f := range v.Failures {
		d.Reasons = append(d.Reasons, fmt.Sprintf("%s [%s -> %s]: %s",
			f.Signal, f.Rule, f.Severity, f.Detail))
	}
	sort.Strings(d.Reasons)
	return d
}
