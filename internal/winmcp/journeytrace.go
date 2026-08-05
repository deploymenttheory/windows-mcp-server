//go:build windows && (amd64 || arm64)

package winmcp

import (
	"fmt"
	"os"

	"github.com/deploymenttheory/windows-mcp-server/internal/journeys"
	"github.com/deploymenttheory/windows-mcp-server/internal/runrecord"
	"github.com/deploymenttheory/windows-mcp-server/pkg/windows"
)

// journeyTracer turns the planner's step events into the run's OpenTelemetry
// trace, described in docs/journey-evidence.md.
//
// The shape follows the flattened compilation: an observe or an action is a child
// of the run, and the assertions and captures that follow an action are children
// of it. That is what makes the trace read like the journey rather than like the
// plan it compiled to.
type journeyTracer struct {
	rec     *runrecord.Recorder
	origins []journeys.Origin
	deps    windows.ToolDependencies

	run    runrecord.SpanID
	action runrecord.SpanID
}

func newJourneyTracer(
	rec *runrecord.Recorder,
	origins []journeys.Origin,
	deps windows.ToolDependencies,
	run runrecord.SpanID,
) *journeyTracer {
	return &journeyTracer{rec: rec, origins: origins, deps: deps, run: run}
}

// observeStep records one executed plan step. It is the planner's step observer.
func (t *journeyTracer) observeStep(e stepEvent) {
	var o journeys.Origin
	if e.Index < len(t.origins) {
		o = t.origins[e.Index]
	}

	span := runrecord.Span{
		Start:   e.Started,
		End:     e.Ended,
		Failed:  e.Outcome != stepOK,
		Message: e.Detail,
		Attrs: []runrecord.Attr{
			runrecord.Int("journey.step.index", int64(e.Index)),
			runrecord.String("journey.step.name", e.Step.Name),
			runrecord.String("journey.step.tool", e.Step.Tool),
			runrecord.String("journey.step.outcome", string(e.Outcome)),
			runrecord.String("journey.step.verdict", e.Verdict),
		},
	}

	switch o.Kind {
	case journeys.OriginAssertion:
		span.Name = fmt.Sprintf("assert %s %s", o.Subject, o.Operator)
		span.Parent = t.parentForChild()
		span.Attrs = append(span.Attrs, t.assertionAttrs(o)...)
		t.rec.Add(span)
		return

	case journeys.OriginEvidence:
		span.Name = "capture " + o.Label
		span.Parent = t.parentForChild()
		span.Attrs = append(span.Attrs, t.evidenceAttrs(o)...)
		t.rec.Add(span)
		return

	case journeys.OriginObserve:
		span.Name = "observe"
		span.Parent = t.run
		span.Attrs = append(span.Attrs,
			runrecord.String("journey.step.verb", string(journeys.VerbObserve)),
			runrecord.Bool("journey.step.synthetic", true),
		)
		// An observe does not become the parent of the assertions that follow: it is
		// the compiler's, not the author's, and hanging their spans off it would
		// misattribute them to a step nobody wrote.
		t.rec.Add(span)
		return

	default:
		span.Name = spanNameForAction(o, e)
		span.Parent = t.run
		span.Attrs = append(span.Attrs, runrecord.String("journey.step.verb", string(o.Verb)))
		span.Attrs = append(span.Attrs, selectorAttrs(o.Selector)...)
		t.action = t.rec.Add(span)
	}
}

// parentForChild returns the action span an assertion or capture belongs to,
// falling back to the run when a journey opens with one.
func (t *journeyTracer) parentForChild() runrecord.SpanID {
	if t.action.IsZero() {
		return t.run
	}
	return t.action
}

// assertionAttrs carries the comparison. journey.assertion.observed is the point
// of the whole record: a failure that reports only the condition says a test
// broke, one that reports what was read usually says why.
func (t *journeyTracer) assertionAttrs(o journeys.Origin) []runrecord.Attr {
	attrs := []runrecord.Attr{
		runrecord.String("journey.assertion.subject", string(o.Subject)),
		runrecord.String("journey.assertion.operator", string(o.Operator)),
		runrecord.String("journey.assertion.message", o.Message),
	}
	if o.Expected != nil {
		attrs = append(attrs, runrecord.String("journey.assertion.expected", fmt.Sprint(o.Expected)))
	}
	if o.Wait != nil {
		attrs = append(attrs, runrecord.Float("journey.assertion.timeout", o.Wait.Resolved().Timeout))
	}
	attrs = append(attrs, selectorAttrs(o.Selector)...)

	// What the tool actually read, via the run-scoped register. Absent only when
	// the assertion never got as far as evaluating — a refusal, or a malformed
	// document — in which case there is genuinely nothing observed to report.
	if reg, ok := t.deps.(windows.AssertionRegister); ok {
		if rec, set := reg.LastAssertion(); set {
			attrs = append(attrs,
				runrecord.String("journey.assertion.observed", rec.Observed),
				runrecord.Bool("journey.assertion.passed", rec.Passed),
				runrecord.Int("journey.assertion.polls", int64(rec.Polls)),
			)
		}
	}
	return attrs
}

// evidenceAttrs names the image this capture wrote, so the record identifies the
// artifact and the manifest proves it has not been altered since.
func (t *journeyTracer) evidenceAttrs(o journeys.Origin) []runrecord.Attr {
	attrs := []runrecord.Attr{runrecord.String("journey.evidence.label", o.Label)}
	sink, ok := t.deps.(windows.EvidenceSink)
	if !ok {
		return attrs
	}
	for _, art := range sink.CapturedEvidence() {
		if art.Label != o.Label {
			continue
		}
		attrs = append(attrs,
			runrecord.String("journey.evidence.path", "evidence/"+art.Path),
			runrecord.String("journey.evidence.sha256", art.SHA256),
			runrecord.Int("journey.evidence.width", int64(art.Width)),
			runrecord.Int("journey.evidence.height", int64(art.Height)),
		)
		break
	}
	return attrs
}

// selectorAttrs records what was targeted and how. journey.selector.durable is
// what makes coordinate fragility a queryable property of a suite rather than a
// suspicion raised after the third mystery failure.
func selectorAttrs(sel *journeys.Selector) []runrecord.Attr {
	if sel == nil {
		return nil
	}
	attrs := []runrecord.Attr{
		runrecord.String("journey.selector.automation_id", sel.AutomationID),
		runrecord.String("journey.selector.name", sel.Name),
		runrecord.String("journey.selector.control_type", sel.ControlType),
		runrecord.String("journey.selector.occurrence", sel.Occurrence.String()),
		runrecord.Bool("journey.selector.durable", len(sel.Point) == 0),
	}
	match := sel.NameMatch
	if match == "" {
		match = journeys.MatchExact
	}
	if sel.Name != "" {
		attrs = append(attrs, runrecord.String("journey.selector.name_match", string(match)))
	}
	scope := sel.Scope
	if scope == "" {
		scope = journeys.ScopeForeground
	}
	attrs = append(attrs, runrecord.String("journey.selector.scope", string(scope)))
	return attrs
}

// spanNameForAction names an action span after the verb and what it acted on.
func spanNameForAction(o journeys.Origin, e stepEvent) string {
	if o.Verb == "" {
		return e.Step.Tool
	}
	if label := o.Selector.Label(); label != "" {
		return fmt.Sprintf("%s %q", o.Verb, label)
	}
	return string(o.Verb)
}

// writeRunRecord serialises the trace next to the session's other evidence.
// Failing to write it never fails the run: the journey's verdict is already on
// the audit chain, and losing the richer record is not a reason to report a
// passing suite as broken.
func writeRunRecord(dir, name, session string, rec *runrecord.Recorder) (string, error) {
	if dir == "" {
		return "", nil
	}
	blob, err := rec.MarshalOTLPJSON()
	if err != nil {
		return "", fmt.Errorf("render run record: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("run record dir: %w", err)
	}
	path := fmt.Sprintf("%s-%s.otlp.json", slugForFile(name), session)
	full := dir + string(os.PathSeparator) + path
	if err := os.WriteFile(full, blob, 0o600); err != nil {
		return "", fmt.Errorf("write run record: %w", err)
	}
	return full, nil
}

// slugForFile renders a journey name as a filename component.
func slugForFile(name string) string {
	out := make([]rune, 0, len(name))
	lastDash := true
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			out, lastDash = append(out, r), false
		case r >= 'A' && r <= 'Z':
			out, lastDash = append(out, r+('a'-'A')), false
		case !lastDash:
			out, lastDash = append(out, '-'), true
		}
	}
	s := string(out)
	for len(s) > 0 && s[len(s)-1] == '-' {
		s = s[:len(s)-1]
	}
	if s == "" {
		return "journey"
	}
	return s
}
