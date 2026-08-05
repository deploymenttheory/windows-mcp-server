package journeys

import (
	"fmt"
	"maps"
	"slices"
	"strconv"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/plan"
)

// The tools a verb or an assertion lowers to. A journey document names none of
// them: the lowering is this package's business, which is what lets the tool
// surface change without invalidating a checked-in suite.
const (
	toolApp             = "App"
	toolClick           = "Click"
	toolType            = "Type"
	toolInvoke          = "Invoke"
	toolShortcut        = "Shortcut"
	toolScroll          = "Scroll"
	toolSnapshot        = "Snapshot"
	toolGetText         = "GetText"
	toolWait            = "Wait"
	toolAssert          = "Assert"
	toolCaptureEvidence = "CaptureEvidence"
	toolCredentials     = "Credentials"
)

// OriginKind says what part of a journey a compiled plan step came from.
type OriginKind string

const (
	// OriginAction is the step's verb.
	OriginAction OriginKind = "action"
	// OriginObserve is a compiler-inserted perception step.
	OriginObserve OriginKind = "observe"
	// OriginAssertion is one of the step's assertions.
	OriginAssertion OriginKind = "assertion"
	// OriginEvidence is one of the step's evidence captures.
	OriginEvidence OriginKind = "evidence"
)

// Origin records which part of the journey one compiled plan step came from.
// Compilation flattens a journey — an action, then its assertions, then its
// captures — so without this the executor sees an undifferentiated list of tool
// calls and cannot attribute a result back to what the author wrote.
//
// It is returned alongside the document rather than carried on it: a plan step's
// fields are hashed into the plan id, and journey provenance is not part of what
// an approval binds to.
type Origin struct {
	// StepIndex is the journey step this came from, or -1 for a step that belongs
	// to no journey step.
	StepIndex int
	Kind      OriginKind
	// Index is the position among the step's assertions or captures.
	Index int

	Verb     Verb
	Selector *Selector

	Subject  Subject
	Operator Operator
	Expected any
	Message  string
	Wait     *Wait

	Label string
}

// Compile turns a validated journey into a plan.Document. It is CompileWithOrigins
// without the provenance, for callers that only need to run the plan.
func Compile(j Journey, sessionID string) (plan.Document, error) {
	doc, _, err := CompileWithOrigins(j, sessionID)
	return doc, err
}

// CompileWithOrigins turns a validated journey into a plan.Document and the
// per-step provenance: each step becomes the tool call its verb lowers to,
// preceded by a perception step where one is needed, followed by one step per
// assertion and one per evidence capture.
//
// The result is an ordinary plan, so it runs through the same executor Apply uses:
// every step is policy-evaluated, audited as plan.step, and fail-stopped on the
// first failure. A failed assertion is an Assert tool error — a failed step — so
// the journey stops there, which is exactly a test runner's behaviour.
//
// The origins slice is parallel to doc.Steps and is what lets the run record
// attribute a span to the verb or assertion an author wrote.
//
// sessionID is stamped onto the document so its audit and any evidence bundle tie
// back to the run; it does not affect the plan id, which is content-derived.
func CompileWithOrigins(j Journey, sessionID string) (plan.Document, []Origin, error) {
	if err := j.Validate(); err != nil {
		return plan.Document{}, nil, err
	}

	var (
		steps   []plan.Step
		origins []Origin
	)
	emit := func(s plan.Step, o Origin) {
		steps = append(steps, s)
		origins = append(origins, o)
	}

	for i, s := range j.Steps {
		// Perception is per step, never ambient: a verb that names an element
		// resolves against a snapshot taken as part of that step, so the same
		// document cannot behave differently depending on what ran before it.
		// Emitting it as a real step also puts the moment of observation on the
		// audit chain and in the change manifest.
		if needsPerception(s) && !lastIsSnapshot(steps) {
			emit(observeStep(s.Target.Scope), Origin{
				StepIndex: i, Kind: OriginObserve, Verb: VerbObserve,
			})
		}

		lowered, err := lowerStep(s, i)
		if err != nil {
			return plan.Document{}, nil, err
		}
		for _, ls := range lowered {
			emit(ls, Origin{StepIndex: i, Kind: OriginAction, Verb: s.Verb, Selector: s.Target})
		}

		for a, as := range s.Assertions {
			emit(assertStep(as, i, a), Origin{
				StepIndex: i, Kind: OriginAssertion, Index: a,
				Subject: as.Subject, Operator: as.Operator, Expected: as.Expected,
				Message: as.Message, Wait: as.Wait, Selector: as.Target,
			})
		}
		for e, label := range s.Evidence {
			emit(plan.Step{
				Name: "evidence: " + label,
				Tool: toolCaptureEvidence,
				Args: map[string]any{"label": label},
			}, Origin{StepIndex: i, Kind: OriginEvidence, Index: e, Label: label})
		}
	}

	doc := plan.Document{
		Version:   plan.SchemaVersion,
		SessionID: sessionID,
		Steps:     steps,
	}
	withID, err := doc.WithID()
	if err != nil {
		return plan.Document{}, nil, fmt.Errorf("compute plan id: %w", err)
	}
	return withID, origins, nil
}

// needsPerception reports whether a step resolves a selector and therefore needs a
// fresh snapshot first. An explicit observe supplies its own.
func needsPerception(s Step) bool {
	return s.Target != nil && s.Verb != VerbObserve
}

// lastIsSnapshot reports whether the previous emitted step already perceived, so
// consecutive selector-bearing steps do not each pay for a redundant tree walk.
func lastIsSnapshot(steps []plan.Step) bool {
	return len(steps) > 0 && steps[len(steps)-1].Tool == toolSnapshot
}

// observeStep builds the perception step for a scope.
func observeStep(scope Scope) plan.Step {
	args := map[string]any{}
	if scope == ScopeAnyWindow {
		args["all_windows"] = true
	}
	return plan.Step{Name: "observe", Tool: toolSnapshot, Args: args}
}

// lowerStep turns one journey step into the tool calls that express it. Most verbs
// are a single call; close_window is two, because sending alt+F4 to whatever
// happens to be foreground is how a journey closes the wrong thing.
func lowerStep(s Step, i int) ([]plan.Step, error) {
	name := actionName(s, i)
	sel := selectorArgs(s.Target)

	one := func(tool string, args map[string]any) ([]plan.Step, error) {
		return []plan.Step{{Name: name, Tool: tool, Args: args}}, nil
	}

	switch s.Verb {
	case VerbOpenApp:
		return one(toolApp, map[string]any{"mode": "launch", "name": s.App})
	case VerbFocusWindow:
		return one(toolApp, map[string]any{"mode": "switch", "name": s.Window})
	case VerbResizeWindow:
		args := map[string]any{"mode": "resize", "name": s.Window}
		if len(s.Position) == 2 {
			args["window_loc"] = s.Position
		}
		if len(s.Size) == 2 {
			args["window_size"] = s.Size
		}
		return one(toolApp, args)
	case VerbCloseWindow:
		return closeWindowSteps(name, s.Window), nil
	case VerbNavigate:
		return one(toolApp, map[string]any{"mode": "launch", "name": s.URL})

	case VerbScroll:
		args := merge(sel, map[string]any{"direction": s.Direction})
		if s.Amount > 0 {
			args["wheel_times"] = s.Amount
		}
		return one(toolScroll, args)

	case VerbClick:
		return one(toolClick, merge(sel, map[string]any{"clicks": 1}))
	case VerbDoubleClick:
		return one(toolClick, merge(sel, map[string]any{"clicks": 2}))
	case VerbRightClick:
		return one(toolClick, merge(sel, map[string]any{"button": "right"}))
	case VerbHover:
		return one(toolClick, merge(sel, map[string]any{"clicks": 0}))

	case VerbInvoke, VerbToggle, VerbSelect, VerbExpand, VerbCollapse:
		return one(toolInvoke, merge(sel, map[string]any{"action": string(s.Verb)}))
	case VerbSetValue:
		return one(toolInvoke, merge(sel, map[string]any{"action": "set_value", "value": s.Value}))

	case VerbTypeText:
		args := merge(sel, map[string]any{"text": s.Text})
		if s.Submit {
			args["press_enter"] = true
		}
		return one(toolType, args)
	case VerbClear:
		return one(toolType, merge(sel, map[string]any{"clear": true, "text": ""}))
	case VerbPressKeys:
		return one(toolShortcut, map[string]any{"shortcut": s.Keys})
	case VerbEnterCredential:
		return one(toolCredentials, credentialArgs(s))

	case VerbObserve:
		return []plan.Step{observeStep(s.Scope)}, nil
	case VerbRead:
		return one(toolGetText, sel)
	case VerbCapture:
		return one(toolCaptureEvidence, map[string]any{"label": s.Label})
	case VerbPause:
		return one(toolWait, map[string]any{"duration": s.Seconds})
	}
	return nil, fmt.Errorf("%w: %q", ErrUnknownVerb, s.Verb)
}

// closeWindowSteps focuses the window, then closes it.
//
// The second step carries an explicit target because the lowering loses what the
// verb meant: the manifest would otherwise show a keyboard chord being executed
// and say nothing about a window being closed. Declaring the derived target
// alongside it keeps the plan's no-understatement rule satisfied — a declaration
// may add to what a step provably touches, never subtract from it.
func closeWindowSteps(name, window string) []plan.Step {
	focus := plan.Step{
		Name: name + " (focus)",
		Tool: toolApp,
		Args: map[string]any{"mode": "switch", "name": window},
	}
	closer := plan.Step{
		Name: name,
		Tool: toolShortcut,
		Args: map[string]any{"shortcut": "alt+f4"},
	}
	derived, _ := plan.DeriveTargets(closer)
	closer.Targets = slices.Concat(derived, []plan.Target{
		{Kind: plan.KindUI, Name: window, Verb: plan.VerbDelete},
	})
	return []plan.Step{focus, closer}
}

// credentialArgs builds an inject call. The Credentials tool spells its target
// argument name_target, because its own name means the credential — a wart the
// verb hides, and one reason a journey names verbs rather than tools.
func credentialArgs(s Step) map[string]any {
	args := map[string]any{"mode": "inject", "name": s.Credential}
	for k, v := range selectorArgs(s.Target) {
		if k == "name" {
			args["name_target"] = v
			continue
		}
		args[k] = v
	}
	if s.Submit {
		args["press_enter"] = true
	}
	return args
}

// selectorArgs encodes a selector as tool arguments. Defaults are left off so a
// step's arguments — and therefore its digest in the audit chain — reflect what
// the document said rather than what the schema filled in.
func selectorArgs(sel *Selector) map[string]any {
	args := map[string]any{}
	if sel == nil {
		return args
	}
	if sel.AutomationID != "" {
		args["automation_id"] = sel.AutomationID
	}
	if sel.Name != "" {
		args["name"] = sel.Name
	}
	if sel.ControlType != "" {
		args["control_type"] = sel.ControlType
	}
	if sel.NameMatch != "" && sel.NameMatch != MatchExact {
		args["name_match"] = string(sel.NameMatch)
	}
	if o := sel.Occurrence.Resolved(); o.Mode != OccurrenceUnique {
		args["occurrence"] = o.String()
	}
	if len(sel.Point) == 2 {
		args["loc"] = sel.Point
	}
	if sel.Scope == ScopeAnyWindow {
		args["scope"] = string(sel.Scope)
	}
	return args
}

// assertStep lowers one assertion to an Assert call.
//
// Every assertion becomes one tool call, waited or not: the wait is a modifier on
// the condition rather than a separate polling tool, which is what collapses the
// two condition vocabularies the previous schema had to reconcile by hand.
func assertStep(as Assertion, stepIdx, idx int) plan.Step {
	args := merge(selectorArgs(as.Target), map[string]any{
		"subject":  string(as.Subject),
		"operator": string(as.Operator),
	})
	if as.Expected != nil {
		args["expected"] = as.Expected
	}
	if as.Message != "" {
		args["message"] = as.Message
	}
	if as.IgnoreCase {
		args["ignore_case"] = true
	}
	if as.Trim {
		args["trim"] = true
	}
	if as.CollapseWhitespace {
		args["collapse_whitespace"] = true
	}
	if as.Wait != nil {
		w := as.Wait.Resolved()
		args["timeout"] = w.Timeout
		args["interval"] = w.Interval
	}
	return plan.Step{
		Name: fmt.Sprintf("assert[%d.%d]: %s", stepIdx, idx, assertDescription(as)),
		Tool: toolAssert,
		Args: args,
	}
}

// merge copies extra over base, returning base. Both maps are compiler-owned.
func merge(base, extra map[string]any) map[string]any {
	if base == nil {
		base = map[string]any{}
	}
	maps.Copy(base, extra)
	return base
}

// actionName labels the action step: the journey step's name, else its verb and
// what it acts on.
func actionName(s Step, i int) string {
	if s.Name != "" {
		return s.Name
	}
	if subject := s.subjectLabel(); subject != "" {
		return fmt.Sprintf("step %d: %s %s", i, s.Verb, subject)
	}
	return fmt.Sprintf("step %d: %s", i, s.Verb)
}

// subjectLabel renders what a step acts on, for a step name.
func (s Step) subjectLabel() string {
	switch {
	case s.Target != nil:
		return strconv.Quote(s.Target.Label())
	case s.App != "":
		return strconv.Quote(s.App)
	case s.Window != "":
		return strconv.Quote(s.Window)
	case s.URL != "":
		return s.URL
	case s.Keys != "":
		return s.Keys
	case s.Label != "":
		return strconv.Quote(s.Label)
	default:
		return ""
	}
}

// Label renders a selector compactly: its identifying key, which is also the name
// the change manifest shows for what the step touches.
func (s *Selector) Label() string {
	switch {
	case s == nil:
		return ""
	case s.AutomationID != "":
		return s.AutomationID
	case s.Name != "":
		return s.Name
	case len(s.Point) == 2:
		return fmt.Sprintf("(%d,%d)", s.Point[0], s.Point[1])
	default:
		return ""
	}
}

// assertDescription renders an assertion compactly for a step name.
func assertDescription(as Assertion) string {
	if as.Message != "" {
		return as.Message
	}
	out := string(as.Subject) + " " + string(as.Operator)
	if as.Expected != nil {
		out += fmt.Sprintf(" %v", as.Expected)
	}
	return out
}
