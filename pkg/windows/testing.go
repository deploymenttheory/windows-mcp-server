//go:build windows && (amd64 || arm64)

package windows

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/windows-mcp-server/internal/desktop"
	"github.com/deploymenttheory/windows-mcp-server/pkg/inventory"
)

// Assert wait bounds, matching the journey vocabulary so a document cannot ask
// for a poll the tool would silently clamp.
const (
	defaultAssertInterval = 400 * time.Millisecond
	maxAssertTimeout      = 120.0
)

// Assert checks a UI condition and returns an explicit PASS/FAIL result, for use
// as a test assertion. A failed assertion is returned as a tool error so the
// agent treats it as a test failure.
//
// The condition is subject × operator × expected (docs/journey-taxonomy.md §5),
// not a fixed list of named checks. Waiting is a modifier on the same call rather
// than a separate polling tool, which is what removes the two parallel condition
// vocabularies this replaced — text_present here and text_exists there, for the
// same check.
func Assert() inventory.ServerTool {
	return NewToolFromHandler(
		ToolsetTesting,
		mcp.Tool{
			Name: "Assert",
			Description: "Assert a UI condition for a test and return PASS or FAIL. State what to read " +
				"('subject'), how to compare it ('operator'), and what you expect ('expected'). " +
				"Element subjects need a target: 'automation_id' (most stable) or 'name' " +
				"(+ optional 'control_type'). Set 'timeout' to wait for the condition instead of " +
				"checking once. The failure message reports what was actually observed. " +
				"A failed assertion is reported as an error.",
			Annotations: &mcp.ToolAnnotations{Title: "Assert UI condition", ReadOnlyHint: true},
			InputSchema: assertSchema(),
		},
		assertHandler,
	)
}

func assertSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "object",
		Properties: map[string]*jsonschema.Schema{
			"subject": {
				Type: "string", Enum: AssertSubjects,
				Description: "What to read: screen.text, window.title, window, element, " +
					"element.name/.value/.control_type/.enabled/.checked/.selected/.focused/.count, result.text.",
			},
			"operator": {
				Type: "string", Enum: AssertOperators,
				Description: "How to compare. Text: is, is_not, contains, does_not_contain, " +
					"starts_with, ends_with, matches (full-match regex), does_not_match, is_empty, " +
					"is_not_empty, is_one_of. Boolean: is_true, is_false. Existence: exists, " +
					"does_not_exist. Number: greater_than, less_than, and their or_equal forms.",
			},
			"expected": {Description: "The expected value. Omit for operators that take none (is_true, exists, …)."},
			"message":  {Type: "string", Description: "Optional description of what is being verified."},

			"automation_id": {Type: "string", Description: "Target by the developer-assigned automation id (most stable)."},
			"name":          {Type: "string", Description: "Target by accessible name from the most recent Snapshot."},
			"control_type":  {Type: "string", Description: "Narrow a target by control type (e.g. Button, Edit)."},
			"name_match": {
				Type: "string", Enum: []any{"exact", "contains", "matches"},
				Description: "How 'name' is matched. Default exact — a substring match must be asked for.",
			},
			"occurrence": {
				Type: "string",
				Description: "What to do when several elements match: 'unique' (default, ambiguity " +
					"fails), 'first', or a 0-based index.",
			},
			"scope": {
				Type: "string", Enum: []any{"foreground", "any_window"},
				Description: "How wide to search. Default foreground.",
			},

			"timeout":  {Type: "number", Description: "Seconds to wait for the condition. Omit to check once. Max 120."},
			"interval": {Type: "number", Description: "Poll period in seconds (default 0.4)."},

			"ignore_case":         {Type: "boolean", Description: "Fold case on both sides of a text comparison."},
			"trim":                {Type: "boolean", Description: "Strip leading/trailing whitespace from the observed value."},
			"collapse_whitespace": {Type: "boolean", Description: "Collapse whitespace runs to one space."},
		},
		Required: []string{"subject", "operator"},
	}
}

func assertHandler(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args, err := ArgsMap(req)
	if err != nil {
		return NewToolResultError(err.Error()), nil
	}
	spec, err := parseAssertion(args)
	if err != nil {
		return NewToolResultError(err.Error()), nil
	}

	pass, obs, polls, err := runAssertion(ctx, deps, spec)
	if err != nil {
		// A malformed assertion is a broken document, not a failed test. Say so
		// distinctly, or an author debugs the application instead of the journey.
		return NewToolResultErrorFromErr("assert", err), nil
	}

	// Hand the comparison to the run record. This is what carries the observed
	// value into the evidence; the model gets the same information as text.
	if reg, ok := deps.(AssertionRegister); ok {
		reg.RecordAssertion(AssertionRecord{
			Subject: spec.subject, Operator: spec.operator,
			Expected: spec.expectedText(), Observed: obs.Render(),
			Passed: pass, Polls: polls, Timeout: spec.timeout.Seconds(),
		})
	}

	if pass {
		return NewToolResultTextf("PASS: %s (observed %s)", spec.description(), obs.Render()), nil
	}
	return NewToolResultErrorf("FAIL: %s — expected %s, observed %s",
		spec.description(), spec.expectedText(), obs.Render()), nil
}

// assertionSpec is one parsed assertion.
type assertionSpec struct {
	subject  string
	operator string
	expected any
	message  string
	selector desktop.SelectorSpec
	scope    string
	timeout  time.Duration
	interval time.Duration
	opts     CompareOptions
}

// description renders what is being verified, for the PASS/FAIL line. The
// author's message wins: the previous shape dropped it for every polled
// assertion, so exactly the assertions most likely to fail were the ones that
// failed without an explanation.
func (s assertionSpec) description() string {
	if s.message != "" {
		return s.message
	}
	if s.selector.Empty() {
		return fmt.Sprintf("%s %s", s.subject, s.operator)
	}
	return fmt.Sprintf("%s %s [%s]", s.subject, s.operator, s.selector.Describe())
}

func (s assertionSpec) expectedText() string {
	if s.expected == nil {
		return s.operator
	}
	return fmt.Sprintf("%v", s.expected)
}

func parseAssertion(args map[string]any) (assertionSpec, error) {
	var s assertionSpec
	var err error

	if s.subject, err = OptionalStringEnum(args, "subject", "", toStrings(AssertSubjects)...); err != nil {
		return s, err
	}
	if s.operator, err = OptionalStringEnum(args, "operator", "", toStrings(AssertOperators)...); err != nil {
		return s, err
	}
	if s.subject == "" || s.operator == "" {
		return s, errors.New("assert needs both a subject and an operator")
	}

	s.expected = args["expected"]
	s.message = OptionalString(args, "message", "")
	s.scope = OptionalString(args, "scope", "")
	s.selector = desktop.SelectorSpec{
		AutomationID: OptionalString(args, "automation_id", ""),
		Name:         OptionalString(args, "name", ""),
		ControlType:  OptionalString(args, "control_type", ""),
		NameMatch:    OptionalString(args, "name_match", ""),
		Occurrence:   OptionalString(args, "occurrence", ""),
	}
	if SubjectNeedsTarget(s.subject) && s.selector.Empty() {
		return s, fmt.Errorf("subject %s needs a target: give automation_id or name", s.subject)
	}

	timeout, err := OptionalFloat(args, "timeout", 0)
	if err != nil {
		return s, err
	}
	if timeout > maxAssertTimeout {
		timeout = maxAssertTimeout
	}
	s.timeout = time.Duration(timeout * float64(time.Second))

	interval, err := OptionalFloat(args, "interval", 0)
	if err != nil {
		return s, err
	}
	s.interval = defaultAssertInterval
	if interval > 0 {
		s.interval = time.Duration(interval * float64(time.Second))
	}

	s.opts = CompareOptions{
		IgnoreCase:         OptionalBool(args, "ignore_case", false),
		Trim:               OptionalBool(args, "trim", false),
		CollapseWhitespace: OptionalBool(args, "collapse_whitespace", false),
	}
	return s, nil
}

// runAssertion evaluates the assertion, polling while a timeout remains. It
// returns the final observation either way, so a failure reports what was on
// screen rather than only that the condition was not met, and the poll count, so
// "passed immediately" and "passed on the last poll" are distinguishable.
func runAssertion(ctx context.Context, deps ToolDependencies, s assertionSpec) (bool, Observation, int, error) {
	deadline := time.Now().Add(s.timeout)
	polls := 0
	for {
		polls++
		obs, err := observeSubject(deps, s)
		if err != nil {
			return false, obs, polls, err
		}
		pass, err := EvalAssertion(s.operator, obs, s.expected, s.opts)
		if err != nil {
			return false, obs, polls, err
		}
		if pass || time.Now().After(deadline) {
			return pass, obs, polls, nil
		}
		select {
		case <-ctx.Done():
			return false, obs, polls, ctx.Err()
		case <-time.After(s.interval):
		}
	}
}

// observeSubject reads the subject from the live desktop. Every evaluation takes
// its own snapshot, so a polled assertion re-reads the screen on every poll —
// which is what makes polling mean anything.
func observeSubject(deps ToolDependencies, s assertionSpec) (Observation, error) {
	kind, ok := SubjectKind(s.subject)
	if !ok {
		return Observation{}, fmt.Errorf("%w: unknown subject %q", ErrAssertionShape, s.subject)
	}

	if s.subject == SubjectResultText {
		return observeRegister(deps, kind), nil
	}

	dsk := deps.Desktop()
	state, err := dsk.Snapshot(desktop.SnapshotOptions{AllWindows: s.scope == "any_window"})
	if err != nil {
		return Observation{}, fmt.Errorf("snapshot failed: %w", err)
	}

	switch s.subject {
	case SubjectScreenText:
		return Observation{Kind: kind, Text: state.TreeText}, nil
	case SubjectWindowTitle:
		return Observation{Kind: kind, Text: state.Foreground.Title}, nil
	case SubjectWindow:
		return Observation{Kind: kind, Exists: windowMatches(state, s.selector)}, nil
	}

	matches, err := dsk.Matches(s.selector)
	if err != nil {
		return Observation{}, err
	}
	if s.subject == SubjectElementCount {
		return Observation{Kind: kind, Number: float64(len(matches))}, nil
	}
	if s.subject == SubjectElement {
		return Observation{Kind: kind, Exists: len(matches) > 0}, nil
	}

	// Everything below reads one element, so ambiguity is resolved — or refused —
	// before anything is read.
	label, _, err := dsk.Resolve(s.selector)
	if err != nil {
		if errors.Is(err, desktop.ErrNoMatch) {
			return Observation{Kind: kind, Absent: true, AbsentReason: "no matching element"}, nil
		}
		return Observation{}, err
	}
	st, err := dsk.ElementState(label)
	if err != nil {
		return Observation{}, err
	}
	return observeElement(s.subject, kind, st), nil
}

// observeRegister reads what the most recent read step returned.
func observeRegister(deps ToolDependencies, kind ValueKind) Observation {
	reg, ok := deps.(ReadRegister)
	if !ok {
		return Observation{Kind: kind, Absent: true, AbsentReason: "no read register on this session"}
	}
	text, set := reg.LastRead()
	if !set {
		return Observation{Kind: kind, Absent: true, AbsentReason: "nothing has been read yet"}
	}
	return Observation{Kind: kind, Text: text}
}

// observeElement maps one element's state onto the requested subject. The Has*
// flags matter: a Button has no toggle state, and reporting that is not the same
// as reporting that it is unchecked.
func observeElement(subject string, kind ValueKind, st desktop.ElementState) Observation {
	switch subject {
	case SubjectElementName:
		return Observation{Kind: kind, Text: st.Name}
	case SubjectElementControlType:
		return Observation{Kind: kind, Text: st.ControlType}
	case SubjectElementValue:
		if !st.HasValue {
			return Observation{Kind: kind, Absent: true, AbsentReason: "the element exposes no value"}
		}
		return Observation{Kind: kind, Text: st.Value}
	case SubjectElementEnabled:
		return Observation{Kind: kind, Bool: st.Enabled}
	case SubjectElementFocused:
		return Observation{Kind: kind, Bool: st.Focused}
	case SubjectElementChecked:
		if !st.HasToggle {
			return Observation{Kind: kind, Absent: true, AbsentReason: "the element has no checked state"}
		}
		return Observation{Kind: kind, Bool: st.Checked}
	case SubjectElementSelected:
		if !st.HasSelection {
			return Observation{Kind: kind, Absent: true, AbsentReason: "the element has no selected state"}
		}
		return Observation{Kind: kind, Bool: st.Selected}
	default:
		return Observation{Kind: kind, Absent: true, AbsentReason: "unreadable subject"}
	}
}

// windowMatches reports whether any window's title satisfies the selector,
// honouring name_match so window existence is decided the same way element
// existence is.
func windowMatches(state *desktop.DesktopState, spec desktop.SelectorSpec) bool {
	needle := spec.Name
	if needle == "" {
		needle = spec.AutomationID // a window has no automation id; treat it as the title
	}
	for _, w := range state.Windows {
		switch spec.NameMatch {
		case desktop.MatchContains:
			if strings.Contains(strings.ToLower(w.Title), strings.ToLower(needle)) {
				return true
			}
		default:
			if strings.EqualFold(strings.TrimSpace(w.Title), strings.TrimSpace(needle)) {
				return true
			}
		}
	}
	return false
}

func toStrings(vals []any) []string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// CaptureEvidence captures a screenshot and the UI-tree snapshot together, for
// test evidence and debugging.
func CaptureEvidence() inventory.ServerTool {
	return NewToolFromHandler(
		ToolsetTesting,
		mcp.Tool{
			Name: "CaptureEvidence",
			Description: "Capture test evidence in one call: a screenshot image plus the labeled " +
				"UI-tree snapshot text. Use at key test steps and on failure. Read-only.",
			Annotations: &mcp.ToolAnnotations{Title: "Capture test evidence", ReadOnlyHint: true},
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"label": {Type: "string", Description: "Optional caption identifying this evidence (e.g. the test step)."},
				},
			},
		},
		func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args, err := ArgsMap(req)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			label := OptionalString(args, "label", "")
			dsk := deps.Desktop()

			state, err := dsk.Snapshot(desktop.SnapshotOptions{})
			if err != nil {
				return NewToolResultErrorFromErr("evidence: snapshot failed", err), nil
			}
			pngData, w, h, denom, err := dsk.Screenshot()
			if err != nil {
				return NewToolResultErrorFromErr("evidence: screenshot failed", err), nil
			}

			var caption strings.Builder
			if label != "" {
				fmt.Fprintf(&caption, "Evidence: %s\n", label)
			}
			fmt.Fprintf(&caption, "Screenshot %dx%d", w, h)
			if denom > 1 {
				fmt.Fprintf(&caption, " (downscaled %dx)", denom)
			}

			// Persist the image when the session has somewhere to put it. A capture
			// that returns a picture to the model and writes nothing leaves the
			// durable record of a run with no pictures of it.
			if sink, ok := deps.(EvidenceSink); ok {
				art, written, werr := sink.WriteEvidence(label, pngData, w, h)
				switch {
				case werr != nil:
					// The evidence still reached the model; failing the step would turn a
					// disk problem into a failed test.
					deps.Logger(ctx).Warn("evidence capture not persisted", "label", label, "error", werr)
				case written:
					fmt.Fprintf(&caption, "\nSaved %s (sha256 %s)", art.Path, art.SHA256[:12])
				}
			}

			caption.WriteString("\n\n")
			caption.WriteString(formatSnapshot(state))

			return NewToolResultImage(caption.String(), pngData, "image/png"), nil
		},
	)
}
