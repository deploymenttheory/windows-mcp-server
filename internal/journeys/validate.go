package journeys

import (
	"fmt"
	"regexp"
	"strings"
)

// Validate checks a journey against the closed vocabulary: a supported version, a
// name, at least one step, every verb known and carrying exactly the parameters it
// takes, every selector well-formed, every assertion a legal subject/operator pair
// with a correctly typed expected value, and every expected-evidence label
// actually captured by some step.
//
// It reports every problem at once, so an author fixing a file does not discover
// them one run at a time. Everything it checks is checkable offline: the verbs
// carry their own types, so no tool schema — and therefore no Windows host — is
// needed, and `journey validate` is a CI check rather than a smoke test.
func (j Journey) Validate() error {
	if j.Version != SchemaVersion {
		return fmt.Errorf("%w: got %d, want %d", ErrJourneyVersion, j.Version, SchemaVersion)
	}

	v := &validator{}
	if strings.TrimSpace(j.Name) == "" {
		v.add("journey has no name")
	}
	if len(j.Steps) == 0 {
		v.add("journey has no steps, so it verifies nothing")
	}

	produced := map[string]bool{}
	readSeen := false
	for i, s := range j.Steps {
		v.step(s, i)
		// A step's assertions are checked after its action, so a read step has
		// already filled the register by the time its own assertions run.
		if s.Verb == VerbRead {
			readSeen = true
		}
		for a, as := range s.Assertions {
			v.assertion(as, i, a, readSeen)
		}
		for _, label := range s.Evidence {
			produced[label] = true
		}
	}
	for _, want := range j.ExpectedEvidence {
		if !produced[want] {
			v.add("expected_evidence %q is never captured by any step", want)
		}
	}

	return v.err()
}

// validator accumulates problems so a document is reported on whole.
type validator struct{ problems []string }

func (v *validator) add(format string, args ...any) {
	v.problems = append(v.problems, fmt.Sprintf(format, args...))
}

func (v *validator) err() error {
	if len(v.problems) == 0 {
		return nil
	}
	return fmt.Errorf("%w:\n  - %s", ErrInvalidJourney, strings.Join(v.problems, "\n  - "))
}

// step checks one step's verb and parameters.
func (v *validator) step(s Step, i int) {
	label := stepLabel(s, i)
	spec, ok := verbs[s.Verb]
	if !ok {
		if strings.TrimSpace(string(s.Verb)) == "" {
			v.add("step %d (%s): no verb named", i, label)
			return
		}
		v.add("%v: step %d (%s) has verb %q", ErrUnknownVerb, i, label, s.Verb)
		return
	}

	present := s.params()
	if missing := spec.required &^ present; missing != 0 {
		v.add("step %d (%s): %s needs %s", i, label, s.Verb, strings.Join(missing.names(), ", "))
	}
	if extra := present &^ spec.accepts(); extra != 0 {
		v.add("step %d (%s): %s does not take %s", i, label, s.Verb, strings.Join(extra.names(), ", "))
	}

	if s.Target != nil {
		v.selector(s.Target, fmt.Sprintf("step %d (%s) target", i, label))
	}
	v.stepValues(s, i, label)
}

// stepValues checks the parameter values a verb carries, beyond their presence.
func (v *validator) stepValues(s Step, i int, label string) {
	where := fmt.Sprintf("step %d (%s)", i, label)

	if s.Verb == VerbScroll && !isScrollDirection(s.Direction) {
		v.add("%s: direction %q must be up, down, left or right", where, s.Direction)
	}
	if s.Verb == VerbPause && (s.Seconds <= 0 || s.Seconds > MaxPauseSeconds) {
		v.add("%s: seconds must be greater than 0 and at most %g", where, MaxPauseSeconds)
	}
	if s.Verb == VerbNavigate && !strings.Contains(s.URL, "://") {
		v.add("%s: url %q needs an explicit scheme", where, s.URL)
	}
	if s.Scope != "" && !s.Scope.Known() {
		v.add("%s: scope %q must be foreground or any_window", where, s.Scope)
	}
	if len(s.Position) > 0 && len(s.Position) != 2 {
		v.add("%s: position must be [x, y]", where)
	}
	if len(s.Size) > 0 && len(s.Size) != 2 {
		v.add("%s: size must be [width, height]", where)
	}
	if s.Verb == VerbEnterCredential && strings.TrimSpace(s.Credential) == "" {
		// A recorded draft leaves this blank on purpose, so the message says what to
		// do rather than merely that it is missing.
		v.add("%s: credential names which stored credential to inject; a recorded "+
			"draft leaves it blank for you to fill in", where)
	}
}

// selector checks one selector is unambiguous and well-formed.
func (v *validator) selector(sel *Selector, where string) {
	switch n := sel.identifiers(); {
	case n == 0:
		v.add("%s: needs automation_id, name or point", where)
	case n > 1:
		v.add("%s: give exactly one of automation_id, name or point", where)
	}
	if len(sel.Point) > 0 && len(sel.Point) != 2 {
		v.add("%s: point must be [x, y]", where)
	}
	if sel.NameMatch != "" {
		if !sel.NameMatch.Known() {
			v.add("%s: name_match %q must be exact, contains or matches", where, sel.NameMatch)
		}
		if sel.Name == "" {
			// An automation_id is an identifier: there is nothing to relax, and a
			// name_match beside one is an author believing something untrue.
			v.add("%s: name_match qualifies name and belongs only with it", where)
		}
	}
	if sel.NameMatch == MatchMatches && sel.Name != "" {
		v.pattern(sel.Name, where+" name")
	}
	if sel.Occurrence.Mode != "" {
		switch sel.Occurrence.Mode {
		case OccurrenceUnique, OccurrenceFirst, OccurrenceIndex:
		default:
			v.add("%s: occurrence %q is not a mode this build resolves", where, sel.Occurrence.Mode)
		}
	}
	if sel.Scope != "" && !sel.Scope.Known() {
		v.add("%s: scope %q must be foreground or any_window", where, sel.Scope)
	}
}

// assertion checks one assertion: a known subject and operator, a legal pair, a
// correctly typed expected value, and a wait within bounds.
func (v *validator) assertion(as Assertion, stepIdx, idx int, readSeen bool) {
	where := fmt.Sprintf("step %d assertion %d", stepIdx, idx)

	ss, known := subjects[as.Subject]
	if !known {
		v.add("%v: %s has subject %q", ErrUnknownSubject, where, as.Subject)
		return
	}
	os, known := operators[as.Operator]
	if !known {
		v.add("%v: %s has operator %q", ErrUnknownOperator, where, as.Operator)
		return
	}
	if !os.appliesTo(ss.valueType) {
		v.add("%s: operator %q does not apply to %s, which reads a %s value",
			where, as.Operator, as.Subject, ss.valueType)
		return
	}

	switch {
	case ss.needsTarget && as.Target == nil:
		v.add("%s: subject %s needs a target", where, as.Subject)
	case !ss.needsTarget && as.Target != nil:
		v.add("%s: subject %s reads no particular element, so it takes no target", where, as.Subject)
	case as.Target != nil:
		v.selector(as.Target, where+" target")
	}

	if as.Subject == SubjectResultText && !readSeen {
		v.add("%s: subject result.text reads what a read step returned, and no read "+
			"precedes this assertion", where)
	}

	v.expected(as, os, ss.valueType, where)
	v.wait(as.Wait, where)
}

// expected checks the operand against what the operator takes and the subject
// reads.
func (v *validator) expected(as Assertion, os operatorSpec, t ValueType, where string) {
	switch os.operand {
	case operandNone:
		if as.Expected != nil {
			v.add("%s: operator %q takes no expected value", where, as.Operator)
		}
	case operandScalar:
		if as.Expected == nil {
			v.add("%s: operator %q needs an expected value", where, as.Operator)
			return
		}
		if !typeMatches(as.Expected, t) {
			v.add("%s: expected %v is not a %s value, which is what %s reads",
				where, as.Expected, t, as.Subject)
			return
		}
		if os.regex {
			v.pattern(fmt.Sprint(as.Expected), where)
		}
	case operandList:
		list, ok := as.Expected.([]any)
		if !ok {
			v.add("%s: operator %q needs an array of expected values", where, as.Operator)
			return
		}
		if len(list) == 0 {
			v.add("%s: operator %q needs at least one expected value", where, as.Operator)
			return
		}
		for n, item := range list {
			if !typeMatches(item, t) {
				v.add("%s: expected[%d] %v is not a %s value", where, n, item, t)
			}
		}
	}
}

// pattern compiles a regex at validation time, so a bad one fails offline rather
// than mid-run with earlier steps already applied.
func (v *validator) pattern(pat, where string) {
	if len(pat) > MaxPatternLength {
		v.add("%s: pattern is %d characters, over the %d cap", where, len(pat), MaxPatternLength)
		return
	}
	if _, err := regexp.Compile(pat); err != nil {
		v.add("%s: pattern does not compile: %v", where, err)
	}
}

// wait checks a poll budget is within the bounds the executor honours, so a
// journey never asks for something that would be silently clamped.
func (v *validator) wait(w *Wait, where string) {
	if w == nil {
		return
	}
	if w.Timeout < 0 || w.Timeout > MaxWaitTimeout {
		v.add("%s: wait.timeout must be between 0 and %g seconds", where, MaxWaitTimeout)
	}
	if w.Interval < 0 || (w.Interval > 0 && w.Interval < MinWaitInterval) {
		v.add("%s: wait.interval must be at least %g seconds", where, MinWaitInterval)
	}
	if w.Interval > 0 && w.Timeout > 0 && w.Interval > w.Timeout {
		v.add("%s: wait.interval exceeds wait.timeout, so the condition is checked once", where)
	}
}

// typeMatches reports whether a decoded JSON value is of the subject's value type.
// encoding/json decodes every number into float64 when the target is `any`, so a
// numeric subject accepts exactly that.
func typeMatches(val any, t ValueType) bool {
	switch t {
	case TypeText:
		_, ok := val.(string)
		return ok
	case TypeNumber:
		switch val.(type) {
		case float64, int:
			return true
		default:
			return false
		}
	case TypeBoolean:
		_, ok := val.(bool)
		return ok
	default:
		return false
	}
}

func isScrollDirection(d string) bool {
	switch d {
	case "up", "down", "left", "right":
		return true
	default:
		return false
	}
}
