//go:build windows && (amd64 || arm64)

package desktop

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Selector resolution is where a journey's determinism lives: it is the point at
// which a document's intent meets a screen that is never quite the same twice.
//
// The rules implemented here are docs/journey-taxonomy.md §4.2. Two of them
// replace behaviour that silently widened a selector:
//
//   - Matching no longer falls back from an exact name to a substring. That
//     fallback meant a selector for "Save" resolved to "Save As…" on any screen
//     with no exact match — and the step passed, having acted on the wrong
//     control. Substring matching is still available, as name_match: contains,
//     but only when it is asked for.
//   - More than one match is an error naming the count, not a silent pick of
//     index 0. Choosing among matches is legal, and has to be written down.

// Selector matching and occurrence modes, matching the journey vocabulary.
const (
	MatchExact    = "exact"
	MatchContains = "contains"
	MatchMatches  = "matches"

	OccurrenceUnique = "unique"
	OccurrenceFirst  = "first"
)

// ErrNoMatch reports a selector that matched nothing; ErrAmbiguousSelector
// reports one that matched more than one element under unique occurrence.
var (
	ErrNoMatch            = errors.New("no element matched")
	ErrAmbiguousSelector  = errors.New("the selector matches more than one element")
	ErrOccurrenceOutOfRan = errors.New("the occurrence index is past the last match")
	ErrBadOccurrence      = errors.New(`occurrence must be "unique", "first", or a 0-based index`)
	ErrBadNameMatch       = errors.New(`name_match must be "exact", "contains" or "matches"`)
	// ErrLabelNotFound reports a label that is not in the current snapshot, which
	// normally means the tree has been rebuilt since it was issued.
	ErrLabelNotFound = errors.New("label not found in the last Snapshot; take a fresh Snapshot first")
)

// SelectorSpec identifies a UI element. Exactly one of AutomationID or Name
// identifies it; ControlType may narrow either.
//
// AutomationID is the top of the stability ladder: it is developer-assigned and,
// unlike the accessible name, survives translation.
type SelectorSpec struct {
	AutomationID string
	Name         string
	ControlType  string
	// NameMatch qualifies Name. Empty means MatchExact.
	NameMatch string
	// Occurrence is "unique" (default), "first", or a 0-based index.
	Occurrence string
}

// Empty reports whether the spec identifies nothing.
func (s SelectorSpec) Empty() bool {
	return s.AutomationID == "" && s.Name == ""
}

// Describe renders the spec for an error message.
func (s SelectorSpec) Describe() string {
	var parts []string
	if s.AutomationID != "" {
		parts = append(parts, "automation_id="+strconv.Quote(s.AutomationID))
	}
	if s.Name != "" {
		parts = append(parts, "name="+strconv.Quote(s.Name))
	}
	if s.ControlType != "" {
		parts = append(parts, "control_type="+s.ControlType)
	}
	if s.NameMatch != "" && s.NameMatch != MatchExact {
		parts = append(parts, "name_match="+s.NameMatch)
	}
	return strings.Join(parts, " ")
}

// Matches returns every interactive element in the most recent snapshot that the
// spec matches, in tree order. It is what element.count reads, and what makes the
// ambiguity check possible: the count is the ground truth a hand-written selector
// can only guess at.
func (d *Desktop) Matches(spec SelectorSpec) ([]LabeledElement, error) {
	pred, err := spec.predicate()
	if err != nil {
		return nil, err
	}
	d.stateMu.Lock()
	defer d.stateMu.Unlock()
	if d.lastState == nil {
		return nil, nil
	}
	var out []LabeledElement
	for i := range d.lastState.Interactive {
		if e := &d.lastState.Interactive[i]; pred(e) {
			out = append(out, *e)
		}
	}
	return out, nil
}

// Resolve returns the label the spec designates, and how many elements it
// matched. The count is returned even on failure, so a caller can report that a
// selector was ambiguous rather than merely unsatisfied.
func (d *Desktop) Resolve(spec SelectorSpec) (label, candidates int, err error) {
	found, err := d.Matches(spec)
	if err != nil {
		return 0, 0, err
	}
	n := len(found)
	if n == 0 {
		return 0, 0, fmt.Errorf("%w for %s; take a fresh Snapshot and check the name",
			ErrNoMatch, spec.Describe())
	}

	switch occ := spec.Occurrence; occ {
	case "", OccurrenceUnique:
		if n > 1 {
			return 0, n, fmt.Errorf("%w: %s matches %d elements (%s). Narrow it with "+
				"control_type, or choose one with occurrence",
				ErrAmbiguousSelector, spec.Describe(), n, describeCandidates(found))
		}
		return found[0].Label, 1, nil
	case OccurrenceFirst:
		return found[0].Label, n, nil
	default:
		idx, convErr := strconv.Atoi(occ)
		if convErr != nil || idx < 0 {
			return 0, n, fmt.Errorf("%w: got %q", ErrBadOccurrence, occ)
		}
		if idx >= n {
			return 0, n, fmt.Errorf("%w: %s matches %d element(s), so index %d does not exist",
				ErrOccurrenceOutOfRan, spec.Describe(), n, idx)
		}
		return found[idx].Label, n, nil
	}
}

// predicate compiles the spec into a match test, so the pattern is compiled once
// rather than per element.
func (s SelectorSpec) predicate() (func(*LabeledElement) bool, error) {
	typeOK := func(e *LabeledElement) bool {
		return s.ControlType == "" || strings.EqualFold(e.Info.ControlType, s.ControlType)
	}

	// An automation id is an identifier, so it is matched exactly and there is
	// nothing to relax. It is checked first because it is the stabler key.
	if s.AutomationID != "" {
		return func(e *LabeledElement) bool {
			return typeOK(e) && e.Info.AutomationID == s.AutomationID
		}, nil
	}

	needle := strings.TrimSpace(s.Name)
	if needle == "" {
		return func(*LabeledElement) bool { return false }, nil
	}

	switch s.NameMatch {
	case "", MatchExact:
		// Exact means the whole name, compared without regard to case. Case folding
		// cannot widen a selector across two differently-named controls — only across
		// two that differ by case alone, which the ambiguity check above then catches
		// rather than resolving arbitrarily.
		return func(e *LabeledElement) bool {
			return typeOK(e) && strings.EqualFold(strings.TrimSpace(e.Info.Name), needle)
		}, nil
	case MatchContains:
		lower := strings.ToLower(needle)
		return func(e *LabeledElement) bool {
			return typeOK(e) && strings.Contains(strings.ToLower(e.Info.Name), lower)
		}, nil
	case MatchMatches:
		re, err := regexp.Compile(needle)
		if err != nil {
			return nil, fmt.Errorf("selector name pattern %q does not compile: %w", needle, err)
		}
		return func(e *LabeledElement) bool {
			return typeOK(e) && re.MatchString(e.Info.Name)
		}, nil
	default:
		return nil, fmt.Errorf("%w: got %q", ErrBadNameMatch, s.NameMatch)
	}
}

// describeCandidates lists what an ambiguous selector matched, so the failure
// tells an author how to disambiguate rather than only that they must.
func describeCandidates(found []LabeledElement) string {
	const max = 5
	parts := make([]string, 0, max)
	for i, e := range found {
		if i == max {
			parts = append(parts, fmt.Sprintf("and %d more", len(found)-max))
			break
		}
		label := e.Info.Name
		if e.Info.AutomationID != "" {
			label = e.Info.AutomationID + " / " + label
		}
		parts = append(parts, fmt.Sprintf("[%d] %s %s", e.Label, e.Info.ControlType, strconv.Quote(label)))
	}
	return strings.Join(parts, ", ")
}
