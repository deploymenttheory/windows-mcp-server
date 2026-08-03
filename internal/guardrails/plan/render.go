package plan

import (
	"fmt"
	"slices"
	"strings"
)

// Render produces the human-readable change manifest: what the plan will change,
// grouped by the class of thing touched, with each step annotated. It is the
// terraform-plan-esque view — deliberately a list of declared and derived changes, not
// a before/after state diff, because reading the current state would itself be an
// action and may exceed what the session is allowed to do.
//
// The machine-readable form is the Document's own JSON; this is for a reviewer.
func (d Document) Render() string {
	var b strings.Builder

	destructive := 0
	undeclarable := 0
	byKind := map[TargetKind][]string{}

	fmt.Fprintf(&b, "Plan %s — %d step(s)\n", short(d.PlanID), len(d.Steps))

	for i, s := range d.Steps {
		flags := ""
		if s.Destructive() {
			destructive++
			flags += " ⚠ destructive"
		}
		if s.Undeclarable() {
			undeclarable++
			flags += " ⚠ undeclarable blast radius"
		}
		name := s.Name
		if name == "" {
			name = s.Tool
		}
		fmt.Fprintf(&b, "\n  %d. %s [%s]%s\n", i+1, name, s.Tool, flags)
		for _, t := range s.EffectiveTargets() {
			fmt.Fprintf(&b, "       %-8s %-7s %s\n", t.Kind, t.Verb, t.Name)
			byKind[t.Kind] = append(byKind[t.Kind], string(t.Verb)+" "+t.Name)
		}
	}

	b.WriteString("\nSummary:\n")
	for _, k := range sortedKinds(byKind) {
		fmt.Fprintf(&b, "  %s: %d\n", k, len(byKind[k]))
	}
	fmt.Fprintf(&b, "  %d of %d step(s) destructive", destructive, len(d.Steps))
	if undeclarable > 0 {
		fmt.Fprintf(&b, ", %d with an undeclarable blast radius", undeclarable)
	}
	b.WriteString("\n")
	return b.String()
}

func sortedKinds(m map[TargetKind][]string) []TargetKind {
	out := make([]TargetKind, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func short(id string) string {
	if len(id) <= 12 {
		if id == "" {
			return "(unhashed)"
		}
		return id
	}
	return id[:12]
}
