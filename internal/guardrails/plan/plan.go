// Package plan is the serialisable model of a proposed sequence of tool calls,
// plus the derivation and rendering that turn it into a reviewable change
// manifest. It is what lets the policy engine adjudicate a whole plan up front —
// "here is everything this will touch" — rather than one call at a time, which is
// how benign steps compose into a destructive outcome.
//
// It is a leaf of the guardrails stack: it depends only on the standard library.
// The policy engine evaluates the subjects a plan maps to (see EvaluatePlan on the
// engine); the plan package itself takes no dependency on the engine or the tool
// inventory, so it is testable on any platform.
package plan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
)

// SchemaVersion is the plan document version this build understands.
const SchemaVersion = 1

// ErrPlanVersion reports a document from an unsupported schema version.
// ErrUnderstatedTargets reports a step whose declared targets omit something its
// tool provably touches — an attempt, deliberate or not, to hide blast radius.
var (
	ErrPlanVersion        = errors.New("unsupported plan version")
	ErrUnderstatedTargets = errors.New("declared targets understate what the step touches")
)

// Document is a proposed sequence of tool calls, submitted whole so it can be
// reviewed and adjudicated before any of it runs.
type Document struct {
	Version int `json:"version"`
	// PlanID is the SHA-256 of the canonical document with this field cleared, so
	// an approval binds to exact content: change any step and the id changes.
	PlanID string `json:"plan_id,omitempty"`
	// CreatedAt and SessionID are caller-supplied context, carried verbatim. The
	// package never reads the clock, so a document hashes deterministically.
	CreatedAt string `json:"created_at,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	Steps     []Step `json:"steps"`
}

// Step is one tool call in a plan.
type Step struct {
	Name string `json:"name,omitempty"`
	// Tool is the MCP tool name, matching the served manifest.
	Tool string `json:"tool"`
	// Args are the call arguments, used both to run the step and to derive what it
	// touches.
	Args map[string]any `json:"args,omitempty"`
	// Targets are what the step declares it touches. For tools the plan can
	// introspect they are checked against the derivation (a step cannot understate
	// its reach); for a tool it cannot — PowerShell — they are the only signal
	// there is, and the step is flagged as having an undeclarable blast radius.
	Targets []Target `json:"targets,omitempty"`
}

// Target is one thing a step touches: a file, a registry key, a process, a host,
// a UI element, a package, a scheduled task, or an opaque shell.
type Target struct {
	Kind TargetKind `json:"kind"`
	Name string     `json:"name"`
	Verb TargetVerb `json:"verb"`
}

// TargetKind is the class of thing touched.
type TargetKind string

const (
	KindFile     TargetKind = "file"
	KindRegistry TargetKind = "registry"
	KindProcess  TargetKind = "process"
	KindHost     TargetKind = "host"
	KindUI       TargetKind = "ui"
	KindPackage  TargetKind = "package"
	KindTask     TargetKind = "task"
	KindShell    TargetKind = "shell"
)

// TargetVerb is what is done to the target, ordered by how much it mutates.
type TargetVerb string

const (
	VerbRead    TargetVerb = "read"
	VerbReach   TargetVerb = "reach"
	VerbInvoke  TargetVerb = "invoke"
	VerbCreate  TargetVerb = "create"
	VerbWrite   TargetVerb = "write"
	VerbExecute TargetVerb = "execute"
	VerbDelete  TargetVerb = "delete"
	VerbKill    TargetVerb = "kill"
)

var verbRank = map[TargetVerb]int{
	VerbRead: 0, VerbReach: 1, VerbInvoke: 2, VerbCreate: 3,
	VerbWrite: 4, VerbExecute: 5, VerbDelete: 6, VerbKill: 7,
}

// Mutating reports whether a verb changes state (as opposed to reading or
// reaching), which is what makes a step count as destructive in the manifest.
func (v TargetVerb) Mutating() bool {
	switch v {
	case VerbCreate, VerbWrite, VerbExecute, VerbDelete, VerbKill:
		return true
	default:
		return false
	}
}

// ComputeID returns the canonical SHA-256 of the document with PlanID cleared.
// Marshalling is deterministic: struct fields keep declaration order and
// encoding/json sorts map keys, so the same content always hashes the same.
func (d Document) ComputeID() (string, error) {
	c := d
	c.PlanID = ""
	b, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("canonicalize plan: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// WithID returns a copy of the document with PlanID set to its computed hash.
func (d Document) WithID() (Document, error) {
	id, err := d.ComputeID()
	if err != nil {
		return Document{}, err
	}
	d.PlanID = id
	return d, nil
}

// EffectiveTargets returns the union of a step's declared targets and the targets
// derived from its tool and args, de-duplicated. It is what the manifest renders
// and what an executor should treat as the step's reach — declared targets can
// add to the derived set but, per Validate, cannot subtract from it.
func (s Step) EffectiveTargets() []Target {
	derived, _ := DeriveTargets(s)
	seen := map[Target]bool{}
	var out []Target
	for _, t := range slices.Concat(derived, s.Targets) {
		if seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	return out
}

// Undeclarable reports whether the step's tool has a blast radius the plan cannot
// derive (PowerShell). Such a step is not refused — it is flagged, so a reviewer
// knows the manifest is incomplete for it.
func (s Step) Undeclarable() bool {
	_, undeclarable := DeriveTargets(s)
	return undeclarable
}

// Destructive reports whether the step mutates state, or cannot be shown not to.
func (s Step) Destructive() bool {
	if s.Undeclarable() {
		return true
	}
	for _, t := range s.EffectiveTargets() {
		if t.Verb.Mutating() {
			return true
		}
	}
	return false
}

// Validate checks the document is well-formed and that no step understates its
// reach. It reports every problem at once, wrapped in the relevant sentinel.
func (d Document) Validate() error {
	if d.Version != SchemaVersion {
		return fmt.Errorf("%w: got %d, want %d", ErrPlanVersion, d.Version, SchemaVersion)
	}
	var problems []string
	for i, s := range d.Steps {
		if s.Tool == "" {
			problems = append(problems, fmt.Sprintf("step %d: no tool named", i))
			continue
		}
		for _, missing := range understated(s) {
			problems = append(problems, fmt.Sprintf(
				"step %d (%s): declares targets but omits %s %q (%s)",
				i, s.Tool, missing.Kind, missing.Name, missing.Verb))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w:\n  - %s", ErrUnderstatedTargets, join(problems))
	}
	return nil
}

// understated returns the derived targets a step declared targets but failed to
// cover. A step that declares nothing understates nothing — the derivation stands
// in for it. A step that declares some targets must cover every derived one, at a
// verb at least as mutating, or it is hiding reach.
func understated(s Step) []Target {
	if len(s.Targets) == 0 {
		return nil
	}
	derived, _ := DeriveTargets(s)
	var missing []Target
	for _, d := range derived {
		if !coveredBy(s.Targets, d) {
			missing = append(missing, d)
		}
	}
	return missing
}

func coveredBy(declared []Target, want Target) bool {
	for _, t := range declared {
		if t.Kind == want.Kind && t.Name == want.Name && verbRank[t.Verb] >= verbRank[want.Verb] {
			return true
		}
	}
	return false
}

func join(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += "\n  - "
		}
		out += p
	}
	return out
}
