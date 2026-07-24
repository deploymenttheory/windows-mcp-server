package guardrails

import (
	"slices"
	"strings"
)

// Registry holds the available guardrails and resolves a selection.
type Registry struct {
	order []string
	byID  map[string]Guardrail
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{byID: map[string]Guardrail{}} }

// Register adds or replaces a guardrail.
func (r *Registry) Register(g Guardrail) {
	if _, ok := r.byID[g.ID]; !ok {
		r.order = append(r.order, g.ID)
	}
	r.byID[g.ID] = g
}

// Get returns a guardrail by id.
func (r *Registry) Get(id string) (Guardrail, bool) {
	g, ok := r.byID[id]
	return g, ok
}

// IDs returns all registered guardrail ids in registration order.
func (r *Registry) IDs() []string { return slices.Clone(r.order) }

// selected pairs a guardrail with its resolved argument.
type selected struct {
	g   Guardrail
	arg string
}

// Select resolves the guardrails to run for cfg (baseline run-context, the
// enterprise preset, and explicit --guardrail ids), plus any unknown ids named.
func (r *Registry) Select(cfg Config) (out []selected, unknown []string) {
	seen := map[string]bool{}
	add := func(id, arg string) {
		if id == "" || seen[id] {
			return
		}
		g, ok := r.byID[id]
		if !ok {
			unknown = append(unknown, id)
			return
		}
		seen[id] = true
		out = append(out, selected{g: g, arg: arg})
	}

	// Baseline: always verify the run context when guardrails are active.
	add("run-context", "")
	// Enterprise preset.
	if cfg.Enterprise {
		for _, id := range r.order {
			if r.byID[id].Enterprise {
				add(id, "")
			}
		}
	}
	// Explicit additive selections: "id" or "id=arg".
	for _, spec := range cfg.Extra {
		id, arg, _ := strings.Cut(spec, "=")
		add(strings.TrimSpace(id), strings.TrimSpace(arg))
	}
	return out, unknown
}
