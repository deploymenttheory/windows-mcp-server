package signals

import (
	"slices"
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
