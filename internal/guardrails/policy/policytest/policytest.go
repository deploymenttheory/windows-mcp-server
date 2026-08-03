// Package policytest provides reusable fixtures for exercising the policy engine
// without a Windows host or live device signals: a static tool index and a signal
// registry whose outcomes the caller sets. It keeps the engine's decision testable
// against fakes — which is the whole point of the ToolIndex and SystemProbe
// interfaces — and is shared by the engine property tests and the `policy test`
// CLI verb, so the two reason about a policy the same way.
package policytest

import (
	"context"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/policy"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/signals"
)

// StaticIndex is a policy.ToolIndex backed by a fixed map of tool facts.
type StaticIndex map[string]policy.ToolFacts

// Lookup implements policy.ToolIndex.
func (s StaticIndex) Lookup(tool string) (policy.ToolFacts, bool) {
	facts, ok := s[tool]
	return facts, ok
}

// StaticSignals builds a registry whose signals report the statuses held in
// states. It reads the map live on every check, so a caller that mutates states
// between evaluations (with the signal at ttl 0) sees the change — which is how a
// test drives a signal from failing to passing to prove that a recovered device
// restores service without a restart.
func StaticSignals(states map[string]signals.Status) *signals.Registry {
	reg := signals.NewRegistry()
	for id := range states {
		id := id
		reg.Register(signals.Guardrail{
			ID: id,
			Check: func(context.Context, *signals.Env) signals.Result {
				return signals.Result{ID: id, Status: states[id]}
			},
		})
	}
	return reg
}

// NewEngine builds an engine over a policy, a static tool index, and a set of
// signal states — everything a decision needs and nothing that touches the OS.
func NewEngine(p *policy.Policy, index policy.ToolIndex, states map[string]signals.Status) *policy.Engine {
	return policy.NewEngine(p, StaticSignals(states), index, func() *signals.Env { return &signals.Env{} })
}
