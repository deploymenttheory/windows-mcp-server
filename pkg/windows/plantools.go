//go:build windows && (amd64 || arm64)

package windows

import (
	"context"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/windows-mcp-server/pkg/inventory"
)

// Planner is the plan-and-apply engine: it adjudicates a whole proposed plan
// before any of it runs, and later executes an approved one. winmcp implements it
// with the policy engine, the audit log and the tool registry; the Plan and Apply
// tools here are thin wrappers, so plan-and-apply composes with the same
// middleware, toolset filtering and policy the rest of the surface does.
type Planner interface {
	// Propose validates and adjudicates a submitted plan document (raw JSON),
	// stores it under a content hash, and returns the change manifest and plan id.
	Propose(ctx context.Context, rawPlan []byte) (PlanProposal, error)
	// Apply executes a previously proposed plan by id, re-checking posture first
	// and stopping at the first step that fails or is refused.
	Apply(ctx context.Context, planID string) (PlanApplication, error)
}

// PlanProposal is the result of proposing a plan.
type PlanProposal struct {
	PlanID   string
	Allowed  bool
	Severity string
	Manifest string
}

// PlanApplication is the result of applying a plan.
type PlanApplication struct {
	PlanID string
	Report string
}

// PlannerProvider is the optional capability a ToolDependencies exposes when
// plan-and-apply is wired in. The Plan and Apply tools degrade to an error result
// when it is absent, so a dependency stand-in without a planner simply cannot plan.
type PlannerProvider interface {
	Planner() Planner
}

func plannerFrom(deps ToolDependencies) (Planner, bool) {
	p, ok := deps.(PlannerProvider)
	if !ok {
		return nil, false
	}
	planner := p.Planner()
	return planner, planner != nil
}

// Plan proposes a sequence of tool calls for whole-plan adjudication. It changes
// nothing: it validates the plan, evaluates the whole thing against current
// posture, and returns a change manifest and a plan id to apply.
func Plan() inventory.ServerTool {
	return NewToolFromHandler(
		ToolsetPlanning,
		mcp.Tool{
			Name: "Plan",
			Description: "Propose a sequence of tool calls to be adjudicated as a whole before any of it runs. " +
				"Returns a change manifest (what the plan would touch, grouped and flagged) and a plan_id. " +
				"Nothing is executed; call Apply with the plan_id to run it.",
			Annotations: &mcp.ToolAnnotations{Title: "Propose a plan", ReadOnlyHint: true},
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"version": {Type: "integer", Description: "Plan schema version (1)."},
					"steps": {
						Type:        "array",
						Description: "The tool calls, in order.",
						Items: &jsonschema.Schema{
							Type: "object",
							Properties: map[string]*jsonschema.Schema{
								"name": {Type: "string", Description: "Optional human label for the step."},
								"tool": {Type: "string", Description: "The tool to call."},
								"args": {Type: "object", Description: "The tool's arguments."},
								"targets": {
									Type:        "array",
									Description: "Optional: what the step touches. Derived automatically for known tools; used to declare reach for tools that cannot be introspected.",
									Items: &jsonschema.Schema{
										Type: "object",
										Properties: map[string]*jsonschema.Schema{
											"kind": {Type: "string", Description: "file, registry, process, host, ui, package, task or shell."},
											"name": {Type: "string"},
											"verb": {Type: "string", Description: "read, reach, invoke, create, write, execute, delete or kill."},
										},
									},
								},
							},
							Required: []string{"tool"},
						},
					},
				},
				Required: []string{"version", "steps"},
			},
		},
		func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			planner, ok := plannerFrom(deps)
			if !ok {
				return NewToolResultError("planning is not available in this configuration"), nil
			}
			proposal, err := planner.Propose(ctx, req.Params.Arguments)
			if err != nil {
				return NewToolResultErrorFromErr("plan rejected", err), nil
			}
			return NewToolResultText(proposal.Manifest), nil
		},
	)
}

// Apply executes a plan previously returned by Plan, by its id. It re-checks
// posture, then runs the steps in order, stopping at the first that fails or is
// refused. It is destructive: it performs the plan's actions.
func Apply() inventory.ServerTool {
	destructive := true
	return NewToolFromHandler(
		ToolsetPlanning,
		mcp.Tool{
			Name: "Apply",
			Description: "Execute a plan previously returned by Plan, identified by its plan_id. Re-checks " +
				"device posture, then runs the steps in order, stopping at the first that fails or is refused. " +
				"The steps run exactly as proposed — their arguments come from the approved plan, not from this call.",
			Annotations: &mcp.ToolAnnotations{
				Title:           "Apply a plan",
				ReadOnlyHint:    false,
				DestructiveHint: &destructive,
			},
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"plan_id": {Type: "string", Description: "The id returned by Plan."},
				},
				Required: []string{"plan_id"},
			},
		},
		func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args, err := ArgsMap(req)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			planID, err := RequiredString(args, "plan_id")
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			planner, ok := plannerFrom(deps)
			if !ok {
				return NewToolResultError("planning is not available in this configuration"), nil
			}
			application, err := planner.Apply(ctx, planID)
			if err != nil {
				return NewToolResultErrorFromErr("apply failed", err), nil
			}
			return NewToolResultText(application.Report), nil
		},
	)
}
