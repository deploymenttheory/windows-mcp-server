//go:build windows && (amd64 || arm64)

package windows

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/windows-mcp-server/pkg/inventory"
)

// AllPrompts returns the full prompt manifest.
//
// Prompts are workflow templates that pair a persona's standing guidance with a
// concrete task. They deliberately reuse Personas[...].Instructions rather than
// restating it, so persona guidance has exactly one source of truth — a prompt
// that drifted from the persona it names would be worse than no prompt.
//
// Each is attached to a toolset that also contains tools, because the toolset
// bookkeeping (AvailableToolsets, EnabledToolsets, instructions generation)
// iterates tools only.
func AllPrompts() []inventory.ServerPrompt {
	return []inventory.ServerPrompt{
		RPAJourneyPrompt(),
		TriageSupportIssuePrompt(),
		CaptureEvidencePrompt(),
	}
}

// NewPromptFromHandler builds a prompt.
//
// Note the asymmetry with tools and resources: inventory.ServerPrompt carries a
// bare mcp.PromptHandler with no deps argument, so a prompt that needs the engine
// must read it from the request context. That works because InjectDepsMiddleware
// covers every MCP method, not just tools/call.
func NewPromptFromHandler(
	toolset inventory.ToolsetMetadata,
	prompt mcp.Prompt,
	handler mcp.PromptHandler,
) inventory.ServerPrompt {
	return inventory.NewServerPrompt(toolset, prompt, handler)
}

// promptResult builds a single-message prompt result.
func promptResult(description string, text string) *mcp.GetPromptResult {
	return &mcp.GetPromptResult{
		Description: description,
		Messages: []*mcp.PromptMessage{
			{Role: "user", Content: &mcp.TextContent{Text: text}},
		},
	}
}

// personaGuidance returns a persona's standing instructions, so prompts and the
// --persona flag cannot drift apart.
func personaGuidance(id string) string {
	if p, ok := LookupPersona(id); ok {
		return p.Instructions
	}
	return ""
}

// argOr returns a named argument, or a fallback when absent or empty.
func argOr(req *mcp.GetPromptRequest, name, fallback string) string {
	if req == nil || req.Params == nil {
		return fallback
	}
	if v, ok := req.Params.Arguments[name]; ok && strings.TrimSpace(v) != "" {
		return v
	}
	return fallback
}

// RPAJourneyPrompt drives a scripted user journey through the real UI.
func RPAJourneyPrompt() inventory.ServerPrompt {
	return NewPromptFromHandler(
		ToolsetInteraction,
		mcp.Prompt{
			Name:        "rpa-journey",
			Title:       "Run a user journey",
			Description: "Drive a scripted end-user journey through the real Windows UI, verifying each step.",
			Arguments: []*mcp.PromptArgument{
				{Name: "goal", Description: "What the journey should accomplish, in plain language.", Required: true},
				{Name: "app", Description: "Application to start from (e.g. msedge, notepad)."},
			},
		},
		func(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			goal := argOr(req, "goal", "")
			if goal == "" {
				return nil, fmt.Errorf("the 'goal' argument is required")
			}
			app := argOr(req, "app", "")

			var b strings.Builder
			b.WriteString(personaGuidance("business-user"))
			b.WriteString("\n\nJourney goal: ")
			b.WriteString(goal)
			if app != "" {
				fmt.Fprintf(&b, "\nStart from the application: %s (launch it with the App tool if it is not already open).", app)
			}
			b.WriteString("\n\nFollow the loop for every step: perceive with Snapshot, target an element by its " +
				"label, act (prefer the UIA actions Invoke/SetValue/Toggle over raw Click/Type), synchronize with " +
				"WaitFor, then verify with Assert before moving on. Re-Snapshot after the UI changes. " +
				"Report each step and stop at the first failed Assert rather than continuing.")
			return promptResult("A verified end-user journey", b.String()), nil
		},
	)
}

// TriageSupportIssuePrompt structures a first-line diagnostic pass.
func TriageSupportIssuePrompt() inventory.ServerPrompt {
	return NewPromptFromHandler(
		ToolsetDiagnostics,
		mcp.Prompt{
			Name:        "triage-support-issue",
			Title:       "Triage a support issue",
			Description: "Diagnose a reported Windows problem, gathering state before making any change.",
			Arguments: []*mcp.PromptArgument{
				{Name: "symptom", Description: "What the user reports going wrong.", Required: true},
			},
		},
		func(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			symptom := argOr(req, "symptom", "")
			if symptom == "" {
				return nil, fmt.Errorf("the 'symptom' argument is required")
			}

			var b strings.Builder
			b.WriteString(personaGuidance("first-line-support"))
			b.WriteString("\n\nReported symptom: ")
			b.WriteString(symptom)
			b.WriteString("\n\nDiagnose before acting. Gather state first — Snapshot for what is on screen, " +
				"SystemInfo for the machine, Process and Service for what is running. Form a hypothesis and say " +
				"what evidence supports it. State any destructive or disruptive step and why before you take it. " +
				"Finish with a plain-language summary of the cause, what you changed, and what the user should do next.")
			return promptResult("A structured triage pass", b.String()), nil
		},
	)
}

// CaptureEvidencePrompt produces a reproducible evidence record.
func CaptureEvidencePrompt() inventory.ServerPrompt {
	return NewPromptFromHandler(
		ToolsetTesting,
		mcp.Prompt{
			Name:        "capture-evidence",
			Title:       "Capture evidence for a test step",
			Description: "Record reproducible evidence of the current UI state for a test or support case.",
			Arguments: []*mcp.PromptArgument{
				{Name: "step", Description: "What this evidence is documenting.", Required: true},
			},
		},
		func(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			step := argOr(req, "step", "")
			if step == "" {
				return nil, fmt.Errorf("the 'step' argument is required")
			}

			var b strings.Builder
			b.WriteString(personaGuidance("qa-test-engineer"))
			b.WriteString("\n\nEvidence for: ")
			b.WriteString(step)
			b.WriteString("\n\nCapture with CaptureEvidence so the screenshot and the labeled element tree are " +
				"recorded together. If a session recording is active, add a timeline marker with the Recording tool " +
				"so the video can be aligned to this step. State what the evidence shows and whether it matches the " +
				"expected outcome.")
			return promptResult("Evidence for one step", b.String()), nil
		},
	)
}
