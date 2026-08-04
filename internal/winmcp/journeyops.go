//go:build windows && (amd64 || arm64)

package winmcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/deploymenttheory/windows-mcp-server/internal/desktop"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/audit"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/policy"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/signals"
	"github.com/deploymenttheory/windows-mcp-server/internal/journeys"
	"github.com/deploymenttheory/windows-mcp-server/pkg/windows"
)

// JourneyReport is the outcome of running one journey.
type JourneyReport struct {
	Name      string `json:"name"`
	PlanID    string `json:"plan_id"`
	Passed    bool   `json:"passed"`
	Completed int    `json:"completed"`
	Failed    int    `json:"failed"`
	Skipped   int    `json:"skipped"`
	// Report is the human-readable per-step apply log.
	Report string `json:"report"`
	// Manifest is the change manifest the plan adjudicated to before running.
	Manifest string `json:"manifest,omitempty"`
}

// RunJourney compiles a journey file to a plan and executes it against the live
// desktop, through the same planner Apply uses: every step is policy-evaluated,
// audited as plan.step, and fail-stopped on the first failure. A failed assertion
// is an Assert/WaitFor tool error — a failed step — so the run stops and reports
// it, which is what makes a journey a test.
//
// It reads live device state and drives the real UI, so it runs only on an
// interactive desktop; a machine that cannot host UI automation returns an error
// from the desktop engine rather than a spurious pass.
func RunJourney(ctx context.Context, cfg Config, path string) (JourneyReport, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // an operator-supplied journey path
	if err != nil {
		return JourneyReport{}, fmt.Errorf("read journey %s: %w", path, err)
	}
	j, err := journeys.Parse(raw)
	if err != nil {
		return JourneyReport{}, fmt.Errorf("journey %s: %w", path, err)
	}
	if err := j.Validate(); err != nil {
		return JourneyReport{}, fmt.Errorf("journey %s: %w", path, err)
	}

	logger, cleanup, err := newLogger(cfg.LogFile)
	if err != nil {
		return JourneyReport{}, err
	}
	defer cleanup()

	reg := newGuardrailRegistry(cfg, logger)
	devicePolicy, err := loadPolicy(cfg, reg, logger)
	if err != nil {
		return JourneyReport{}, err
	}
	cfg.EnforceHTTPS = devicePolicy.EnforceHTTPS
	// A journey's assertions and evidence compile to the testing tools, so that
	// toolset must be served whatever else the selection is.
	cfg.Toolsets = withToolset(cfg.Toolsets, string(windows.ToolsetTesting.ID))

	// One session stamp ties the run's audit chain (and any retrospective evidence
	// bundle) together, exactly as a served session does.
	sessionStamp := time.Now().Format("20060102-150405")
	dest, err := audit.OpenDestination(devicePolicy.Transparency.AuditDestination, sessionStamp,
		[]byte(os.Getenv("WINDOWS_MCP_AUDIT_KEY")))
	if err != nil {
		return JourneyReport{}, fmt.Errorf("audit log: %w", err)
	}
	auditLog := audit.NewAuditLog(dest, audit.WithHMACKey([]byte(os.Getenv("WINDOWS_MCP_AUDIT_KEY"))))
	defer func() { _ = auditLog.Close() }()

	// The engine owns its own lifetime; see the note in RunStdio.
	dsk, err := desktop.New(logger, desktop.Options{ //nolint:contextcheck // owns its lifetime
		SecurityOverlay: devicePolicy.Transparency.Banner,
	})
	if err != nil {
		return JourneyReport{}, fmt.Errorf("failed to start desktop engine: %w", err)
	}
	defer func() { _ = dsk.Close() }()

	envFn := func() *signals.Env { return guardrailEnv(cfg, dsk, logger) }
	engine := policy.NewEngine(devicePolicy, reg, nil, envFn)

	inv, _, err := buildInventory(cfg, false)
	if err != nil {
		return JourneyReport{}, fmt.Errorf("build inventory: %w", err)
	}
	engine.SetIndex(newToolIndex(ctx, inv))

	deps := windows.NewBaseDeps(dsk, logger, nil).
		WithEnforceHTTPS(enforceHTTPS(cfg)).
		WithProtectedPaths(protectedPaths(cfg, devicePolicy))
	runner := inventoryRegistry{inv: inv, deps: deps}
	sessionPlanner := newPlanner(engine, auditLog, runner, nil)
	deps.WithPlanner(sessionPlanner)

	doc, err := journeys.Compile(j, sessionStamp)
	if err != nil {
		return JourneyReport{}, fmt.Errorf("compile journey: %w", err)
	}
	rawPlan, err := json.Marshal(doc)
	if err != nil {
		return JourneyReport{}, fmt.Errorf("marshal compiled journey: %w", err)
	}

	_, _ = auditLog.Append("journey.started", map[string]any{
		"name": j.Name, "steps": len(doc.Steps), "session": sessionStamp,
	})

	prop, err := sessionPlanner.Propose(ctx, rawPlan)
	if err != nil {
		return JourneyReport{}, fmt.Errorf("compile journey to a plan: %w", err)
	}
	if !prop.Allowed {
		_, _ = auditLog.Append(
			"journey.finished",
			map[string]any{"name": j.Name, "passed": false, "reason": "blocked by policy"},
		)
		return JourneyReport{
			Name: j.Name, PlanID: prop.PlanID, Passed: false, Failed: len(doc.Steps),
			Report:   fmt.Sprintf("blocked by device policy before running (%s)", prop.Severity),
			Manifest: prop.Manifest,
		}, nil
	}

	app, err := sessionPlanner.Apply(ctx, prop.PlanID)
	if err != nil {
		return JourneyReport{}, fmt.Errorf("run journey: %w", err)
	}
	passed := app.Failed == 0 && app.Skipped == 0 && app.Completed == len(doc.Steps)
	_, _ = auditLog.Append("journey.finished", map[string]any{
		"name": j.Name, "passed": passed,
		"completed": app.Completed, "failed": app.Failed, "skipped": app.Skipped,
	})

	return JourneyReport{
		Name: j.Name, PlanID: app.PlanID, Passed: passed,
		Completed: app.Completed, Failed: app.Failed, Skipped: app.Skipped,
		Report: app.Report, Manifest: prop.Manifest,
	}, nil
}
