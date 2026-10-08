//go:build windows && (amd64 || arm64)

package winmcp

import (
	"context"
	"fmt"
	"os"

	"github.com/deploymenttheory/agentweave-harness/guardrails/audit"
	"github.com/deploymenttheory/agentweave-harness/guardrails/policy"
	"github.com/deploymenttheory/agentweave-harness/guardrails/signals"
	"github.com/deploymenttheory/mcp-server-core/runtime"
	"github.com/deploymenttheory/mcp-server-core/toolkit"
	"github.com/deploymenttheory/windows-mcp-server/internal/desktop"
	"github.com/deploymenttheory/windows-mcp-server/pkg/windows"
)

// JourneyReport is the outcome of running one journey.
type JourneyReport = runtime.JourneyReport

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
	logger, cleanup, err := runtime.NewLogger(cfg.LogFile)
	if err != nil {
		return JourneyReport{}, fmt.Errorf("logger: %w", err)
	}
	defer cleanup()

	reg := runtime.NewGuardrailRegistry(envNames, logger)
	devicePolicy, err := runtime.LoadPolicy(cfg.PolicyConfig, reg, logger)
	if err != nil {
		return JourneyReport{}, fmt.Errorf("policy: %w", err)
	}
	cfg.EnforceHTTPS = devicePolicy.EnforceHTTPS
	// A journey's assertions and evidence compile to the testing tools, so that
	// toolset must be served whatever else the selection is.
	cfg.Toolsets = runtime.WithToolset(cfg.Toolsets, string(windows.ToolsetTesting.ID))

	// One session stamp ties the run's audit chain (and any retrospective evidence
	// bundle) together, exactly as a served session does.
	sessionStamp := runtime.SessionStamp()
	auditKey := runtime.ResolveAuditKey(envNames, devicePolicy.Transparency.AuditDestination, logger)
	dest, err := audit.OpenDestination(devicePolicy.Transparency.AuditDestination, sessionStamp, auditKey)
	if err != nil {
		return JourneyReport{}, fmt.Errorf("audit log: %w", err)
	}
	auditLog := audit.NewAuditLog(dest, audit.WithHMACKey(auditKey))
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
	engine.SetIndex(runtime.NewToolIndex(ctx, inv))

	// Where the run's own evidence goes: the captured images and the OTLP/JSON run
	// record, alongside the audit chain the same session stamp names.
	evidenceRoot := devicePolicy.Transparency.EvidenceDir
	deps := windows.NewBaseDeps(dsk, logger, nil)
	deps.WithEnforceHTTPS(cfg.EnforceHTTPS).
		WithProtectedPaths(guardrailPaths(cfg, devicePolicy)).
		WithEvidenceDir(runtime.EvidenceSubdir(evidenceRoot, "evidence"))

	rep, err := runtime.RunJourney(ctx, raw, path, runtime.JourneyRun{
		Engine: engine, Inventory: inv, Deps: deps,
		EvidenceSink: deps, ReadRegister: deps,
		SetPlanner: func(p toolkit.Planner) { deps.WithPlanner(p) },
		AuditLog:   auditLog, SessionStamp: sessionStamp, EvidenceRoot: evidenceRoot,
		ServiceName: ServerName, Version: cfg.Version, Logger: logger,
	})
	if err != nil {
		return JourneyReport{}, fmt.Errorf("journey: %w", err)
	}
	return rep, nil
}
