//go:build windows && (amd64 || arm64)

package winmcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/deploymenttheory/windows-mcp-server/internal/desktop"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/audit"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/policy"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/signals"
	"github.com/deploymenttheory/windows-mcp-server/internal/journeys"
	"github.com/deploymenttheory/windows-mcp-server/internal/runrecord"
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
	// RunRecord is where the run's OTLP/JSON trace was written, when an evidence
	// directory is configured.
	RunRecord string `json:"run_record,omitempty"`
	// Evidence lists the images the run captured.
	Evidence []string `json:"evidence,omitempty"`
	// MissingEvidence lists expected_evidence labels the run did not produce. A
	// non-empty list fails the run even when every assertion passed.
	MissingEvidence []string `json:"missing_evidence,omitempty"`
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

	// Where the run's own evidence goes: the captured images and the OTLP/JSON run
	// record, alongside the audit chain the same session stamp names.
	evidenceRoot := devicePolicy.Transparency.EvidenceDir
	deps := windows.NewBaseDeps(dsk, logger, nil).
		WithEnforceHTTPS(enforceHTTPS(cfg)).
		WithProtectedPaths(protectedPaths(cfg, devicePolicy)).
		WithEvidenceDir(evidenceSubdir(evidenceRoot, "evidence"))
	runner := inventoryRegistry{inv: inv, deps: deps}

	doc, origins, err := journeys.CompileWithOrigins(j, sessionStamp)
	if err != nil {
		return JourneyReport{}, fmt.Errorf("compile journey: %w", err)
	}

	// A run is a trace. The recorder is separate from the OTLP exporter on
	// purpose: telemetry.sample_ratio governs what is exported, and must not
	// govern what is recorded — a run record holding a statistical subset of its
	// own steps is not evidence.
	host, _ := os.Hostname()
	rec := runrecord.New(runrecord.Options{
		ServiceName: "windows-mcp-server", ServiceVersion: cfg.Version,
		SessionID: sessionStamp, HostName: host,
	})
	runStarted := time.Now()
	runSpan, closeRun := rec.Open(runrecord.Span{
		Name:  "journey " + j.Name,
		Start: runStarted,
		Attrs: []runrecord.Attr{
			runrecord.String("journey.name", j.Name),
			runrecord.Int("journey.version", int64(j.Version)),
			runrecord.String("journey.document.sha256", documentDigest(raw)),
			runrecord.String("journey.plan.id", doc.PlanID),
			runrecord.String("journey.session.id", sessionStamp),
			runrecord.Int("journey.steps.total", int64(len(doc.Steps))),
		},
	})
	tracer := newJourneyTracer(rec, origins, deps, runSpan)

	sessionPlanner := newPlanner(engine, auditLog, runner, nil).
		withReadRegister(deps).
		withStepObserver(tracer.observeStep)
	deps.WithPlanner(sessionPlanner)
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
		reason := fmt.Sprintf("blocked by device policy before running (%s)", prop.Severity)
		closeRun(time.Now(), true, reason, runrecord.Bool("journey.passed", false))
		_, _ = auditLog.Append(
			"journey.finished",
			map[string]any{"name": j.Name, "passed": false, "reason": "blocked by policy"},
		)
		report := JourneyReport{
			Name: j.Name, PlanID: prop.PlanID, Passed: false, Failed: len(doc.Steps),
			Report: reason, Manifest: prop.Manifest,
		}
		report.RunRecord = persistRunRecord(evidenceRoot, j.Name, sessionStamp, rec, logger)
		return report, nil
	}

	app, err := sessionPlanner.Apply(ctx, prop.PlanID)
	if err != nil {
		return JourneyReport{}, fmt.Errorf("run journey: %w", err)
	}

	// Expected evidence is checked against the run, not against the document. The
	// static check at validate time only says some step claims it will capture the
	// label — which a run that fail-stopped at step 2 satisfies without ever having
	// produced it.
	captured, missing := reconcileEvidence(j.ExpectedEvidence, deps.CapturedEvidence())

	passed := app.Failed == 0 && app.Skipped == 0 &&
		app.Completed == len(doc.Steps) && len(missing) == 0
	report := app.Report
	if len(missing) > 0 {
		report += fmt.Sprintf("  expected evidence never captured: %s\n", strings.Join(missing, ", "))
	}

	closeRun(time.Now(), !passed, journeyStatusMessage(passed, app.Failed, missing),
		runrecord.Bool("journey.passed", passed),
		runrecord.Int("journey.steps.completed", int64(app.Completed)),
		runrecord.Int("journey.steps.failed", int64(app.Failed)),
		runrecord.Int("journey.steps.skipped", int64(app.Skipped)),
	)

	_, _ = auditLog.Append("journey.finished", map[string]any{
		"name": j.Name, "passed": passed,
		"completed": app.Completed, "failed": app.Failed, "skipped": app.Skipped,
		"evidence": captured, "missing_evidence": missing,
	})

	return JourneyReport{
		Name: j.Name, PlanID: app.PlanID, Passed: passed,
		Completed: app.Completed, Failed: app.Failed, Skipped: app.Skipped,
		Report: report, Manifest: prop.Manifest,
		RunRecord:       persistRunRecord(evidenceRoot, j.Name, sessionStamp, rec, logger),
		Evidence:        captured,
		MissingEvidence: missing,
	}, nil
}

// reconcileEvidence compares what the journey said a passing run must produce
// against what it actually captured.
func reconcileEvidence(expected []string, artifacts []windows.EvidenceArtifact) (captured, missing []string) {
	seen := map[string]bool{}
	for _, a := range artifacts {
		seen[a.Label] = true
		captured = append(captured, a.Label)
	}
	for _, want := range expected {
		if !seen[want] {
			missing = append(missing, want)
		}
	}
	return captured, missing
}

// journeyStatusMessage renders the run span's status description.
func journeyStatusMessage(passed bool, failed int, missing []string) string {
	switch {
	case passed:
		return "passed"
	case failed > 0:
		return fmt.Sprintf("%d step(s) failed", failed)
	case len(missing) > 0:
		return "expected evidence never captured: " + strings.Join(missing, ", ")
	default:
		return "did not complete"
	}
}

// persistRunRecord writes the trace, logging rather than failing on error: the
// journey's verdict is already on the audit chain, and losing the richer record
// is not a reason to report a passing suite as broken.
func persistRunRecord(root, name, session string, rec *runrecord.Recorder, logger *slog.Logger) string {
	path, err := writeRunRecord(evidenceSubdir(root, "journeys"), name, session, rec)
	if err != nil {
		logger.Error("journey run record not written", "error", err)
		return ""
	}
	return path
}

// evidenceSubdir returns a subdirectory of the evidence root, or "" when no
// evidence directory is configured — which disables persistence rather than
// failing, since a missing output directory is a configuration choice.
func evidenceSubdir(root, sub string) string {
	if root == "" {
		return ""
	}
	return filepath.Join(root, sub)
}

// documentDigest is the SHA-256 of the journey document as written. It is the
// stable identity of what ran: trace ids differ between runs of the same file,
// and this does not.
func documentDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
