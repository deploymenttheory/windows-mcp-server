//go:build windows && (amd64 || arm64)

package winmcp

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/deploymenttheory/agentweave-harness/guardrails/policy"
	"github.com/deploymenttheory/agentweave-harness/guardrails/signals"
	"github.com/deploymenttheory/mcp-server-core/runtime"
	"github.com/deploymenttheory/windows-mcp-server/internal/desktop"
)

// The operator-facing operations behind the `policy` subcommands: is this
// document valid, what does this device look like right now, why was that
// call refused, and do these fixtures pass. None starts a server.

// PolicyCoverage is what covers one tool, for `policy explain`.
type PolicyCoverage = runtime.PolicyCoverage

// PolicyTestReport is the outcome of one fixture file, for `policy test`.
type PolicyTestReport = runtime.PolicyTestReport

// ValidatePolicy loads and validates a policy document.
//
// It touches no device: validation is about the document and the set of signals
// this build can evaluate, so it runs anywhere, including in CI on a machine
// with no TPM and no domain.
func ValidatePolicy(cfg Config) (*policy.Policy, error) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	p, err := runtime.ValidatePolicy(cfg.PolicyConfig, runtime.NewGuardrailRegistry(envNames, logger))
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	return p, nil
}

// EvaluatePolicy reads every signal the policy declares, live and cache
// bypassed, and returns the decision for the startup scope. That makes it
// slow — seconds, on a device where dsregcmd, WMI and tpmtool all have to run
// — which is correct for a diagnostic and is exactly why the request path does
// not work this way.
func EvaluatePolicy(ctx context.Context, cfg Config) (signals.Decision, error) {
	logger, cleanup, err := runtime.NewLogger(cfg.LogFile)
	if err != nil {
		return signals.Decision{}, fmt.Errorf("logger: %w", err)
	}
	defer cleanup()

	reg := runtime.NewGuardrailRegistry(envNames, logger)
	devicePolicy, err := runtime.LoadPolicy(cfg.PolicyConfig, reg, logger)
	if err != nil {
		return signals.Decision{}, fmt.Errorf("policy: %w", err)
	}
	cfg.EnforceHTTPS = devicePolicy.EnforceHTTPS

	// The engine owns its own lifetime; see the note in RunStdio.
	dsk, err := desktop.New(logger, desktop.Options{}) //nolint:contextcheck // owns its lifetime
	if err != nil {
		return signals.Decision{}, fmt.Errorf("failed to start desktop engine: %w", err)
	}
	defer func() { _ = dsk.Close() }()

	return runtime.EvaluatePolicy(ctx, devicePolicy, reg,
		func() *signals.Env { return guardrailEnv(cfg, dsk, logger) }), nil
}

// ExplainPolicy reports which rules cover a tool and what they require,
// evaluating nothing: an operator asking why a call was refused should not
// have to run device probes, and should be able to ask on a machine that is
// not the one that refused it.
func ExplainPolicy(ctx context.Context, cfg Config, tool string) (PolicyCoverage, error) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	reg := runtime.NewGuardrailRegistry(envNames, logger)
	devicePolicy, err := runtime.LoadPolicy(cfg.PolicyConfig, reg, logger)
	if err != nil {
		return PolicyCoverage{}, fmt.Errorf("policy: %w", err)
	}
	inv, _, err := buildInventory(cfg, false)
	if err != nil {
		return PolicyCoverage{}, fmt.Errorf("build inventory: %w", err)
	}
	return runtime.ExplainPolicy(devicePolicy, reg, runtime.NewToolIndex(ctx, inv), tool), nil
}

// TestPolicy runs fixture files against the signal set this build knows.
func TestPolicy(fixturePaths []string) ([]PolicyTestReport, error) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	known := runtime.NewGuardrailRegistry(envNames, logger).IDs()
	reports, err := runtime.RunPolicyFixtures(known, fixturePaths)
	if err != nil {
		return nil, fmt.Errorf("policy test: %w", err)
	}
	return reports, nil
}
