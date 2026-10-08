//go:build windows && (amd64 || arm64) && conformance

// This file exists only under the `conformance` build tag. `go build ./...`
// does not compile it, so the released binary has no HTTP listener and remains
// stdio-only — the posture the guardrail threat model is written against.
//
// It exists because the official MCP conformance suite
// (github.com/modelcontextprotocol/conformance) can only reach a server over
// HTTP: `--url` is a required option of its `server` command and there is no
// stdio path. Proving conformance therefore requires an endpoint the harness can
// connect to, and this is the smallest one that still serves the real thing.

package winmcp

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/agentweave-harness/guardrails/audit"
	"github.com/deploymenttheory/agentweave-harness/guardrails/contain"
	"github.com/deploymenttheory/agentweave-harness/guardrails/enforce"
	"github.com/deploymenttheory/agentweave-harness/guardrails/policy"
	"github.com/deploymenttheory/agentweave-harness/guardrails/signals"
	"github.com/deploymenttheory/agentweave-harness/guardrails/status"
	"github.com/deploymenttheory/agentweave-harness/guardrails/watch"
	"github.com/deploymenttheory/mcp-server-core/conformance"
	"github.com/deploymenttheory/mcp-server-core/runtime"
	"github.com/deploymenttheory/mcp-server-core/surface"
	"github.com/deploymenttheory/windows-mcp-server/internal/desktop"
	"github.com/deploymenttheory/windows-mcp-server/pkg/windows"
)

// ConformanceConfig configures the loopback host.
type ConformanceConfig struct {
	// Addr is the listen address. It must be a loopback address.
	Addr string
	// Path is the HTTP path the MCP endpoint is served on.
	Path string
	// Fixtures registers the named tools, resources and prompts the conformance
	// suite requires in order to exercise tools/call, resources/read and
	// prompts/get at all (mcp-server-core/conformance).
	//
	// This is the difference between the suite's two passes. Without it the run
	// measures the manifest this server actually ships; with it the run measures
	// how our handler-to-wire path behaves, at the cost of no longer being the
	// shipped manifest. Recording them separately is what keeps both claims honest.
	Fixtures bool
}

// RunConformanceHost serves this server's MCP surface over Streamable HTTP on
// loopback so the official conformance suite can connect to it.
//
// What makes the evidence meaningful is that the surface is built by
// newSurface and wrapped in the same middleware chain as RunStdio, in the same
// order: inject-deps and cache hints from the shared constructor, then audit,
// rug-pull and the policy engine. Only the transport differs.
func RunConformanceHost(ctx context.Context, cfg Config, hostCfg ConformanceConfig) error {
	if err := conformance.RequireLoopback(hostCfg.Addr); err != nil {
		return fmt.Errorf("conformance host: %w", err)
	}
	// Logs go to stderr: stdout carries the bound URL for the harness runner.
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	server, err := buildConformanceServer(ctx, cfg, hostCfg.Fixtures, logger)
	if err != nil {
		return err
	}
	if err := conformance.Serve(ctx, server, hostCfg.Addr, hostCfg.Path, logger); err != nil {
		return fmt.Errorf("conformance host: %w", err)
	}
	return nil
}

// buildConformanceServer assembles the server the host serves. It is separate
// from the transport so a test can drive the same object over an in-memory
// transport and compare its manifest with the stdio one.
//
// Three deliberate differences from a production run, each to avoid measuring
// something other than protocol conformance:
//
//   - The policy engine runs under the built-in default policy, which evaluates
//     and records but refuses nothing. The engine has to be in the chain — a
//     conformance result gathered without it would describe a server nobody runs
//     — but a policy that refused calls partway through would report its own
//     refusals as protocol failures.
//   - The desktop engine is best-effort. It is created when the environment can
//     host one, so resources/read returns real state; where it cannot, the server
//     still serves, because most of the suite needs no engine and losing the run
//     to obtain one would be a bad trade.
//   - Handler panics are recovered rather than fatal. Finishing the run and
//     reporting is the whole job here; see conformance.RecoverMiddleware.
func buildConformanceServer(
	ctx context.Context, cfg Config, fixturesEnabled bool, logger *slog.Logger,
) (*mcp.Server, error) {
	inv, personaInstructions, err := buildInventory(cfg, false)
	if err != nil {
		return nil, fmt.Errorf("build inventory: %w", err)
	}

	// A real engine when the runner can host one, so resources/read returns real
	// desktop state and the suite's caching checks measure something. A headless
	// or UIA-less environment degrades to a nil engine rather than refusing to
	// serve.
	dsk, err := desktop.New(logger, desktop.Options{}) //nolint:contextcheck // owns its lifetime
	if err != nil {
		logger.Warn("no desktop engine for the conformance host; "+
			"engine-backed resources will report an error rather than data", "error", err)
		dsk = nil
	}

	deps := windows.NewBaseDeps(dsk, logger, nil)
	deps.WithEnforceHTTPS(cfg.EnforceHTTPS)
	s := newSurface(cfg, inv, personaInstructions, deps)
	server := s.Server

	// The transparency services, as RunStdio wires them. A trip here logs and
	// records rather than actuating containment: the conformance host has no
	// desktop to contain, and a kill mid-suite would destroy the evidence.
	auditLog := audit.NewAuditLog(&conformance.AuditDestination{Logger: logger})
	rugpull := watch.NewRugPull(func(reason string) {
		logger.Error("guardrail.rugpull", "reason", reason)
	}, auditLog)

	engine := policy.NewEngine(policy.Default(), runtime.NewGuardrailRegistry(envNames, logger), nil,
		func() *signals.Env { return &signals.Env{Sys: &conformance.Probe{}, Logger: logger} })

	// One call, outermost first — see Surface.InstallReceiving for why it cannot
	// be several. The recover layer is the first inside the unconditional two, so
	// nothing a handler does can take the process down: without it one handler
	// dereferencing a nil engine killed the host mid-suite, and every scenario
	// after that point reported "fetch failed".
	s.InstallReceiving(
		conformance.RecoverMiddleware(logger),
		auditLog.Middleware(),
		rugpull.Middleware(),
		rugpull.PromptMiddleware(),
		rugpull.ResourceMiddleware(),
		rugpull.DiscoverMiddleware(),
		enforce.Middleware(engine, enforce.EnforcerDeps{Audit: auditLog, Logger: logger}),
	)

	inv.RegisterAll(ctx, server, deps)
	engine.SetIndex(runtime.NewToolIndex(ctx, inv))

	kill := contain.NewKillSwitch(nil)
	statusTool, statusHandler := status.StatusTool(
		func() signals.Decision { return signals.Decision{} },
		func() status.ServerStatus { return status.ServerStatus{} },
		kill,
	)
	server.AddTool(statusTool, statusHandler)
	killTool, killHandler := status.KillTool(func(string) {})
	server.AddTool(killTool, killHandler)

	// Baselines are pinned after the fixtures are registered, over what the server
	// will actually serve. Pinning the product manifest and then adding fixtures
	// would trip the rug-pull detector on the suite's first tools/list — correctly,
	// since the manifest really would have changed after the baseline.
	fixtures := conformance.RegisterFixtures(server, fixturesEnabled)
	tools := append(surface.MCPTools(ctx, inv), statusTool, killTool)
	rugpull.SetBaseline(append(tools, fixtures.Tools...))
	rugpull.SetPromptBaseline(append(surface.MCPPrompts(ctx, inv), fixtures.Prompts...))
	rugpull.SetResourceBaseline(append(surface.MCPResources(ctx, inv), fixtures.Resources...))
	rugpull.SetDiscoverBaseline(s.Capabilities, s.Instructions)

	return server, nil
}
