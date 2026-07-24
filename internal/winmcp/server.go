//go:build windows && (amd64 || arm64)

// Package winmcp wires the Windows automation engine and tool inventory into an
// MCP server and runs it over a transport. It is the bootstrap layer between
// the cobra CLI (cmd/windows-mcp-server) and the domain package (pkg/windows).
package winmcp

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/windows-mcp-server/internal/desktop"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails"
	"github.com/deploymenttheory/windows-mcp-server/pkg/inventory"
	"github.com/deploymenttheory/windows-mcp-server/pkg/windows"
)

// Config controls how the server is assembled and which tools it exposes.
type Config struct {
	// Version is reported in the MCP server implementation info.
	Version string

	// Persona, if set, selects a built-in preset (see windows.Personas) that
	// determines the toolset selection and read-only default. Explicit Toolsets
	// / ReadOnly settings override the persona.
	Persona string

	// Toolsets is the toolset selection (values accepted by
	// Builder.WithToolsets, including "all"/"default"). When nil and no persona
	// is set, the default toolsets are used.
	Toolsets []string
	// Tools is an additive allow-list of individual tools that bypass toolset
	// filtering.
	Tools []string
	// ExcludeTools is a deny-list applied last.
	ExcludeTools []string
	// ReadOnly, when true, exposes only read-only tools.
	ReadOnly bool
	// readOnlySet records whether ReadOnly was explicitly provided, so a persona
	// default is not silently overridden by the zero value.
	readOnlySet bool

	// LogFile, if set, directs debug logs to this file; otherwise info-level
	// logs go to stderr. stdout is reserved for the MCP stdio transport.
	LogFile string

	// Overlay enables visual-feedback overlays (green hue around the focused
	// window, orange flash at click points) for screen capture and video.
	Overlay bool

	// RecordDir, when set, records the whole session to a video file in this
	// directory so every session is tracked. RecordFPS and RecordCodec tune it.
	RecordDir   string
	RecordFPS   int
	RecordCodec string

	// RunContext declares the expected process context ("user" default, or
	// "system"). It is validated against the actual token; personas force user.
	RunContext string

	// Guardrails configuration.
	Guardrails            string        // mode: off|audit|enforce
	EnterpriseGuardrails  bool          // alias ⇒ enforce + enterprise preset
	Guardrail             []string      // additive guardrails: "id" or "id=arg"
	GuardrailsInterval    time.Duration // periodic re-eval (0 disables)
	GuardrailsStatusAddr  string        // loopback HTTP status endpoint (empty disables)
	GuardrailsStatusToken string        // bearer token for the status endpoint
	GuardrailsControlDir  string        // local sentinel dir (empty disables)
	GuardrailsBypass      bool          // break-glass (logged)
	CircuitBreaker        bool          // inline destructive-action circuit breaker

	// Authoritative (tier-2) remote checks. GraphTenant/ClientID/ClientSecret
	// enable the Entra + Intune compliance guardrails via Microsoft Graph.
	// RemotePolicyToken is the bearer token presented to a remote-policy=<url>
	// may-run endpoint.
	GraphTenant       string
	GraphClientID     string
	GraphClientSecret string
	RemotePolicyToken string
}

// SetReadOnly records an explicit read-only choice (distinguishing it from the
// zero value so it can override a persona default).
func (c *Config) SetReadOnly(v bool) {
	c.ReadOnly = v
	c.readOnlySet = true
}

// RunStdio builds the server and serves the MCP protocol over stdio until the
// context is cancelled or the client disconnects.
func RunStdio(ctx context.Context, cfg Config) error {
	logger, cleanup, err := newLogger(cfg.LogFile)
	if err != nil {
		return err
	}
	defer cleanup()

	dsk, err := desktop.New(logger, desktop.Options{
		Overlay: cfg.Overlay,
		Record: desktop.RecorderOptions{
			Dir:   cfg.RecordDir,
			FPS:   cfg.RecordFPS,
			Codec: cfg.RecordCodec,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to start desktop engine: %w", err)
	}
	defer func() { _ = dsk.Close() }()

	// --- Guardrails: run context + startup admission (PEP #1) ---
	reg := newGuardrailRegistry(cfg, logger)
	gcfg := guardrailConfig(cfg)
	runner := guardrails.NewRunner(reg, gcfg, logger)
	for _, u := range runner.Unknown() {
		logger.Warn("unknown guardrail requested", "guardrail", u)
	}
	holder := &decisionHolder{}

	decision := runner.Evaluate(ctx, guardrailEnv(dsk, logger))
	holder.set(decision)

	requestedSystem := strings.EqualFold(cfg.RunContext, "system")
	autoLimit := requestedSystem || decision.RunContext.IsSystem
	if cfg.Persona != "" && autoLimit {
		return fmt.Errorf("persona %q requires an interactive user context, but the process is running as SYSTEM", cfg.Persona)
	}

	if gcfg.Bypass {
		logger.Warn("GUARDRAILS BYPASSED (break-glass) — device policy NOT enforced")
	}
	if gcfg.Active() {
		if runner.Blocks(decision) {
			guardrails.LogDecision(logger, "deny", decision)
			dsk.Notify("Windows MCP: startup blocked", "Device did not meet policy: "+strings.Join(decision.Reasons, "; "))
			return fmt.Errorf("guardrails denied startup: %s", strings.Join(decision.Reasons, "; "))
		}
		guardrails.LogDecision(logger, "admit", decision)
	}

	inv, personaInstructions, err := buildInventory(cfg, autoLimit)
	if err != nil {
		return err
	}
	for _, unknown := range inv.UnrecognizedToolsets() {
		logger.Warn("unrecognized toolset requested", "toolset", unknown)
	}
	if autoLimit {
		logger.Warn("run-context is SYSTEM: desktop-automation toolsets disabled (Session 0 cannot drive the desktop)")
		dsk.Notify("Windows MCP: limited mode", "Running as SYSTEM — desktop automation is disabled; diagnostics/system tools only.")
	}

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "windows-mcp-server",
		Title:   "Windows MCP Server",
		Version: cfg.Version,
	}, &mcp.ServerOptions{
		Instructions: combineInstructions(personaInstructions, inv.Instructions()),
	})

	// --- Kill switch: cancel the server context (out-of-band from the agent) ---
	runCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	kill := guardrails.NewKillSwitch(func(reason string) {
		logger.Error("guardrail.kill", "reason", reason)
		dsk.MarkRecording("KILL: " + reason)
		// Cancel slightly deferred so any in-flight tool response (the Kill
		// tool's own reply, or a circuit-breaker block message) flushes to the
		// client before the transport closes.
		time.AfterFunc(300*time.Millisecond, func() {
			cancel(fmt.Errorf("guardrail kill: %s", reason))
		})
	})

	deps := windows.NewBaseDeps(dsk, logger, nil)
	server.AddReceivingMiddleware(windows.InjectDepsMiddleware(deps))

	// --- PEP #2: inline tool-call policy + circuit breaker ---
	circuitEnabled := cfg.CircuitBreaker || runner.Mode() == guardrails.ModeEnforce
	server.AddReceivingMiddleware(guardrails.ToolPolicyMiddleware(guardrails.CircuitConfig{
		Enabled: circuitEnabled,
		Logger:  logger,
		OnTrip:  kill.Trip,
	}))

	inv.RegisterTools(runCtx, server, deps)

	// Guardrail tools are registered unconditionally so every session can be
	// queried and stopped regardless of persona/toolset selection.
	statusTool, statusHandler := guardrails.StatusTool(holder.get, kill)
	server.AddTool(statusTool, statusHandler)
	killTool, killHandler := guardrails.KillTool(kill)
	server.AddTool(killTool, killHandler)

	// --- Continuous verification + local sentinel ---
	guardrails.StartMonitor(runCtx, guardrails.MonitorConfig{
		Interval:   cfg.GuardrailsInterval,
		ControlDir: cfg.GuardrailsControlDir,
		Kill:       kill,
		Logger:     logger,
		Evaluate: func(c context.Context) guardrails.Decision {
			d := runner.Evaluate(c, guardrailEnv(dsk, logger))
			holder.set(d)
			return d
		},
	})

	// --- Status endpoint for external polling / revoke ---
	if cfg.GuardrailsStatusAddr != "" {
		ss := &guardrails.StatusServer{
			Addr:    cfg.GuardrailsStatusAddr,
			Token:   cfg.GuardrailsStatusToken,
			Current: holder.get,
			Kill:    kill,
			Logger:  logger,
		}
		if err := ss.Start(runCtx); err != nil {
			logger.Warn("guardrails status endpoint disabled", "error", err)
		}
	}

	logger.Info("starting windows-mcp-server over stdio",
		"version", cfg.Version,
		"enabled_toolsets", toolsetIDs(inv.EnabledToolsets()),
		"guardrails", string(runner.Mode()),
		"circuit_breaker", circuitEnabled,
	)

	err = server.Run(runCtx, &mcp.StdioTransport{})
	if tripped, reason := kill.Tripped(); tripped {
		logger.Error("session terminated by kill switch", "reason", reason)
		return fmt.Errorf("session terminated by kill switch: %s", reason)
	}
	if err != nil {
		return fmt.Errorf("server run: %w", err)
	}
	return nil
}

// EvaluateGuardrails runs the guardrail set once against the live device and
// returns the decision document, without starting the MCP server. It backs the
// `check` subcommand: a dry-run of device posture for operators, CI, and health
// probes — and the way to exercise the elevated TPM platform attestation.
func EvaluateGuardrails(ctx context.Context, cfg Config) (guardrails.Decision, error) {
	logger, cleanup, err := newLogger(cfg.LogFile)
	if err != nil {
		return guardrails.Decision{}, err
	}
	defer cleanup()

	dsk, err := desktop.New(logger, desktop.Options{})
	if err != nil {
		return guardrails.Decision{}, fmt.Errorf("failed to start desktop engine: %w", err)
	}
	defer func() { _ = dsk.Close() }()

	reg := newGuardrailRegistry(cfg, logger)
	runner := guardrails.NewRunner(reg, guardrailConfig(cfg), logger)
	for _, u := range runner.Unknown() {
		logger.Warn("unknown guardrail requested", "guardrail", u)
	}
	return runner.Evaluate(ctx, guardrailEnv(dsk, logger)), nil
}

// buildInventory applies persona, toolset, read-only, and allow/deny
// configuration to the full tool manifest. It also returns the selected
// persona's instructions (empty when no persona is selected).
func buildInventory(cfg Config, autoLimit bool) (*inventory.Inventory, string, error) {
	toolsets := cfg.Toolsets
	readOnly := cfg.ReadOnly
	var personaInstructions string

	if cfg.Persona != "" {
		persona, ok := windows.LookupPersona(cfg.Persona)
		if !ok {
			return nil, "", fmt.Errorf("unknown persona %q", cfg.Persona)
		}
		personaInstructions = persona.Instructions
		// Explicit --toolsets overrides the persona's selection.
		if toolsets == nil {
			toolsets = persona.Toolsets
		}
		// Explicit --read-only overrides the persona default.
		if !cfg.readOnlySet {
			readOnly = persona.ReadOnly
		}
	}

	if autoLimit {
		// SYSTEM context: restrict to non-desktop toolsets (Session 0 cannot
		// drive the interactive desktop). Overrides any wider selection.
		toolsets = nonAutomationToolsets
	}

	inv, err := windows.NewInventory().
		WithToolsets(toolsets).
		WithReadOnly(readOnly).
		WithTools(cfg.Tools).
		WithExcludeTools(cfg.ExcludeTools).
		WithServerInstructions().
		Build()
	if err != nil {
		return nil, "", fmt.Errorf("failed to build tool inventory: %w", err)
	}
	return inv, personaInstructions, nil
}

// combineInstructions joins the persona guidance and the toolset-derived
// instructions, omitting empty parts.
func combineInstructions(parts ...string) string {
	var nonEmpty []string
	for _, p := range parts {
		if p != "" {
			nonEmpty = append(nonEmpty, p)
		}
	}
	return strings.Join(nonEmpty, "\n\n")
}

func toolsetIDs(tss []inventory.ToolsetMetadata) []string {
	ids := make([]string, len(tss))
	for i, ts := range tss {
		ids[i] = string(ts.ID)
	}
	return ids
}

// newLogger returns a structured logger writing to logFile (debug level) or, if
// empty, to stderr (info level). stdout is never used, so it stays clean for
// the MCP stdio transport.
func newLogger(logFile string) (*slog.Logger, func(), error) {
	var w io.Writer = os.Stderr
	level := slog.LevelInfo
	cleanup := func() {}

	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to open log file %q: %w", logFile, err)
		}
		w = f
		level = slog.LevelDebug
		cleanup = func() { _ = f.Close() }
	}

	logger := slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level}))
	return logger, cleanup, nil
}
