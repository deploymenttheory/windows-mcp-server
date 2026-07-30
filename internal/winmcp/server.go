//go:build windows && (amd64 || arm64)

// Package winmcp wires the Windows automation engine and tool inventory into an
// MCP server and runs it over a transport. It is the bootstrap layer between
// the cobra CLI (cmd/windows-mcp-server) and the domain package (pkg/windows).
package winmcp

import (
	"context"
	"errors"
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

	// Security is the master switch for the four-layer security architecture. It
	// forces enforce mode, the always-on transparency services (audit log,
	// heartbeat, rug-pull detection, status), and auto-enables the overlay +
	// recording so the security banner is shown and captured.
	Security bool

	// --- Layer 1: pre-flight checks (evaluated once at startup) ---
	WithMDM             bool   // device is MDM-enrolled (local dsregcmd MdmUrl)
	WithLoggedOnAccount string // regex the interactive user must match
	WithUserContext     bool   // require an interactive user (not SYSTEM/Session 0)
	IsNotAdmin          bool   // interactive user must NOT be a local admin
	RunContext          string // legacy: expected context "user"|"system"

	// --- Layer 2: in-flight polling ---
	GuardrailsInterval   time.Duration // posture re-eval cadence (0 = default)
	GuardrailsControlDir string        // local "kill" sentinel dir (empty disables)

	// --- Layer 3: guardrails (inline tool-call policy) ---
	Guardrails       string        // mode: off|audit|enforce
	Guardrail        []string      // additive guardrails: "id" or "id=arg"
	CircuitBreaker   bool          // inline destructive-action circuit breaker
	CircuitWindow    time.Duration // sliding window (0 = default 10s)
	CircuitThreshold int           // sensitive calls before tripping (0 = default 3)
	// EnforceHTTPS blocks plaintext http:// targets: the Scrape tool, a URL-shaped
	// App launch (which Start-Process hands to the default browser), and the
	// remote may-run endpoint. Forced on by --security.
	EnforceHTTPS bool

	// --- Layer 4: transparency / always-on ---
	WithVideoSessionRecording string        // record path (implies recording)
	WithLogging               string        // audit-log sink target ("" = stderr)
	HeartbeatInterval         time.Duration // heartbeat cadence (0 = default)
	Overlay                   bool          // decorative overlays
	RecordDir                 string        // legacy recording dir
	RecordFPS                 int
	RecordCodec               string

	// --- Credentials ---
	// CredentialsFile is a JSON document of credentials to install into the
	// Windows Credential Manager at init. Secrets are never accepted as flags:
	// argv is readable by any process on the machine. Enabling this also enables
	// the "credentials" toolset.
	CredentialsFile string

	// --- Kill switch: triggers (separate from actions) ---
	WithKillSwitch     bool
	KillOnPostureDrift bool
	KillOnCircuitTrip  bool
	KillOnRugpull      bool
	KillOnHeartbeatGap bool

	// --- Kill switch: actions (opt-in, applied in order) ---
	KillActionIsolate       bool
	KillActionKillProcs     bool
	KillActionProcNames     []string
	KillActionLock          bool
	KillActionShutdown      bool
	KillActionShutdownDelay time.Duration

	GuardrailsStatusAddr  string // loopback HTTP status endpoint (empty disables)
	GuardrailsStatusToken string // bearer token for the status endpoint
	GuardrailsBypass      bool   // break-glass (logged)
	EnterpriseGuardrails  bool   // legacy alias ⇒ enforce + enterprise preset

	// Tier-2 (SET ASIDE): only wired when EnableTier2 is true, which the
	// four-layer core never sets. Kept for later re-integration.
	EnableTier2       bool
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

// ErrPersonaNeedsUser reports a persona requested in a context that cannot
// drive the desktop. Personas are desktop-automation presets, and Session 0
// has no desktop to drive, so this is a configuration error rather than a
// policy denial — it is not routed through the guardrail decision.
var ErrPersonaNeedsUser = errors.New(
	"persona requires an interactive user context, but the process is running as SYSTEM",
)

// RunStdio builds the server and serves the MCP protocol over stdio until the
// context is cancelled or the client disconnects.
func RunStdio(ctx context.Context, cfg Config) error {
	logger, cleanup, err := newLogger(cfg.LogFile)
	if err != nil {
		return err
	}
	defer cleanup()

	// --- Layer 4a: hash-chained audit log (built first so startup is recorded) ---
	sink, err := guardrails.NewSink(cfg.WithLogging)
	if err != nil {
		return fmt.Errorf("audit log: %w", err)
	}
	audit := guardrails.NewAuditLog(sink)
	defer func() { _ = audit.Close() }()
	_, _ = audit.Append("server.start", map[string]any{"version": cfg.Version})

	// Under --security, force transparency capture: overlay (for the banner) and
	// recording, even if the decorative --overlay flag is off.
	recordDir := cfg.RecordDir
	if cfg.WithVideoSessionRecording != "" {
		recordDir = cfg.WithVideoSessionRecording
	}
	// contextcheck reports the recorder's ffmpeg child here because it does not
	// inherit this context. That is deliberate: the encoder must survive the
	// cancellation that ends the session, or the kill path would kill ffmpeg
	// mid-write and truncate the very recording the transparency layer exists to
	// produce. It has its own bounded lifetime instead — see ffmpeg.go's
	// ffmpegFinalizeTimeout, which Close enforces.
	dsk, err := desktop.New(logger, desktop.Options{ //nolint:contextcheck // see above
		Overlay:         cfg.Overlay || cfg.Security,
		SecurityOverlay: cfg.Security,
		Record:          desktop.RecorderOptions{Dir: recordDir, FPS: cfg.RecordFPS, Codec: cfg.RecordCodec},
	})
	if err != nil {
		return fmt.Errorf("failed to start desktop engine: %w", err)
	}
	defer func() { _ = dsk.Close() }()

	// --- Layer 1: pre-flight admission gate ---
	reg := newGuardrailRegistry(cfg, logger)
	gcfg := guardrailConfig(cfg)
	runner := guardrails.NewRunner(reg, gcfg, logger)
	for _, u := range runner.Unknown() {
		logger.Warn("unknown guardrail requested", "guardrail", u)
	}
	holder := &decisionHolder{}
	decision := runner.Evaluate(ctx, guardrailEnv(cfg, dsk, logger))
	holder.set(decision)
	_, _ = audit.Append("preflight.decision", decision)

	requestedSystem := strings.EqualFold(cfg.RunContext, "system")
	autoLimit := requestedSystem || decision.RunContext.IsSystem
	if cfg.Persona != "" && autoLimit {
		return fmt.Errorf("%w: %q", ErrPersonaNeedsUser, cfg.Persona)
	}

	if gcfg.Bypass {
		logger.Warn("GUARDRAILS BYPASSED (break-glass) — device policy NOT enforced")
	}
	if gcfg.Active() {
		if runner.Blocks(decision) {
			guardrails.LogDecision(logger, "deny", decision)
			_, _ = audit.Append("preflight.deny", decision.Reasons)
			_ = audit.Flush()
			dsk.ShowSecurityBanner("STARTUP BLOCKED — device did not meet policy")
			dsk.Notify(ctx, "Windows MCP: startup blocked",
				"Device did not meet policy: "+strings.Join(decision.Reasons, "; "))
			return fmt.Errorf("guardrails denied startup: %s", strings.Join(decision.Reasons, "; "))
		}
		guardrails.LogDecision(logger, "admit", decision)
	}

	// --- Init-time credentials ---
	// Provisioned only after admission, so a denied startup never installs
	// credentials, and removed again on every shutdown path below.
	installedCreds, cleanupCreds, err := provisionCredentials(dsk, cfg, audit, logger)
	if err != nil {
		return err
	}
	defer cleanupCreds()

	inv, personaInstructions, err := buildInventory(cfg, autoLimit)
	if err != nil {
		return err
	}
	for _, unknown := range inv.UnrecognizedToolsets() {
		logger.Warn("unrecognized toolset requested", "toolset", unknown)
	}
	if autoLimit {
		logger.Warn("run-context is SYSTEM: desktop-automation toolsets disabled (Session 0 cannot drive the desktop)")
		dsk.Notify(ctx, "Windows MCP: limited mode",
			"Running as SYSTEM — desktop automation is disabled; diagnostics/system tools only.")
	}

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "windows-mcp-server",
		Title:   "Windows MCP Server",
		Version: cfg.Version,
	}, &mcp.ServerOptions{
		Instructions:      combineInstructions(personaInstructions, inv.Instructions()),
		Capabilities:      pinnedCapabilities(),
		CompletionHandler: completionHandler(inv),
	})

	// --- Out-of-band kill switch + tiered action executor ---
	runCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	startedAt := time.Now()
	actuator := guardrails.NewSystemActuator(logger)
	executor := guardrails.NewKillExecutor(guardrails.KillExecutorDeps{
		Config:   killActionConfig(cfg),
		Actuator: actuator,
		Audit:    audit,
		Logger:   logger,
		Banner:   dsk.ShowSecurityBanner,
		Finalize: func() {
			// Revoke credentials before tearing the engine down: containment must not
			// leave session credentials installed on the machine.
			cleanupCreds()
			_ = dsk.Close() // finalize recording synchronously (idempotent)
		},
		Abort: func(cause error) {
			// Deferred so an in-flight reply (Kill tool / circuit-breaker block)
			// flushes to the client before the transport closes.
			time.AfterFunc(300*time.Millisecond, func() { cancel(cause) })
		},
	})
	kill := guardrails.NewKillSwitch(executor.OnTrip)
	defer func() { _ = executor.Restore() }() // undo firewall isolation on exit

	// Kill triggers are gated by the master --with-kill-switch plus each trigger's
	// own --kill-on-* flag. A disarmed trigger is report-only: still detected and
	// audited, but it contains nothing and the server keeps serving.
	armed := cfg.WithKillSwitch
	tripSentinel := tripFunc("sentinel", armed, kill, audit, logger)
	tripPostureDrift := tripFunc("posture-drift", armed && cfg.KillOnPostureDrift, kill, audit, logger)
	tripCircuit := tripFunc("circuit-trip", armed && cfg.KillOnCircuitTrip, kill, audit, logger)
	tripRugpull := tripFunc("rugpull", armed && cfg.KillOnRugpull, kill, audit, logger)
	tripHeartbeat := tripFunc("heartbeat-gap", armed && cfg.KillOnHeartbeatGap, kill, audit, logger)

	// --- Layer 4d: rug-pull detector (baseline pinned after all AddTool) ---
	heartbeat := guardrails.NewHeartbeat(audit)
	rugpull := guardrails.NewRugPull(tripRugpull, audit)

	deps := windows.NewBaseDeps(dsk, logger, nil).
		WithCredentials(credentialInfos(installedCreds)).
		WithEnforceHTTPS(enforceHTTPS(cfg))
	// Receiving middleware (outermost first): inject deps, audit, rug-pull, policy.
	server.AddReceivingMiddleware(windows.InjectDepsMiddleware(deps))
	server.AddReceivingMiddleware(audit.Middleware())
	server.AddReceivingMiddleware(rugpull.Middleware())
	server.AddReceivingMiddleware(rugpull.PromptMiddleware())
	server.AddReceivingMiddleware(rugpull.ResourceMiddleware())

	// --- Layer 3: inline tool-call policy + circuit breaker ---
	circuitEnabled := cfg.CircuitBreaker || runner.Mode() == guardrails.ModeEnforce
	server.AddReceivingMiddleware(guardrails.ToolPolicyMiddleware(guardrails.CircuitConfig{
		Enabled:   circuitEnabled,
		Window:    cfg.CircuitWindow,
		Threshold: cfg.CircuitThreshold,
		Logger:    logger,
		OnTrip:    tripCircuit,
	}))

	// RegisterAll rather than RegisterTools: resources and prompts are part of the
	// served surface too. Note RegisterResources (fixed URIs) and
	// RegisterResourceTemplates populate disjoint SDK collections — resources/list
	// returns only the former.
	inv.RegisterAll(runCtx, server, deps)

	// Guardrail tools registered unconditionally (present under any persona).
	statusTool, statusHandler := guardrails.StatusTool(
		holder.get,
		snapshotFn(startedAt, rugpull, heartbeat, audit, kill),
		kill,
	)
	server.AddTool(statusTool, statusHandler)
	// The agent-facing Kill tool always stops the session, but only actuates the
	// containment ladder when the operator armed the switch.
	stopSession := executor.StopGracefully
	if armed {
		stopSession = kill.Trip
	}
	killTool, killHandler := guardrails.KillTool(stopSession)
	server.AddTool(killTool, killHandler)

	// Pin the rug-pull baselines over the full served surface. Prompts and
	// resources are pinned too: a mutated prompt changes the instructions the
	// model follows, and a mutated resource URI changes what it reads, so both are
	// rug-pull vectors as much as a mutated tool is.
	baselineTools := append(invMCPTools(runCtx, inv), statusTool, killTool)
	baseHash := rugpull.SetBaseline(baselineTools)
	_, _ = audit.Append("tools.baseline", map[string]any{"hash": baseHash, "count": len(baselineTools)})

	basePrompts := invMCPPrompts(runCtx, inv)
	promptHash := rugpull.SetPromptBaseline(basePrompts)
	_, _ = audit.Append("prompts.baseline", map[string]any{"hash": promptHash, "count": len(basePrompts)})

	baseResources := invMCPResources(runCtx, inv)
	resourceHash := rugpull.SetResourceBaseline(baseResources)
	_, _ = audit.Append("resources.baseline", map[string]any{"hash": resourceHash, "count": len(baseResources)})

	// --- Layer 2: in-flight polling — posture drift, sentinel, always-on verifiers ---
	guardrails.StartMonitor(runCtx, guardrails.MonitorConfig{
		Interval:         cfg.GuardrailsInterval,
		ControlDir:       cfg.GuardrailsControlDir,
		TripSentinel:     tripSentinel,
		TripPostureDrift: tripPostureDrift,
		Stopped:          func() bool { tripped, _ := kill.Tripped(); return tripped },
		Logger:           logger,
		Evaluate: func(c context.Context) guardrails.Decision {
			d := runner.Evaluate(c, guardrailEnv(cfg, dsk, logger))
			holder.set(d)
			return d
		},
		Verify: monitorVerifiers(heartbeat, rugpull, func() []*mcp.Tool {
			return baselineTools
		}, tripHeartbeat, tripRugpull),
	})
	if cfg.HeartbeatInterval > 0 {
		// Started regardless of arming: a stalled heartbeat is reported even when
		// the operator chose not to contain on it.
		heartbeat.StartWatchdog(runCtx, 3*cfg.HeartbeatInterval, tripHeartbeat)
	}

	// --- Status endpoint (always-on when an address is configured) ---
	if cfg.GuardrailsStatusAddr != "" {
		ss := &guardrails.StatusServer{
			Addr:     cfg.GuardrailsStatusAddr,
			Token:    cfg.GuardrailsStatusToken,
			Current:  holder.get,
			Snapshot: snapshotFn(startedAt, rugpull, heartbeat, audit, kill),
			Kill:     kill,
			Logger:   logger,
		}
		if err := ss.Start(runCtx); err != nil {
			logger.Warn("guardrails status endpoint disabled", "error", err)
		}
	}

	logger.Info("starting windows-mcp-server over stdio",
		"version", cfg.Version,
		"enabled_toolsets", toolsetIDs(inv.EnabledToolsets()),
		"security", cfg.Security,
		"guardrails", string(runner.Mode()),
		"circuit_breaker", circuitEnabled,
	)

	err = server.Run(runCtx, &mcp.StdioTransport{})
	if tripped, reason := kill.Tripped(); tripped {
		logger.Error("session terminated by kill switch", "reason", reason)
		return fmt.Errorf("session terminated by kill switch: %s", reason)
	}
	// A requested stop (the Kill tool with the switch unarmed) is a normal
	// shutdown, not a failure — exit cleanly so the host does not read it as a crash.
	if cause := context.Cause(runCtx); errors.Is(cause, guardrails.ErrSessionStopped) {
		logger.Info("session stopped on request", "cause", cause.Error())
		return nil
	}
	if err != nil {
		return fmt.Errorf("server run: %w", err)
	}
	return nil
}

// snapshotFn builds the always-on server-status snapshot provider.
func snapshotFn(
	startedAt time.Time,
	rp *guardrails.RugPull,
	hb *guardrails.Heartbeat,
	audit *guardrails.AuditLog,
	kill *guardrails.KillSwitch,
) guardrails.SnapshotProvider {
	return func() guardrails.ServerStatus {
		beats, age := hb.Snapshot()
		seq, head := audit.Head()
		tripped, reason := kill.Tripped()
		return guardrails.ServerStatus{
			UptimeSec:        time.Since(startedAt).Seconds(),
			ToolManifestHash: rp.Baseline(),
			HeartbeatSeq:     beats,
			HeartbeatAgeSec:  age.Seconds(),
			AuditSeq:         seq,
			AuditChainHead:   head,
			Killed:           tripped,
			KillReason:       reason,
		}
	}
}

// invMCPTools returns the registered tool definitions as []*mcp.Tool for
// fingerprinting.
func invMCPTools(ctx context.Context, inv *inventory.Inventory) []*mcp.Tool {
	sts := inv.AvailableTools(ctx)
	out := make([]*mcp.Tool, 0, len(sts))
	for i := range sts {
		t := sts[i].Tool
		out = append(out, &t)
	}
	return out
}

// invMCPPrompts returns the registered prompts as []*mcp.Prompt for fingerprinting.
func invMCPPrompts(ctx context.Context, inv *inventory.Inventory) []*mcp.Prompt {
	sps := inv.AvailablePrompts(ctx)
	out := make([]*mcp.Prompt, 0, len(sps))
	for i := range sps {
		p := sps[i].Prompt
		out = append(out, &p)
	}
	return out
}

// invMCPResources returns the registered fixed-URI resources as []*mcp.Resource
// for fingerprinting.
func invMCPResources(ctx context.Context, inv *inventory.Inventory) []*mcp.Resource {
	srs := inv.AvailableResources(ctx)
	out := make([]*mcp.Resource, 0, len(srs))
	for i := range srs {
		res := srs[i].Resource
		out = append(out, &res)
	}
	return out
}

// monitorVerifiers assembles the always-on in-flight checks (heartbeat + rug-pull
// recheck). They run on every monitor tick and are not agent-disableable. Each
// carries its own caller-gated trip function so the two triggers arm separately.
func monitorVerifiers(
	hb *guardrails.Heartbeat,
	rp *guardrails.RugPull,
	tools func() []*mcp.Tool,
	tripHeartbeat, tripRugpull func(string),
) []guardrails.VerifyFunc {
	return []guardrails.VerifyFunc{
		{Name: "heartbeat", Run: hb.Beat, Trip: tripHeartbeat},
		{Name: "rug-pull", Run: func(context.Context) error { return rp.Recheck(tools()) }, Trip: tripRugpull},
	}
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

	// The engine owns its own lifetime; see the note in RunStdio.
	dsk, err := desktop.New(logger, desktop.Options{}) //nolint:contextcheck // owns its lifetime
	if err != nil {
		return guardrails.Decision{}, fmt.Errorf("failed to start desktop engine: %w", err)
	}
	defer func() { _ = dsk.Close() }()

	reg := newGuardrailRegistry(cfg, logger)
	runner := guardrails.NewRunner(reg, guardrailConfig(cfg), logger)
	for _, u := range runner.Unknown() {
		logger.Warn("unknown guardrail requested", "guardrail", u)
	}
	return runner.Evaluate(ctx, guardrailEnv(cfg, dsk, logger)), nil
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
	} else if cfg.CredentialsFile != "" {
		// Supplying credentials is the opt-in for the credentials toolset: there is
		// nothing for it to operate on otherwise. Skipped under autoLimit, because
		// Session 0 cannot drive the sign-in UI the injection targets.
		toolsets = withToolset(toolsets, string(windows.ToolsetCredentials.ID))
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

// withToolset adds id to a toolset selection. A nil selection means "the default
// set", so it is made explicit as "default" plus id rather than collapsing to id
// alone, which would silently drop every default toolset.
func withToolset(toolsets []string, id string) []string {
	if len(toolsets) == 0 {
		return []string{"default", id}
	}
	for _, t := range toolsets {
		if t == id || t == "all" {
			return toolsets
		}
	}
	return append(append([]string(nil), toolsets...), id)
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
