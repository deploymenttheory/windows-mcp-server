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
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/audit"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/contain"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/egress"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/enforce"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/policy"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/signals"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/status"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/watch"
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

	// PolicyConfig is the path to the device-policy document. Empty uses the
	// embedded default, which evaluates every declared signal, records every
	// verdict, and refuses nothing.
	//
	// Everything the security subsystem does is configured there rather than
	// here: which signals are read and how often, which rules cover which tools,
	// what a failure does, what trips the kill switch and what it actuates, and
	// where the audit chain is written.
	PolicyConfig string

	// EnforceHTTPS blocks plaintext http:// targets: the Scrape tool, a URL-shaped
	// App launch (which Start-Process hands to the default browser), and the
	// remote may-run endpoint. It is set from the policy document at startup, not
	// from a flag; it lives here because it has to reach the tool dependencies and
	// the guardrail Env, neither of which carries a policy.
	EnforceHTTPS bool

	// --- Presentation and capture (not policy) ---
	Overlay     bool   // decorative window hue and click flash
	RecordFPS   int    // session recording frame rate
	RecordCodec string // session recording codec

	// --- Credentials ---
	// CredentialsFile is a JSON document of credentials to install into the
	// Windows Credential Manager at init. Secrets are never accepted as flags:
	// argv is readable by any process on the machine. Enabling this also enables
	// the "credentials" toolset.
	CredentialsFile string
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

// ErrStartupDenied reports a device that did not meet the startup-scoped rules
// of the active policy.
var ErrStartupDenied = errors.New("device devicePolicy denied startup")

// ErrCredentialExposureDenied reports a --credentials-file served alongside a
// toolset that can read the installed credentials back (shell or filesystem)
// without the policy acknowledging the exposure. It is a configuration error, not
// a device denial: the fix is to the toolset selection or the policy document, so
// it is not routed through the guardrail decision.
var ErrCredentialExposureDenied = errors.New(
	"credentials exposed to a toolset that can read them back",
)

// RunStdio builds the server and serves the MCP protocol over stdio until the
// context is cancelled or the client disconnects.
func RunStdio(ctx context.Context, cfg Config) error {
	logger, cleanup, err := newLogger(cfg.LogFile)
	if err != nil {
		return err
	}
	defer cleanup()

	// The policy is loaded before anything else it configures. It names the audit
	// sink, the heartbeat cadence, whether the session is recorded and where — so
	// a bad document must fail before any of that is stood up, and certainly
	// before a desktop engine exists.
	reg := newGuardrailRegistry(cfg, logger)
	devicePolicy, err := loadPolicy(cfg, reg, logger)
	if err != nil {
		return err
	}
	// Carried onto Config because it has to reach the tool dependencies and the
	// guardrail Env, neither of which holds a policy.
	cfg.EnforceHTTPS = devicePolicy.EnforceHTTPS

	// --- Hash-chained audit log (built early so startup is recorded) ---
	// One session stamp, minted here and shared with the recorder, so that in
	// directory-sink mode the audit file (session-<stamp>.audit.jsonl) and the
	// recording (session-<stamp>.mp4) correlate by name — the correlation an
	// evidence bundle later relies on.
	sessionStamp := time.Now().Format("20060102-150405")
	sink, err := audit.OpenSink(devicePolicy.Transparency.AuditSink, sessionStamp)
	if err != nil {
		return fmt.Errorf("audit log: %w", err)
	}
	// The HMAC key is an environment secret, never a flag or policy field: argv is
	// world-readable and the policy is meant to be checked in. Absent, the chain is
	// unkeyed — the default — so a device that worked yesterday still starts. (The
	// local name shadows the package; on the right-hand side it is still the
	// package, since a := binding is not in scope until after the statement.)
	audit := audit.NewAuditLog(sink, audit.WithHMACKey([]byte(os.Getenv("WINDOWS_MCP_AUDIT_KEY"))))
	defer func() { _ = audit.Close() }()
	_, _ = audit.Append("server.start", map[string]any{"version": cfg.Version, "session": sessionStamp})

	// Off-box anchoring of the chain head, if the policy asks for it. It is
	// defence-in-depth beyond keying — the key lives on this box, the anchor does
	// not — and never gates startup.
	stopAnchor := startAnchor(ctx, devicePolicy.Transparency.Anchor, audit, logger)
	defer stopAnchor()

	// contextcheck reports the recorder's ffmpeg child here because it does not
	// inherit this context. That is deliberate: the encoder must survive the
	// cancellation that ends the session, or the kill path would kill ffmpeg
	// mid-write and truncate the very recording the transparency layer exists to
	// produce. It has its own bounded lifetime instead — see ffmpeg.go's
	// ffmpegFinalizeTimeout, which Close enforces.
	//
	// Overlay is the decorative hue and click flash, which stays a flag because it
	// is a display choice rather than a control. SecurityOverlay starts the overlay
	// manager without the decoration, so the policy can guarantee the kill banner
	// has somewhere to draw without also putting a green border on the screen.
	dsk, err := desktop.New(logger, desktop.Options{ //nolint:contextcheck // see above
		Overlay:         cfg.Overlay,
		SecurityOverlay: devicePolicy.Transparency.Banner,
		Record: desktop.RecorderOptions{
			Dir:   devicePolicy.Transparency.RecordingDir,
			FPS:   cfg.RecordFPS,
			Codec: cfg.RecordCodec,
			Stamp: sessionStamp,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to start desktop engine: %w", err)
	}
	defer func() { _ = dsk.Close() }()
	envFn := func() *signals.Env { return guardrailEnv(cfg, dsk, logger) }
	// The index is supplied once the manifest exists; a startup decision has no
	// tool to resolve.
	engine := policy.NewEngine(devicePolicy, reg, nil, envFn)
	holder := &decisionHolder{}

	probe := envFn().Sys
	runContext := probe.RunContext()

	// Startup admission. Rules scoped "startup" are evaluated once, before any
	// tool surface is assembled, so a refused device never gets as far as
	// registering tools or provisioning credentials.
	startup := engine.Evaluate(ctx, policy.StartupSubject())
	decision := engine.DecisionFrom(startup, probe.DeviceIdentity(), runContext)
	holder.set(decision)
	_, _ = audit.Append("devicePolicy.startup", decision)

	// Session 0 has no desktop to drive, so the automation toolsets are dropped
	// there regardless of what was asked for. This is detected rather than
	// declared: the old --run-context flag let an operator assert a context the
	// process was not actually in, which could only ever be wrong.
	autoLimit := runContext.IsSystem
	if cfg.Persona != "" && autoLimit {
		return fmt.Errorf("%w: %q", ErrPersonaNeedsUser, cfg.Persona)
	}

	if !startup.Allowed() {
		signals.LogDecision(logger, "deny", decision)
		_, _ = audit.Append("devicePolicy.startup.deny", decision.Reasons)
		_ = audit.Flush()
		dsk.ShowSecurityBanner("STARTUP BLOCKED — device did not meet devicePolicy")
		dsk.Notify(ctx, "Windows MCP: startup blocked",
			"Device did not meet devicePolicy: "+startup.Reason())
		return fmt.Errorf("%w: %s", ErrStartupDenied, startup.Reason())
	}
	signals.LogDecision(logger, "admit", decision)

	// The tool surface is resolved before credentials are provisioned, so the
	// exposure check below sees exactly the toolsets that will be served.
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

	// --- Init-time credentials ---
	// Installed credentials live in the calling user's Credential Manager, so a
	// toolset that can read that back (shell via CredRead, filesystem via a
	// Credential Manager backup) defeats the never-read guarantee. Refuse that
	// exposure before anything is installed, unless the policy explicitly
	// accepts it — the same "refuse rather than serve a weaker posture
	// than the document describes" stance the firewall tiers take. The refusal is
	// audited first, then a typed error names the toolsets and both remedies.
	if cfg.CredentialsFile != "" {
		unacked, acked := splitCredentialExposure(
			inv.EnabledToolsets(),
			devicePolicy.Credentials.AcknowledgeToolsetExposure,
		)
		if len(unacked) > 0 {
			_, _ = audit.Append("credentials.exposure.denied", map[string]any{
				"credentials_file": true,
				"exposed_toolsets": unacked,
			})
			_ = audit.Flush()
			return fmt.Errorf("%w: the %v toolset(s) can read installed credentials back out of the "+
				"Credential Manager; remove them, or acknowledge the exposure in the policy document "+
				"(credentials.acknowledge_toolset_exposure)", ErrCredentialExposureDenied, unacked)
		}
		if len(acked) > 0 {
			logger.Warn(
				"credentials served alongside toolsets that can read them back; exposure acknowledged in policy",
				"toolsets",
				acked,
			)
			_, _ = audit.Append("credentials.exposure.acknowledged", map[string]any{
				"exposed_toolsets": acked,
			})
		}
	}

	// Provisioned only after admission and the exposure check, so a denied
	// startup never installs credentials, and removed again on every shutdown path.
	installedCreds, cleanupCreds, err := provisionCredentials(dsk, cfg, audit, logger)
	if err != nil {
		return err
	}
	defer cleanupCreds()

	deps := windows.NewBaseDeps(dsk, logger, nil).
		WithCredentials(credentialInfos(installedCreds)).
		WithEnforceHTTPS(enforceHTTPS(cfg))

	// Built by the same function the conformance host uses, so the surface the
	// official suite is measured against is the surface this binary serves.
	surface := newMCPSurface(cfg, inv, personaInstructions, deps)
	server := surface.Server

	// --- Out-of-band kill switch + tiered action executor ---
	runCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	// --- Device egress proxy ---
	// Registered before the executor's Restore defer so the deferred stack
	// unwinds in the right order: containment is undone first, then the egress
	// state it was layered over.
	egressSvc, cleanupEgress, suspendEgress, err := provisionEgress(runCtx, devicePolicy, audit, logger)
	if err != nil {
		return err
	}
	defer cleanupEgress()

	startedAt := time.Now()
	actuator := contain.NewSystemActuator(logger)
	executor := contain.NewKillExecutor(contain.KillExecutorDeps{
		Config:   killPolicyConfig(devicePolicy),
		Actuator: actuator,
		Audit:    audit,
		Logger:   logger,
		Banner:   dsk.ShowSecurityBanner,
		Finalize: func() {
			// Revoke credentials before tearing the engine down: containment must not
			// leave session credentials installed on the machine.
			cleanupCreds()
			// Suspend rather than clean up: this stops admitting traffic and
			// disables the allow rules that would otherwise outlive isolation,
			// without restoring the machine's default actions — restoring them
			// here would countermand the containment just applied. Teardown
			// belongs to the exit defer.
			suspendEgress()
			_ = dsk.Close() // finalize recording synchronously (idempotent)
		},
		Abort: func(cause error) {
			// Deferred so an in-flight reply (Kill tool / circuit-breaker block)
			// flushes to the client before the transport closes.
			time.AfterFunc(300*time.Millisecond, func() { cancel(cause) })
		},
	})
	kill := contain.NewKillSwitch(executor.OnTrip)
	defer func() { _ = executor.Restore() }() // undo firewall isolation on exit

	// Kill triggers come from the policy's kill.triggers block. A trigger left off
	// is report-only: still detected and audited, but it contains nothing and the
	// server keeps serving. Transparency is never conditional on containment.
	triggers := devicePolicy.Kill.Triggers
	tripSentinel := tripFunc("sentinel", triggers.Sentinel, kill, audit, logger)
	tripPostureDrift := tripFunc("posture-drift", triggers.PostureDrift, kill, audit, logger)
	tripRugpull := tripFunc("rugpull", triggers.RugPull, kill, audit, logger)
	tripHeartbeat := tripFunc("heartbeat-gap", triggers.HeartbeatGap, kill, audit, logger)
	// A kill verdict needs no trigger switch: the rule that produced it said
	// `on_fail: kill` in this same policy, which is the operator arming it. Audit
	// mode still caps it to a warning, so the engine never reaches here under the
	// default.
	tripPolicy := tripFunc("devicePolicy", true, kill, audit, logger)

	// --- Layer 4d: rug-pull detector (baseline pinned after all AddTool) ---
	heartbeat := watch.NewHeartbeat(audit)
	rugpull := watch.NewRugPull(tripRugpull, audit)

	// Receiving middleware (outermost first). newMCPSurface already installed
	// inject-deps and cache hints; these nest inside them.
	server.AddReceivingMiddleware(audit.Middleware())
	server.AddReceivingMiddleware(rugpull.Middleware())
	server.AddReceivingMiddleware(rugpull.PromptMiddleware())
	server.AddReceivingMiddleware(rugpull.ResourceMiddleware())
	server.AddReceivingMiddleware(rugpull.DiscoverMiddleware())

	// The policy engine, innermost so nothing can route around it and so the audit
	// and rug-pull layers still observe the requests it refuses.
	server.AddReceivingMiddleware(enforce.Middleware(engine, enforce.EnforcerDeps{
		Audit:  audit,
		Kill:   tripPolicy,
		Logger: logger,
	}))

	// RegisterAll rather than RegisterTools: resources and prompts are part of the
	// served surface too. Note RegisterResources (fixed URIs) and
	// RegisterResourceTemplates populate disjoint SDK collections — resources/list
	// returns only the former.
	inv.RegisterAll(runCtx, server, deps)

	// Guardrail tools registered unconditionally (present under any persona).
	statusTool, statusHandler := status.StatusTool(
		holder.get,
		snapshotFn(startedAt, rugpull, heartbeat, audit, kill, egressSvc, devicePolicy.Egress),
		kill,
	)
	server.AddTool(statusTool, statusHandler)
	// The agent-facing Kill tool always stops the session, but only actuates the
	// containment ladder when the policy configures containment. It is not an
	// authoritative trigger: a misbehaving model must not be able to isolate or
	// shut down the device by asking.
	stopSession := executor.StopGracefully
	if devicePolicy.Kill.Actions.Isolate || devicePolicy.Kill.Actions.Lock || devicePolicy.Kill.Actions.Shutdown {
		stopSession = kill.Trip
	}
	killTool, killHandler := status.KillTool(stopSession)
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

	// Protocol 2026-07-28 removed the initialize handshake and made server/discover
	// the canonical advertisement of capabilities and instructions, so it is pinned
	// too — otherwise a widened capability set or rewritten model instructions would
	// drift entirely unwatched.
	discoverHash := rugpull.SetDiscoverBaseline(surface.Capabilities, surface.Instructions)
	_, _ = audit.Append("discover.baseline", map[string]any{"hash": discoverHash})

	// The engine can now resolve tools; from here every request is decided against
	// the manifest that is actually served.
	engine.SetIndex(newToolIndex(runCtx, inv))

	// --- In-flight: signal refresh, posture drift, sentinel, always-on verifiers ---
	verifiers := append(
		// Refreshing the signal cache first means the posture re-evaluation below
		// reads warm values rather than paying for the device probes itself.
		[]watch.VerifyFunc{{
			Name: "signal-refresh",
			Run:  engine.Refresh,
			Trip: tripPostureDrift,
		}},
		monitorVerifiers(heartbeat, rugpull, func() []*mcp.Tool { return baselineTools },
			tripHeartbeat, tripRugpull)...,
	)
	watch.StartMonitor(runCtx, watch.MonitorConfig{
		Interval:         devicePolicy.InFlight.Interval.Std(),
		ControlDir:       devicePolicy.InFlight.ControlDir,
		TripSentinel:     tripSentinel,
		TripPostureDrift: tripPostureDrift,
		Stopped:          func() bool { tripped, _ := kill.Tripped(); return tripped },
		Logger:           logger,
		Evaluate: func(c context.Context) signals.Decision {
			// Re-runs the startup-scoped rules against freshly refreshed signals, so
			// a device that drifts out of admission is noticed even if no tool is
			// being called.
			v := engine.Evaluate(c, policy.StartupSubject())
			d := engine.DecisionFrom(v, probe.DeviceIdentity(), probe.RunContext())
			holder.set(d)
			return d
		},
		Verify: verifiers,
	})
	if heartbeatInterval := devicePolicy.Transparency.Heartbeat.Std(); heartbeatInterval > 0 {
		// Started regardless of arming: a stalled heartbeat is reported even when
		// the operator chose not to contain on it.
		heartbeat.StartWatchdog(runCtx, 3*heartbeatInterval, tripHeartbeat)
	}

	// --- Status endpoint (always-on when an address is configured) ---
	if devicePolicy.Transparency.StatusAddr != "" {
		ss := &status.StatusServer{
			Addr:     devicePolicy.Transparency.StatusAddr,
			Token:    devicePolicy.Transparency.StatusToken,
			Current:  holder.get,
			Snapshot: snapshotFn(startedAt, rugpull, heartbeat, audit, kill, egressSvc, devicePolicy.Egress),
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
		"policy_mode", string(devicePolicy.Mode),
		"policy_signals", devicePolicy.SignalIDs(),
		"policy_rules", len(devicePolicy.Rules),
	)

	err = server.Run(runCtx, &mcp.StdioTransport{})
	if tripped, reason := kill.Tripped(); tripped {
		logger.Error("session terminated by kill switch", "reason", reason)
		return fmt.Errorf("session terminated by kill switch: %s", reason)
	}
	// A requested stop (the Kill tool with the switch unarmed) is a normal
	// shutdown, not a failure — exit cleanly so the host does not read it as a crash.
	if cause := context.Cause(runCtx); errors.Is(cause, contain.ErrSessionStopped) {
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
	rp *watch.RugPull,
	hb *watch.Heartbeat,
	audit *audit.AuditLog,
	kill *contain.KillSwitch,
	egressSvc *egress.Service,
	egressCfg policy.EgressPolicy,
) status.SnapshotProvider {
	return func() status.ServerStatus {
		beats, age := hb.Snapshot()
		seq, head := audit.Head()
		tripped, reason := kill.Tripped()
		return status.ServerStatus{
			UptimeSec:        time.Since(startedAt).Seconds(),
			ToolManifestHash: rp.Baseline(),
			HeartbeatSeq:     beats,
			HeartbeatAgeSec:  age.Seconds(),
			AuditSeq:         seq,
			AuditChainHead:   head,
			Killed:           tripped,
			KillReason:       reason,
			Egress:           egressStatus(egressSvc, egressCfg),
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
	hb *watch.Heartbeat,
	rp *watch.RugPull,
	tools func() []*mcp.Tool,
	tripHeartbeat, tripRugpull func(string),
) []watch.VerifyFunc {
	return []watch.VerifyFunc{
		{Name: "heartbeat", Run: hb.Beat, Trip: tripHeartbeat},
		{Name: "rug-pull", Run: func(context.Context) error { return rp.Recheck(tools()) }, Trip: tripRugpull},
	}
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
