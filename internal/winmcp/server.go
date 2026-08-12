//go:build windows && (amd64 || arm64)

// Package winmcp wires the Windows automation engine and tool inventory into an
// MCP server and runs it over a transport. It is the bootstrap layer between
// the cobra CLI (cmd/windows-mcp-server) and the domain package (pkg/windows).
package winmcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/agentweave-harness/guardrails/audit"
	"github.com/deploymenttheory/agentweave-harness/guardrails/contain"
	"github.com/deploymenttheory/agentweave-harness/guardrails/egress"
	"github.com/deploymenttheory/agentweave-harness/guardrails/enforce"
	"github.com/deploymenttheory/agentweave-harness/guardrails/policy"
	"github.com/deploymenttheory/agentweave-harness/guardrails/signals"
	"github.com/deploymenttheory/agentweave-harness/guardrails/status"
	"github.com/deploymenttheory/agentweave-harness/guardrails/telemetry"
	"github.com/deploymenttheory/agentweave-harness/guardrails/watch"
	"github.com/deploymenttheory/agentweave-harness/wire"
	"github.com/deploymenttheory/windows-mcp-server/internal/desktop"
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

// ErrPersonaToolBypass reports a --tools entry that escapes the active persona's
// toolset selection via the additional-tools bypass. A persona is a documented
// surface guarantee, so this is a configuration error: the fix is to compose the
// surface explicitly with --toolsets, or to drop the tool.
var ErrPersonaToolBypass = errors.New("--tools escapes the persona's toolsets")

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
	// destination, the heartbeat cadence, whether the session is recorded and where — so
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
	// directory-destination mode the audit file (session-<stamp>.audit.jsonl) and the
	// recording (session-<stamp>.mp4) correlate by name — the correlation an
	// evidence bundle later relies on.
	sessionStamp := time.Now().Format("20060102-150405")
	// Keyed by default now: an unkeyed chain is tamper-evident but not
	// unforgeable, since anyone who can write the file can recompute every hash
	// after an edit. See resolveAuditKey for what the generated key does and does
	// not protect against.
	auditKey := resolveAuditKey(devicePolicy.Transparency.AuditDestination, logger)
	dest, err := audit.OpenDestination(devicePolicy.Transparency.AuditDestination, sessionStamp, auditKey)
	if err != nil {
		return fmt.Errorf("audit log: %w", err)
	}
	// The HMAC key is an environment secret, never a flag or policy field: argv is
	// world-readable and the policy is meant to be checked in. Absent, the chain is
	// unkeyed — the default — so a device that worked yesterday still starts. (The
	// local name shadows the package; on the right-hand side it is still the
	// package, since a := binding is not in scope until after the statement.)
	audit := audit.NewAuditLog(dest, audit.WithHMACKey(auditKey))
	// sealAtExit is populated later, once the planner exists and the closing posture
	// is captured. It runs from inside the audit-close defer, so it fires after the
	// chain is sealed and (defers being LIFO) after the recorder is finalized — both
	// are inputs to the bundle.
	var sealAtExit func()
	defer func() {
		_ = audit.Close()
		if sealAtExit != nil {
			sealAtExit()
		}
	}()
	_, _ = audit.Append("server.started", map[string]any{"version": cfg.Version, "session": sessionStamp})

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
	_, _ = audit.Append("devicePolicy.decided", decision)

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
		_, _ = audit.Append("devicePolicy.denied", decision.Reasons)
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

	// Record the resolved tool surface: an operator (or an incident review) can
	// see exactly what was served under which persona and selection, which the
	// per-manifest hash baseline deliberately does not spell out.
	enabledToolsetIDs := toolsetIDs(inv.EnabledToolsets())
	_, _ = audit.Append("server.configured", map[string]any{
		"persona":               cfg.Persona,
		"toolsets":              enabledToolsetIDs,
		"unrecognized_toolsets": inv.UnrecognizedToolsets(),
		"additional_tools":      cfg.Tools,
		"excluded_tools":        cfg.ExcludeTools,
		"read_only":             cfg.ReadOnly,
		"credentials_file":      cfg.CredentialsFile != "",
	})

	// A persona is a documented guarantee about the served surface. --tools bypasses
	// toolset membership (that is its purpose), so combined with a persona it would
	// silently widen that guarantee. Refuse it: name the escaping tools and point at
	// the explicit way to compose a surface by hand.
	if cfg.Persona != "" {
		if outside := toolsOutsidePersona(cfg.Tools, inv.EnabledToolsets()); len(outside) > 0 {
			_, _ = audit.Append("tools.persona_bypass.denied", map[string]any{
				"persona": cfg.Persona,
				"tools":   outside,
			})
			_ = audit.Flush()
			return fmt.Errorf("%w: %v are outside the %q persona's toolsets; select --toolsets "+
				"explicitly instead of a persona, or drop those tools", ErrPersonaToolBypass, outside, cfg.Persona)
		}
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
			credentialsDeclareUnmaskedTargets(cfg.CredentialsFile),
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
		WithEnforceHTTPS(enforceHTTPS(cfg)).
		WithProtectedPaths(protectedPaths(cfg, devicePolicy))

	// Built by the same function the conformance host uses, so the surface the
	// official suite is measured against is the surface this binary serves.
	surface := newMCPSurface(cfg, inv, personaInstructions, deps)
	server := surface.Server

	// --- Out-of-band kill switch + tiered action executor ---
	runCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	startedAt := time.Now()
	actuator := contain.NewSystemActuator(logger)

	// --- agentweave-harness control channel (servant side) ---
	// When the harness spawned this server it left the channel address and a
	// bootstrap token in the environment. Dial back, authenticate, and serve
	// signal evaluation, actuation and liveness for the session. When no harness
	// is present, harnessAddress() is empty and the server runs standalone
	// unchanged.
	//
	// The attach happens before the egress provisioning on purpose: the ack's
	// effective config carries the harness-side proxy's port and executable,
	// which provisionEgress needs so it can point the OS enforcement at the
	// harness instead of starting a listener of its own. The harness teardown
	// defers are registered further down, after the executor's Restore, so the
	// unwind keeps its layering (isolation undone first, then containment,
	// then the egress state it was all layered over).
	//
	// The hello.ack's mode decides how much of the local guardrail stack is
	// wired below. An observe ack is additive: the full in-process stack runs
	// exactly as in standalone mode. An enforce ack means a live policy decider
	// stands between the client and this process — the harness refuses on the
	// wire, audits every frame, and fingerprints the manifest surfaces it
	// serves — so the duplicated in-process layers (enforce, rug-pull,
	// telemetry, the GuardrailStatus/Kill tools) are shed rather than run
	// twice. The harness only acks enforce once its decider is actually
	// installed, which is what makes that shedding safe.
	harnessEnforcing := false
	var harnessProxy harnessEgress
	var servant *harnessServant
	var harnessRestoreMu sync.Mutex
	var harnessRestore func() error
	if pipe, token := harnessAddress(); pipe != "" {
		rungs := buildRungs(rungPrimitives{
			Actuator:     actuator,
			Banner:       dsk.ShowSecurityBanner,
			Seal:         audit.Flush,
			Finalize:     func() { _ = dsk.Close() },
			CleanupCreds: cleanupCreds,
			SetRestore: func(r func() error) {
				harnessRestoreMu.Lock()
				harnessRestore = r
				harnessRestoreMu.Unlock()
			},
			Logger: logger,
		})

		s, ack, derr := attachHarness(pipe, token, cfg.Version, sessionStamp, servantDeps{
			Registry:   reg,
			EnvFn:      envFn,
			Rungs:      rungs,
			Alive:      func() bool { return true },
			RunContext: runContext,
			Elevated:   actuator.Elevated(),
			Logger:     logger,
			OnLost: func(cause error) {
				if cause == nil {
					cancel(errHarnessChannelLost)
					return
				}
				cancel(fmt.Errorf("%w: %w", errHarnessChannelLost, cause))
			},
		})
		// The token has done its job. Scrub both bootstrap vars so no tool the
		// agent runs can read the channel credential back — the same discipline
		// scrubSecretEnv applies to the policy's secrets.
		_ = os.Unsetenv(envHarnessPipe)
		_ = os.Unsetenv(envHarnessToken)
		if derr != nil {
			return fmt.Errorf("agentweave-harness: %w", derr)
		}
		servant = s
		harnessEnforcing = ack.Mode == wire.ModeEnforce
		harnessProxy = harnessEgress{
			Port:       ack.EffectiveConfig.EgressProxyPort,
			Executable: ack.EffectiveConfig.EgressProxyExecutable,
		}
		logger.Info("attached to agentweave-harness", "mode", ack.Mode, "proto", ack.Proto,
			"local_enforcement", !harnessEnforcing, "egress_proxy_port", harnessProxy.Port)
		_, _ = audit.Append("harness.attached", map[string]any{
			"mode": ack.Mode, "local_enforcement": !harnessEnforcing,
			"egress_proxy_port": harnessProxy.Port,
		})
		// Before the servant starts serving and before RegisterAll builds the
		// tool surface, per the wire contract; envFn and the tool deps both see
		// the folded settings from the first call they answer.
		applyEffectiveConfig(ack.EffectiveConfig, &cfg, devicePolicy, deps, dsk.ShowSecurityBanner, logger)

		go servant.serve(runCtx)
		servant.StartHeartbeat(runCtx, heartbeatFromAck(ack))
		if names := installedCredentialNames(installedCreds); len(names) > 0 {
			_ = servant.PushCredentialEvent(wire.CredentialInstalled, names)
		}
	}

	// --- Device egress proxy ---
	// Registered before the executor's Restore defer so the deferred stack
	// unwinds in the right order: containment is undone first, then the egress
	// state it was layered over.
	egressSvc, cleanupEgress, suspendEgress, err := provisionEgress(runCtx, devicePolicy, audit, logger, harnessProxy)
	if err != nil {
		return err
	}
	defer cleanupEgress()
	// The server's own reaching-out (Scrape) routes through whichever proxy
	// this session runs — harness-announced or local — so it is governed by
	// the same allowlist as everything else's. deps is the pointer the
	// middleware captured, and RegisterAll has not run yet.
	switch {
	case harnessProxy.announced():
		deps.WithEgressProxy(fmt.Sprintf("127.0.0.1:%d", harnessProxy.Port))
	case egressSvc != nil:
		deps.WithEgressProxy(egressSvc.Addr())
	}

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

	// The harness teardown defers, registered here rather than at the attach
	// so the LIFO unwind keeps its layering exactly as before the attach moved
	// up: the servant closes and the isolation restore runs first, then the
	// executor's Restore, then the egress teardown they were layered over.
	if servant != nil {
		defer func() {
			harnessRestoreMu.Lock()
			r := harnessRestore
			harnessRestoreMu.Unlock()
			if r != nil {
				_ = r()
			}
		}()
		defer func() { _ = servant.Close() }()
	}

	// Out-of-band approvals for on_fail: hold rules. Off unless a webhook is
	// configured; a policy that uses approve without one is refused at load, so a nil
	// approver here means no approve rule can fire. The signing key is an environment
	// secret, never the policy document — argv and the policy are both reviewable.
	var approver enforce.Approver
	if devicePolicy.Approvals.WebhookURL != "" {
		approver = enforce.NewApprovalClient(enforce.ApprovalConfig{
			WebhookURL:   devicePolicy.Approvals.WebhookURL,
			Timeout:      devicePolicy.Approvals.Timeout.Std(),
			PollInterval: devicePolicy.Approvals.PollInterval.Std(),
			HMACKey:      []byte(os.Getenv("WINDOWS_MCP_APPROVAL_KEY")),
			Logger:       logger,
		})
		logger.Info("dual control enabled", "webhook", devicePolicy.Approvals.WebhookURL,
			"timeout", devicePolicy.Approvals.Timeout)
	}

	// Plan-and-apply. Wired after the kill switch so an apply can abandon its
	// remaining steps when containment trips; deps is a pointer the surface's
	// middleware already captured, so setting the planner now reaches the handlers.
	sessionPlanner := newPlanner(engine, audit, inventoryRegistry{inv: inv, deps: deps},
		func() bool { tripped, _ := kill.Tripped(); return tripped }).
		withReadRegister(deps)
	if approver != nil {
		sessionPlanner.withApprovals(approver, sessionStamp, devicePolicy.Approvals.Timeout.Std())
	}
	deps.WithPlanner(sessionPlanner)

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

	// OTLP export, off unless a collector endpoint is configured. It is
	// observability, not a control, so a construction failure warns and disables it
	// rather than gating startup. Auth headers come from the environment, never the
	// policy document.
	var (
		recordDecision      func(subject, severity, mode string)
		telemetryMiddleware mcp.Middleware
	)
	// Not constructed at all under an enforcing harness: the exporter's spans
	// describe the request path, which the harness now owns, and recordDecision
	// feeds the enforce middleware being shed alongside it — the two go together
	// or a dangling reference is left behind.
	if devicePolicy.Telemetry.Endpoint != "" && !harnessEnforcing {
		tele, terr := telemetry.New(ctx, telemetry.Config{
			Endpoint:    devicePolicy.Telemetry.Endpoint,
			SampleRatio: devicePolicy.Telemetry.SampleRatio,
			Headers:     telemetry.ParseHeaders(os.Getenv("WINDOWS_MCP_OTLP_HEADERS")),
			ServiceName: "windows-mcp-server",
			Version:     cfg.Version,
		})
		if terr != nil {
			logger.Warn("telemetry disabled: could not start the OTLP exporter", "error", terr)
		} else {
			defer tele.Shutdown(context.WithoutCancel(ctx))
			telemetryMiddleware = tele.Middleware()
			recordDecision = tele.RecordDecision
			logger.Info("telemetry enabled", "endpoint", devicePolicy.Telemetry.Endpoint)
		}
	}

	// Read before the scrub below, like every other environment secret, even though
	// the endpoint it belongs to is constructed much further down. Resolving it at
	// the point of use would read a variable this line has already cleared.
	statusToken, err := resolveStatusToken(devicePolicy.Transparency, logger)
	if err != nil {
		return err
	}

	// The evidence export destination, for the same reason: the sink is not used
	// until the seal fires from the audit-close defer, long after the scrub, so its
	// credentials are read into it here. A nil sink means export is off or could
	// not be configured — never a reason to fail the session.
	exportSink := provisionExport(devicePolicy, audit, logger)

	// Every environment secret has now been read into the component that needs it,
	// so clear them from the process environment before any tool can run. This is
	// the second half of the defence; see scrubSecretEnv.
	scrubSecretEnv(devicePolicy, logger)

	// Receiving middleware, outermost first, installed in one call so the order
	// below is the order that actually runs (see installReceiving). Telemetry sits
	// between audit and rug-pull: audit must see every request first, and a span
	// should cover the rug-pull and policy work that follows. The policy engine is
	// innermost, so nothing can route around it and the audit and rug-pull layers
	// still observe the requests it refuses.
	surface.installReceiving(receivingChain(
		harnessEnforcing,
		audit.Middleware(),
		telemetryMiddleware,
		[]mcp.Middleware{
			rugpull.Middleware(),
			rugpull.PromptMiddleware(),
			rugpull.ResourceMiddleware(),
			rugpull.DiscoverMiddleware(),
		},
		enforce.Middleware(engine, enforce.EnforcerDeps{
			Audit:           audit,
			Kill:            tripPolicy,
			RecordDecision:  recordDecision,
			Approver:        approver,
			SessionID:       sessionStamp,
			ApprovalTimeout: devicePolicy.Approvals.Timeout.Std(),
			Logger:          logger,
		}),
	)...)

	// RegisterAll rather than RegisterTools: resources and prompts are part of the
	// served surface too. Note RegisterResources (fixed URIs) and
	// RegisterResourceTemplates populate disjoint SDK collections — resources/list
	// returns only the former.
	inv.RegisterAll(runCtx, server, deps)

	// Guardrail tools and rug-pull baselines are one block, registered together
	// or not at all: the Status/Kill tools are part of the pinned tool surface
	// (they sit in baselineTools), so registering one half without the other
	// would either baseline tools that are never served or serve tools outside
	// the baseline — both read as drift. Under an enforcing harness the whole
	// block is shed: the harness injects and answers its own Status/Kill tools
	// and fingerprints every manifest surface from the wire, where a tampered
	// server cannot vouch for itself.
	var baselineTools []*mcp.Tool
	if !harnessEnforcing {
		// Registered unconditionally within the local stack (present under any
		// persona).
		statusTool, statusHandler := status.StatusTool(
			holder.get,
			snapshotFn(startedAt, rugpull, heartbeat, audit, kill, egressSvc, devicePolicy.Egress,
				exportStatus(devicePolicy.Transparency.Export, exportSink)),
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
		baselineTools = append(invMCPTools(runCtx, inv), statusTool, killTool)
		baseHash := rugpull.SetBaseline(baselineTools)
		_, _ = audit.Append("tools.pinned", map[string]any{"hash": baseHash, "count": len(baselineTools)})

		basePrompts := invMCPPrompts(runCtx, inv)
		promptHash := rugpull.SetPromptBaseline(basePrompts)
		_, _ = audit.Append("prompts.pinned", map[string]any{"hash": promptHash, "count": len(basePrompts)})

		baseResources := invMCPResources(runCtx, inv)
		resourceHash := rugpull.SetResourceBaseline(baseResources)
		_, _ = audit.Append("resources.pinned", map[string]any{"hash": resourceHash, "count": len(baseResources)})

		// Protocol 2026-07-28 removed the initialize handshake and made server/discover
		// the canonical advertisement of capabilities and instructions, so it is pinned
		// too — otherwise a widened capability set or rewritten model instructions would
		// drift entirely unwatched.
		discoverHash := rugpull.SetDiscoverBaseline(surface.Capabilities, surface.Instructions)
		_, _ = audit.Append("discover.pinned", map[string]any{"hash": discoverHash})
	}

	// The engine can now resolve tools; from here every request is decided against
	// the manifest that is actually served.
	engine.SetIndex(newToolIndex(runCtx, inv))

	// --- In-flight: signal refresh, posture drift, sentinel, always-on verifiers ---
	verifiers := []watch.VerifyFunc{
		// Refreshing the signal cache first means the posture re-evaluation below
		// reads warm values rather than paying for the device probes itself.
		{
			Name: "signal-refresh",
			Run:  engine.Refresh,
			Trip: tripPostureDrift,
		},
		// The local heartbeat stays in every mode: it beats into this host's own
		// audit chain, which the harness reads but does not write.
		{Name: "heartbeat", Run: heartbeat.Beat, Trip: tripHeartbeat},
	}
	if !harnessEnforcing {
		// The local rug-pull recheck only exists alongside its baseline; under an
		// enforcing harness the fingerprints are taken from the wire instead.
		verifiers = append(verifiers, rugpullVerifier(rugpull,
			func() []*mcp.Tool { return baselineTools }, tripRugpull))
	}
	watch.StartMonitor(runCtx, watch.MonitorConfig{
		Interval:         devicePolicy.InFlight.Interval.Std(),
		ControlDir:       devicePolicy.InFlight.ControlDir,
		SentinelToken:    sentinelToken(devicePolicy.InFlight.ControlDir, audit, logger),
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
			Addr:    devicePolicy.Transparency.StatusAddr,
			Token:   statusToken,
			Current: holder.get,
			Snapshot: snapshotFn(startedAt, rugpull, heartbeat, audit, kill, egressSvc, devicePolicy.Egress,
				exportStatus(devicePolicy.Transparency.Export, exportSink)),
			Kill:   kill,
			Logger: logger,
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

	// The session is over but the engine and desktop are still up (their defers
	// have not run). Capture the closing posture now, and arm the evidence seal to
	// fire from the audit-close defer once the chain and recording are finalized.
	if devicePolicy.Transparency.EvidenceDir != "" {
		var posture []byte
		if b, mErr := json.Marshal(
			snapshotFn(startedAt, rugpull, heartbeat, audit, kill, egressSvc, devicePolicy.Egress,
				exportStatus(devicePolicy.Transparency.Export, exportSink))(),
		); mErr == nil {
			posture = b
		}
		plans := sessionPlanner.StoredPlans()
		sealAtExit = func() {
			autoSealEvidence(devicePolicy.Transparency, sessionStamp, plans, posture, exportSink, logger)
		}
	}

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
	exportSt *status.ExportStatus,
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
			EvidenceExport:   exportSt,
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
