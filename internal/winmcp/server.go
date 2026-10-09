//go:build windows && (amd64 || arm64)

// Package winmcp wires the Windows automation engine and tool inventory into an
// MCP server and runs it over a transport. It is the bootstrap layer between
// the cobra CLI (cmd/windows-mcp-server) and the domain package (pkg/windows),
// composed from the shared mcp-server-core runtime.
package winmcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/agentweave-harness/guardrails/audit"
	"github.com/deploymenttheory/agentweave-harness/guardrails/contain"
	"github.com/deploymenttheory/agentweave-harness/guardrails/enforce"
	"github.com/deploymenttheory/agentweave-harness/guardrails/policy"
	"github.com/deploymenttheory/agentweave-harness/guardrails/signals"
	"github.com/deploymenttheory/agentweave-harness/guardrails/status"
	"github.com/deploymenttheory/agentweave-harness/guardrails/telemetry"
	"github.com/deploymenttheory/agentweave-harness/guardrails/watch"
	"github.com/deploymenttheory/agentweave-harness/wire"
	"github.com/deploymenttheory/mcp-server-core/inventory"
	"github.com/deploymenttheory/mcp-server-core/runtime"
	"github.com/deploymenttheory/mcp-server-core/surface"
	"github.com/deploymenttheory/windows-mcp-server/internal/desktop"
	"github.com/deploymenttheory/windows-mcp-server/pkg/windows"
)

// ServerName and ServerTitle identify this server in server/discover.
const (
	ServerName  = "windows-mcp-server"
	ServerTitle = "Windows MCP Server"
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

// ErrUnknownPersona reports a persona id that is not registered.
var ErrUnknownPersona = errors.New("unknown persona")

// ErrStartupDenied reports a device that did not meet the startup-scoped rules
// of the active policy.
var ErrStartupDenied = errors.New("device devicePolicy denied startup")

// ErrPersonaToolBypass reports a --tools entry that escapes the active persona's
// toolset selection via the additional-tools bypass. A persona is a documented
// surface guarantee, so this is a configuration error: the fix is to compose the
// surface explicitly with --toolsets, or to drop the tool.
var ErrPersonaToolBypass = errors.New("--tools escapes the persona's toolsets")

// ErrKilled reports a session ended by the kill switch.
var ErrKilled = errors.New("session terminated by kill switch")

// RunStdio builds the server and serves the MCP protocol over stdio until the
// context is cancelled or the client disconnects.
//
// The order is the contract: policy first (it names everything else), then the
// audit chain, the engine, startup admission, the tool surface, credentials,
// the harness attach, egress, the kill ladder, the planner, the middleware
// chain, registration, the guardrail tools and baselines, the in-flight
// monitor, the status endpoint, and only then the transport.
//
//nolint:gocyclo,cyclop,maintidx,funlen,gocognit // the wiring order is the contract
func RunStdio(ctx context.Context, cfg Config) error {
	logger, cleanup, err := runtime.NewLogger(cfg.LogFile)
	if err != nil {
		return fmt.Errorf("logger: %w", err)
	}
	defer cleanup()

	// The policy is loaded before anything else it configures. It names the audit
	// destination, the heartbeat cadence, whether the session is recorded and where — so
	// a bad document must fail before any of that is stood up, and certainly
	// before a desktop engine exists.
	reg := runtime.NewGuardrailRegistry(envNames, logger)
	devicePolicy, err := runtime.LoadPolicy(cfg.PolicyConfig, reg, logger)
	if err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	// Carried onto Config because it has to reach the tool dependencies and the
	// guardrail Env, neither of which holds a policy.
	cfg.EnforceHTTPS = devicePolicy.EnforceHTTPS

	// --- Hash-chained audit log (built early so startup is recorded) ---
	// One session stamp, minted here and shared with the recorder, so that in
	// directory-destination mode the audit file (session-<stamp>.audit.jsonl) and the
	// recording (session-<stamp>.mp4) correlate by name — the correlation an
	// evidence bundle later relies on.
	sessionStamp := runtime.SessionStamp()
	// Keyed by default: an unkeyed chain is tamper-evident but not unforgeable,
	// since anyone who can write the file can recompute every hash after an
	// edit. The HMAC key is an environment secret, never a flag or policy field.
	auditKey := runtime.ResolveAuditKey(envNames, devicePolicy.Transparency.AuditDestination, logger)
	dest, err := audit.OpenDestination(devicePolicy.Transparency.AuditDestination, sessionStamp, auditKey)
	if err != nil {
		return fmt.Errorf("audit log: %w", err)
	}
	auditLog := audit.NewAuditLog(dest, audit.WithHMACKey(auditKey))
	// sealAtExit is populated later, once the planner exists and the closing posture
	// is captured. It runs from inside the audit-close defer, so it fires after the
	// chain is sealed and (defers being LIFO) after the recorder is finalized — both
	// are inputs to the bundle.
	var sealAtExit func()
	defer func() {
		_ = auditLog.Close()
		if sealAtExit != nil {
			sealAtExit()
		}
	}()
	_, _ = auditLog.Append("server.started", map[string]any{"version": cfg.Version, "session": sessionStamp})

	// Off-box anchoring of the chain head, if the policy asks for it. It is
	// defence-in-depth beyond keying — the key lives on this box, the anchor does
	// not — and never gates startup.
	stopAnchor := startAnchor(ctx, devicePolicy.Transparency.Anchor, auditLog, logger)
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
	holder := &runtime.DecisionHolder{}

	probe := envFn().Sys
	runContext := probe.RunContext()

	// Startup admission. Rules scoped "startup" are evaluated once, before any
	// tool surface is assembled, so a refused device never gets as far as
	// registering tools or provisioning credentials.
	startup := engine.Evaluate(ctx, policy.StartupSubject())
	decision := engine.DecisionFrom(startup, probe.DeviceIdentity(), runContext)
	holder.Set(decision)
	_, _ = auditLog.Append("devicePolicy.decided", decision)

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
		_, _ = auditLog.Append("devicePolicy.denied", decision.Reasons)
		_ = auditLog.Flush()
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
	enabledToolsetIDs := surface.ToolsetIDs(inv.EnabledToolsets())
	_, _ = auditLog.Append("server.configured", map[string]any{
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
		if outside := surface.ToolsOutsidePersona(
			cfg.Tools,
			inv.EnabledToolsets(),
			windows.ToolToolsets(),
		); len(
			outside,
		) > 0 {
			_, _ = auditLog.Append("tools.persona_bypass.denied", map[string]any{
				"persona": cfg.Persona,
				"tools":   outside,
			})
			_ = auditLog.Flush()
			return fmt.Errorf("%w: %v are outside the %q persona's toolsets; select --toolsets "+
				"explicitly instead of a persona, or drop those tools", ErrPersonaToolBypass, outside, cfg.Persona)
		}
	}

	// --- Init-time credentials ---
	// Refuse the exposure before anything is installed, unless the policy
	// explicitly accepts it; see refuseCredentialExposure.
	if err := refuseCredentialExposure(cfg, inv, devicePolicy, auditLog, logger); err != nil {
		return err
	}
	// Provisioned only after admission and the exposure check, so a denied
	// startup never installs credentials, and removed again on every shutdown path.
	installedCreds, cleanupCreds, err := provisionCredentials(dsk, cfg, auditLog, logger)
	if err != nil {
		return err
	}
	defer cleanupCreds()

	deps := windows.NewBaseDeps(dsk, logger, nil)
	deps.WithCredentials(credentialInfos(installedCreds)).
		WithEnforceHTTPS(cfg.EnforceHTTPS).
		WithProtectedPaths(guardrailPaths(cfg, devicePolicy))

	// Built by the same function the conformance host uses, so the surface the
	// official suite is measured against is the surface this binary serves.
	s := newSurface(cfg, inv, personaInstructions, deps)
	server := s.Server

	// --- Out-of-band kill switch + tiered action executor ---
	runCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	startedAt := time.Now()
	actuator := contain.NewSystemActuator(logger)

	// --- agentweave-harness control channel (servant side) ---
	// When the harness spawned this server it left the channel address and a
	// bootstrap token in the environment. Dial back, authenticate, and serve
	// signal evaluation, actuation and liveness for the session. When no harness
	// is present, HarnessAddress() is empty and the server runs standalone
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
	var harnessProxy runtime.HarnessEgress
	var servant *runtime.HarnessServant
	var harnessRestoreMu sync.Mutex
	var harnessRestore func() error
	egressRestore := &runtime.EgressRestoreHolder{}
	if pipe, token := runtime.HarnessAddress(); pipe != "" {
		rungs := runtime.BuildRungs(runtime.RungPrimitives{
			Actuator:     actuator,
			Banner:       dsk.ShowSecurityBanner,
			Seal:         auditLog.Flush,
			Finalize:     func() { _ = dsk.Close() },
			CleanupCreds: cleanupCreds,
			SetRestore: func(r func() error) {
				harnessRestoreMu.Lock()
				harnessRestore = r
				harnessRestoreMu.Unlock()
			},
			// The egress rungs drive the composed policy's OS enforcement on
			// this host. A fresh enforcer: its recovery state lives on disk,
			// so it needs no shared object with the local egress path (which,
			// in enforce mode, is not running — the server's own policy has
			// egress off).
			Egress:        newEnforcer(logger),
			EgressRestore: egressRestore,
			Logger:        logger,
		})

		sv, ack, derr := attachHarness(pipe, token, cfg.Version, sessionStamp, runtime.ServantDeps{
			Registry:   reg,
			EnvFn:      envFn,
			Rungs:      rungs,
			Alive:      func() bool { return true },
			RunContext: runContext,
			Elevated:   actuator.Elevated(),
			Logger:     logger,
			OnLost: func(cause error) {
				if cause == nil {
					cancel(runtime.ErrHarnessChannelLost)
					return
				}
				cancel(fmt.Errorf("%w: %w", runtime.ErrHarnessChannelLost, cause))
			},
		})
		// The token has done its job. Scrub both bootstrap vars so no tool the
		// agent runs can read the channel credential back — the same discipline
		// ScrubSecretEnv applies to the policy's secrets.
		_ = os.Unsetenv(runtime.EnvHarnessPipe)
		_ = os.Unsetenv(runtime.EnvHarnessToken)
		if derr != nil {
			return fmt.Errorf("agentweave-harness: %w", derr)
		}
		servant = sv
		harnessEnforcing = ack.Mode == wire.ModeEnforce
		harnessProxy = runtime.HarnessEgress{
			Port:       ack.EffectiveConfig.EgressProxyPort,
			Executable: ack.EffectiveConfig.EgressProxyExecutable,
		}
		logger.Info("attached to agentweave-harness", "mode", ack.Mode, "proto", ack.Proto,
			"local_enforcement", !harnessEnforcing, "egress_proxy_port", harnessProxy.Port)
		_, _ = auditLog.Append("harness.attached", map[string]any{
			"mode": ack.Mode, "local_enforcement": !harnessEnforcing,
			"egress_proxy_port": harnessProxy.Port,
		})
		// Before the servant starts serving and before RegisterAll builds the
		// tool surface, per the wire contract; envFn and the tool deps both see
		// the folded settings from the first call they answer.
		runtime.ApplyEffectiveConfig(ack.EffectiveConfig, &cfg.EnforceHTTPS, deps.BaseDeps,
			guardrailPaths(cfg, devicePolicy), windows.NormalizePath, dsk.ShowSecurityBanner, logger)

		go servant.Serve(runCtx)
		servant.StartHeartbeat(runCtx, runtime.HeartbeatFromAck(ack))
		if names := installedCredentialNames(installedCreds); len(names) > 0 {
			_ = servant.PushCredentialEvent(wire.CredentialInstalled, names)
		}
	}

	// --- Device egress proxy ---
	// Registered before the executor's Restore defer so the deferred stack
	// unwinds in the right order: containment is undone first, then the egress
	// state it was layered over.
	egressSvc, cleanupEgress, suspendEgress, err := provisionEgress(
		runCtx,
		devicePolicy,
		auditLog,
		logger,
		harnessProxy,
	)
	if err != nil {
		return err
	}
	defer cleanupEgress()
	// The server's own reaching-out (Scrape) routes through whichever proxy
	// this session runs — harness-announced or local — so it is governed by
	// the same allowlist as everything else's. deps is the pointer the
	// middleware captured, and RegisterAll has not run yet.
	switch {
	case harnessProxy.Announced():
		deps.WithEgressProxy(fmt.Sprintf("127.0.0.1:%d", harnessProxy.Port))
	case egressSvc != nil:
		deps.WithEgressProxy(egressSvc.Addr())
	}

	executor := contain.NewKillExecutor(contain.KillExecutorDeps{
		Config:   runtime.KillPolicyConfig(devicePolicy),
		Actuator: actuator,
		Audit:    auditLog,
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
		// The egress firewall rules a harness egress_apply installed come out
		// on exit, in case the harness never sent an explicit egress_restore
		// (a crash, a lost channel). Run() is idempotent, so an explicit
		// restore already having fired makes this a no-op.
		defer func() { _ = egressRestore.Run() }()
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
			HMACKey:      []byte(os.Getenv(envNames.ApprovalKey())),
			Logger:       logger,
		})
		logger.Info("dual control enabled", "webhook", devicePolicy.Approvals.WebhookURL,
			"timeout", devicePolicy.Approvals.Timeout)
	}

	// Plan-and-apply. Wired after the kill switch so an apply can abandon its
	// remaining steps when containment trips; deps is a pointer the surface's
	// middleware already captured, so setting the planner now reaches the handlers.
	sessionPlanner := runtime.NewPlanner(engine, auditLog, runtime.InventoryRegistry{Inv: inv, Deps: deps},
		func() bool { tripped, _ := kill.Tripped(); return tripped }).
		WithReadRegister(deps)
	if approver != nil {
		sessionPlanner.WithApprovals(approver, sessionStamp, devicePolicy.Approvals.Timeout.Std())
	}
	deps.WithPlanner(sessionPlanner)

	// Kill triggers come from the policy's kill.triggers block. A trigger left off
	// is report-only: still detected and audited, but it contains nothing and the
	// server keeps serving. Transparency is never conditional on containment.
	triggers := devicePolicy.Kill.Triggers
	tripSentinel := runtime.TripFunc("sentinel", triggers.Sentinel, kill, auditLog, logger)
	tripPostureDrift := runtime.TripFunc("posture-drift", triggers.PostureDrift, kill, auditLog, logger)
	tripRugpull := runtime.TripFunc("rugpull", triggers.RugPull, kill, auditLog, logger)
	tripHeartbeat := runtime.TripFunc("heartbeat-gap", triggers.HeartbeatGap, kill, auditLog, logger)
	// A kill verdict needs no trigger switch: the rule that produced it said
	// `on_fail: kill` in this same policy, which is the operator arming it. Audit
	// mode still caps it to a warning, so the engine never reaches here under the
	// default.
	tripPolicy := runtime.TripFunc("devicePolicy", true, kill, auditLog, logger)

	// --- Layer 4d: rug-pull detector (baseline pinned after all AddTool) ---
	heartbeat := watch.NewHeartbeat(auditLog)
	rugpull := watch.NewRugPull(tripRugpull, auditLog)

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
			Headers:     telemetry.ParseHeaders(os.Getenv(envNames.OTLPHeaders())),
			ServiceName: ServerName,
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
	statusToken, err := runtime.ResolveStatusToken(devicePolicy.Transparency, logger)
	if err != nil {
		return fmt.Errorf("status token: %w", err)
	}

	// The evidence export destination, for the same reason: the sink is not used
	// until the seal fires from the audit-close defer, long after the scrub, so its
	// credentials are read into it here. A nil sink means export is off or could
	// not be configured — never a reason to fail the session.
	exportSink := runtime.ProvisionExport(devicePolicy, auditLog, logger)
	evidenceKeyFile := os.Getenv(envNames.EvidenceKeyFile())

	// Every environment secret has now been read into the component that needs it,
	// so clear them from the process environment before any tool can run. This is
	// the second half of the defence; see ScrubSecretEnv.
	runtime.ScrubSecretEnv(envNames, devicePolicy, logger)

	// Receiving middleware, outermost first, installed in one call so the order
	// below is the order that actually runs (see Surface.InstallReceiving).
	// Telemetry sits between audit and rug-pull: audit must see every request
	// first, and a span should cover the rug-pull and policy work that follows.
	// The policy engine is innermost, so nothing can route around it and the
	// audit and rug-pull layers still observe the requests it refuses.
	s.InstallReceiving(runtime.ReceivingChain(
		harnessEnforcing,
		auditLog.Middleware(),
		telemetryMiddleware,
		[]mcp.Middleware{
			rugpull.Middleware(),
			rugpull.PromptMiddleware(),
			rugpull.ResourceMiddleware(),
			rugpull.DiscoverMiddleware(),
		},
		enforce.Middleware(engine, enforce.EnforcerDeps{
			Audit:           auditLog,
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
	snapshot := runtime.SnapshotFn(startedAt, rugpull, heartbeat, auditLog, kill, egressSvc, devicePolicy.Egress,
		runtime.ExportStatus(devicePolicy.Transparency.Export, exportSink))
	if !harnessEnforcing {
		// Registered unconditionally within the local stack (present under any
		// persona).
		statusTool, statusHandler := status.StatusTool(holder.Get, snapshot, kill)
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
		baselineTools = append(surface.MCPTools(runCtx, inv), statusTool, killTool)
		baseHash := rugpull.SetBaseline(baselineTools)
		_, _ = auditLog.Append("tools.pinned", map[string]any{"hash": baseHash, "count": len(baselineTools)})

		basePrompts := surface.MCPPrompts(runCtx, inv)
		promptHash := rugpull.SetPromptBaseline(basePrompts)
		_, _ = auditLog.Append("prompts.pinned", map[string]any{"hash": promptHash, "count": len(basePrompts)})

		baseResources := surface.MCPResources(runCtx, inv)
		resourceHash := rugpull.SetResourceBaseline(baseResources)
		_, _ = auditLog.Append("resources.pinned", map[string]any{"hash": resourceHash, "count": len(baseResources)})

		// Protocol 2026-07-28 removed the initialize handshake and made server/discover
		// the canonical advertisement of capabilities and instructions, so it is pinned
		// too — otherwise a widened capability set or rewritten model instructions would
		// drift entirely unwatched.
		discoverHash := rugpull.SetDiscoverBaseline(s.Capabilities, s.Instructions)
		_, _ = auditLog.Append("discover.pinned", map[string]any{"hash": discoverHash})
	}

	// The engine can now resolve tools; from here every request is decided against
	// the manifest that is actually served.
	engine.SetIndex(runtime.NewToolIndex(runCtx, inv))

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
		verifiers = append(verifiers, runtime.RugpullVerifier(rugpull,
			func() []*mcp.Tool { return baselineTools }, tripRugpull))
	}
	watch.StartMonitor(runCtx, watch.MonitorConfig{
		Interval:         devicePolicy.InFlight.Interval.Std(),
		ControlDir:       devicePolicy.InFlight.ControlDir,
		SentinelToken:    runtime.SentinelToken(devicePolicy.InFlight.ControlDir, auditLog, logger),
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
			holder.Set(d)
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
			Token:    statusToken,
			Current:  holder.Get,
			Snapshot: snapshot,
			Kill:     kill,
			Logger:   logger,
		}
		if err := ss.Start(runCtx); err != nil {
			logger.Warn("guardrails status endpoint disabled", "error", err)
		}
	}

	logger.Info("starting windows-mcp-server over stdio",
		"version", cfg.Version,
		"enabled_toolsets", enabledToolsetIDs,
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
		if b, mErr := json.Marshal(snapshot()); mErr == nil {
			posture = b
		}
		plans := sessionPlanner.StoredPlans()
		sealAtExit = func() {
			runtime.AutoSealEvidence(devicePolicy.Transparency, sessionStamp, plans, posture, exportSink,
				evidenceKeyFile, logger)
		}
	}

	if tripped, reason := kill.Tripped(); tripped {
		logger.Error("session terminated by kill switch", "reason", reason)
		return fmt.Errorf("%w: %s", ErrKilled, reason)
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

// newSurface is the one constructor for the protocol-facing server. RunStdio,
// CaptureSurface and the conformance host all go through it, so the surface
// the official suite is measured against is the surface the binary serves.
func newSurface(
	cfg Config,
	inv *inventory.Inventory,
	personaInstructions string,
	deps *windows.BaseDeps,
) *surface.Surface {
	return surface.New(
		surface.Config{Name: ServerName, Title: ServerTitle, Version: cfg.Version},
		inv, personaInstructions, deps,
		surface.CompletionHandlerFor(inv, surface.CompletionSources{
			PersonaIDs: windows.PersonaIDs(),
			CommonApps: commonApps,
		}),
	)
}

// commonApps are frequently automated Windows applications, offered as launch
// suggestions. Deliberately a short curated list rather than an enumeration of
// installed software, which would be slow and leak the machine's inventory.
var commonApps = []string{
	"chrome", "explorer", "msedge", "mspaint", "notepad",
	"outlook", "powershell", "taskmgr", "winword", "wt",
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
			return nil, "", fmt.Errorf("%w: %q", ErrUnknownPersona, cfg.Persona)
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
		toolsets = runtime.WithToolset(toolsets, string(windows.ToolsetCredentials.ID))
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

// CaptureSurface assembles the tool manifest this configuration would serve,
// runs a real in-process MCP session against it over an in-memory transport,
// and returns the wire objects a client actually receives.
//
// No desktop engine is created. tools/list never invokes a tool handler, so the
// dependency-injection middleware is wired with a nil engine; a handler call
// here would be a bug, not a supported path.
func CaptureSurface(ctx context.Context, cfg Config) (surface.Captured, error) {
	return captureSurfaceWithProbes(ctx, cfg, nil)
}

func captureSurfaceWithProbes(ctx context.Context, cfg Config, probe surface.ProbeFunc) (surface.Captured, error) {
	logger := slog.New(slog.DiscardHandler)
	inv, personaInstructions, err := buildInventory(cfg, false)
	if err != nil {
		return surface.Captured{}, fmt.Errorf("build inventory: %w", err)
	}
	deps := windows.NewBaseDeps(nil, logger, nil)
	s := newSurface(cfg, inv, personaInstructions, deps)
	s.InstallReceiving()
	got, err := surface.CaptureWithProbes(ctx, s, inv, deps, cfg.Version, probe)
	if err != nil {
		return surface.Captured{}, fmt.Errorf("capture surface: %w", err)
	}
	return got, nil
}
