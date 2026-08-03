//go:build windows && (amd64 || arm64)

package winmcp

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/audit"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/egress"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/hostmatch"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/policy"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/status"
)

// egressSummaryInterval is how often the running totals are folded into the
// audit chain. Per-request records are deliberately not written: the chain is
// hashed and fsynced, so a browser session would dominate it and a client
// rotating hostnames could drive its length.
const egressSummaryInterval = 5 * time.Minute

// provisionEgress starts the device egress proxy when the policy asks for it,
// and returns a cleanup that runs exactly once however the session ends.
//
// It mirrors provisionCredentials: two independent paths reach the teardown —
// the normal-exit defer and the kill executor's Finalize — and both must be safe
// to call, in either order.
func provisionEgress(
	ctx context.Context,
	devicePolicy *policy.Policy,
	auditLog *audit.AuditLog,
	logger *slog.Logger,
) (*egress.Service, func(), func(), error) {
	noop := func() {}
	cfg := devicePolicy.Egress
	enforcer := egress.WindowsEnforcer{Logger: logger}

	// Recovery runs even when egress is disabled now. Firewall rules outlive the
	// process that made them, so a session killed mid-run leaves an application
	// blocked with nothing left to proxy it — and a policy that has since turned
	// egress off would otherwise never clean that up.
	switch recovered, err := enforcer.Recover(); {
	case err != nil:
		logger.Warn("could not clean up egress rules from a previous session", "error", err)
	case recovered > 0:
		_, _ = auditLog.Append("egress.recovered", map[string]any{"rules": recovered})
	}

	if !cfg.Enabled {
		return nil, noop, noop, nil
	}

	allow, err := hostmatch.Compile(cfg.Allow)
	if err != nil {
		// Validation already rejected this at load; reaching here means a Config
		// was built by hand, so fail rather than serve an allowlist that did not
		// compile.
		return nil, noop, noop, fmt.Errorf("egress allowlist: %w", err)
	}

	var token string
	if cfg.AuthTokenEnv != "" {
		token = os.Getenv(cfg.AuthTokenEnv)
		if token == "" {
			logger.Warn("egress auth_token_env names an empty variable; the proxy will not require a credential",
				"variable", cfg.AuthTokenEnv)
		}
	}

	// Enforcement is refused rather than degraded when it cannot be performed.
	// The kill ladder degrades because refusing to contain mid-incident is
	// worse than containing partially; here the opposite holds — an operator
	// whose document says these applications cannot bypass the proxy must never
	// get a server where they silently can.
	wantsEnforcement := len(cfg.Applications) > 0 || cfg.BlockAllOutbound
	if wantsEnforcement && !enforcer.Elevated() {
		_, _ = auditLog.Append("egress.enforce.failed", map[string]any{
			"reason":      "not elevated",
			"enforcement": cfg.Enforcement(),
		})
		return nil, noop, noop, fmt.Errorf("%w: egress.applications and egress.block_all_outbound "+
			"install firewall rules, so the server must run elevated; "+
			"remove them to run the proxy in advisory mode", egress.ErrNotElevated)
	}

	svc, err := egress.Start(ctx, egress.Config{
		Listen:       cfg.Listen,
		Allow:        allow,
		AllowPorts:   cfg.AllowPorts,
		AllowPrivate: cfg.AllowPrivateNetworks,
		AuthToken:    token,
		Enforcement:  cfg.Enforcement(),
		Logger:       logger,
	})
	if err != nil {
		return nil, noop, noop, fmt.Errorf("start egress proxy: %w", err)
	}

	// Rules go in only once the proxy is actually listening: blocking an
	// application before there is anywhere for it to go would cut it off with
	// no route, which is the failure mode an operator would notice as "the
	// browser broke" rather than "policy applied".
	restoreRules, err := enforcer.Apply(egress.EnforceSpec{
		ProxyAddr:      svc.Addr(),
		Applications:   cfg.Applications,
		GlobalBlock:    cfg.BlockAllOutbound,
		AllowPorts:     cfg.AllowPorts,
		SetSystemProxy: cfg.SetSystemProxy,
	})
	if err != nil {
		svc.Stop()
		_, _ = auditLog.Append("egress.enforce.failed", map[string]any{"error": err.Error()})
		return nil, noop, noop, fmt.Errorf("apply egress enforcement: %w", err)
	}
	if wantsEnforcement {
		_, _ = auditLog.Append("egress.enforce.applied", map[string]any{
			"enforcement":  cfg.Enforcement(),
			"applications": len(cfg.Applications),
		})
	}

	_, _ = auditLog.Append("egress.started", map[string]any{
		"listen":         svc.Addr(),
		"enforcement":    cfg.Enforcement(),
		"allow_patterns": allow.Len(),
		"allow_ports":    cfg.AllowPorts,
		"allow_private":  cfg.AllowPrivateNetworks,
		"authenticated":  token != "",
	})

	// The proxy-only tier constrains whatever is configured to use the proxy and
	// nothing else. Saying so once, loudly, is the difference between an
	// operator who knows that and one who believes the device is contained.
	if cfg.Enforcement() == "proxy-only" {
		logger.Warn("egress proxy is advisory: no applications are blocked from bypassing it",
			"hint", "set egress.applications to enforce (requires elevation)")
	}

	summaryCtx, stopSummary := context.WithCancel(ctx)
	go summarizeEgress(summaryCtx, svc, auditLog)

	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			stopSummary()
			svc.Stop()
			// Rules come out after the listener closes, in the reverse of the
			// order they went in. An application unblocked while the proxy is
			// still up would have a moment of unfiltered egress.
			if err := restoreRules(); err != nil {
				// Worth shouting about: rules left installed outlive this
				// process, and the next start's Recover is what will clear them.
				logger.Error("could not remove egress firewall rules; they will be cleaned up on the next start",
					"error", err)
				_, _ = auditLog.Append("egress.enforce.failed",
					map[string]any{"phase": "restore", "error": err.Error()})
			}
			_, _ = auditLog.Append("egress.stopped", map[string]any{
				"counters":     svc.Counters(),
				"denied_hosts": svc.DeniedHosts(),
			})
		})
	}
	// suspend is the kill path's hook. It stops admitting traffic and disables
	// the allow rules that would otherwise survive containment, but restores
	// nothing: undoing state inside Finalize could countermand the isolation the
	// kill ladder has just applied. Full teardown stays with the exit defer.
	suspend := func() {
		svc.Stop()
		if err := enforcer.Suspend(); err != nil {
			logger.Error("could not disable egress allow rules for containment", "error", err)
		}
		_, _ = auditLog.Append("egress.suspended", map[string]any{"counters": svc.Counters()})
	}
	return svc, cleanup, suspend, nil
}

// summarizeEgress folds the running totals into the audit chain periodically, so
// the record shows what the proxy did without carrying one entry per request.
func summarizeEgress(ctx context.Context, svc *egress.Service, auditLog *audit.AuditLog) {
	ticker := time.NewTicker(egressSummaryInterval)
	defer ticker.Stop()
	var last egress.Counters
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current := svc.Counters()
			if current == last {
				continue // nothing happened; an unchanging chain entry says nothing
			}
			last = current
			_, _ = auditLog.Append("egress.summary", map[string]any{
				"counters":     current,
				"denied_hosts": svc.DeniedHosts(),
			})
		}
	}
}

// egressStatus adapts the service to the status snapshot. A nil service means
// egress is off, and the status field is omitted rather than reported as zero.
func egressStatus(svc *egress.Service, cfg policy.EgressPolicy) *status.EgressStatus {
	if svc == nil {
		return nil
	}
	c := svc.Counters()
	return &status.EgressStatus{
		Listen:        svc.Addr(),
		Enforcement:   cfg.Enforcement(),
		AllowPatterns: len(cfg.Allow),
		Allowed:       c.Allowed,
		Denied:        c.Denied(),
		DeniedHost:    c.DeniedHost,
		DeniedAddress: c.DeniedAddress,
	}
}
