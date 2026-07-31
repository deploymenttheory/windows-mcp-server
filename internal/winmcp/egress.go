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
) (*egress.Service, func(), error) {
	noop := func() {}
	cfg := devicePolicy.Egress
	if !cfg.Enabled {
		return nil, noop, nil
	}

	allow, err := hostmatch.Compile(cfg.Allow)
	if err != nil {
		// Validation already rejected this at load; reaching here means a Config
		// was built by hand, so fail rather than serve an allowlist that did not
		// compile.
		return nil, noop, fmt.Errorf("egress allowlist: %w", err)
	}

	var token string
	if cfg.AuthTokenEnv != "" {
		token = os.Getenv(cfg.AuthTokenEnv)
		if token == "" {
			logger.Warn("egress auth_token_env names an empty variable; the proxy will not require a credential",
				"variable", cfg.AuthTokenEnv)
		}
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
		return nil, noop, fmt.Errorf("start egress proxy: %w", err)
	}

	_, _ = auditLog.Append("egress.start", map[string]any{
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
			counters := svc.Counters()
			_, _ = auditLog.Append("egress.stop", map[string]any{
				"counters":     counters,
				"denied_hosts": svc.DeniedHosts(),
			})
		})
	}
	return svc, cleanup, nil
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
