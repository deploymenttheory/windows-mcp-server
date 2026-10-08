//go:build windows && (amd64 || arm64)

package winmcp

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/deploymenttheory/agentweave-harness/guardrails/audit"
	"github.com/deploymenttheory/agentweave-harness/guardrails/egress"
	"github.com/deploymenttheory/agentweave-harness/guardrails/policy"
	"github.com/deploymenttheory/mcp-server-core/runtime"
)

// newEnforcer is the one place the platform firewall enforcer is constructed,
// so every path — local egress, delegated egress, the harness rungs — gets
// the same Windows Firewall / WinINET implementation. A fresh value each time:
// its recovery state lives on disk, not in a shared object.
func newEnforcer(logger *slog.Logger) egress.WindowsEnforcer {
	return egress.WindowsEnforcer{Logger: logger}
}

// provisionEgress is the core provisioning with the Windows enforcer plugged
// in. When the harness announced a proxy, the local listener is skipped — that
// is the only thing skipped. Recovery still runs (rules outlive processes),
// the elevation refusal still applies, and OS enforcement still installs,
// pointed at the harness's port with the allow rule naming the harness
// executable.
func provisionEgress(
	ctx context.Context,
	devicePolicy *policy.Policy,
	auditLog *audit.AuditLog,
	logger *slog.Logger,
	harnessProxy runtime.HarnessEgress,
) (*egress.Service, func(), func(), error) {
	svc, cleanup, suspend, err := runtime.ProvisionEgress(
		ctx,
		devicePolicy,
		auditLog,
		logger,
		harnessProxy,
		newEnforcer(logger),
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("egress: %w", err)
	}
	return svc, cleanup, suspend, nil
}
