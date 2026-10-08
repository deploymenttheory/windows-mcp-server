//go:build windows && (amd64 || arm64)

package winmcp

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/deploymenttheory/agentweave-harness/guardrails/contain"
	"github.com/deploymenttheory/agentweave-harness/guardrails/policy"
	"github.com/deploymenttheory/agentweave-harness/guardrails/signals"
	"github.com/deploymenttheory/mcp-server-core/runtime"
	"github.com/deploymenttheory/mcp-server-core/toolkit"
	"github.com/deploymenttheory/windows-mcp-server/internal/desktop"
	"github.com/deploymenttheory/windows-mcp-server/pkg/windows"
)

// EnvPrefix is the prefix of every environment variable this server reads.
const EnvPrefix = "WINDOWS_MCP_"

// envNames derives the secret-carrying variable names from the prefix. They
// are read from the environment rather than from flags or the policy document
// because they are secrets: argv is world-readable, and a policy document is
// meant to be reviewable and checked in.
var envNames = runtime.EnvNames{Prefix: EnvPrefix}

// systemProbe adapts the desktop engine to signals.SystemProbe. A fresh probe
// is created per evaluation so posture-drift re-checks see current WMI facts;
// within a single evaluation the WMI query is cached.
type systemProbe struct {
	dsk      *desktop.Desktop
	once     sync.Once
	facts    desktop.HostFacts
	entraID  string
	tenantID string
}

func (p *systemProbe) load() {
	p.once.Do(func() {
		p.facts, _ = p.dsk.DomainAndSKU()
		// Entra device ID + tenant from dsregcmd, for device-allowlist matching
		// and as the key for Graph compliance lookups.
		if res, err := p.dsk.RunPowerShell(context.Background(), "dsregcmd /status", 10*time.Second); err == nil {
			m := signals.ParseDsreg(res.Output)
			p.entraID = m["DeviceId"]
			p.tenantID = m["TenantId"]
		}
	})
}

func (p *systemProbe) RunShell(ctx context.Context, command string) (string, error) {
	res, err := p.dsk.RunPowerShell(ctx, command, 15*time.Second)
	if err != nil {
		return "", err
	}
	return res.Output, nil
}

func (p *systemProbe) DomainSKU() (signals.DomainSKU, error) {
	p.load()
	return signals.DomainSKU{
		PartOfDomain: p.facts.PartOfDomain,
		Domain:       p.facts.Domain,
		OSSKU:        p.facts.OSSKU,
		OSCaption:    p.facts.OSCaption,
	}, nil
}

func (p *systemProbe) RunContext() signals.RunContext { return signals.DetectRunContext() }

func (p *systemProbe) IsAdmin() bool { return contain.CurrentUserIsAdmin() }

func (p *systemProbe) DeviceIdentity() signals.DeviceIdentity {
	p.load()
	return signals.DeviceIdentity{
		Hostname:      p.facts.Hostname,
		Serial:        p.facts.Serial,
		EntraDeviceID: p.entraID,
		TenantID:      p.tenantID,
	}
}

// guardrailEnv builds a fresh evaluation environment. The same systemProbe backs
// both the SystemProbe and HealthProbe surfaces (it reads live OS/hardware state
// on every call), so posture is measured just-in-time on each evaluation.
//
// EnforceHTTPS lives on Config rather than being read from the policy at each
// call site because it has to reach the tool dependencies and the guardrail
// Env, and neither carries a policy. RunStdio copies it across immediately
// after loading, so the policy remains the only place an operator sets it.
func guardrailEnv(cfg Config, dsk *desktop.Desktop, logger *slog.Logger) *signals.Env {
	p := &systemProbe{dsk: dsk}
	return &signals.Env{Sys: p, Health: p, Logger: logger, EnforceHTTPS: cfg.EnforceHTTPS}
}

// guardrailPaths lists the guardrail files the FileSystem tool must not touch
// for this configuration, normalised the Windows way.
func guardrailPaths(cfg Config, p *policy.Policy) []toolkit.ProtectedPath {
	return runtime.GuardrailPaths(runtime.GuardrailPathsConfig{
		CredentialsFile: cfg.CredentialsFile,
		PolicyConfig:    cfg.PolicyConfig,
		Normalize:       windows.NormalizePath,
	}, p)
}

// nonAutomationToolsets is the toolset set permitted when the server runs in
// SYSTEM context (Session 0 cannot drive the interactive desktop).
var nonAutomationToolsets = []string{"system", "shell", "filesystem", "diagnostics", "web"}
