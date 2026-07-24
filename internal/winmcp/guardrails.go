//go:build windows && (amd64 || arm64)

package winmcp

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/deploymenttheory/windows-mcp-server/internal/desktop"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails"
)

// systemProbe adapts the desktop engine to guardrails.SystemProbe. A fresh probe
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
			m := guardrails.ParseDsreg(res.Output)
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

func (p *systemProbe) DomainSKU() (guardrails.DomainSKU, error) {
	p.load()
	return guardrails.DomainSKU{
		PartOfDomain: p.facts.PartOfDomain,
		Domain:       p.facts.Domain,
		OSSKU:        p.facts.OSSKU,
		OSCaption:    p.facts.OSCaption,
	}, nil
}

func (p *systemProbe) RunContext() guardrails.RunContext { return guardrails.DetectRunContext() }

func (p *systemProbe) DeviceIdentity() guardrails.DeviceIdentity {
	p.load()
	return guardrails.DeviceIdentity{
		Hostname:      p.facts.Hostname,
		Serial:        p.facts.Serial,
		EntraDeviceID: p.entraID,
		TenantID:      p.tenantID,
	}
}

// guardrailEnv builds a fresh evaluation environment. The same systemProbe backs
// both the SystemProbe and HealthProbe surfaces (it reads live OS/hardware state
// on every call), so posture is measured just-in-time on each evaluation.
func guardrailEnv(dsk *desktop.Desktop, logger *slog.Logger) *guardrails.Env {
	p := &systemProbe{dsk: dsk}
	return &guardrails.Env{Sys: p, Health: p, Logger: logger}
}

// newGuardrailRegistry builds the guardrail registry: tier-1 local checks, the
// JIT at-source device-posture checks, and (when configured) the authoritative
// tier-2 Graph and remote-policy providers.
func newGuardrailRegistry(cfg Config, logger *slog.Logger) *guardrails.Registry {
	reg := guardrails.NewRegistry()
	guardrails.RegisterBuiltins(reg)
	guardrails.RegisterHealth(reg) // JIT at-source device-posture checks
	if gc := (guardrails.GraphConfig{TenantID: cfg.GraphTenant, ClientID: cfg.GraphClientID, ClientSecret: cfg.GraphClientSecret}); gc.Configured() {
		guardrails.RegisterGraph(reg, guardrails.NewGraphClient(gc))
		if logger != nil {
			logger.Info("authoritative Graph guardrails enabled (Entra + Intune compliance)")
		}
	}
	if cfg.RemotePolicyToken != "" {
		guardrails.RegisterRemotePolicy(reg, cfg.RemotePolicyToken)
	}
	return reg
}

// guardrailConfig maps the server Config to a guardrails.Config.
func guardrailConfig(cfg Config) guardrails.Config {
	mode := guardrails.ParseMode(cfg.Guardrails)
	if cfg.EnterpriseGuardrails && mode == guardrails.ModeOff {
		mode = guardrails.ModeEnforce
	}
	return guardrails.Config{
		Mode:       mode,
		Enterprise: cfg.EnterpriseGuardrails,
		Extra:      cfg.Guardrail,
		Bypass:     cfg.GuardrailsBypass,
		BypassNote: "operator --guardrails-bypass",
	}
}

// decisionHolder stores the latest decision for the status surface.
type decisionHolder struct {
	mu sync.Mutex
	d  guardrails.Decision
}

func (h *decisionHolder) set(d guardrails.Decision) { h.mu.Lock(); h.d = d; h.mu.Unlock() }
func (h *decisionHolder) get() guardrails.Decision  { h.mu.Lock(); defer h.mu.Unlock(); return h.d }

// nonAutomationToolsets is the toolset set permitted when the server runs in
// SYSTEM context (Session 0 cannot drive the interactive desktop).
var nonAutomationToolsets = []string{"system", "shell", "filesystem", "diagnostics", "web"}
