//go:build windows && (amd64 || arm64)

package winmcp

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/windows-mcp-server/internal/desktop"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails"
	"github.com/deploymenttheory/windows-mcp-server/pkg/inventory"
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

func (p *systemProbe) IsAdmin() bool { return guardrails.CurrentUserIsAdmin() }

func (p *systemProbe) DeviceIdentity() guardrails.DeviceIdentity {
	p.load()
	return guardrails.DeviceIdentity{
		Hostname:      p.facts.Hostname,
		Serial:        p.facts.Serial,
		EntraDeviceID: p.entraID,
		TenantID:      p.tenantID,
	}
}

// loadPolicy resolves the active device policy.
//
// With no --policy-config the embedded default applies: the engine is present,
// every declared signal is evaluated and every verdict recorded, but nothing is
// refused. That is deliberate — an engine that arrived enforcing would start
// refusing tool calls on devices that worked the day before, with no operator
// action and no document to point at.
//
// A named policy that fails to load is fatal. Falling back to the default would
// silently run a device under weaker policy than its operator wrote, which is the
// worst of the available outcomes.
func loadPolicy(cfg Config, reg *guardrails.Registry, logger *slog.Logger) (*guardrails.Policy, error) {
	if cfg.PolicyConfig == "" {
		logger.Info("device policy: built-in default (audit only, nothing refused)")
		return guardrails.DefaultPolicy(), nil
	}
	policy, err := guardrails.LoadPolicy(cfg.PolicyConfig, reg.IDs())
	if err != nil {
		return nil, fmt.Errorf("device policy: %w", err)
	}
	logger.Info("device policy loaded",
		"path", cfg.PolicyConfig,
		"mode", string(policy.Mode),
		"signals", policy.SignalIDs(),
		"rules", len(policy.Rules),
	)
	return policy, nil
}

// killPolicyConfig maps the policy's containment actions to the executor's config.
func killPolicyConfig(policy *guardrails.Policy) guardrails.KillActionConfig {
	a := policy.Kill.Actions
	return guardrails.KillActionConfig{
		Isolate:       a.Isolate,
		KillProcs:     len(a.KillProcs) > 0,
		ProcNames:     a.KillProcs,
		Lock:          a.Lock,
		Shutdown:      a.Shutdown,
		ShutdownDelay: a.ShutdownDelay.Std(),
	}
}

// toolIndex adapts the served inventory to guardrails.ToolIndex, so policy rules
// can match on the toolset and annotations a tool actually carries.
//
// It is a snapshot taken once the manifest is assembled, not a live view: the
// manifest cannot change while the process runs — the rug-pull detector trips the
// kill switch if it does — so a snapshot is accurate, and it keeps the lookup a
// map read on the request path rather than a filter pass over every tool.
type toolIndex map[string]guardrails.ToolFacts

func (i toolIndex) Lookup(tool string) (guardrails.ToolFacts, bool) {
	facts, ok := i[tool]
	return facts, ok
}

// newToolIndex builds the index from the assembled inventory.
func newToolIndex(ctx context.Context, inv *inventory.Inventory) toolIndex {
	tools := inv.AvailableTools(ctx)
	index := make(toolIndex, len(tools))
	for i := range tools {
		st := &tools[i]
		facts := guardrails.ToolFacts{
			Name:    st.Tool.Name,
			Toolset: string(st.Toolset.ID),
		}
		// A tool with no annotations is treated as neither read-only nor
		// destructive: it then matches only the broad rules, which is the safe
		// reading of "the manifest does not say".
		if a := st.Tool.Annotations; a != nil {
			facts.ReadOnly = a.ReadOnlyHint
			facts.OpenWorld = a.OpenWorldHint != nil && *a.OpenWorldHint
			facts.Destructive = a.DestructiveHint != nil && *a.DestructiveHint
		}
		index[st.Tool.Name] = facts
	}
	return index
}

// guardrailEnv builds a fresh evaluation environment. The same systemProbe backs
// both the SystemProbe and HealthProbe surfaces (it reads live OS/hardware state
// on every call), so posture is measured just-in-time on each evaluation.
func guardrailEnv(cfg Config, dsk *desktop.Desktop, logger *slog.Logger) *guardrails.Env {
	p := &systemProbe{dsk: dsk}
	return &guardrails.Env{Sys: p, Health: p, Logger: logger, EnforceHTTPS: enforceHTTPS(cfg)}
}

// enforceHTTPS resolves the Enforce HTTPS setting. --security force-enables it,
// matching how the master switch force-enables the transparency services.
func enforceHTTPS(cfg Config) bool { return cfg.EnforceHTTPS || cfg.Security }

// newGuardrailRegistry builds the guardrail registry: tier-1 local checks, the
// JIT at-source device-posture checks, and (when configured) the authoritative
// tier-2 Graph and remote-policy providers.
func newGuardrailRegistry(cfg Config, logger *slog.Logger) *guardrails.Registry {
	reg := guardrails.NewRegistry()
	guardrails.RegisterBuiltins(reg)
	guardrails.RegisterHealth(reg) // JIT at-source device-posture checks
	// Tier-2 (Graph / remote may-run PDP) is SET ASIDE: only wired when the
	// operator explicitly opts in, which the four-layer core never does.
	if cfg.EnableTier2 {
		if gc := (guardrails.GraphConfig{TenantID: cfg.GraphTenant, ClientID: cfg.GraphClientID, ClientSecret: cfg.GraphClientSecret}); gc.Configured() {
			guardrails.RegisterGraph(reg, guardrails.NewGraphClient(gc))
			if logger != nil {
				logger.Info("authoritative Graph guardrails enabled (Entra + Intune compliance)")
			}
		}
		if cfg.RemotePolicyToken != "" {
			guardrails.RegisterRemotePolicy(reg, cfg.RemotePolicyToken)
		}
	}
	return reg
}

// preflightExtras maps the Layer-1 With* flags to guardrail selection specs.
func preflightExtras(cfg Config) []string {
	extra := append([]string(nil), cfg.Guardrail...)
	if cfg.WithMDM {
		extra = append(extra, "mdm-enrolled")
	}
	if cfg.WithUserContext {
		extra = append(extra, "run-context")
	}
	if cfg.IsNotAdmin {
		extra = append(extra, "not-admin")
	}
	if cfg.WithLoggedOnAccount != "" {
		extra = append(extra, "logged-on-account="+cfg.WithLoggedOnAccount)
	}
	return extra
}

// effectiveMode resolves the guardrail mode. --security and any explicit
// pre-flight check imply enforce (the whole point is to gate); otherwise the
// mode comes from --guardrails (with the legacy enterprise alias).
func effectiveMode(cfg Config) guardrails.Mode {
	mode := guardrails.ParseMode(cfg.Guardrails)
	preflightSet := cfg.WithMDM || cfg.WithUserContext || cfg.IsNotAdmin || cfg.WithLoggedOnAccount != ""
	if (cfg.Security || cfg.EnterpriseGuardrails || preflightSet) && mode == guardrails.ModeOff {
		mode = guardrails.ModeEnforce
	}
	return mode
}

// guardrailConfig maps the server Config to a guardrails.Config.
func guardrailConfig(cfg Config) guardrails.Config {
	return guardrails.Config{
		Mode:       effectiveMode(cfg),
		Enterprise: cfg.EnterpriseGuardrails,
		Extra:      preflightExtras(cfg),
		Bypass:     cfg.GuardrailsBypass,
		BypassNote: "operator --guardrails-bypass",
	}
}

// killActionConfig maps the Config kill-action flags to the executor config.
// The default (kill switch armed with no explicit actions) is isolate + abort,
// which the --kill-action-isolate flag defaults to true.
func killActionConfig(cfg Config) guardrails.KillActionConfig {
	return guardrails.KillActionConfig{
		Isolate:       cfg.KillActionIsolate,
		KillProcs:     cfg.KillActionKillProcs,
		Lock:          cfg.KillActionLock,
		Shutdown:      cfg.KillActionShutdown,
		ProcNames:     cfg.KillActionProcNames,
		ShutdownDelay: cfg.KillActionShutdownDelay,
	}
}

// tripFunc returns the trip function for one kill trigger. When the kill switch
// is armed (--with-kill-switch) and this trigger is enabled (--kill-on-<trigger>),
// it is the switch's Trip, which runs the full containment ladder. Otherwise it is
// report-only: the event is still audited and logged, because Layer 4 transparency
// must not be conditional on containment — the operator sees that a trigger fired
// even when they chose not to act on it.
func tripFunc(
	trigger string,
	armed bool,
	kill *guardrails.KillSwitch,
	audit *guardrails.AuditLog,
	logger *slog.Logger,
) func(string) {
	if armed {
		return kill.Trip
	}
	return func(reason string) {
		if audit != nil {
			_, _ = audit.Append("killswitch.disarmed", map[string]any{
				"trigger": trigger,
				"reason":  reason,
			})
		}
		if logger != nil {
			logger.Warn("kill trigger fired but is disarmed; not containing",
				"trigger", trigger,
				"reason", reason,
				"enable_with", "--with-kill-switch",
			)
		}
	}
}

// pinnedCapabilities declares every server capability explicitly.
//
// This must stay explicit. The SDK *infers* capabilities it finds unset:
// registering a prompt or resource makes Server.capabilities() fill in
// Prompts/Resources with ListChanged: true. That would re-open exactly the silent
// re-advertisement channel the tools capability was pinned to close — a mutated
// manifest could be pushed to the client without the client re-listing, which is
// what rug-pull detection exists to catch. Any non-nil field we set wins over
// inference, so pinning each one with ListChanged false keeps the manifest static
// and drift detectable.
//
// Two fields are deliberately left unset. Extensions (added in 2026-07-28) stays
// absent because this server implements no protocol extension — declaring one it
// does not honour would be a false advertisement, and the rug-pull discover
// baseline trips if a future SDK starts populating it. Logging stays absent
// because SEP-2577 deprecated the feature and this server logs to stderr or a
// file, never as MCP notifications.
func pinnedCapabilities() *mcp.ServerCapabilities {
	return &mcp.ServerCapabilities{
		Tools:       &mcp.ToolCapabilities{},
		Prompts:     &mcp.PromptCapabilities{},
		Resources:   &mcp.ResourceCapabilities{},
		Completions: &mcp.CompletionCapabilities{},
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
