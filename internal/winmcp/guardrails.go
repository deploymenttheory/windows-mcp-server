//go:build windows && (amd64 || arm64)

package winmcp

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/windows-mcp-server/internal/desktop"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/audit"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/contain"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/policy"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/signals"
	"github.com/deploymenttheory/windows-mcp-server/pkg/inventory"
)

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

// Load resolves the active device devicePolicy.
//
// With no --devicePolicy-config the embedded default applies: the engine is present,
// every declared signal is evaluated and every verdict recorded, but nothing is
// refused. That is deliberate — an engine that arrived enforcing would start
// refusing tool calls on devices that worked the day before, with no operator
// action and no document to point at.
//
// A named devicePolicy that fails to load is fatal. Falling back to the default would
// silently run a device under weaker devicePolicy than its operator wrote, which is the
// worst of the available outcomes.
func loadPolicy(cfg Config, reg *signals.Registry, logger *slog.Logger) (*policy.Policy, error) {
	if cfg.PolicyConfig == "" {
		logger.Info("device devicePolicy: built-in default (audit only, nothing refused)")
		return policy.Default(), nil
	}
	devicePolicy, err := policy.Load(cfg.PolicyConfig, reg.IDs())
	if err != nil {
		return nil, fmt.Errorf("device devicePolicy: %w", err)
	}
	logger.Info("device devicePolicy loaded",
		"path", cfg.PolicyConfig,
		"mode", string(devicePolicy.Mode),
		"signals", devicePolicy.SignalIDs(),
		"rules", len(devicePolicy.Rules),
	)
	return devicePolicy, nil
}

// killPolicyConfig maps the devicePolicy's containment actions to the executor's config.
func killPolicyConfig(devicePolicy *policy.Policy) contain.KillActionConfig {
	a := devicePolicy.Kill.Actions
	return contain.KillActionConfig{
		Isolate:       a.Isolate,
		KillProcs:     len(a.KillProcs) > 0,
		ProcNames:     a.KillProcs,
		Lock:          a.Lock,
		Shutdown:      a.Shutdown,
		ShutdownDelay: a.ShutdownDelay.Std(),
	}
}

// toolIndex adapts the served inventory to policy.ToolIndex, so devicePolicy rules
// can match on the toolset and annotations a tool actually carries.
//
// It is a snapshot taken once the manifest is assembled, not a live view: the
// manifest cannot change while the process runs — the rug-pull detector trips the
// kill switch if it does — so a snapshot is accurate, and it keeps the lookup a
// map read on the request path rather than a filter pass over every tool.
type toolIndex map[string]policy.ToolFacts

func (i toolIndex) Lookup(tool string) (policy.ToolFacts, bool) {
	facts, ok := i[tool]
	return facts, ok
}

// newToolIndex builds the index from the assembled inventory.
func newToolIndex(ctx context.Context, inv *inventory.Inventory) toolIndex {
	tools := inv.AvailableTools(ctx)
	index := make(toolIndex, len(tools))
	for i := range tools {
		st := &tools[i]
		facts := policy.ToolFacts{
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
func guardrailEnv(cfg Config, dsk *desktop.Desktop, logger *slog.Logger) *signals.Env {
	p := &systemProbe{dsk: dsk}
	return &signals.Env{Sys: p, Health: p, Logger: logger, EnforceHTTPS: enforceHTTPS(cfg)}
}

// enforceHTTPS resolves the Enforce HTTPS setting.
//
// The value lives on Config rather than being read from the devicePolicy at each call
// site because it has to reach the tool dependencies and the guardrail Env, and
// neither carries a devicePolicy. RunStdio copies it across immediately after loading,
// so the devicePolicy remains the only place an operator sets it.
func enforceHTTPS(cfg Config) bool { return cfg.EnforceHTTPS }

// Environment variables carrying the tier-2 credentials. They are read from the
// environment rather than from flags or the devicePolicy document because they are
// secrets: argv is world-readable, and a devicePolicy document is meant to be
// reviewable and checked in. This mirrors the credentials invariant — a secret
// may be used, but it is never written somewhere it can be read back.
const (
	envGraphTenant   = "WINDOWS_MCP_GRAPH_TENANT"
	envGraphClientID = "WINDOWS_MCP_GRAPH_CLIENT_ID"
	// These two are variable *names*, not values — which is the whole point of
	// reading them from the environment.
	envGraphClientSecret = "WINDOWS_MCP_GRAPH_CLIENT_SECRET" //nolint:gosec // an env var name, not a secret
	envRemotePolicyToken = "WINDOWS_MCP_REMOTE_POLICY_TOKEN" //nolint:gosec // an env var name, not a secret
)

// newGuardrailRegistry builds the signal registry: the tier-1 local checks, the
// just-in-time at-source device-posture checks, and — when the credentials are
// present in the environment — the authoritative tier-2 Graph and remote-devicePolicy
// providers.
//
// Registering a signal only makes it available for a devicePolicy to declare. Nothing
// here decides whether it is evaluated; that is the devicePolicy's job.
func newGuardrailRegistry(_ Config, logger *slog.Logger) *signals.Registry {
	reg := signals.NewRegistry()
	signals.RegisterBuiltins(reg)
	signals.RegisterHealth(reg) // JIT at-source device-posture checks

	gc := signals.GraphConfig{
		TenantID:     os.Getenv(envGraphTenant),
		ClientID:     os.Getenv(envGraphClientID),
		ClientSecret: os.Getenv(envGraphClientSecret),
	}
	if gc.Configured() {
		signals.RegisterGraph(reg, signals.NewGraphClient(gc))
		if logger != nil {
			logger.Info("tier-2 Graph signals available (Entra + Intune compliance)")
		}
	}
	if token := os.Getenv(envRemotePolicyToken); token != "" {
		signals.RegisterRemotePolicy(reg, token)
	}
	return reg
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
	kill *contain.KillSwitch,
	audit *audit.AuditLog,
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
	d  signals.Decision
}

func (h *decisionHolder) set(d signals.Decision) { h.mu.Lock(); h.d = d; h.mu.Unlock() }
func (h *decisionHolder) get() signals.Decision  { h.mu.Lock(); defer h.mu.Unlock(); return h.d }

// nonAutomationToolsets is the toolset set permitted when the server runs in
// SYSTEM context (Session 0 cannot drive the interactive desktop).
var nonAutomationToolsets = []string{"system", "shell", "filesystem", "diagnostics", "web"}
