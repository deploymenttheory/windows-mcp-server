package guardrails

import (
	"context"
	"log/slog"
	"strings"
)

// Mode controls how guardrail failures are treated.
type Mode string

const (
	// ModeOff disables guardrails entirely.
	ModeOff Mode = "off"
	// ModeAudit evaluates and logs but never blocks (rollout / observation).
	ModeAudit Mode = "audit"
	// ModeEnforce refuses to serve when a required guardrail fails (fail-closed).
	ModeEnforce Mode = "enforce"
)

// ParseMode parses a mode string, defaulting to off.
func ParseMode(s string) Mode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "audit":
		return ModeAudit
	case "enforce":
		return ModeEnforce
	default:
		return ModeOff
	}
}

// Config selects and configures the guardrail run.
type Config struct {
	Mode       Mode
	Enterprise bool     // enable the --enterprise-guardrails preset
	Extra      []string // additional guardrails: "id" or "id=arg"
	Bypass     bool     // break-glass: skip checks (logged)
	BypassNote string
}

// Active reports whether guardrails run at all.
func (c Config) Active() bool { return c.Mode != ModeOff }

// Runner is the policy decision point: it evaluates the selected guardrails
// into a Decision.
type Runner struct {
	reg     *Registry
	cfg     Config
	logger  *slog.Logger
	unknown []string
}

// NewRunner builds a Runner and records any unrecognized guardrail ids.
func NewRunner(reg *Registry, cfg Config, logger *slog.Logger) *Runner {
	_, unknown := reg.Select(cfg)
	if logger == nil {
		logger = slog.Default()
	}
	return &Runner{reg: reg, cfg: cfg, logger: logger, unknown: unknown}
}

// Mode returns the configured mode.
func (r *Runner) Mode() Mode { return r.cfg.Mode }

// Unknown returns guardrail ids that were requested but not registered.
func (r *Runner) Unknown() []string { return r.unknown }

// Evaluate runs the selected guardrails against env and returns the Decision.
func (r *Runner) Evaluate(ctx context.Context, env *Env) Decision {
	d := Decision{
		Mode:       string(r.cfg.Mode),
		RunContext: env.Sys.RunContext(),
		Device:     env.Sys.DeviceIdentity(),
		Admit:      true,
	}
	if r.cfg.Bypass {
		d.Results = append(d.Results, Result{
			ID: "bypass", Status: Skip,
			Detail: "guardrails bypassed (break-glass): " + r.cfg.BypassNote,
		})
		return d // admit stays true; the caller logs the bypass prominently
	}
	selected, _ := r.reg.Select(r.cfg)
	for _, s := range selected {
		e := *env
		e.Arg = s.arg
		res := s.g.Check(ctx, &e)
		d.Results = append(d.Results, res)
		if res.Status == Fail || res.Status == Error {
			d.Admit = false
			d.Reasons = append(d.Reasons, s.g.ID+": "+res.Detail)
		}
	}
	return d
}

// Blocks reports whether serving should be refused for this decision: enforce
// mode and not admitted. Audit and off never block.
func (r *Runner) Blocks(d Decision) bool {
	return r.cfg.Mode == ModeEnforce && !d.Admit
}
