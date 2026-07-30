// Package guardrails is an admission-control and runtime-policy framework for
// the Windows MCP server. It follows a policy-decision-point / policy-
// enforcement-point (PDP/PEP) split: a Runner evaluates pluggable guardrails
// into a single Decision document, and enforcement points (startup gate,
// tool-call middleware, periodic monitor) act on it. This core is
// platform-agnostic and unit-testable; Windows-specific checks reach the OS
// through the SystemProbe interface.
package guardrails

import (
	"context"
	"log/slog"
)

// Status is the outcome of a single guardrail check.
type Status string

const (
	Pass  Status = "pass"
	Fail  Status = "fail"
	Error Status = "error"
	Skip  Status = "skip"
)

// Result is one guardrail's evaluation.
type Result struct {
	ID     string         `json:"id"`
	Status Status         `json:"status"`
	Detail string         `json:"detail,omitempty"`
	Data   map[string]any `json:"data,omitempty"`
}

// pass/fail/skip/errf are small constructors for check functions.
func pass(id, detail string) Result { return Result{ID: id, Status: Pass, Detail: detail} }
func fail(id, detail string) Result { return Result{ID: id, Status: Fail, Detail: detail} }
func skip(id, detail string) Result { return Result{ID: id, Status: Skip, Detail: detail} }
func errf(id, detail string) Result { return Result{ID: id, Status: Error, Detail: detail} }

// RunContext describes the server process's Windows security context.
type RunContext struct {
	IsSystem  bool   `json:"is_system"`
	SessionID uint32 `json:"session_id"`
	Elevated  bool   `json:"elevated"`
	User      string `json:"user,omitempty"`
}

// IsInteractiveUser reports whether the process runs as a normal user in an
// interactive session (not SYSTEM, not Session 0) — the only context in which
// desktop automation works.
func (r RunContext) IsInteractiveUser() bool { return !r.IsSystem && r.SessionID != 0 }

// DeviceIdentity identifies the host for the decision document / may-run request.
type DeviceIdentity struct {
	Hostname      string `json:"hostname,omitempty"`
	Serial        string `json:"serial,omitempty"`
	EntraDeviceID string `json:"entra_device_id,omitempty"`
	TenantID      string `json:"tenant_id,omitempty"`
}

// DomainSKU carries domain-join and OS-edition facts used by providers.
type DomainSKU struct {
	PartOfDomain bool
	Domain       string
	OSSKU        uint32
	OSCaption    string
}

// SystemProbe is the OS capability surface guardrail checks use. The Windows
// implementation wraps the desktop engine; tests supply a fake. Keeping checks
// behind this interface keeps the guardrails core cross-platform (CI-testable).
type SystemProbe interface {
	// RunShell runs a PowerShell command and returns combined output.
	RunShell(ctx context.Context, command string) (string, error)
	// DomainSKU returns domain-join and OS-SKU facts (via WMI).
	DomainSKU() (DomainSKU, error)
	// RunContext returns the process security context.
	RunContext() RunContext
	// DeviceIdentity returns host identity facts.
	DeviceIdentity() DeviceIdentity
	// IsAdmin reports whether the interactive user is a member of the local
	// Administrators group (distinct from RunContext.Elevated, which is whether
	// the process currently holds an elevated token).
	IsAdmin() bool
}

// Env is passed to each guardrail check.
type Env struct {
	Sys SystemProbe
	// Health reads live hardware/OS security posture directly from the source
	// (Secure Boot, TPM, VBS/HVCI, BitLocker, TPM attestation). It may be nil on
	// platforms/tests that do not supply it; health checks skip when so.
	Health HealthProbe
	Logger *slog.Logger
	// Arg is the optional argument supplied for this guardrail (e.g. an
	// allowlist path for device-allowlist, or a URL for remote-policy).
	Arg string
	// EnforceHTTPS mirrors the server's Enforce HTTPS setting. Checks that reach
	// the network must refuse a plaintext http:// endpoint when it is set.
	EnforceHTTPS bool
}

// CheckFunc evaluates a guardrail against the environment.
type CheckFunc func(ctx context.Context, env *Env) Result

// Guardrail is a named admission/posture check.
type Guardrail struct {
	ID          string
	Description string
	// Enterprise marks membership in the --enterprise-guardrails preset.
	Enterprise bool
	Check      CheckFunc
}
