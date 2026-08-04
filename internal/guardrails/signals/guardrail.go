// Package signals is the device-signal vocabulary and catalogue: what a signal
// is, how one is evaluated, and the checks this build knows how to run.
//
// It is the bottom of the guardrails stack and imports nothing else from it.
// Everything here is platform-agnostic behind the SystemProbe and HealthProbe
// interfaces, with the Windows implementations supplied by internal/winmcp, so
// the catalogue is unit-testable without a Windows host — and, unlike every
// other package here, without the MCP SDK.
//
// Registering a signal only makes it available for a policy to declare. Whether
// it is ever evaluated is the policy's decision, not this package's.
package signals

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
	// TokenUnread reports that the process token could not be read, so IsSystem
	// and Elevated are zero values rather than answers.
	//
	// Without this the two are indistinguishable: a failed OpenProcessToken left
	// IsSystem false, and IsInteractiveUser was then true for any session but 0 —
	// so an error reading the token produced a pass on the one signal the shipped
	// default policy requires. The engine already scores an errored signal at the
	// rule's full severity; this lets the check report the error it had.
	TokenUnread bool `json:"token_unread,omitempty"`
}

// IsInteractiveUser reports whether the process runs as a normal user in an
// interactive session (not SYSTEM, not Session 0) — the only context in which
// desktop automation works.
//
// False when the token could not be read: "we could not tell" is not "yes".
func (r RunContext) IsInteractiveUser() bool {
	return !r.TokenUnread && !r.IsSystem && r.SessionID != 0
}

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
	Check       CheckFunc
}
