// Package policy is the decision point: the policy document, the signal cache,
// and the engine that turns a request into a verdict.
//
// It holds no MCP types and performs no enforcement. Given a subject and a set
// of signal readings it answers allow, warn, deny or kill, and that is all — the
// acting on it lives in package enforce, and the containment in package contain.
//
// Keeping the decision free of the SDK is what makes it testable against fake
// signals and a fake tool index, with no transport and no Windows host.
package policy

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/hostmatch"
)

// SchemaVersion is the only schema version this build understands.
//
// The document is version-tagged so an operator running an older server against a
// newer policy gets a refusal at load rather than silent partial enforcement: a
// rule this build cannot parse is a rule it cannot apply, and quietly ignoring it
// would mean serving under weaker policy than the file describes.
const SchemaVersion = 1

//go:embed policy_default.json
var defaultPolicyJSON []byte

// PolicyMode caps how severe a verdict may become.
type PolicyMode string

const (
	// ModeAuditOnly evaluates every signal and records every verdict, but caps
	// severity at SeverityWarn: nothing is refused and nothing is contained. This
	// is the shipped default, so adopting the engine cannot break a working
	// deployment before its policy has been written.
	ModeAuditOnly PolicyMode = "audit"
	// ModeEnforcing applies verdicts as written.
	ModeEnforcing PolicyMode = "enforce"
)

// clamp caps a severity according to the mode.
//
// Audit mode never exceeds SeverityWarn. Note that it caps rather than skips:
// the signals are still read and the verdict is still recorded, so an operator
// can see exactly what a policy would have refused before switching it on. A
// mode that skipped evaluation would report nothing and prove nothing.
func (m PolicyMode) clamp(s Severity) Severity {
	if m == ModeEnforcing || s < SeverityWarn {
		return s
	}
	return SeverityWarn
}

// Severity is what a failed requirement does to the request. The order is
// meaningful: a call's verdict is the highest severity among its failures.
type Severity int

const (
	// SeverityAllow is green: the failure is recorded and the call proceeds.
	SeverityAllow Severity = iota
	// SeverityWarn is amber: the call proceeds, the verdict is audited, and the
	// warning is attached to the result so the caller can see it.
	SeverityWarn
	// SeverityHold suspends the call on an out-of-band human decision: the
	// enforcement point holds it, asks the configured approvals webhook, and
	// proceeds only if the request comes back approved. A timeout denies. It sits
	// between warn and deny — stronger than a warning the model can ignore, weaker
	// than an outright refusal, because a person can still let it through. The word
	// names what happens to the call (it is held); the webhook that resolves it is
	// still an approval (a person approves or denies the held call).
	SeverityHold
	// SeverityDeny is red: this call is refused. Nothing latches — the next call
	// is evaluated afresh, so a signal that recovers restores service without a
	// restart.
	SeverityDeny
	// SeverityKill is the out-of-bounds case: the device should not be running
	// this session at all. The kill switch trips and the containment ladder runs.
	SeverityKill
)

var severityNames = map[Severity]string{
	SeverityAllow: "allow",
	SeverityWarn:  "warn",
	SeverityHold:  "hold",
	SeverityDeny:  "deny",
	SeverityKill:  "kill",
}

func (s Severity) String() string {
	if name, ok := severityNames[s]; ok {
		return name
	}
	return fmt.Sprintf("severity(%d)", int(s))
}

// MarshalJSON renders the severity by name, so a decision document is readable.
func (s Severity) MarshalJSON() ([]byte, error) {
	name, ok := severityNames[s]
	if !ok {
		return nil, fmt.Errorf("%w: %d", ErrUnknownSeverity, int(s))
	}
	raw, err := json.Marshal(name)
	if err != nil {
		return nil, fmt.Errorf("marshal severity: %w", err)
	}
	return raw, nil
}

func (s *Severity) UnmarshalJSON(raw []byte) error {
	var name string
	if err := json.Unmarshal(raw, &name); err != nil {
		return fmt.Errorf("severity must be a string: %w", err)
	}
	for sev, n := range severityNames {
		if n == strings.ToLower(strings.TrimSpace(name)) {
			*s = sev
			return nil
		}
	}
	return fmt.Errorf("%w: %q (want allow, warn, hold, deny or kill)", ErrUnknownSeverity, name)
}

// Errors surfaced by loading and validation. They are distinct values so the
// `policy validate` command can report a precise cause rather than a string.
var (
	ErrUnknownSeverity  = errors.New("unknown severity")
	ErrPolicyVersion    = errors.New("unsupported policy version")
	ErrUnknownMode      = errors.New("unknown policy mode")
	ErrUnknownSignal    = errors.New("unknown signal")
	ErrUndeclaredSignal = errors.New("rule requires a signal that is not declared")
	ErrEmptyMatch       = errors.New("rule matches nothing")
	ErrInvalidRateLimit = errors.New("invalid rate limit")
	ErrInvalidEgress      = errors.New("invalid egress policy")
	ErrInvalidAnchor      = errors.New("invalid anchor policy")
	ErrInvalidCredentials = errors.New("invalid credentials policy")
	ErrInvalidRequirePlan = errors.New("invalid require_plan selector")
	ErrInvalidTelemetry   = errors.New("invalid telemetry policy")
	ErrInvalidApprovals   = errors.New("invalid approvals policy")
	// ErrNotLoopback covers every address this server is willing to bind. Both
	// listeners it can stand up are loopback-only by design.
	ErrNotLoopback = errors.New("address is not loopback")
	// ErrInvalidPolicy wraps the collected validation problems, so a caller can
	// test for "the policy is bad" without matching on the rendered list.
	ErrInvalidPolicy = errors.New("invalid policy")
)

// Duration is a time.Duration written as a string ("60s", "5m") in JSON.
//
// encoding/json would otherwise demand an integer count of nanoseconds, which is
// unreadable in a document an operator is expected to review.
type Duration time.Duration

func (d Duration) String() string { return time.Duration(d).String() }

// Std returns the standard-library duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

func (d Duration) MarshalJSON() ([]byte, error) {
	raw, err := json.Marshal(time.Duration(d).String())
	if err != nil {
		return nil, fmt.Errorf("marshal duration: %w", err)
	}
	return raw, nil
}

func (d *Duration) UnmarshalJSON(raw []byte) error {
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return fmt.Errorf("duration must be a string like \"60s\": %w", err)
	}
	parsed, err := time.ParseDuration(strings.TrimSpace(text))
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", text, err)
	}
	*d = Duration(parsed)
	return nil
}

// StringSet accepts either a single string or an array of strings, so a match
// can be written `"toolset": "system"` or `"tool": ["PowerShell", "Registry"]`
// without the author having to remember which fields take a list.
type StringSet []string

func (s StringSet) MarshalJSON() ([]byte, error) {
	raw, err := json.Marshal([]string(s))
	if err != nil {
		return nil, fmt.Errorf("marshal string set: %w", err)
	}
	return raw, nil
}

func (s *StringSet) UnmarshalJSON(raw []byte) error {
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		*s = StringSet{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return fmt.Errorf("want a string or an array of strings: %w", err)
	}
	*s = many
	return nil
}

// Contains reports case-insensitive membership, treating "*" as matching anything.
func (s StringSet) Contains(v string) bool {
	for _, item := range s {
		if item == "*" || strings.EqualFold(item, v) {
			return true
		}
	}
	return false
}

// Policy is the whole configuration document.
type Policy struct {
	Version int        `json:"version"`
	Mode    PolicyMode `json:"mode"`
	// Signals declares which device signals this policy evaluates, and how long a
	// reading stays usable. A signal not declared here is never evaluated, however
	// many rules reference it — validation rejects that rather than silently
	// treating the requirement as satisfied.
	Signals map[string]SignalConfig `json:"signals"`
	Rules   []Rule                  `json:"rules"`
	// RateLimits replace the hardcoded sensitive-tool list: how often a matching
	// subject may be invoked before the limit's severity applies.
	RateLimits   []RateLimit        `json:"rate_limits,omitempty"`
	Kill         KillPolicy         `json:"kill"`
	Transparency TransparencyPolicy `json:"transparency"`
	InFlight     InFlightPolicy     `json:"inflight"`
	// EnforceHTTPS refuses plaintext http:// targets at the tool layer.
	EnforceHTTPS bool `json:"enforce_https"`
	// Egress declares the domains the device may reach, served by a loopback
	// proxy. Absent or disabled, the device's networking is untouched.
	Egress EgressPolicy `json:"egress,omitempty"`
	// Credentials governs how far installed credentials may be exposed to the rest
	// of the tool surface. Absent, the safe default applies (refuse the risky
	// exposures).
	Credentials CredentialsPolicy `json:"credentials,omitempty"`
	// RequirePlan lists selectors for tools that may only run inside an approved
	// plan. A direct call to a matching tool is refused; the same tool runs
	// normally as a step of a plan, because plan steps are executed by the planner
	// and do not pass through the enforcement gate. This is the preventive tier of
	// plan-and-apply: detective by default (a direct call is recorded), preventive
	// where an operator names the tools that must go through review.
	RequirePlan []Match `json:"require_plan,omitempty"`
	// Telemetry exports activity to an OpenTelemetry collector. Empty endpoint (the
	// default) disables it — nothing is exported and no exporter is constructed.
	Telemetry TelemetryPolicy `json:"telemetry,omitempty"`
	// Approvals configures the out-of-band authoriser for `on_fail: hold` rules.
	// A rule that uses that disposition without a webhook here is refused at load —
	// dual control that cannot ask anyone is not dual control.
	Approvals ApprovalsPolicy `json:"approvals,omitempty"`
}

// ApprovalsPolicy configures out-of-band human authorisation for rules whose
// on_fail is SeverityHold. The server holds no inbound listener — the
// stdio-only posture is inviolable — so authorisation is solicited outbound: the
// enforcement point POSTs the pending call to a webhook the operator runs and
// blocks on the answer.
type ApprovalsPolicy struct {
	// WebhookURL receives a POST describing each call awaiting approval and returns
	// the decision. Required when any rule uses `on_fail: hold`. The request is
	// signed with WINDOWS_MCP_APPROVAL_KEY (an environment secret, never this
	// document) so the webhook can authenticate it.
	WebhookURL string `json:"webhook_url,omitempty"`
	// Timeout bounds how long a call may block waiting for a decision. A call still
	// undecided at the deadline is denied — dual control fails closed. Empty means
	// DefaultApprovalTimeout.
	Timeout Duration `json:"timeout,omitempty"`
	// PollInterval is how often to re-poll the webhook while a decision is pending.
	// Empty means DefaultApprovalPoll.
	PollInterval Duration `json:"poll_interval,omitempty"`
}

// Defaults for an approvals block. Two minutes is long enough for a human to see
// a prompt and act, short enough that a wedged approver does not hang a session
// indefinitely; the poll interval keeps the outbound traffic modest.
const (
	DefaultApprovalTimeout = 2 * time.Minute
	DefaultApprovalPoll    = 5 * time.Second
)

// usesHold reports whether any call-scope rule disposes to SeverityHold.
func (p *Policy) usesHold() bool {
	for _, r := range p.Rules {
		if r.OnFail == SeverityHold && r.scope() == ScopeCall {
			return true
		}
	}
	return false
}

// TelemetryPolicy configures OTLP export. Off unless Endpoint is set.
type TelemetryPolicy struct {
	// Endpoint is the OTLP/HTTP collector: "host:4318" (plaintext) or a URL like
	// "https://collector:4318". Auth headers come from WINDOWS_MCP_OTLP_HEADERS,
	// not this document, because they are secrets.
	Endpoint string `json:"endpoint,omitempty"`
	// Protocol is "http" (the only one implemented); empty means http.
	Protocol string `json:"protocol,omitempty"`
	// SampleRatio is the trace sampling ratio in [0,1]; zero means sample all.
	SampleRatio float64 `json:"sample_ratio,omitempty"`
}

// CredentialsPolicy governs how far installed credentials may be exposed to the
// tool surface.
type CredentialsPolicy struct {
	// AcknowledgeToolsetExposure lists risky toolsets the operator accepts serving
	// alongside a --credentials-file. Installed generic credentials live in the
	// calling user's Credential Manager, so a toolset that can read that back —
	// "shell" (CredRead via PowerShell) or "filesystem" (a Credential Manager
	// backup is a file) — defeats the never-read guarantee. Naming one here lets a
	// server start with the exposure, recorded in the audit chain; leaving it out
	// makes that exposure refuse at startup. The only accepted values are
	// "shell" and "filesystem".
	AcknowledgeToolsetExposure StringSet `json:"acknowledge_toolset_exposure,omitempty"`
}

// SignalConfig is how one device signal is read.
type SignalConfig struct {
	// TTL is how long a reading stays usable. Zero means evaluate live on every
	// request — correct, and appropriate for cheap in-process signals, but on a
	// signal backed by dsregcmd, WMI or tpmtool it puts hundreds of milliseconds
	// on the critical path of every tool call.
	TTL Duration `json:"ttl"`
	// Arg is the signal's parameter, for the checks that take one (a path for
	// device-allowlist, a regex for logged-on-account, a URL for remote-policy).
	Arg string `json:"arg,omitempty"`
}

// Scope distinguishes when a rule is evaluated.
const (
	// ScopeCall is the default: evaluated on every MCP request the rule matches.
	ScopeCall = "call"
	// ScopeStartup is evaluated once, before the server serves anything.
	ScopeStartup = "startup"
)

// Match selects the requests a rule covers.
type Match struct {
	// Scope is "call" (default) or "startup".
	Scope string `json:"scope,omitempty"`
	// Tool matches by tool name.
	Tool StringSet `json:"tool,omitempty"`
	// Toolset matches by toolset id; "*" matches every tool.
	Toolset StringSet `json:"toolset,omitempty"`
	// Annotation matches by tool annotation: read-only, destructive, open-world.
	Annotation StringSet `json:"annotation,omitempty"`
}

// Tool annotation names a rule may match on.
const (
	AnnotationReadOnly    = "read-only"
	AnnotationDestructive = "destructive"
	AnnotationOpenWorld   = "open-world"
)

// Rule requires a set of signals to pass for the requests it matches.
type Rule struct {
	// Name is optional and used only in explain output and audit records. A rule
	// without one is identified by its index, which is worse to read in an
	// incident, so the shipped examples all name theirs.
	Name    string   `json:"name,omitempty"`
	Match   Match    `json:"match"`
	Require []string `json:"require"`
	OnFail  Severity `json:"on_fail"`
}

// scope returns the rule's scope, defaulting to call.
func (r Rule) scope() string {
	if r.Match.Scope == "" {
		return ScopeCall
	}
	return strings.ToLower(r.Match.Scope)
}

// specificity ranks how narrowly a rule selects, for the precedence order
// documented on Engine.Evaluate. Naming a tool is the narrowest statement an
// author can make and therefore wins; matching every toolset is the broadest.
func (r Rule) specificity() int {
	switch {
	case len(r.Match.Tool) > 0:
		return 3
	case len(r.Match.Annotation) > 0:
		return 2
	case len(r.Match.Toolset) > 0 && !r.Match.Toolset.Contains("*"):
		return 1
	default:
		return 0
	}
}

// RateLimit bounds how often matching subjects may be invoked.
type RateLimit struct {
	Name     string   `json:"name,omitempty"`
	Match    Match    `json:"match"`
	Window   Duration `json:"window"`
	Max      int      `json:"max"`
	OnExceed Severity `json:"on_exceed"`
}

// KillPolicy configures the out-of-band stop control: which events trip it, and
// what containment runs when it does. Triggers and actions stay separate — the
// existing design deliberately lets an operator detect without containing.
type KillPolicy struct {
	Triggers KillTriggers `json:"triggers"`
	Actions  KillActions  `json:"actions"`
}

// KillTriggers gate the trip sources that have no severity of their own. A
// disabled trigger is still detected and audited, it simply does not contain:
// transparency is never conditional on containment.
//
// A rule's `on_fail: kill` and a rate limit's `on_exceed: kill` are deliberately
// NOT listed here. Those already say, in the same document, that the operator
// wants containment for that case; making them depend on a second switch
// elsewhere in the file would mean a policy that reads as arming the kill switch
// quietly does not.
type KillTriggers struct {
	// PostureDrift fires when a background re-evaluation of the signals stops
	// admitting. It has no rule severity behind it, so it needs its own switch.
	PostureDrift bool `json:"posture_drift"`
	// RugPull fires when the served manifest changes after startup.
	RugPull bool `json:"rugpull"`
	// HeartbeatGap fires when the audit heartbeat stalls.
	HeartbeatGap bool `json:"heartbeat_gap"`
	// Sentinel watches InFlight.ControlDir for a "kill" file.
	Sentinel bool `json:"sentinel"`
}

// KillActions selects the containment ladder. Order of application is fixed in
// killaction.go and is not configurable.
type KillActions struct {
	Isolate       bool     `json:"isolate"`
	Lock          bool     `json:"lock"`
	Shutdown      bool     `json:"shutdown"`
	ShutdownDelay Duration `json:"shutdown_delay,omitempty"`
	KillProcs     []string `json:"kill_procs,omitempty"`
}

// TransparencyPolicy configures the always-on services.
type TransparencyPolicy struct {
	// AuditDestination is "stderr" (or empty) for JSONL on stderr, a directory for
	// per-session files plus a chained manifest, otherwise a single file path.
	AuditDestination string `json:"audit_destination,omitempty"`
	// AuditSink is the pre-rename name of AuditDestination, accepted as a
	// deprecated alias so a policy written before the rename still loads. Parse
	// folds it into AuditDestination and clears it; nothing else reads it.
	AuditSink string   `json:"audit_sink,omitempty"`
	Heartbeat Duration `json:"heartbeat,omitempty"`
	// RecordingDir enables session video recording when set.
	RecordingDir string `json:"recording_dir,omitempty"`
	// EvidenceDir enables automatic evidence-bundle sealing at session end: a
	// signed archive of the session's audit chain, verdicts, plan documents and
	// recording is written here. Empty disables it (the default). Requires a
	// directory-mode audit_destination, since there is otherwise no per-session file.
	EvidenceDir string `json:"evidence_dir,omitempty"`
	// Banner shows the on-screen security banner on a kill.
	Banner bool `json:"banner"`
	// StatusAddr is a loopback address for the status endpoint; empty disables.
	StatusAddr  string `json:"status_addr,omitempty"`
	StatusToken string `json:"status_token,omitempty"`
	// Anchor periodically publishes the audit chain head off the box. Empty
	// destination disables it (the default).
	Anchor AnchorPolicy `json:"anchor,omitempty"`
}

// AnchorPolicy configures periodic off-box anchoring of the audit chain head.
//
// Keying the chain (WINDOWS_MCP_AUDIT_KEY) makes it unforgeable without the key,
// but the key sits on the same box; anchoring is what buys resistance to an
// on-box adversary, by putting the head somewhere the session cannot reach back
// into. The key is an environment secret, never a policy field — argv and the
// policy document are both readable — but *where and how often* to anchor is a
// reviewable operational choice, so it lives here.
type AnchorPolicy struct {
	// Destination names the off-box destination. "eventlog" writes the head to the
	// Windows Application event log. Empty disables anchoring.
	Destination string `json:"destination,omitempty"`
	// Cadence is how often to anchor. Required when Destination is set.
	Cadence Duration `json:"cadence,omitempty"`
}

// AnchorEventLog is the only anchor destination implemented today. "otlp" is
// reserved for the telemetry exporter.
const AnchorEventLog = "eventlog"

// EgressPolicy configures the device egress proxy: a loopback CONNECT/HTTP
// proxy that admits only the declared domains.
//
// The proxy alone is cooperative — it constrains whatever is configured to use
// it. Naming applications (or opting into a machine-wide outbound block) is what
// makes it enforcement, and both of those need elevation. Which tier is in force
// is reported in the status snapshot so an operator cannot mistake one for the
// other.
type EgressPolicy struct {
	Enabled bool `json:"enabled"`
	// Allow lists the destinations the device may reach: exact hostnames, IP
	// literals, or "*.example.com", which covers the apex and every depth below
	// it. An enabled policy with an empty list is refused rather than treated as
	// "allow nothing" — it is far more likely to be an unfinished document.
	Allow StringSet `json:"allow,omitempty"`
	// Listen is the proxy's loopback address; empty means DefaultEgressListen.
	// Non-loopback is refused at load, for the same reason the transport is
	// stdio-only: this server does not stand up listeners the network can reach.
	Listen string `json:"listen,omitempty"`
	// AllowPorts bounds the ports a CONNECT may target; empty means 443 and 80.
	// Without it a tunnel to an allowed host is a generic TCP relay to any port
	// on it.
	AllowPorts []int `json:"allow_ports,omitempty"`
	// Applications are full paths of executables given outbound-block firewall
	// rules, so they cannot go around the proxy. Requires elevation.
	Applications StringSet `json:"applications,omitempty"`
	// BlockAllOutbound flips the machine's default outbound action to block.
	// This is the strong posture and the disruptive one; it is opt-in, needs
	// elevation, and carries its own exception set.
	BlockAllOutbound bool `json:"block_all_outbound"`
	// SetSystemProxy points this user's WinINET settings at the proxy. A
	// convenience, not enforcement: an application is free to ignore it.
	SetSystemProxy bool `json:"set_system_proxy"`
	// AllowPrivateNetworks permits targets that resolve into RFC1918 space, for
	// an allowlist that names intranet hosts. Loopback, link-local and multicast
	// stay refused regardless.
	AllowPrivateNetworks bool `json:"allow_private_networks"`
	// AuthTokenEnv names an environment variable holding a shared secret every
	// client must present as Proxy-Authorization. It names the variable, never
	// the value: the policy document is meant to be reviewable and checked in.
	AuthTokenEnv string `json:"auth_token_env,omitempty"`
}

// Defaults for an enabled egress policy.
const (
	DefaultEgressListen = "127.0.0.1:8181"
)

// DefaultEgressPorts is the port allowlist applied when none is written.
func DefaultEgressPorts() []int { return []int{443, 80} }

// Enforcement names the tier in force, for the status snapshot and the audit
// record. The distinction matters: "proxy-only" constrains whatever opts in,
// where the other two constrain the workload whether it wants to be or not.
func (e EgressPolicy) Enforcement() string {
	switch {
	case !e.Enabled:
		return "off"
	case e.BlockAllOutbound:
		return "global"
	case len(e.Applications) > 0:
		return "scoped"
	default:
		return "proxy-only"
	}
}

// InFlightPolicy configures continuous verification.
type InFlightPolicy struct {
	// Interval is how often expired signals are refreshed in the background. It
	// bounds how stale a cached signal can be in practice, independently of any
	// individual TTL.
	Interval Duration `json:"interval,omitempty"`
	// ControlDir is watched for a "kill" sentinel file; empty disables.
	ControlDir string `json:"control_dir,omitempty"`
}

// Default returns the embedded default: the engine present, evaluating and
// recording, refusing nothing.
//
// It panics on a malformed embedded document because that is a build defect, not
// a runtime condition — TestDefaultPolicyIsAuditOnly catches it long before a
// release.
func Default() *Policy {
	p, err := Parse(defaultPolicyJSON)
	if err != nil {
		panic("embedded default policy is invalid: " + err.Error())
	}
	return p
}

// Load reads and validates a policy document.
func Load(path string, known []string) (*Policy, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // an operator-supplied policy path
	if err != nil {
		return nil, fmt.Errorf("read policy %s: %w", path, err)
	}
	p, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("policy %s: %w", path, err)
	}
	if err := p.Validate(known); err != nil {
		return nil, fmt.Errorf("policy %s: %w", path, err)
	}
	return p, nil
}

// Parse decodes a policy document without validating it against a signal
// registry. Unknown fields are rejected: a typo in a key would otherwise be
// silently dropped, leaving the operator believing a control is in force.
func Parse(raw []byte) (*Policy, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	if p.Version != SchemaVersion {
		return nil, fmt.Errorf("%w: %d (this build understands %d)",
			ErrPolicyVersion, p.Version, SchemaVersion)
	}
	if p.Mode == "" {
		p.Mode = ModeAuditOnly
	}
	// Fold the deprecated audit_sink alias into audit_destination, so a policy
	// written before the rename still loads. Clearing it keeps the canonical form
	// (and the marshal/parse round-trip) on the new name.
	if p.Transparency.AuditSink != "" {
		if p.Transparency.AuditDestination == "" {
			p.Transparency.AuditDestination = p.Transparency.AuditSink
		}
		p.Transparency.AuditSink = ""
	}
	// Defaults are applied only to an enabled egress block, so a disabled one
	// stays the zero value and Validate can tell "written but not in force" from
	// "not written at all".
	if p.Egress.Enabled {
		if p.Egress.Listen == "" {
			p.Egress.Listen = DefaultEgressListen
		}
		if len(p.Egress.AllowPorts) == 0 {
			p.Egress.AllowPorts = DefaultEgressPorts()
		}
	}
	// Fill approval timings whenever a webhook is named, so the defaults are visible
	// to the engine and the round-trip, and an operator who set only the webhook
	// still gets the fail-closed timeout rather than an unbounded wait.
	if p.Approvals.WebhookURL != "" {
		if p.Approvals.Timeout <= 0 {
			p.Approvals.Timeout = Duration(DefaultApprovalTimeout)
		}
		if p.Approvals.PollInterval <= 0 {
			p.Approvals.PollInterval = Duration(DefaultApprovalPoll)
		}
	}
	return &p, nil
}

// Validate checks the document against the set of signal ids this build knows
// how to evaluate.
//
// Everything here fails at load, never at the first tool call. A policy that
// names a signal this build cannot evaluate is a policy whose author believes a
// control is in force when it is not, and discovering that mid-session is far
// worse than refusing to start.
func (p *Policy) Validate(known []string) error {
	knownSet := map[string]bool{}
	for _, id := range known {
		knownSet[id] = true
	}

	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	if p.Mode != ModeAuditOnly && p.Mode != ModeEnforcing {
		add("%v: %q (want %q or %q)", ErrUnknownMode, p.Mode, ModeAuditOnly, ModeEnforcing)
	}
	for _, id := range sortedKeys(p.Signals) {
		if len(knownSet) > 0 && !knownSet[id] {
			add("%v: signals.%s is not a signal this build can evaluate", ErrUnknownSignal, id)
		}
		if p.Signals[id].TTL < 0 {
			add("signals.%s: ttl must not be negative", id)
		}
	}
	for i, r := range p.Rules {
		label := ruleLabel(r.Name, i)
		if r.scope() != ScopeCall && r.scope() != ScopeStartup {
			add("%s: unknown scope %q (want %q or %q)", label, r.Match.Scope, ScopeCall, ScopeStartup)
		}
		if r.scope() == ScopeCall && r.specificity() == 0 && !r.Match.Toolset.Contains("*") {
			add("%v: %s selects no requests; use toolset \"*\" to mean every tool", ErrEmptyMatch, label)
		}
		if len(r.Require) == 0 {
			add("%s: requires no signals, so it can never fail", label)
		}
		// A startup admission is a one-shot go/no-go with no request to suspend and
		// no session yet to solicit a decision from, so hold has no meaning there.
		if r.OnFail == SeverityHold && r.scope() == ScopeStartup {
			add("%v: %s uses on_fail hold on a startup rule; hold is only valid on call-scope rules",
				ErrInvalidApprovals, label)
		}
		for _, id := range r.Require {
			if _, declared := p.Signals[id]; !declared {
				add("%v: %s requires %q, which is not declared in signals", ErrUndeclaredSignal, label, id)
			}
		}
	}
	for i, rl := range p.RateLimits {
		label := ruleLabel(rl.Name, i)
		if rl.Window <= 0 {
			add("%v: %s window must be positive", ErrInvalidRateLimit, label)
		}
		if rl.Max <= 0 {
			add("%v: %s max must be positive", ErrInvalidRateLimit, label)
		}
		// A rate limit fires on a stream of calls, not a single decidable request, so
		// there is no one call to hold for a human — hold does not fit here.
		if rl.OnExceed == SeverityHold {
			add("%v: %s uses on_exceed hold; a rate limit cannot suspend on approval, "+
				"use warn, deny or kill", ErrInvalidApprovals, label)
		}
	}

	// The status endpoint is an unauthenticated listener unless a token is set,
	// and it reports device posture. It has always been described as
	// loopback-bound; nothing enforced it, so a document could quietly expose it
	// to the network. Validated here for the same reason egress.listen is.
	if p.Transparency.StatusAddr != "" {
		if err := validateLoopbackAddr(p.Transparency.StatusAddr); err != nil {
			add("transparency.status_addr %v", err)
		} else if p.Transparency.StatusToken == "" {
			add("transparency.status_addr is set without a status_token: any local " +
				"process could read the device posture and trip the kill switch")
		}
	}

	// Anchoring is off unless a destination is named; a named destination must be
	// one we implement and must carry a cadence, or the operator has written a
	// control that would silently do nothing.
	if d := p.Transparency.Anchor.Destination; d != "" {
		if d != AnchorEventLog {
			add("%v: transparency.anchor.destination %q is not a known destination (want %q)",
				ErrInvalidAnchor, d, AnchorEventLog)
		}
		if p.Transparency.Anchor.Cadence.Std() <= 0 {
			add("%v: transparency.anchor.destination is set without a positive cadence",
				ErrInvalidAnchor)
		}
	}

	// Only "shell" and "filesystem" expose installed credentials, so only those may
	// be acknowledged. The canonical toolset list lives in pkg/windows; these two
	// IDs are stable and duplicated here rather than importing the tool layer into
	// the platform-agnostic policy engine.
	for _, ts := range p.Credentials.AcknowledgeToolsetExposure {
		if ts != "shell" && ts != "filesystem" {
			add("%v: credentials.acknowledge_toolset_exposure %q is not a toolset that exposes "+
				"credentials (want \"shell\" or \"filesystem\")", ErrInvalidCredentials, ts)
		}
	}

	// Each require_plan selector must be call-scoped and actually select something,
	// or it is a control that gates nothing.
	for i, m := range p.RequirePlan {
		if m.Scope != "" && strings.ToLower(m.Scope) != ScopeCall {
			add("%v: require_plan[%d] must be call-scoped", ErrInvalidRequirePlan, i)
		}
		if len(m.Tool) == 0 && len(m.Toolset) == 0 && len(m.Annotation) == 0 {
			add("%v: require_plan[%d] selects nothing (name a tool, toolset or annotation)", ErrInvalidRequirePlan, i)
		}
	}

	// Telemetry is off unless an endpoint is named; a named endpoint must use a
	// protocol we implement and a sample ratio in range.
	if p.Telemetry.Endpoint != "" {
		if pr := strings.ToLower(p.Telemetry.Protocol); pr != "" && pr != "http" {
			add("%v: telemetry.protocol %q is not supported (only \"http\")", ErrInvalidTelemetry, p.Telemetry.Protocol)
		}
		if p.Telemetry.SampleRatio < 0 || p.Telemetry.SampleRatio > 1 {
			add("%v: telemetry.sample_ratio %v is out of range [0,1]", ErrInvalidTelemetry, p.Telemetry.SampleRatio)
		}
	}

	p.validateApprovals(add)
	p.validateEgress(add)

	if len(problems) > 0 {
		// Every problem is reported at once: an operator fixing a policy one error
		// per run will give up before the policy is right.
		return fmt.Errorf("%w:\n  - %s", ErrInvalidPolicy, strings.Join(problems, "\n  - "))
	}
	return nil
}

// validateApprovals checks the dual-control configuration: a rule that disposes to
// approve must have a webhook to ask, and a webhook that is named must be reachable
// in shape (an absolute http/https URL) with sane timings.
func (p *Policy) validateApprovals(add func(string, ...any)) {
	a := p.Approvals
	if p.usesHold() && a.WebhookURL == "" {
		add("%v: a rule uses on_fail hold but approvals.webhook_url is not set; "+
			"dual control needs an authoriser to ask", ErrInvalidApprovals)
	}
	if a.WebhookURL == "" {
		// Nothing else to validate: an absent webhook with no approve rule is simply
		// dual control switched off, the default.
		return
	}
	u, err := url.Parse(a.WebhookURL)
	switch {
	case err != nil:
		add("%v: approvals.webhook_url %q is not a URL: %v", ErrInvalidApprovals, a.WebhookURL, err)
	case u.Scheme != "http" && u.Scheme != "https":
		add("%v: approvals.webhook_url %q must be http or https", ErrInvalidApprovals, a.WebhookURL)
	case u.Host == "":
		add("%v: approvals.webhook_url %q has no host", ErrInvalidApprovals, a.WebhookURL)
	}
	if a.Timeout.Std() <= 0 {
		add("%v: approvals.timeout must be positive", ErrInvalidApprovals)
	}
	if a.PollInterval.Std() <= 0 {
		add("%v: approvals.poll_interval must be positive", ErrInvalidApprovals)
	}
	if a.PollInterval.Std() > a.Timeout.Std() {
		add("%v: approvals.poll_interval (%s) exceeds the timeout (%s), so no poll would ever run",
			ErrInvalidApprovals, a.PollInterval, a.Timeout)
	}
}

// validateEgress checks the egress block, appending to the collected problems
// rather than returning, so one run reports everything wrong with the document.
func (p *Policy) validateEgress(add func(string, ...any)) {
	e := p.Egress
	if !e.Enabled {
		// A control written but not switched on is the failure this whole package
		// exists to prevent: the author believes the device is constrained and it
		// is not. Refusing is louder than a log line nobody reads.
		if len(e.Allow) > 0 || len(e.Applications) > 0 || e.BlockAllOutbound ||
			e.SetSystemProxy || e.Listen != "" || len(e.AllowPorts) > 0 || e.AuthTokenEnv != "" {
			add("%v: egress is configured but egress.enabled is false, so none of it is in force",
				ErrInvalidEgress)
		}
		return
	}

	if len(e.Allow) == 0 {
		add("%v: egress.enabled is true with an empty egress.allow; list the domains the device may reach",
			ErrInvalidEgress)
	}
	if e.BlockAllOutbound && len(e.AllowPorts) == 0 {
		// Unreachable in practice, since Parse defaults the ports — but a Policy
		// built in code could reach it, and a global block whose proxy has no
		// permitted ports would cut the machine off with no route out at all.
		add("%v: egress.block_all_outbound needs at least one entry in egress.allow_ports, "+
			"or the proxy itself has no permitted route out", ErrInvalidEgress)
	}
	if _, err := hostmatch.Compile(e.Allow); err != nil {
		add("%v: %v", ErrInvalidEgress, err)
	}
	if err := validateLoopbackAddr(e.Listen); err != nil {
		add("%v: egress.listen %v", ErrInvalidEgress, err)
	}
	for _, port := range e.AllowPorts {
		if port < 1 || port > 65535 {
			add("%v: egress.allow_ports has %d, which is not a port", ErrInvalidEgress, port)
		}
	}
	for _, app := range e.Applications {
		if strings.TrimSpace(app) == "" {
			add("%v: egress.applications has an empty entry", ErrInvalidEgress)
			continue
		}
		if !looksAbsoluteWindowsPath(app) {
			add("%v: egress.applications %q must be a full path, since a firewall rule names an image",
				ErrInvalidEgress, app)
		}
	}
}

// validateLoopbackAddr refuses anything the network could reach. The egress
// proxy is unauthenticated by default, and this server's whole posture is that
// it does not expose listeners off the machine.
func validateLoopbackAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%w: %q is not host:port", ErrNotLoopback, addr)
	}
	if port == "" {
		return fmt.Errorf("%w: %q names no port", ErrNotLoopback, addr)
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return fmt.Errorf("%w: %q is not an IP address or localhost", ErrNotLoopback, host)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("%w: %q is not a loopback address; this server does not "+
			"expose listeners the network can reach", ErrNotLoopback, host)
	}
	return nil
}

// looksAbsoluteWindowsPath is a deliberately lenient check. This package is
// platform-agnostic and its tests run anywhere, so it cannot use the host's path
// semantics to judge a path that will be used on Windows.
func looksAbsoluteWindowsPath(p string) bool {
	if strings.HasPrefix(p, `\\`) { // UNC
		return true
	}
	return len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/')
}

// SignalIDs returns the declared signal ids, sorted.
func (p *Policy) SignalIDs() []string { return sortedKeys(p.Signals) }

func ruleLabel(name string, index int) string {
	if name != "" {
		return fmt.Sprintf("rule %q", name)
	}
	return fmt.Sprintf("rule #%d", index)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
