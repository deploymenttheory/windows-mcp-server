package policy

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// knownSignals is the id set a real build would supply from the registry.
var knownSignals = []string{
	"run-context", "mdm-enrolled", "bitlocker", "secure-boot", "not-admin", "device-allowlist",
}

// TestDefaultPolicyIsAuditOnly is the guard that matters most in this package.
//
// The default policy ships in every binary and applies whenever no --policy-config
// is given. If it ever denied or killed, upgrading the server would start refusing
// tool calls on devices that were working the day before, with no operator action
// and no config to point at.
func TestDefaultPolicyIsAuditOnly(t *testing.T) {
	p := Default()

	if p.Mode != ModeAuditOnly {
		t.Fatalf("default mode = %q, want %q", p.Mode, ModeAuditOnly)
	}
	if err := p.Validate(knownSignals); err != nil {
		t.Fatalf("default policy must validate against the real signal set: %v", err)
	}
	// Audit mode caps severity, so no rule can refuse anything. Assert the cap
	// rather than the rules: it is the cap that makes the default safe.
	for i, r := range p.Rules {
		if got := p.Mode.clamp(r.OnFail); got >= SeverityDeny {
			t.Errorf("rule #%d yields %v under the default mode; the default must never refuse", i, got)
		}
	}
	// Containment must be entirely off, so that a trip detected under the default
	// is recorded and nothing else.
	if k := p.Kill; k.Triggers.PostureDrift || k.Triggers.RugPull ||
		k.Triggers.HeartbeatGap || k.Triggers.Sentinel {
		t.Errorf("default policy arms a kill trigger: %+v", k.Triggers)
	}
	if a := p.Kill.Actions; a.Isolate || a.Lock || a.Shutdown || len(a.KillProcs) > 0 {
		t.Errorf("default policy configures a containment action: %+v", a)
	}
	// Transparency stays on: observing is the whole point of the default.
	if p.Transparency.Heartbeat <= 0 {
		t.Error("default policy disables the heartbeat; the default should observe, not go quiet")
	}
	// The default must not stand up a listener or touch the device's networking.
	// A server that started proxying traffic on upgrade, with no operator action,
	// is the same class of regression as one that started refusing tool calls.
	if p.Egress.Enabled {
		t.Error("default policy enables the egress proxy; the default must not alter the device's networking")
	}
	if p.Egress.Enforcement() != "off" {
		t.Errorf("default egress enforcement = %q, want off", p.Egress.Enforcement())
	}
}

func TestParsePolicyRejectsUnknownVersion(t *testing.T) {
	_, err := Parse([]byte(`{"version":99,"mode":"audit"}`))
	if !errors.Is(err, ErrPolicyVersion) {
		t.Fatalf("want ErrPolicyVersion, got %v", err)
	}
}

// TestParsePolicyRejectsUnknownFields covers the typo case. A dropped key would
// leave the operator believing a control is in force when it is not.
func TestParsePolicyRejectsUnknownFields(t *testing.T) {
	_, err := Parse([]byte(`{"version":1,"mode":"audit","signalz":{}}`))
	if err == nil {
		t.Fatal("a misspelled key must be an error, not silently ignored")
	}
	if !strings.Contains(err.Error(), "signalz") {
		t.Errorf("error should name the offending key, got: %v", err)
	}
}

func TestSeverityRoundTrips(t *testing.T) {
	for _, sev := range []Severity{SeverityAllow, SeverityWarn, SeverityHold, SeverityDeny, SeverityKill} {
		raw, err := json.Marshal(sev)
		if err != nil {
			t.Fatal(err)
		}
		var back Severity
		if err := json.Unmarshal(raw, &back); err != nil {
			t.Fatal(err)
		}
		if back != sev {
			t.Errorf("%v round-tripped to %v via %s", sev, back, raw)
		}
	}
	var bad Severity
	if err := json.Unmarshal([]byte(`"nuke"`), &bad); !errors.Is(err, ErrUnknownSeverity) {
		t.Errorf("want ErrUnknownSeverity for an invented severity, got %v", err)
	}
}

// TestSeverityOrderingIsMeaningful pins the numeric order the verdict maths
// depends on: a call's verdict is the maximum severity among its failures, so
// reordering these constants would silently downgrade enforcement.
func TestSeverityOrderingIsMeaningful(t *testing.T) {
	if !(SeverityAllow < SeverityWarn && SeverityWarn < SeverityHold &&
		SeverityHold < SeverityDeny && SeverityDeny < SeverityKill) {
		t.Fatal("severities must be ordered allow < warn < hold < deny < kill")
	}
}

func TestDurationAcceptsStrings(t *testing.T) {
	var cfg SignalConfig
	if err := json.Unmarshal([]byte(`{"ttl":"90s"}`), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.TTL.Std() != 90*time.Second {
		t.Errorf("ttl = %v, want 90s", cfg.TTL)
	}
	if err := json.Unmarshal([]byte(`{"ttl":"soon"}`), &cfg); err == nil {
		t.Error("an unparseable duration must fail at load")
	}
	if err := json.Unmarshal([]byte(`{"ttl":90}`), &cfg); err == nil {
		t.Error("a bare number must be rejected; nanoseconds are not a readable unit in a policy")
	}
}

func TestStringSetAcceptsScalarOrList(t *testing.T) {
	var m Match
	if err := json.Unmarshal([]byte(`{"toolset":"system","tool":["A","B"]}`), &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Toolset) != 1 || m.Toolset[0] != "system" {
		t.Errorf("scalar toolset = %v", m.Toolset)
	}
	if len(m.Tool) != 2 {
		t.Errorf("list tool = %v", m.Tool)
	}
	if !m.Toolset.Contains("SYSTEM") {
		t.Error("membership should be case-insensitive")
	}
	star := StringSet{"*"}
	if !star.Contains("anything") {
		t.Error(`"*" should match anything`)
	}
}

// TestValidateReportsEveryProblemAtOnce matters for usability: an operator fixing
// a policy one error per run will give up. It also pins that each class of
// problem is caught at load rather than at the first tool call.
func TestValidateReportsEveryProblemAtOnce(t *testing.T) {
	p, err := Parse([]byte(`{
	  "version": 1,
	  "mode": "paranoid",
	  "signals": { "not-a-signal": { "ttl": "5m" } },
	  "rules": [
	    { "name": "bad-require", "match": { "toolset": "*" }, "require": ["bitlocker"], "on_fail": "deny" },
	    { "name": "no-require",  "match": { "toolset": "*" }, "require": [], "on_fail": "deny" },
	    { "name": "bad-scope",   "match": { "scope": "someday", "toolset": "*" }, "require": ["not-a-signal"], "on_fail": "warn" }
	  ],
	  "rate_limits": [ { "name": "bad-window", "match": { "toolset": "*" }, "window": "0s", "max": 0, "on_exceed": "deny" } ]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	err = p.Validate(knownSignals)
	if err == nil {
		t.Fatal("expected validation to fail")
	}
	for _, want := range []string{
		"paranoid",     // unknown mode
		"not-a-signal", // signal this build cannot evaluate
		"bad-require",  // requires a signal that is not declared
		"no-require",   // requires nothing, so can never fail
		"someday",      // unknown scope
		"bad-window",   // window and max must be positive
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("validation output does not mention %q:\n%v", want, err)
		}
	}
}

// TestValidateRejectsARuleThatMatchesNothing guards a silent-no-op: a rule with an
// empty match reads as "applies to everything" but selects nothing, so the control
// its author intended would never fire.
func TestValidateRejectsARuleThatMatchesNothing(t *testing.T) {
	p, err := Parse([]byte(`{
	  "version": 1, "mode": "enforce",
	  "signals": { "run-context": { "ttl": "0s" } },
	  "rules": [ { "name": "empty", "match": {}, "require": ["run-context"], "on_fail": "deny" } ]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Validate(knownSignals); !errors.Is(err, ErrEmptyMatch) && !strings.Contains(err.Error(), "selects no requests") {
		t.Errorf("want an empty-match rejection, got %v", err)
	}
}

// TestPostureDriftNeedsSomethingToReEvaluate pins a trigger that could be armed
// and still never fire.
//
// Drift is detected by re-evaluating the startup subject on each monitor
// interval, and a startup subject matches startup-scope rules only. With no such
// rule the monitor runs, logs, and can never trip: the operator asked for drift
// detection and got a timer. The other route to the trigger, the signal cache's
// Refresh, returns nil unconditionally and deliberately, so nothing else can fire
// it either.
func TestPostureDriftNeedsSomethingToReEvaluate(t *testing.T) {
	const armed = `{
	  "version": 1, "mode": "enforce",
	  "signals": { "run-context": { "ttl": "0s" } },
	  "rules": [ { "name": "calls", "match": { "toolset": "*" }, "require": ["run-context"], "on_fail": "deny" } ],
	  "kill": { "triggers": { "posture_drift": true } }
	}`
	p, err := Parse([]byte(armed))
	if err != nil {
		t.Fatal(err)
	}
	err = p.Validate(knownSignals)
	if err == nil {
		t.Fatal("arming posture_drift with no startup rule must be refused")
	}
	// Validate collects problems into one ErrInvalidPolicy, rendering each cause
	// rather than wrapping it, so match the way the sibling tests do.
	if !errors.Is(err, ErrNoStartupRule) && !strings.Contains(err.Error(), "can never fire") {
		t.Errorf("want a posture-drift rejection, got %v", err)
	}

	// Add a startup rule and the same document is fine.
	withStartup, err := Parse([]byte(`{
	  "version": 1, "mode": "enforce",
	  "signals": { "run-context": { "ttl": "0s" } },
	  "rules": [
	    { "name": "admission", "match": { "scope": "startup" }, "require": ["run-context"], "on_fail": "deny" },
	    { "name": "calls", "match": { "toolset": "*" }, "require": ["run-context"], "on_fail": "deny" }
	  ],
	  "kill": { "triggers": { "posture_drift": true } }
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := withStartup.Validate(knownSignals); err != nil {
		t.Errorf("posture_drift with a startup rule to re-evaluate is valid: %v", err)
	}

	// And the trigger off is fine either way -- this must not become a blanket
	// requirement that every policy carry a startup rule.
	unarmed, err := Parse([]byte(`{
	  "version": 1, "mode": "enforce",
	  "signals": { "run-context": { "ttl": "0s" } },
	  "rules": [ { "name": "calls", "match": { "toolset": "*" }, "require": ["run-context"], "on_fail": "deny" } ]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := unarmed.Validate(knownSignals); err != nil {
		t.Errorf("a policy that does not arm posture_drift needs no startup rule: %v", err)
	}
}

// TestStartupRuleNeedsNoSelector: a startup rule is evaluated once for the
// process, so it has no tool to select and an empty match is correct there.
func TestStartupRuleNeedsNoSelector(t *testing.T) {
	p, err := Parse([]byte(`{
	  "version": 1, "mode": "enforce",
	  "signals": { "run-context": { "ttl": "0s" } },
	  "rules": [ { "name": "admission", "match": { "scope": "startup" }, "require": ["run-context"], "on_fail": "deny" } ]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Validate(knownSignals); err != nil {
		t.Errorf("a startup rule needs no selector: %v", err)
	}
}

func TestRuleSpecificityOrdering(t *testing.T) {
	cases := []struct {
		name string
		rule Rule
		want int
	}{
		{"tool is narrowest", Rule{Match: Match{Tool: StringSet{"PowerShell"}}}, 3},
		{"annotation next", Rule{Match: Match{Annotation: StringSet{AnnotationDestructive}}}, 2},
		{"named toolset next", Rule{Match: Match{Toolset: StringSet{"system"}}}, 1},
		{"star toolset is broadest", Rule{Match: Match{Toolset: StringSet{"*"}}}, 0},
	}
	for _, tc := range cases {
		if got := tc.rule.specificity(); got != tc.want {
			t.Errorf("%s: specificity = %d, want %d", tc.name, got, tc.want)
		}
	}
}

// TestPlaintextApprovalWebhookIsRejected pins that dual control cannot run over a
// channel an on-path attacker can rewrite. Over plaintext http, answering
// "approve" for every held call is trivial, and the chain records a
// legitimate-looking approval.decided.
func TestPlaintextApprovalWebhookIsRejected(t *testing.T) {
	rejected := []string{
		"http://approvals.corp.local/decide",
		"HTTP://approvals.corp.local/decide", // scheme comparison must be case-insensitive
		"http://10.1.2.3/decide",
	}
	for _, raw := range rejected {
		doc := []byte(`{"version":1,"approvals":{"webhook_url":"` + raw + `"}}`)
		pol, err := Parse(doc)
		if err != nil {
			t.Errorf("%s: parse failed unexpectedly: %v", raw, err)
			continue
		}
		if err := pol.Validate(nil); err == nil {
			t.Errorf("%s: a plaintext approvals webhook must be refused at load", raw)
		}
	}

	accepted := []string{
		"https://approvals.corp.local/decide",
		"http://127.0.0.1:9000/decide", // loopback: cannot leave the machine
		"http://localhost:9000/decide",
	}
	for _, raw := range accepted {
		doc := []byte(`{"version":1,"approvals":{"webhook_url":"` + raw + `"}}`)
		pol, err := Parse(doc)
		if err != nil {
			t.Errorf("%s: parse failed: %v", raw, err)
			continue
		}
		if err := pol.Validate(nil); err != nil {
			t.Errorf("%s should be accepted, got %v", raw, err)
		}
	}
}

// TestTelemetryEndpointMustNotExportInClear pins that a collector off this
// machine is reached over TLS.
//
// The exporter treats a schemeless endpoint as plaintext, and "collector:4318" is
// the form the field's own documentation offers first -- so the default reading of
// the docs exported tool names, service identity and the WINDOWS_MCP_OTLP_HEADERS
// bearer credentials in clear, with nothing in the document showing it.
func TestTelemetryEndpointMustNotExportInClear(t *testing.T) {
	rejected := []string{
		"collector:4318",             // schemeless, remote: the documented form
		"http://collector.corp:4318", // explicit plaintext, remote
		"HTTP://collector.corp:4318", // scheme comparison must be case-insensitive
		"ftp://collector:4318",       // not a scheme we speak
	}
	for _, ep := range rejected {
		if err := requireSecureEndpoint(ep); err == nil {
			t.Errorf("%s must be refused: it would export in clear or over an unknown protocol", ep)
		}
	}

	accepted := []string{
		"https://collector.corp:4318", // TLS to a remote collector
		"localhost:4318",              // schemeless loopback: the usual dev setup
		"127.0.0.1:4318",
		"http://localhost:4318", // explicit plaintext loopback
	}
	for _, ep := range accepted {
		if err := requireSecureEndpoint(ep); err != nil {
			t.Errorf("%s should be accepted, got %v", ep, err)
		}
	}
}
