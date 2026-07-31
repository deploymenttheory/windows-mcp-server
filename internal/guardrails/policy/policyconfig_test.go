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
	for _, sev := range []Severity{SeverityAllow, SeverityWarn, SeverityDeny, SeverityKill} {
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
	if !(SeverityAllow < SeverityWarn && SeverityWarn < SeverityDeny && SeverityDeny < SeverityKill) {
		t.Fatal("severities must be ordered allow < warn < deny < kill")
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
