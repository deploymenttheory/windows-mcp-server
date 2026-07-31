package policy

import (
	"errors"
	"strings"
	"testing"
)

func egressDoc(t *testing.T, egress string) *Policy {
	t.Helper()
	raw := `{"version":1,"mode":"audit","signals":{"run-context":{"ttl":"0s"}},
	  "rules":[{"name":"baseline","match":{"toolset":"*"},"require":["run-context"],"on_fail":"warn"}],
	  "egress":` + egress + `}`
	p, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return p
}

func TestEgressDefaultsApplyOnlyWhenEnabled(t *testing.T) {
	enabled := egressDoc(t, `{"enabled":true,"allow":["example.com"]}`)
	if enabled.Egress.Listen != DefaultEgressListen {
		t.Errorf("listen = %q, want the default %q", enabled.Egress.Listen, DefaultEgressListen)
	}
	if len(enabled.Egress.AllowPorts) != 2 {
		t.Errorf("allow_ports = %v, want the default", enabled.Egress.AllowPorts)
	}

	// A disabled block stays the zero value, so Validate can tell "written but
	// not in force" from "not written at all".
	disabled := egressDoc(t, `{"enabled":false}`)
	if disabled.Egress.Listen != "" || len(disabled.Egress.AllowPorts) != 0 {
		t.Errorf("a disabled egress block should stay zero, got %+v", disabled.Egress)
	}
}

func TestEgressValidationRejectsMisconfiguration(t *testing.T) {
	for _, tc := range []struct {
		name   string
		egress string
		want   string
	}{
		{
			name:   "enabled with no allowlist",
			egress: `{"enabled":true}`,
			want:   "empty egress.allow",
		},
		{
			name:   "allow everything",
			egress: `{"enabled":true,"allow":["*"]}`,
			want:   "allow every host",
		},
		{
			name:   "malformed wildcard",
			egress: `{"enabled":true,"allow":["*.*.example.com"]}`,
			want:   "wildcard",
		},
		{
			name:   "pattern carrying a scheme",
			egress: `{"enabled":true,"allow":["https://example.com"]}`,
			want:   "scheme",
		},
		{
			name:   "pattern carrying a port",
			egress: `{"enabled":true,"allow":["example.com:443"]}`,
			want:   "port",
		},
		{
			name:   "non-loopback listener",
			egress: `{"enabled":true,"allow":["example.com"],"listen":"0.0.0.0:8181"}`,
			want:   "loopback",
		},
		{
			name:   "listener with no port",
			egress: `{"enabled":true,"allow":["example.com"],"listen":"127.0.0.1"}`,
			want:   "host:port",
		},
		{
			name:   "port out of range",
			egress: `{"enabled":true,"allow":["example.com"],"allow_ports":[70000]}`,
			want:   "not a port",
		},
		{
			name:   "relative application path",
			egress: `{"enabled":true,"allow":["example.com"],"applications":["chrome.exe"]}`,
			want:   "full path",
		},
		{
			name:   "empty application entry",
			egress: `{"enabled":true,"allow":["example.com"],"applications":[""]}`,
			want:   "empty entry",
		},
		{
			// The failure this whole package exists to prevent: an operator who
			// believes a control is in force when it is not.
			name:   "configured but switched off",
			egress: `{"enabled":false,"allow":["example.com"]}`,
			want:   "egress.enabled is false",
		},
		{
			name:   "enforcement requested but switched off",
			egress: `{"enabled":false,"block_all_outbound":true}`,
			want:   "egress.enabled is false",
		},
		{
			// Accepting a setting this build cannot honour would leave the
			// operator believing the machine is default-deny.
			name:   "global block is not implemented yet",
			egress: `{"enabled":true,"allow":["example.com"],"block_all_outbound":true}`,
			want:   "not implemented in this build",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := egressDoc(t, tc.egress)
			err := p.Validate(knownSignals)
			if err == nil {
				t.Fatalf("%s should be rejected", tc.name)
			}
			if !errors.Is(err, ErrInvalidPolicy) {
				t.Errorf("want ErrInvalidPolicy, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error should explain %q, got: %v", tc.want, err)
			}
		})
	}
}

func TestEgressValidationAcceptsWorkableDocuments(t *testing.T) {
	for _, egress := range []string{
		`{"enabled":false}`,
		`{"enabled":true,"allow":["example.com"]}`,
		`{"enabled":true,"allow":["*.contoso.com","login.microsoftonline.com","203.0.113.7"],
		  "listen":"127.0.0.1:9000","allow_ports":[443],"allow_private_networks":true,
		  "auth_token_env":"WINDOWS_MCP_EGRESS_TOKEN"}`,
		`{"enabled":true,"allow":["*.contoso.com"],
		  "applications":["C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"]}`,
		`{"enabled":true,"allow":["*.contoso.com"],"applications":["\\\\server\\share\\app.exe"]}`,
		`{"enabled":true,"allow":["*.contoso.com"],"listen":"localhost:8181"}`,
	} {
		p := egressDoc(t, egress)
		if err := p.Validate(knownSignals); err != nil {
			t.Errorf("%s should validate: %v", egress, err)
		}
	}
}

// TestEgressEnforcementNamesTheTier pins the distinction an operator reads in
// the status snapshot: a proxy nothing is forced through is not enforcement.
func TestEgressEnforcementNamesTheTier(t *testing.T) {
	for _, tc := range []struct {
		egress EgressPolicy
		want   string
	}{
		{EgressPolicy{}, "off"},
		{EgressPolicy{Enabled: true, Allow: StringSet{"example.com"}}, "proxy-only"},
		{EgressPolicy{Enabled: true, Applications: StringSet{`C:\a.exe`}}, "scoped"},
		// Global is still the name for the tier even though Validate refuses it
		// in this build: Enforcement() reports what the document asks for.
		{EgressPolicy{Enabled: true, BlockAllOutbound: true}, "global"},
		// Global outranks scoped: it is the broader statement.
		{EgressPolicy{Enabled: true, Applications: StringSet{`C:\a.exe`}, BlockAllOutbound: true}, "global"},
	} {
		if got := tc.egress.Enforcement(); got != tc.want {
			t.Errorf("Enforcement(%+v) = %q, want %q", tc.egress, got, tc.want)
		}
	}
}

// TestEgressValidationReportsEveryProblemAtOnce matches the rest of the package:
// an operator fixing a document one error per run gives up before it is right.
func TestEgressValidationReportsEveryProblemAtOnce(t *testing.T) {
	p := egressDoc(t, `{"enabled":true,"allow":["*"],"listen":"0.0.0.0:1","allow_ports":[0]}`)
	err := p.Validate(knownSignals)
	if err == nil {
		t.Fatal("expected a rejection")
	}
	for _, want := range []string{"allow every host", "loopback", "not a port"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("every problem should be reported; %q missing from: %v", want, err)
		}
	}
}
