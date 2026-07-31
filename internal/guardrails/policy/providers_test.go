package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/signals"
)

// These exercise the real signal providers through the engine, which is the path
// production uses: registry lookup, signal cache, rule match, verdict. Testing
// them here rather than in the signal package is deliberate — a provider only
// matters in terms of the verdict it produces.

// deviceProbe is a signals.SystemProbe describing a fake device.
type deviceProbe struct {
	rc    signals.RunContext
	dsreg string
	id    signals.DeviceIdentity
}

func (p deviceProbe) RunShell(context.Context, string) (string, error) { return p.dsreg, nil }
func (p deviceProbe) DomainSKU() (signals.DomainSKU, error) {
	return signals.DomainSKU{OSSKU: 4, OSCaption: "Windows 11 Enterprise"}, nil
}
func (p deviceProbe) RunContext() signals.RunContext         { return p.rc }
func (p deviceProbe) DeviceIdentity() signals.DeviceIdentity { return p.id }
func (p deviceProbe) IsAdmin() bool                          { return false }

const dsregCompliant = `
AzureAdJoined : YES
TenantName : Contoso
MdmUrl : https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc
`

const dsregUnmanaged = `
AzureAdJoined : NO
MdmUrl : NULL
`

func managedDevice() deviceProbe {
	return deviceProbe{
		rc:    signals.RunContext{IsSystem: false, SessionID: 1, User: "tester"},
		dsreg: dsregCompliant,
		id:    signals.DeviceIdentity{Hostname: "WS-1", Serial: "SN-123"},
	}
}

// evaluateAgainst runs a policy over a fake device through the real engine and
// the real provider registry.
func evaluateAgainst(t *testing.T, probe deviceProbe, policyJSON string) Verdict {
	t.Helper()
	reg := signals.NewRegistry()
	signals.RegisterBuiltins(reg)

	p, err := Parse([]byte(policyJSON))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Validate(reg.IDs()); err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(p, reg, testIndex, func() *signals.Env { return &signals.Env{Sys: probe} })
	return engine.Evaluate(context.Background(), engine.SubjectForTool("tools/call", "Snapshot"))
}

// managedDevicePolicy is the shape an enterprise deployment writes: an
// interactive session on an MDM-enrolled, Entra-joined device.
const managedDevicePolicy = `{
  "version": 1, "mode": "enforce",
  "signals": {
    "run-context":  { "ttl": "0s" },
    "mdm-enrolled": { "ttl": "0s" },
    "entra-joined": { "ttl": "0s" }
  },
  "rules": [ { "name": "managed", "match": { "toolset": "*" },
    "require": ["run-context", "mdm-enrolled", "entra-joined"], "on_fail": "deny" } ]
}`

func TestManagedDeviceIsAdmitted(t *testing.T) {
	v := evaluateAgainst(t, managedDevice(), managedDevicePolicy)
	if !v.Allowed() {
		t.Fatalf("a compliant device should be allowed, failures: %+v", v.Failures)
	}
}

func TestUnmanagedDeviceIsRefused(t *testing.T) {
	p := managedDevice()
	p.dsreg = dsregUnmanaged

	v := evaluateAgainst(t, p, managedDevicePolicy)
	if v.Allowed() {
		t.Fatal("an unmanaged device should be refused")
	}
	failed := map[string]bool{}
	for _, f := range v.Failures {
		failed[f.Signal] = true
	}
	for _, want := range []string{"mdm-enrolled", "entra-joined"} {
		if !failed[want] {
			t.Errorf("expected %q to fail on an unmanaged device, got %+v", want, v.Failures)
		}
	}
}

// TestSystemContextIsRefused covers the check that gates desktop automation:
// Session 0 has no desktop to drive.
func TestSystemContextIsRefused(t *testing.T) {
	p := managedDevice()
	p.rc = signals.RunContext{IsSystem: true, SessionID: 0}

	v := evaluateAgainst(t, p, `{
	  "version": 1, "mode": "enforce",
	  "signals": { "run-context": { "ttl": "0s" } },
	  "rules": [ { "name": "interactive", "match": { "toolset": "*" },
	    "require": ["run-context"], "on_fail": "deny" } ]
	}`)
	if v.Allowed() {
		t.Error("a SYSTEM context should fail the run-context signal")
	}
}

// TestDeviceAllowlist covers a signal's `arg`, which is how a policy passes a
// parameter to a check.
func TestDeviceAllowlist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.txt")
	if err := os.WriteFile(path, []byte("# devices\nSN-123\nOTHER-HOST\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	policyJSON := `{
	  "version": 1, "mode": "enforce",
	  "signals": { "device-allowlist": { "ttl": "0s", "arg": "` + filepath.ToSlash(path) + `" } },
	  "rules": [ { "name": "allowlisted", "match": { "toolset": "*" },
	    "require": ["device-allowlist"], "on_fail": "deny" } ]
	}`

	if v := evaluateAgainst(t, managedDevice(), policyJSON); !v.Allowed() {
		t.Errorf("serial SN-123 is on the list and should be allowed: %+v", v.Failures)
	}

	off := managedDevice()
	off.id = signals.DeviceIdentity{Hostname: "WS-9", Serial: "SN-999"}
	if v := evaluateAgainst(t, off, policyJSON); v.Allowed() {
		t.Error("a device not on the allowlist should be refused")
	}
}
