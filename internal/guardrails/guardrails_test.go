package guardrails

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// fakeProbe is a SystemProbe for tests. It is shared with graph_test.go,
// preflight_test.go and remote_test.go.
type fakeProbe struct {
	rc     RunContext
	dsreg  string
	domain DomainSKU
	id     DeviceIdentity
	admin  bool
	err    error
}

func (f fakeProbe) RunShell(context.Context, string) (string, error) { return f.dsreg, f.err }
func (f fakeProbe) DomainSKU() (DomainSKU, error)                    { return f.domain, nil }
func (f fakeProbe) RunContext() RunContext                           { return f.rc }
func (f fakeProbe) DeviceIdentity() DeviceIdentity                   { return f.id }
func (f fakeProbe) IsAdmin() bool                                    { return f.admin }

const dsregCompliant = `
             Device State
AzureAdJoined : YES
EnterpriseJoined : NO
DomainJoined : NO
TenantName : Contoso
MdmUrl : https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc
`

const dsregUnmanaged = `
AzureAdJoined : NO
MdmUrl : NULL
`

func newReg() *Registry {
	r := NewRegistry()
	RegisterBuiltins(r)
	return r
}

func interactiveProbe() fakeProbe {
	return fakeProbe{
		rc:     RunContext{IsSystem: false, SessionID: 1, User: "tester"},
		dsreg:  dsregCompliant,
		domain: DomainSKU{PartOfDomain: false, OSSKU: 4, OSCaption: "Windows 11 Enterprise"},
		id:     DeviceIdentity{Hostname: "WS-1", Serial: "SN-123"},
	}
}

// evaluateAgainst runs a policy over a fake device through the real engine.
//
// These providers are exercised end-to-end rather than by calling their
// CheckFunc directly, because the path that matters is the one production uses:
// registry lookup, signal cache, rule match, verdict.
func evaluateAgainst(t *testing.T, probe fakeProbe, policyJSON string) Verdict {
	t.Helper()
	reg := newReg()
	p, err := ParsePolicy([]byte(policyJSON))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Validate(reg.IDs()); err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(p, reg, testIndex, func() *Env { return &Env{Sys: probe} })
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
	v := evaluateAgainst(t, interactiveProbe(), managedDevicePolicy)
	if !v.Allowed() {
		t.Fatalf("a compliant device should be allowed, failures: %+v", v.Failures)
	}
}

func TestUnmanagedDeviceIsRefused(t *testing.T) {
	p := interactiveProbe()
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
	p := interactiveProbe()
	p.rc = RunContext{IsSystem: true, SessionID: 0}

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

// TestDeviceAllowlist covers the signal's `arg`, which is how a policy passes a
// parameter to a check.
func TestDeviceAllowlist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.txt")
	if err := os.WriteFile(path, []byte("# devices\nSN-123\nOTHER-HOST\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	policy := `{
	  "version": 1, "mode": "enforce",
	  "signals": { "device-allowlist": { "ttl": "0s", "arg": "` + filepath.ToSlash(path) + `" } },
	  "rules": [ { "name": "allowlisted", "match": { "toolset": "*" },
	    "require": ["device-allowlist"], "on_fail": "deny" } ]
	}`

	if v := evaluateAgainst(t, interactiveProbe(), policy); !v.Allowed() {
		t.Errorf("serial SN-123 is on the list and should be allowed: %+v", v.Failures)
	}

	off := interactiveProbe()
	off.id = DeviceIdentity{Hostname: "WS-9", Serial: "SN-999"}
	if v := evaluateAgainst(t, off, policy); v.Allowed() {
		t.Error("a device not on the allowlist should be refused")
	}
}

func TestDsregParse(t *testing.T) {
	m := dsregParse(dsregCompliant)
	if m["AzureAdJoined"] != "YES" {
		t.Errorf("AzureAdJoined = %q", m["AzureAdJoined"])
	}
	if isNull(m["MdmUrl"]) {
		t.Error("MdmUrl should be non-null")
	}
	if !isNull(dsregParse(dsregUnmanaged)["MdmUrl"]) {
		t.Error("unmanaged MdmUrl should be null")
	}
}
