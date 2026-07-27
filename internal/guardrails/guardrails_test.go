package guardrails

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// fakeProbe is a SystemProbe for tests.
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

func TestEnterprisePresetAdmitsCompliant(t *testing.T) {
	r := NewRunner(newReg(), Config{Mode: ModeEnforce, Enterprise: true}, nil)
	d := r.Evaluate(context.Background(), &Env{Sys: interactiveProbe()})
	if !d.Admit {
		t.Fatalf("expected admit, got reasons %v", d.Reasons)
	}
	if r.Blocks(d) {
		t.Error("compliant device should not be blocked")
	}
}

func TestEnterprisePresetBlocksUnmanaged(t *testing.T) {
	p := interactiveProbe()
	p.dsreg = dsregUnmanaged
	r := NewRunner(newReg(), Config{Mode: ModeEnforce, Enterprise: true}, nil)
	d := r.Evaluate(context.Background(), &Env{Sys: p})
	if d.Admit {
		t.Fatal("unmanaged device should not be admitted")
	}
	if !r.Blocks(d) {
		t.Error("enforce mode should block an unmanaged device")
	}
}

func TestAuditNeverBlocks(t *testing.T) {
	p := interactiveProbe()
	p.dsreg = dsregUnmanaged
	r := NewRunner(newReg(), Config{Mode: ModeAudit, Enterprise: true}, nil)
	d := r.Evaluate(context.Background(), &Env{Sys: p})
	if d.Admit {
		t.Error("decision should reflect the failure (admit=false)")
	}
	if r.Blocks(d) {
		t.Error("audit mode must never block")
	}
}

func TestRunContextSystemFails(t *testing.T) {
	p := interactiveProbe()
	p.rc = RunContext{IsSystem: true, SessionID: 0}
	r := NewRunner(newReg(), Config{Mode: ModeEnforce}, nil)
	d := r.Evaluate(context.Background(), &Env{Sys: p})
	if d.Admit {
		t.Error("SYSTEM context should fail the run-context guardrail")
	}
}

func TestBypassAdmits(t *testing.T) {
	p := interactiveProbe()
	p.dsreg = dsregUnmanaged
	r := NewRunner(newReg(), Config{Mode: ModeEnforce, Enterprise: true, Bypass: true, BypassNote: "break-glass"}, nil)
	d := r.Evaluate(context.Background(), &Env{Sys: p})
	if !d.Admit {
		t.Error("bypass should admit regardless of checks")
	}
	if len(d.Results) != 1 || d.Results[0].Status != Skip {
		t.Errorf("bypass should record a single skip, got %+v", d.Results)
	}
}

func TestDeviceAllowlist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.txt")
	if err := os.WriteFile(path, []byte("# devices\nSN-123\nOTHER-HOST\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := NewRunner(newReg(), Config{Mode: ModeEnforce, Extra: []string{"device-allowlist=" + path}}, nil)
	d := r.Evaluate(context.Background(), &Env{Sys: interactiveProbe()})
	if !d.Admit {
		t.Errorf("device with serial SN-123 should be allowlisted, reasons %v", d.Reasons)
	}
	// Not on the list.
	p := interactiveProbe()
	p.id = DeviceIdentity{Hostname: "WS-9", Serial: "SN-999"}
	d = r.Evaluate(context.Background(), &Env{Sys: p})
	if d.Admit {
		t.Error("device not on the allowlist should fail")
	}
}

func TestUnknownGuardrail(t *testing.T) {
	r := NewRunner(newReg(), Config{Mode: ModeEnforce, Extra: []string{"nope"}}, nil)
	if len(r.Unknown()) == 0 {
		t.Error("expected 'nope' to be reported as unknown")
	}
}

func TestParseMode(t *testing.T) {
	cases := map[string]Mode{"": ModeOff, "off": ModeOff, "audit": ModeAudit, "ENFORCE": ModeEnforce, "junk": ModeOff}
	for in, want := range cases {
		if got := ParseMode(in); got != want {
			t.Errorf("ParseMode(%q) = %q, want %q", in, got, want)
		}
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
