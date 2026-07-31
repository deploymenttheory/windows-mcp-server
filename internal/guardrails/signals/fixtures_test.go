package signals

import (
	"context"
	"encoding/json"
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

// TestDecisionJSONRoundTrips guards the shape of the document surfaced three
// ways: the audit record, the status payload, and `policy check`.
func TestDecisionJSONRoundTrips(t *testing.T) {
	d := Decision{
		Device:  DeviceIdentity{Hostname: "H"},
		Mode:    "enforce",
		Admit:   false,
		Reasons: []string{"x"},
		Results: []Result{{ID: "run-context", Status: Pass}},
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var back Decision
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Admit || back.Mode != "enforce" || len(back.Results) != 1 {
		t.Errorf("round-trip mismatch: %+v", back)
	}
}
