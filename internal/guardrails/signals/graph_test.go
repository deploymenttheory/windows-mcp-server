package signals

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// graphStub emulates the token endpoint plus /devices and /managedDevices.
type graphStub struct {
	entra  *entraDevice
	intune *intuneDevice
	calls  int
}

func (g *graphStub) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "fake-token", "expires_in": 3600})
	})
	mux.HandleFunc("/devices", func(w http.ResponseWriter, r *http.Request) {
		g.calls++
		out := map[string]any{"value": []any{}}
		if g.entra != nil {
			out["value"] = []*entraDevice{g.entra}
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("/deviceManagement/managedDevices", func(w http.ResponseWriter, r *http.Request) {
		g.calls++
		out := map[string]any{"value": []any{}}
		if g.intune != nil {
			out["value"] = []*intuneDevice{g.intune}
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func graphClientFor(srv *httptest.Server) *GraphClient {
	return NewGraphClient(GraphConfig{
		TenantID: "t", ClientID: "c", ClientSecret: "s",
		Base:     srv.URL,
		TokenURL: srv.URL + "/token",
	})
}

// envWithDevice returns an Env whose probe reports a known Entra device ID.
func envWithDevice(id string) *Env {
	return &Env{Sys: fakeProbe{id: DeviceIdentity{EntraDeviceID: id, Hostname: "H"}}}
}

func TestGraphEntraCompliant(t *testing.T) {
	stub := &graphStub{
		entra: &entraDevice{
			DeviceID:       "abc",
			DisplayName:    "PC1",
			IsCompliant:    true,
			AccountEnabled: true,
			TrustType:      "AzureAd",
		},
	}
	c := graphClientFor(stub.server(t))
	if got := c.checkEntraCompliant(context.Background(), envWithDevice("abc")); got.Status != Pass {
		t.Errorf("compliant device: got %s (%s)", got.Status, got.Detail)
	}

	stub.entra.IsCompliant = false
	if got := c.checkEntraCompliant(context.Background(), envWithDevice("abc")); got.Status != Fail {
		t.Errorf("non-compliant device: got %s", got.Status)
	}
}

func TestGraphEntraNotFound(t *testing.T) {
	stub := &graphStub{entra: nil}
	c := graphClientFor(stub.server(t))
	got := c.checkEntraRegistered(context.Background(), envWithDevice("missing"))
	if got.Status != Fail || !strings.Contains(got.Detail, "not found") {
		t.Errorf("missing device should Fail with not-found, got %s (%s)", got.Status, got.Detail)
	}
}

func TestGraphIntuneComplianceAndEnrollment(t *testing.T) {
	stub := &graphStub{
		intune: &intuneDevice{
			AzureADDeviceID:      "abc",
			DeviceName:           "PC1",
			ComplianceState:      "compliant",
			ManagementState:      "managed",
			DeviceEnrollmentType: "azureADJoin",
		},
	}
	c := graphClientFor(stub.server(t))
	if got := c.checkIntuneEnrolled(context.Background(), envWithDevice("abc")); got.Status != Pass {
		t.Errorf("enrolled: got %s (%s)", got.Status, got.Detail)
	}
	if got := c.checkIntuneCompliant(context.Background(), envWithDevice("abc")); got.Status != Pass {
		t.Errorf("compliant: got %s (%s)", got.Status, got.Detail)
	}
	stub.intune.ComplianceState = "noncompliant"
	if got := c.checkIntuneCompliant(context.Background(), envWithDevice("abc")); got.Status != Fail {
		t.Errorf("noncompliant should Fail, got %s", got.Status)
	}
}

func TestGraphAttestation(t *testing.T) {
	stub := &graphStub{
		intune: &intuneDevice{
			AzureADDeviceID:         "abc",
			DeviceHealthAttestation: &healthAttestation{SecureBoot: "Enabled", BitLockerStatus: "Enabled"},
		},
	}
	c := graphClientFor(stub.server(t))
	if got := c.checkAttested(context.Background(), envWithDevice("abc")); got.Status != Pass {
		t.Errorf("healthy attestation: got %s (%s)", got.Status, got.Detail)
	}
	stub.intune.DeviceHealthAttestation.SecureBoot = "Disabled"
	if got := c.checkAttested(context.Background(), envWithDevice("abc")); got.Status != Fail {
		t.Errorf("secure boot off should Fail, got %s", got.Status)
	}
	stub.intune.DeviceHealthAttestation = nil
	if got := c.checkAttested(context.Background(), envWithDevice("abc")); got.Status != Skip {
		t.Errorf("no attestation state should Skip, got %s", got.Status)
	}
}

// TestGraphRegistersItsSignals checks the Graph signals become available for a
// policy to declare. Registering only makes a signal available; whether it is
// evaluated is the policy's decision, so there is nothing else to assert here.
func TestGraphRegistersItsSignals(t *testing.T) {
	reg := NewRegistry()
	RegisterBuiltins(reg)
	RegisterGraph(reg, NewGraphClient(GraphConfig{TenantID: "t", ClientID: "c", ClientSecret: "s"}))

	joined := strings.Join(reg.IDs(), ",")
	for _, want := range []string{"graph-entra-compliant", "graph-intune-compliant", "graph-intune-enrolled"} {
		if !strings.Contains(joined, want) {
			t.Errorf("registry is missing %s (have %s)", want, joined)
		}
	}
}
