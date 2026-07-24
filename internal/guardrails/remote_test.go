package guardrails

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRemotePolicyAllowDeny(t *testing.T) {
	var gotAuth string
	var gotBody mayRunRequest
	mux := http.NewServeMux()
	var allow bool
	mux.HandleFunc("/mayrun", func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]any{"allow": allow, "reason": "policy says so"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	reg := NewRegistry()
	RegisterBuiltins(reg)
	RegisterRemotePolicy(reg, "secret-token")
	g, _ := reg.Get("remote-policy")
	check := g.Check
	env := &Env{Sys: fakeProbe{id: DeviceIdentity{Hostname: "WS-1", EntraDeviceID: "abc"}}, Arg: srv.URL + "/mayrun"}

	allow = true
	if got := check(context.Background(), env); got.Status != Pass {
		t.Errorf("allow: got %s (%s)", got.Status, got.Detail)
	}
	if gotAuth != "Bearer secret-token" {
		t.Errorf("token not presented: %q", gotAuth)
	}
	if gotBody.Device.EntraDeviceID != "abc" {
		t.Errorf("may-run body missing device identity: %+v", gotBody.Device)
	}

	allow = false
	if got := check(context.Background(), env); got.Status != Fail {
		t.Errorf("deny: got %s", got.Status)
	}
}

func TestRemotePolicyOPAShape(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// OPA data API shape: {"result": {"allow": true}}
		_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"allow": true}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	check := remotePolicyCheck("")
	env := &Env{Sys: fakeProbe{}, Arg: srv.URL}
	if got := check(context.Background(), env); got.Status != Pass {
		t.Errorf("OPA-style allow: got %s (%s)", got.Status, got.Detail)
	}
}

func TestRemotePolicySkipsWithoutURL(t *testing.T) {
	check := remotePolicyCheck("")
	if got := check(context.Background(), &Env{Sys: fakeProbe{}}); got.Status != Skip {
		t.Errorf("no URL should Skip, got %s", got.Status)
	}
}
