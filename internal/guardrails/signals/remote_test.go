package signals

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

// TestRemotePolicyRefusesPlaintextWhenEnforcing covers the Enforce HTTPS gate on
// the may-run endpoint. The request carries device identity and a bearer token, so
// a plaintext endpoint must Fail rather than Skip — skipping would let a
// misconfigured URL quietly stop being a control.
func TestRemotePolicyRefusesPlaintextWhenEnforcing(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"allow": true})
	})
	srv := httptest.NewServer(mux) // httptest.NewServer is plaintext http://
	defer srv.Close()

	check := remotePolicyCheck("secret-token")

	// Enforcing: the plaintext endpoint is refused before any request is made.
	got := check(context.Background(), &Env{Sys: fakeProbe{}, Arg: srv.URL, EnforceHTTPS: true})
	if got.Status != Fail {
		t.Errorf("plaintext endpoint under Enforce HTTPS: got %s (%s), want Fail", got.Status, got.Detail)
	}
	if !strings.Contains(got.Detail, "Enforce HTTPS") {
		t.Errorf("detail should name the setting, got %q", got.Detail)
	}

	// Not enforcing: the same endpoint is reached as before.
	got = check(context.Background(), &Env{Sys: fakeProbe{}, Arg: srv.URL})
	if got.Status != Pass {
		t.Errorf("plaintext endpoint with the setting off: got %s (%s), want Pass", got.Status, got.Detail)
	}
}

// TestRemotePolicyAllowsHTTPSWhenEnforcing confirms the gate keys on the scheme
// rather than blocking every endpoint once enforcing is on.
func TestRemotePolicyAllowsHTTPSWhenEnforcing(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"allow": true})
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	check := remotePolicyCheck("")
	got := check(context.Background(), &Env{Sys: fakeProbe{}, Arg: srv.URL, EnforceHTTPS: true})
	// The self-signed test certificate is not trusted, so the request itself
	// errors — but it must be a transport Error, not the scheme Fail above.
	if got.Status == Fail && strings.Contains(got.Detail, "Enforce HTTPS") {
		t.Errorf("an https endpoint must pass the scheme gate, got %q", got.Detail)
	}
}
