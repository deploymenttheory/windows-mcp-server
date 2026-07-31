package signals

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// graphStatusServer answers the token endpoint normally and every device lookup
// with the given HTTP status, so a check runs its "unexpected status" path.
func graphStatusServer(t *testing.T, status int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "fake-token", "expires_in": 3600})
	})
	mux.HandleFunc("/devices", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
	})
	mux.HandleFunc("/deviceManagement/managedDevices", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestGraphStatusIsNotDeviceNotFound pins the distinction the two sentinels
// exist to draw. An unexpected HTTP status means the check could not reach a
// verdict; "device absent from the directory" means it reached a negative one.
// Collapsing them would let a throttled or misconfigured tenant read as "this
// device is not registered", which is a policy answer the response never gave.
func TestGraphStatusIsNotDeviceNotFound(t *testing.T) {
	c := graphClientFor(graphStatusServer(t, http.StatusTooManyRequests))

	if _, err := c.entraDevice(context.Background(), "abc"); !errors.Is(err, ErrGraphStatus) {
		t.Errorf("entraDevice on HTTP 429: want ErrGraphStatus, got %v", err)
	} else if errors.Is(err, ErrDeviceNotInGraph) {
		t.Error("an unexpected status must not match ErrDeviceNotInGraph")
	}

	if _, err := c.intuneDevice(context.Background(), "abc"); !errors.Is(err, ErrGraphStatus) {
		t.Errorf("intuneDevice on HTTP 429: want ErrGraphStatus, got %v", err)
	}
}

// TestGraphStatusReportsErrorNotFail: the check surfaces an inconclusive result
// (Error), never Fail. Under a blocking guardrail preset the difference decides
// whether a tenant-side outage blocks every startup on the fleet.
func TestGraphStatusReportsErrorNotFail(t *testing.T) {
	c := graphClientFor(graphStatusServer(t, http.StatusServiceUnavailable))
	env := envWithDevice("abc")

	for name, got := range map[string]Result{
		"entra-registered": c.checkEntraRegistered(context.Background(), env),
		"entra-compliant":  c.checkEntraCompliant(context.Background(), env),
		"intune-enrolled":  c.checkIntuneEnrolled(context.Background(), env),
		"intune-compliant": c.checkIntuneCompliant(context.Background(), env),
	} {
		if got.Status != Error {
			t.Errorf("%s on HTTP 503: want Error, got %s (%s)", name, got.Status, got.Detail)
		}
	}
}

// TestGraphStatusErrorCarriesTheCode keeps the status code in the message: an
// operator triaging a failed startup needs to tell 401 from 429.
func TestGraphStatusErrorCarriesTheCode(t *testing.T) {
	c := graphClientFor(graphStatusServer(t, http.StatusUnauthorized))
	_, err := c.entraDevice(context.Background(), "abc")
	if err == nil {
		t.Fatal("want an error for HTTP 401")
	}
	if want := "401"; !strings.Contains(err.Error(), want) {
		t.Errorf("error %q should mention %s", err, want)
	}
}
