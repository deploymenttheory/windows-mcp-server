package signals

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// mayRunRequest is the body POSTed to an external may-run policy (PDP). It
// carries device identity and run context — not the local results — so the
// remote authority decides from its own source of truth (Intune/CMDB/etc.)
// without any dependency on the spoofable local checks.
type mayRunRequest struct {
	Device     DeviceIdentity `json:"device"`
	RunContext RunContext     `json:"run_context"`
	Hostname   string         `json:"hostname,omitempty"`
}

// mayRunResponse accepts both a flat {allow,reason} shape and an OPA-style
// {result:{allow}} document, so the endpoint can be a bespoke service or a
// plain OPA data API.
type mayRunResponse struct {
	Allow  bool   `json:"allow"`
	Reason string `json:"reason"`
	Result struct {
		Allow  bool   `json:"allow"`
		Reason string `json:"reason"`
	} `json:"result"`
}

func (r mayRunResponse) allowed() (bool, string) {
	if r.Allow || r.Result.Allow {
		return true, firstNonEmpty(r.Reason, r.Result.Reason)
	}
	return false, firstNonEmpty(r.Reason, r.Result.Reason)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// RegisterRemotePolicy overrides the built-in remote-policy provider with one
// that presents a bearer token to the may-run endpoint. Register it after
// RegisterBuiltins when a token is configured.
func RegisterRemotePolicy(reg *Registry, token string) {
	reg.Register(Guardrail{
		ID:          "remote-policy",
		Description: "External may-run policy authorizes this device (arg=url)",
		Check:       remotePolicyCheck(token),
	})
}

// remotePolicyCheck builds the remote may-run check. The endpoint URL is the
// guardrail's argument (remote-policy=<url>); an https URL is expected in
// production. A deny result flips admit and, via the periodic monitor, trips the
// kill switch.
func remotePolicyCheck(token string) CheckFunc {
	httpc := &http.Client{Timeout: 15 * time.Second}
	return func(ctx context.Context, env *Env) Result {
		endpoint := env.Arg
		if endpoint == "" {
			return skip("remote-policy", "no may-run endpoint configured")
		}
		// The may-run request carries device identity and usually a bearer token, so
		// a plaintext endpoint discloses both. Fail rather than skip: skipping would
		// let a misconfigured endpoint silently stop being a control.
		if env.EnforceHTTPS {
			u, err := url.Parse(endpoint)
			if err != nil {
				return errf("remote-policy", "bad may-run endpoint: "+err.Error())
			}
			if strings.EqualFold(u.Scheme, "http") {
				return fail("remote-policy",
					"may-run endpoint is plaintext http:// and Enforce HTTPS is on; "+
						"it would disclose device identity and the bearer token")
			}
		}
		id := env.Sys.DeviceIdentity()
		body, _ := json.Marshal(mayRunRequest{Device: id, RunContext: env.Sys.RunContext(), Hostname: id.Hostname})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return errf("remote-policy", "bad may-run endpoint: "+err.Error())
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := httpc.Do(req)
		if err != nil {
			// Fail-closed on transport error is enforced by the caller's mode;
			// report Error so audit records the outage.
			return errf("remote-policy", "may-run request failed: "+err.Error())
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fail("remote-policy", fmt.Sprintf("may-run endpoint returned HTTP %d", resp.StatusCode))
		}
		var out mayRunResponse
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return errf("remote-policy", "cannot parse may-run response: "+err.Error())
		}
		if ok, reason := out.allowed(); ok {
			return pass("remote-policy", "authorized by may-run endpoint"+suffix(reason))
		} else {
			return fail("remote-policy", "may-run denied"+suffix(reason))
		}
	}
}

func suffix(reason string) string {
	if reason == "" {
		return ""
	}
	return ": " + reason
}
