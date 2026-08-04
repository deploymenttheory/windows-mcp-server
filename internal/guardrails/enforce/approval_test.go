package enforce

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/audit"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/signals"
)

// reply is a small helper to answer a webhook call with a decision.
// testApprovalKey is the shared secret these tests sign replies with. A reply is
// only a decision if it authenticates, so the fake webhook has to hold a key just
// as a real one does.
var testApprovalKey = []byte("test-approval-key")

// reply writes a signed webhook reply for request id "r", which is what every
// test in this file uses.
func reply(w http.ResponseWriter, decision, approver string) {
	replyFor(w, "r", decision, approver)
}

// replyFor writes a reply signed for a specific request id, so a test can forge a
// mismatch deliberately.
func replyFor(w http.ResponseWriter, requestID, decision, approver string) {
	r := webhookReply{Decision: decision, Approver: approver, RequestID: requestID}
	if decision != "pending" {
		r.Signature = signBody(testApprovalKey, []byte(requestID+"|"+decision))
	}
	_ = json.NewEncoder(w).Encode(r)
}

func testClient(url string, key []byte) *ApprovalClient {
	if key == nil {
		key = testApprovalKey
	}
	return NewApprovalClient(ApprovalConfig{
		WebhookURL:   url,
		Timeout:      2 * time.Second,
		PollInterval: 10 * time.Millisecond,
		HMACKey:      key,
	})
}

func TestApprovalClientDecisions(t *testing.T) {
	t.Run("approve", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			reply(w, "approve", "alice")
		}))
		defer srv.Close()
		d := testClient(srv.URL, nil).Await(context.Background(), ApprovalRequest{RequestID: "r"})
		if d.Outcome != OutcomeApprove || d.Approver != "alice" {
			t.Fatalf("got %+v", d)
		}
	})

	t.Run("deny", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			reply(w, "deny", "bob")
		}))
		defer srv.Close()
		if d := testClient(srv.URL, nil).Await(context.Background(), ApprovalRequest{RequestID: "r"}); d.Outcome != OutcomeDeny {
			t.Fatalf("got %+v", d)
		}
	})

	t.Run("pending then approve on poll", func(t *testing.T) {
		var calls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if calls.Add(1) == 1 {
				reply(w, "pending", "")
				return
			}
			reply(w, "approve", "carol")
		}))
		defer srv.Close()
		d := testClient(srv.URL, nil).Await(context.Background(), ApprovalRequest{RequestID: "r"})
		if d.Outcome != OutcomeApprove {
			t.Fatalf("a pending decision should resolve on a later poll, got %+v", d)
		}
		if calls.Load() < 2 {
			t.Errorf("expected at least one poll after the initial POST, calls=%d", calls.Load())
		}
	})

	t.Run("unresolved decision times out and fails closed", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			reply(w, "pending", "")
		}))
		defer srv.Close()
		c := NewApprovalClient(ApprovalConfig{
			WebhookURL: srv.URL, Timeout: 120 * time.Millisecond, PollInterval: 20 * time.Millisecond,
		})
		if d := c.Await(context.Background(), ApprovalRequest{RequestID: "r"}); d.Outcome != OutcomeTimeout {
			t.Fatalf("an unresolved decision must time out, got %+v", d)
		}
	})

	t.Run("unreachable webhook fails closed as an error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		url := srv.URL
		srv.Close() // nothing is listening now
		if d := testClient(url, nil).Await(context.Background(), ApprovalRequest{RequestID: "r"}); d.Outcome != OutcomeError {
			t.Fatalf("an unreachable webhook must fail closed as an error, got %+v", d)
		}
	})

	t.Run("non-2xx is an error, not a silent pending", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()
		if d := testClient(srv.URL, nil).Await(context.Background(), ApprovalRequest{RequestID: "r"}); d.Outcome != OutcomeError {
			t.Fatalf("a 500 must not be read as approval, got %+v", d)
		}
	})

	t.Run("cancelled context stops waiting", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			reply(w, "pending", "")
		}))
		defer srv.Close()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if d := testClient(srv.URL, nil).Await(ctx, ApprovalRequest{RequestID: "r"}); d.Outcome == OutcomeApprove {
			t.Fatalf("a cancelled wait must not approve, got %+v", d)
		}
	})
}

// TestApprovalRequestIsSignedAndDigested checks the webhook can authenticate the
// request via the HMAC header and that only a digest of the arguments travels.
func TestApprovalRequestIsSignedAndDigested(t *testing.T) {
	// The same key signs the request and the reply, as a real deployment does.
	key := testApprovalKey
	var sawSecret, verified atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "SUPERSECRET") {
			sawSecret.Store(true)
		}
		want := hmacHex(key, body)
		if hmac.Equal([]byte(r.Header.Get(SignatureHeader)), []byte(want)) {
			verified.Store(true)
		}
		reply(w, "approve", "alice")
	}))
	defer srv.Close()

	req := ApprovalRequest{RequestID: "r", Tool: "PowerShell", ArgsDigest: "abc123"}
	if d := testClient(srv.URL, key).Await(context.Background(), req); d.Outcome != OutcomeApprove {
		t.Fatalf("got %+v", d)
	}
	if !verified.Load() {
		t.Error("the webhook must be able to verify the HMAC signature")
	}
	if sawSecret.Load() {
		t.Error("the request body must never carry raw arguments")
	}
}

func hmacHex(key, body []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

// --- middleware integration ---

// fakeApprover returns a fixed outcome and records the request it saw.
type fakeApprover struct {
	outcome Outcome
	calls   atomic.Int32
	gotReq  ApprovalRequest
}

func (f *fakeApprover) Await(_ context.Context, req ApprovalRequest) Decision {
	f.calls.Add(1)
	f.gotReq = req
	return Decision{Outcome: f.outcome, Approver: "bob", Detail: "test"}
}

const holdPolicy = `{
  "version": 1, "mode": "enforce",
  "signals": { "bitlocker": { "ttl": "0s" } },
  "rules": [ { "name": "gate", "match": { "toolset": "*" }, "require": ["bitlocker"], "on_fail": "hold" } ],
  "approvals": { "webhook_url": "https://approver.example/hook" }
}`

func newApprovalHarness(t *testing.T, outcome Outcome, status signals.Status) (*enforceHarness, *fakeApprover) {
	t.Helper()
	e := newTestEngine(t, holdPolicy, map[string]signals.Status{"bitlocker": status})
	fa := &fakeApprover{outcome: outcome}
	h := &enforceHarness{engine: e, dest: &memDest{}}
	next := func(context.Context, string, mcp.Request) (mcp.Result, error) {
		h.reached.Add(1)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}, nil
	}
	h.handler = Middleware(e, EnforcerDeps{
		Audit:    audit.NewAuditLog(h.dest),
		Approver: fa,
		Kill:     func(string) { h.kills.Add(1) },
	})(next)
	return h, fa
}

func TestHoldVerdictProceedsWhenApproved(t *testing.T) {
	h, fa := newApprovalHarness(t, OutcomeApprove, signals.Fail)

	res, err := h.call("tools/call", &mcp.CallToolParamsRaw{
		Name: "PowerShell", Arguments: []byte(`{"command":"SUPERSECRET"}`),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctr, ok := res.(*mcp.CallToolResult); !ok || ctr.IsError {
		t.Fatalf("an approved call must pass, got %T %+v", res, res)
	}
	if h.reached.Load() != 1 {
		t.Error("an approved call must reach the handler")
	}
	if fa.calls.Load() != 1 {
		t.Error("the approver should have been asked exactly once")
	}
	// The request identifies the call by digest, never by raw arguments.
	if fa.gotReq.Tool != "PowerShell" || fa.gotReq.ArgsDigest == "" {
		t.Errorf("approval request = %+v, want the tool named and args digested", fa.gotReq)
	}
	events := h.events()
	if !slices.Contains(events, "approval.requested") || !slices.Contains(events, "approval.decided") {
		t.Errorf("an approved call must audit request and decision, got %v", events)
	}
	if events[0] != "policy.decided" {
		t.Errorf("the verdict must be recorded before the approval handshake, got %v", events)
	}
	for _, e := range h.dest.entries {
		if strings.Contains(string(e.Payload), "SUPERSECRET") {
			t.Fatalf("no audit record may carry the raw argument: %s", e.Payload)
		}
	}
}

func TestHoldVerdictRefusedOnDeny(t *testing.T) {
	h, _ := newApprovalHarness(t, OutcomeDeny, signals.Fail)

	res, err := h.call("tools/call", &mcp.CallToolParamsRaw{Name: "PowerShell"})
	if err != nil {
		t.Fatalf("a denial must be an IsError result, not a Go error: %v", err)
	}
	if ctr, ok := res.(*mcp.CallToolResult); !ok || !ctr.IsError {
		t.Fatalf("a denied approval must refuse the call, got %T %+v", res, res)
	}
	if h.reached.Load() != 0 {
		t.Error("a denied call must not reach the handler")
	}
	if !slices.Contains(h.events(), "approval.decided") {
		t.Errorf("a denial must be audited approval.decision, got %v", h.events())
	}
}

func TestHoldVerdictRefusedOnTimeout(t *testing.T) {
	h, _ := newApprovalHarness(t, OutcomeTimeout, signals.Fail)

	if _, err := h.call("tools/call", &mcp.CallToolParamsRaw{Name: "PowerShell"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.reached.Load() != 0 {
		t.Error("a timed-out call must not reach the handler")
	}
	if !slices.Contains(h.events(), "approval.timed_out") {
		t.Errorf("a timeout must be audited distinctly, got %v", h.events())
	}
}

func TestHoldIsNotAskedWhenTheDevicePasses(t *testing.T) {
	h, fa := newApprovalHarness(t, OutcomeApprove, signals.Pass)

	if _, err := h.call("tools/call", &mcp.CallToolParamsRaw{Name: "PowerShell"}); err != nil {
		t.Fatal(err)
	}
	if h.reached.Load() != 1 {
		t.Error("a passing device must let the call through without approval")
	}
	if fa.calls.Load() != 0 {
		t.Error("no approval should be sought when the signal passes")
	}
	if events := h.events(); len(events) != 1 || events[0] != "policy.decided" {
		t.Errorf("a passing call needs only the decision record, got %v", events)
	}
}

// TestHoldWithNoApproverFailsClosed: if an hold verdict somehow reaches the
// middleware with no approver wired, it must refuse rather than fall through.
func TestHoldWithNoApproverFailsClosed(t *testing.T) {
	e := newTestEngine(t, holdPolicy, map[string]signals.Status{"bitlocker": signals.Fail})
	h := &enforceHarness{engine: e, dest: &memDest{}}
	next := func(context.Context, string, mcp.Request) (mcp.Result, error) {
		h.reached.Add(1)
		return &mcp.CallToolResult{}, nil
	}
	h.handler = Middleware(e, EnforcerDeps{Audit: audit.NewAuditLog(h.dest)})(next) // no Approver

	res, err := h.call("tools/call", &mcp.CallToolParamsRaw{Name: "PowerShell"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctr, ok := res.(*mcp.CallToolResult); !ok || !ctr.IsError {
		t.Fatalf("a missing approver must refuse, got %T %+v", res, res)
	}
	if h.reached.Load() != 0 {
		t.Error("a call with no approver must not reach the handler")
	}
}

// TestUnauthenticatedRepliesAreRefused is a regression test for the control that
// gates the riskiest calls. The request was HMAC-signed, but the reply was not
// authenticated at all: any 2xx body saying {"decision":"approve"} was obeyed. An
// attacker who could answer the endpoint -- or sit on the path of a plaintext
// one -- could approve any held call, and the audit chain would record a
// legitimate-looking approval.decided.
func TestUnauthenticatedRepliesAreRefused(t *testing.T) {
	cases := []struct {
		name  string
		write func(w http.ResponseWriter)
	}{
		{"unsigned approval", func(w http.ResponseWriter) {
			_ = json.NewEncoder(w).Encode(webhookReply{Decision: "approve", Approver: "mallory", RequestID: "r"})
		}},
		{"wrong signature", func(w http.ResponseWriter) {
			_ = json.NewEncoder(w).Encode(webhookReply{
				Decision: "approve", RequestID: "r", Signature: "00deadbeef",
			})
		}},
		{"signed for a different request", func(w http.ResponseWriter) {
			replyFor(w, "some-other-request", "approve", "mallory")
		}},
		{"signature over the wrong decision", func(w http.ResponseWriter) {
			_ = json.NewEncoder(w).Encode(webhookReply{
				Decision:  "approve",
				RequestID: "r",
				Signature: signBody(testApprovalKey, []byte("r|deny")),
			})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				tc.write(w)
			}))
			defer srv.Close()
			d := testClient(srv.URL, nil).Await(context.Background(), ApprovalRequest{RequestID: "r"})
			if d.Outcome == OutcomeApprove {
				t.Fatalf("an unauthenticated reply must never approve; got %+v", d)
			}
		})
	}
}

// TestApprovalWithoutAKeyCannotApprove pins the fail-closed default. With no
// WINDOWS_MCP_APPROVAL_KEY there is nothing to verify a reply against, so a hold
// must refuse rather than trust whatever answered.
func TestApprovalWithoutAKeyCannotApprove(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(webhookReply{Decision: "approve", RequestID: "r"})
	}))
	defer srv.Close()

	c := NewApprovalClient(ApprovalConfig{
		WebhookURL: srv.URL, Timeout: time.Second, PollInterval: 10 * time.Millisecond,
	})
	if d := c.Await(context.Background(), ApprovalRequest{RequestID: "r"}); d.Outcome == OutcomeApprove {
		t.Fatalf("an unkeyed client must not approve; got %+v", d)
	}
}
