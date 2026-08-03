package enforce

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/audit"
)

// Outcome is how an approval request resolved.
type Outcome string

const (
	// OutcomeApprove is the only outcome that lets the call proceed.
	OutcomeApprove Outcome = "approve"
	// OutcomeDeny is an explicit refusal by the authoriser.
	OutcomeDeny Outcome = "deny"
	// OutcomeTimeout is the deadline passing with no decision: dual control fails
	// closed, so this refuses too, but it is audited distinctly so an operator can
	// tell "a human said no" from "no human answered".
	OutcomeTimeout Outcome = "timeout"
	// OutcomeError is the webhook being unreachable or answering unintelligibly. It
	// also refuses — an approval channel that is down must not become an open door.
	OutcomeError Outcome = "error"
)

// ApprovalRequest is what the enforcement point sends to the authoriser. It
// carries identifiers and a digest, never the raw arguments — the webhook decides
// on the shape of the call, not its contents, the same discipline the audit chain
// follows.
type ApprovalRequest struct {
	RequestID     string    `json:"request_id"`
	SessionID     string    `json:"session_id,omitempty"`
	Method        string    `json:"method,omitempty"`
	Tool          string    `json:"tool,omitempty"`
	ArgsDigest    string    `json:"args_sha256,omitempty"`
	Rules         []string  `json:"rules,omitempty"`
	FailedSignals []string  `json:"failed_signals,omitempty"`
	Reason        string    `json:"reason,omitempty"`
	RequestedAt   time.Time `json:"requested_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// Decision is the resolved answer for one ApprovalRequest.
type Decision struct {
	Outcome  Outcome
	Approver string
	Detail   string
}

// Approver adjudicates an approve verdict out of band. Await blocks until the
// external authority decides, the deadline passes, or ctx is cancelled (a kill
// stop), and reports the outcome. It never returns OutcomeApprove on doubt.
type Approver interface {
	Await(ctx context.Context, req ApprovalRequest) Decision
}

// webhookReply is the authoriser's response to a POST or a poll.
type webhookReply struct {
	// Decision is "approve", "deny" or "pending". Anything else is treated as an
	// error, since an approval channel that speaks a language we do not is not one
	// we can safely read as a yes.
	Decision string `json:"decision"`
	Approver string `json:"approver,omitempty"`
	// PollURL, when the decision is pending, is where to GET for the resolved
	// answer. Absent, we re-POST the original request to the webhook instead.
	PollURL string `json:"poll_url,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// ApprovalClient asks a webhook to authorise a call and, while the answer is
// pending, polls until it resolves or the deadline passes.
//
// It holds no inbound listener: the request is solicited outbound, which is what
// lets dual control exist without breaking the stdio-only posture. It is pure net
// and crypto, so it is testable against an httptest server with no MCP transport.
type ApprovalClient struct {
	httpClient   *http.Client
	webhookURL   string
	timeout      time.Duration
	pollInterval time.Duration
	hmacKey      []byte
	logger       *slog.Logger
	// now is injectable so a test can pin the deadline; production uses the real clock.
	now func() time.Time
}

// ApprovalConfig configures an ApprovalClient.
type ApprovalConfig struct {
	WebhookURL   string
	Timeout      time.Duration
	PollInterval time.Duration
	// HMACKey signs each request body so the webhook can authenticate it. Empty
	// leaves requests unsigned (the client logs a warning once at construction).
	HMACKey []byte
	Logger  *slog.Logger
}

// SignatureHeader carries the hex HMAC-SHA256 of the request body.
const SignatureHeader = "X-WindowsMCP-Signature"

// errWebhookStatus is the base for a non-2xx webhook response, wrapped with the
// actual code so the failure is a static sentinel with dynamic detail.
var errWebhookStatus = errors.New("approval webhook returned a non-2xx status")

// NewApprovalClient builds a client from config, applying the package defaults for
// any timing left zero.
func NewApprovalClient(cfg ApprovalConfig) *ApprovalClient {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if len(cfg.HMACKey) == 0 {
		logger.Warn("approval requests are unsigned: set WINDOWS_MCP_APPROVAL_KEY so the webhook can authenticate them")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	poll := cfg.PollInterval
	if poll <= 0 {
		poll = 5 * time.Second
	}
	return &ApprovalClient{
		// Per-request timeout well under the overall approval timeout: one slow HTTP
		// call must not consume the whole budget, so polling can keep trying.
		httpClient:   &http.Client{Timeout: 30 * time.Second},
		webhookURL:   cfg.WebhookURL,
		timeout:      timeout,
		pollInterval: poll,
		hmacKey:      cfg.HMACKey,
		logger:       logger,
		now:          time.Now,
	}
}

// Await runs the full handshake: POST the request, and while the answer is pending
// poll until it resolves, the deadline passes, or ctx is cancelled.
func (c *ApprovalClient) Await(ctx context.Context, req ApprovalRequest) Decision {
	deadline := req.ExpiresAt
	if deadline.IsZero() {
		deadline = c.now().Add(c.timeout)
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	reply, err := c.post(ctx, c.webhookURL, req)
	if err != nil {
		return c.failClosed(ctx, req, err)
	}

	for {
		switch reply.Decision {
		case "approve":
			return Decision{Outcome: OutcomeApprove, Approver: reply.Approver, Detail: reply.Detail}
		case "deny":
			return Decision{Outcome: OutcomeDeny, Approver: reply.Approver, Detail: reply.Detail}
		case "pending":
			// keep polling below
		default:
			return Decision{
				Outcome: OutcomeError,
				Detail:  "approval webhook returned an unknown decision " + reply.Decision,
			}
		}

		select {
		case <-ctx.Done():
			return c.failClosed(ctx, req, ctx.Err())
		case <-time.After(c.pollInterval):
		}

		target := reply.PollURL
		next, err := c.poll(ctx, target, req)
		if err != nil {
			return c.failClosed(ctx, req, err)
		}
		reply = next
	}
}

// failClosed turns a transport error or a passed deadline into a refusal, telling
// timeout apart from a genuine error so the caller can audit them distinctly.
func (c *ApprovalClient) failClosed(ctx context.Context, _ ApprovalRequest, cause error) Decision {
	if ctx.Err() != nil {
		return Decision{Outcome: OutcomeTimeout, Detail: "no approval decision before the deadline"}
	}
	c.logger.Warn("approval webhook error; failing closed", "error", cause)
	return Decision{Outcome: OutcomeError, Detail: "approval webhook unreachable: " + cause.Error()}
}

// post sends the request body to url and decodes the reply.
func (c *ApprovalClient) post(ctx context.Context, url string, req ApprovalRequest) (webhookReply, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return webhookReply{}, fmt.Errorf("marshal approval request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return webhookReply{}, fmt.Errorf("build approval request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if len(c.hmacKey) > 0 {
		httpReq.Header.Set(SignatureHeader, signBody(c.hmacKey, body))
	}
	return c.do(httpReq)
}

// poll re-solicits a pending decision. A poll URL is used with a GET; absent one,
// the original request is re-POSTed to the webhook.
func (c *ApprovalClient) poll(ctx context.Context, pollURL string, req ApprovalRequest) (webhookReply, error) {
	if pollURL == "" {
		return c.post(ctx, c.webhookURL, req)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, pollURL, nil)
	if err != nil {
		return webhookReply{}, fmt.Errorf("build approval poll: %w", err)
	}
	return c.do(httpReq)
}

// do executes an HTTP request and decodes the JSON reply, treating any non-2xx as
// an error so a webhook's 500 is not read as a silent pending.
func (c *ApprovalClient) do(httpReq *http.Request) (webhookReply, error) {
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return webhookReply{}, fmt.Errorf("approval webhook request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	// Cap the body: an approval reply is tiny, and an approver that streams
	// megabytes must not be able to exhaust memory on the request path.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return webhookReply{}, fmt.Errorf("read approval reply: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return webhookReply{}, fmt.Errorf("%w: %d", errWebhookStatus, resp.StatusCode)
	}
	var reply webhookReply
	if err := json.Unmarshal(raw, &reply); err != nil {
		return webhookReply{}, fmt.Errorf("decode approval reply: %w", err)
	}
	return reply, nil
}

// signBody returns the hex HMAC-SHA256 of body under key.
func signBody(key, body []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

// NewRequestID mints an opaque request id for callers building an ApprovalRequest
// outside this package (the plan executor). It shares randomID's properties.
func NewRequestID() string { return randomID() }

// randomID mints an opaque request id. crypto/rand rather than a counter so ids do
// not leak call volume and cannot be predicted by a webhook.
func randomID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand.Read does not fail in practice; fall back to a time-derived id so a
		// request still has some identifier rather than an empty one.
		return "req-" + time.Now().Format("20060102150405.000000000")
	}
	return "req-" + hex.EncodeToString(b[:])
}

// Adjudicate runs one approval to completion around the audit chain: it records the
// request, blocks on the approver, and records the outcome (a timeout distinctly),
// returning the decision. Both approver and auditLog must be non-nil.
//
// It is shared by the enforcement middleware and the plan executor so a suspended
// direct call and a suspended plan step leave the same pair of records in the
// chain.
func Adjudicate(ctx context.Context, approver Approver, auditLog *audit.AuditLog, req ApprovalRequest) Decision {
	if auditLog != nil {
		_, _ = auditLog.Append("approval.requested", map[string]any{
			"request_id":     req.RequestID,
			"subject":        approvalSubject(req),
			"rules":          req.Rules,
			"failed_signals": req.FailedSignals,
			"args_sha256":    req.ArgsDigest,
		})
	}
	d := approver.Await(ctx, req)
	if auditLog != nil {
		event := "approval.decision"
		if d.Outcome == OutcomeTimeout {
			event = "approval.timeout"
		}
		_, _ = auditLog.Append(event, map[string]any{
			"request_id": req.RequestID,
			"subject":    approvalSubject(req),
			"outcome":    string(d.Outcome),
			"approver":   d.Approver,
			"detail":     d.Detail,
		})
	}
	return d
}

// approvalSubject renders a request for the audit record, matching the verdict
// subject shape ("method tool") the rest of the chain uses.
func approvalSubject(req ApprovalRequest) string {
	if req.Tool != "" {
		if req.Method != "" {
			return req.Method + " " + req.Tool
		}
		return req.Tool
	}
	return req.Method
}
