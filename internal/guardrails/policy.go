package guardrails

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// CircuitConfig configures the inline tool-call policy / circuit breaker.
type CircuitConfig struct {
	Enabled   bool
	Window    time.Duration // sliding window (default 10s)
	Threshold int           // sensitive calls in window before tripping (default 3)
	Logger    *slog.Logger
	OnTrip    func(reason string) // fires the kill switch
}

func (c CircuitConfig) withDefaults() CircuitConfig {
	if c.Window <= 0 {
		c.Window = 10 * time.Second
	}
	if c.Threshold <= 0 {
		c.Threshold = 3
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	return c
}

// sensitiveTools are state-changing / high-risk tools counted by the breaker.
var sensitiveTools = map[string]bool{
	"Credentials": true,
	"PowerShell":  true, "Registry": true, "Process": true,
	"Service": true, "FileSystem": true, "App": true,
}

// tripwireSubstrings, if found (case-insensitively) in a tool call's arguments,
// indicate an attempt to remove a device protection — an immediate trip. This
// is a heuristic; the periodic posture monitor is the authoritative detector.
var tripwireSubstrings = []string{
	"disablerealtimemonitoring",
	"set-mppreference -disable",
	"stop-service", "windefend", "sense", // Defender / MDE service names
	"advfirewall set allprofiles state off",
	"set-netfirewallprofile -enabled false",
	"disable-bitlocker", "manage-bde -off",
	"clouddomainjoin", `\enrollments`, "deviceenroller",
}

// ToolPolicyMiddleware returns MCP receiving middleware that classifies each
// tools/call, rate-limits sensitive calls, and trips on destructive tripwire
// patterns. It runs on the receiving path so the agent cannot bypass it.
func ToolPolicyMiddleware(cfg CircuitConfig) mcp.Middleware {
	cfg = cfg.withDefaults()
	var mu sync.Mutex
	var hits []time.Time

	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			// resources/read returns desktop and system state to the caller, so it is
			// a data-egress path and belongs under the same rate limit as a sensitive
			// tool. Without this it would be an unthrottled way to pull the same
			// information the Snapshot and SystemInfo tools are throttled for.
			if method == "resources/read" {
				if p, ok := req.GetParams().(*mcp.ReadResourceParams); ok {
					if msg, blocked := countSensitive(&mu, &hits, cfg, "resource:"+p.URI); blocked {
						return nil, blockedError(msg)
					}
				}
				return next(ctx, method, req)
			}
			// subscriptions/listen (2026-07-28, SEP-2575) opens a long-lived
			// server-to-client stream in place of the HTTP GET stream and
			// resources/subscribe. It is counted once, at open: the stream is a
			// standing egress channel, and opening many of them is exactly the
			// pattern the window exists to notice.
			if method == "subscriptions/listen" {
				if msg, blocked := countSensitive(&mu, &hits, cfg, "subscriptions/listen"); blocked {
					return nil, blockedError(msg)
				}
				return next(ctx, method, req)
			}
			// server/discover is deliberately NOT counted. It replaced the initialize
			// handshake, carries no server state, and a client may legitimately probe
			// it before every request under the stateless protocol — rate-limiting it
			// would break conformant clients rather than contain a hostile one. It is
			// audited instead.
			if method != "tools/call" {
				return next(ctx, method, req)
			}
			name, args := toolNameArgs(req)

			// Content tripwire: high-risk protection-removal attempt.
			if pat := matchTripwire(args); pat != "" {
				cfg.Logger.Error("guardrail.circuit_trip", "reason", "tripwire", "tool", name, "pattern", pat)
				if cfg.OnTrip != nil {
					cfg.OnTrip(fmt.Sprintf("tripwire %q via %s", pat, name))
				}
				if cfg.Enabled {
					return blockedResult("attempt to remove a device protection was blocked"), nil
				}
			}

			// Rate-based circuit breaker over sensitive tools.
			if sensitiveTools[name] {
				if msg, blocked := countSensitive(&mu, &hits, cfg, name); blocked {
					return blockedResult(msg), nil
				}
			}

			return next(ctx, method, req)
		}
	}
}

// countSensitive records one sensitive invocation in the sliding window and
// reports whether the threshold is reached, with the message to refuse with.
//
// Shared by the tools/call, resources/read and subscriptions/listen paths so all
// are counted against the *same* window: an agent must not be able to stay under
// the limit by alternating between a tool and a resource that expose the same
// data, or by moving to a subscription stream.
//
// It returns the message rather than a built result because how a block is
// expressed depends on the method — see blockedResult and blockedError.
func countSensitive(mu *sync.Mutex, hits *[]time.Time, cfg CircuitConfig, subject string) (string, bool) {
	mu.Lock()
	now := time.Now()
	cutoff := now.Add(-cfg.Window)
	kept := (*hits)[:0]
	for _, t := range *hits {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	*hits = kept
	count := len(kept)
	mu.Unlock()

	cfg.Logger.Info("guardrail.sensitive_call", "subject", subject, "window_count", count)
	if cfg.Enabled && count >= cfg.Threshold {
		cfg.Logger.Error("guardrail.circuit_trip", "reason", "rate", "subject", subject,
			"count", count, "window", cfg.Window.String())
		if cfg.OnTrip != nil {
			cfg.OnTrip(fmt.Sprintf("circuit breaker: %d sensitive calls within %s", count, cfg.Window))
		}
		return fmt.Sprintf("too many sensitive actions (%d within %s)", count, cfg.Window), true
	}
	return "", false
}

func toolNameArgs(req mcp.Request) (name, args string) {
	if p, ok := req.GetParams().(*mcp.CallToolParamsRaw); ok {
		return p.Name, strings.ToLower(string(p.Arguments))
	}
	return "", ""
}

func matchTripwire(args string) string {
	for _, pat := range tripwireSubstrings {
		if strings.Contains(args, pat) {
			return pat
		}
	}
	return ""
}

// blockedResult refuses a tools/call. An IsError result with a nil Go error is
// the tools convention: the model reads the message and self-corrects.
func blockedResult(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: "Blocked by guardrail policy: " + msg}},
	}
}

// blockedError refuses a method that has no IsError result envelope.
//
// The IsError convention belongs to tools/call alone. resources/read must return
// a ReadResourceResult and subscriptions/listen a SubscriptionsListenResult, so
// answering either with a CallToolResult puts a tool-result envelope on the wire
// where the schema requires something else — a conformance failure, and one a
// client would have no way to interpret. A JSON-RPC error is the protocol's own
// way to refuse.
//
// The code is InvalidRequest rather than an MCP-specific one: 2026-07-28 reserves
// -32020..-32099 for the specification itself, so a server-policy refusal has no
// business minting a code in that range.
func blockedError(msg string) error {
	return &jsonrpc.Error{
		Code:    jsonrpc.CodeInvalidRequest,
		Message: "Blocked by guardrail policy: " + msg,
	}
}
