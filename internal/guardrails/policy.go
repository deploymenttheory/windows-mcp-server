package guardrails

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

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
	"PowerShell": true, "Registry": true, "Process": true,
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
				mu.Lock()
				now := time.Now()
				cutoff := now.Add(-cfg.Window)
				kept := hits[:0]
				for _, t := range hits {
					if t.After(cutoff) {
						kept = append(kept, t)
					}
				}
				kept = append(kept, now)
				hits = kept
				count := len(hits)
				mu.Unlock()

				cfg.Logger.Info("guardrail.sensitive_call", "tool", name, "window_count", count)
				if cfg.Enabled && count >= cfg.Threshold {
					cfg.Logger.Error("guardrail.circuit_trip", "reason", "rate", "tool", name, "count", count, "window", cfg.Window.String())
					if cfg.OnTrip != nil {
						cfg.OnTrip(fmt.Sprintf("circuit breaker: %d sensitive tool calls within %s", count, cfg.Window))
					}
					return blockedResult(fmt.Sprintf("too many sensitive actions (%d within %s)", count, cfg.Window)), nil
				}
			}

			return next(ctx, method, req)
		}
	}
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

func blockedResult(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: "Blocked by guardrail policy: " + msg}},
	}
}
