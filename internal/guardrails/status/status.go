// Package status is the operator's read-only view: the loopback status endpoint
// and the two agent-facing tools.
//
// It sits at the top of the stack and is the only package here that both reads
// the whole picture and exposes any of it to the agent — and then only what is
// safe to expose. GuardrailStatus is read-only, and Kill stops the session
// without being able to actuate containment the policy did not configure.
package status

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/contain"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/signals"
)

// StatusProvider returns the current decision document (the "may-run" posture).
type StatusProvider func() signals.Decision

// ServerStatus is the always-on server + device snapshot exposed for external
// polling. It lets a watcher confirm liveness (heartbeat), integrity (audit
// chain head, tool-manifest hash for rug-pull), and kill state — none of which
// the agent can disable.
type ServerStatus struct {
	UptimeSec        float64 `json:"uptime_sec"`
	ToolManifestHash string  `json:"tool_manifest_hash,omitempty"`
	HeartbeatSeq     uint64  `json:"heartbeat_seq"`
	HeartbeatAgeSec  float64 `json:"heartbeat_age_sec"`
	AuditSeq         uint64  `json:"audit_seq"`
	AuditChainHead   string  `json:"audit_chain_head,omitempty"`
	Killed           bool    `json:"killed"`
	KillReason       string  `json:"kill_reason,omitempty"`
}

// SnapshotProvider returns the current server/device status snapshot.
type SnapshotProvider func() ServerStatus

// StatusServer serves the guardrail posture for external polling and accepts a
// revoke command. It is loopback-bound and bearer-token protected per MCP
// security best practices (no sessions-for-auth; validate inbound).
type StatusServer struct {
	Addr     string
	Token    string
	Current  StatusProvider
	Snapshot SnapshotProvider
	Kill     *contain.KillSwitch
	Logger   *slog.Logger
}

// Start binds and serves until ctx is cancelled. It returns an error if the
// listener cannot bind.
func (s *StatusServer) Start(ctx context.Context) error {
	if s.Logger == nil {
		s.Logger = slog.Default()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/guardrails", s.auth(s.handleStatus))
	mux.HandleFunc("/healthz", s.auth(s.handleStatus))
	mux.HandleFunc("/revoke", s.auth(s.handleRevoke))

	// ListenConfig.Listen honours ctx during listener setup, so a cancelled
	// startup does not leave a socket bound. The ctx does not govern the
	// listener's lifetime; the srv.Close goroutine below does that.
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("guardrails status listen %s: %w", s.Addr, err)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			s.Logger.Warn("guardrails status server stopped", "error", err)
		}
	}()
	s.Logger.Info("guardrails status endpoint listening", "addr", ln.Addr().String())
	return nil
}

func (s *StatusServer) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.Token != "" {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if subtle.ConstantTimeCompare([]byte(got), []byte(s.Token)) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		h(w, r)
	}
}

func (s *StatusServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	d := s.Current()
	tripped, reason := s.Kill.Tripped()
	var snap ServerStatus
	if s.Snapshot != nil {
		snap = s.Snapshot()
	}
	body := struct {
		signals.Decision
		Server     ServerStatus `json:"server"`
		Killed     bool         `json:"killed"`
		KillReason string       `json:"kill_reason,omitempty"`
	}{Decision: d, Server: snap, Killed: tripped, KillReason: reason}
	w.Header().Set("Content-Type", "application/json")
	if !d.Admit || tripped {
		w.WriteHeader(http.StatusForbidden) // may-run = no
	}
	_ = json.NewEncoder(w).Encode(body)
}

func (s *StatusServer) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.Kill.Trip("remote revoke via status endpoint")
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte("revoked\n"))
}

// StatusTool returns the GuardrailStatus MCP tool (read-only) reporting the
// current posture to the connected client.
func StatusTool(
	current StatusProvider,
	snapshot SnapshotProvider,
	kill *contain.KillSwitch,
) (*mcp.Tool, mcp.ToolHandler) {
	tool := &mcp.Tool{
		Name:        "GuardrailStatus",
		Description: "Report the current guardrail posture (the may-run decision): mode, run context, per-check results, the always-on server/device snapshot (uptime, tool-manifest hash, heartbeat, audit chain head), whether the session is admitted, and whether a kill has been triggered. Read-only.",
		Annotations: &mcp.ToolAnnotations{Title: "Guardrail status", ReadOnlyHint: true},
		InputSchema: map[string]any{"type": "object"},
	}
	handler := func(_ context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		d := current()
		tripped, reason := kill.Tripped()
		var snap ServerStatus
		if snapshot != nil {
			snap = snapshot()
		}
		payload := struct {
			signals.Decision
			Server     ServerStatus `json:"server"`
			Killed     bool         `json:"killed"`
			KillReason string       `json:"kill_reason,omitempty"`
		}{Decision: d, Server: snap, Killed: tripped, KillReason: reason}
		b, _ := json.MarshalIndent(payload, "", "  ")
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, nil
	}
	return tool, handler
}

// KillTool returns the Kill MCP tool that stops the session. stop is supplied by
// the server layer: the kill switch's Trip when the switch is armed, otherwise a
// containment-free graceful stop. Either way the session ends, but an agent can
// never escalate "stop this session" into network isolation or a shutdown on an
// operator who did not arm the switch.
func KillTool(stop func(reason string)) (*mcp.Tool, mcp.ToolHandler) {
	destructive := true
	tool := &mcp.Tool{
		Name:        "Kill",
		Description: "Immediately and cleanly stop this MCP session (finalizing any recording). Use to abort automation. This is the agent-facing convenience trigger; authoritative kill triggers are independent of the agent.",
		Annotations: &mcp.ToolAnnotations{Title: "Kill session", ReadOnlyHint: false, DestructiveHint: &destructive},
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"reason": map[string]any{"type": "string", "description": "Why the session is being stopped."},
			},
		},
	}
	handler := func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		reason := "kill requested via MCP Kill tool"
		var args struct {
			Reason string `json:"reason"`
		}
		if len(req.Params.Arguments) > 0 {
			_ = json.Unmarshal(req.Params.Arguments, &args)
			if args.Reason != "" {
				reason = "MCP Kill tool: " + args.Reason
			}
		}
		if stop != nil {
			stop(reason)
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Session stopping: " + reason}}}, nil
	}
	return tool, handler
}
