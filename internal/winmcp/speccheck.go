//go:build windows && (amd64 || arm64)

package winmcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails"
	"github.com/deploymenttheory/windows-mcp-server/internal/mcpspec"
	"github.com/deploymenttheory/windows-mcp-server/pkg/windows"
)

// captureTimeout bounds the in-process session so `spec-check` can never hang CI.
const captureTimeout = 30 * time.Second

// CaptureSurface assembles the tool manifest this configuration would serve, runs
// a real in-process MCP session against it over an in-memory transport, and
// returns the wire objects a client actually receives — the negotiated protocol
// version, the handshake result, the declared capabilities, and the tools/list
// result.
//
// Scoring the real wire bytes rather than a re-marshalling of our Go types is the
// point: it catches divergence between this project's hand-written tool schemas,
// the SDK's serialization, and the published spec.
//
// No desktop engine is created. tools/list never invokes a tool handler, so the
// dependency-injection middleware is wired with a nil engine; a handler call here
// would be a bug, not a supported path.
func CaptureSurface(ctx context.Context, cfg Config) (mcpspec.Input, error) {
	var in mcpspec.Input

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	inv, personaInstructions, err := buildInventory(cfg, false)
	if err != nil {
		return in, fmt.Errorf("build inventory: %w", err)
	}

	// Mirror RunStdio's server construction exactly, so the captured manifest and
	// capabilities are the ones a real client would receive.
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "windows-mcp-server",
		Title:   "Windows MCP Server",
		Version: cfg.Version,
	}, &mcp.ServerOptions{
		Instructions: combineInstructions(personaInstructions, inv.Instructions()),
		Capabilities: &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{}},
	})

	deps := windows.NewBaseDeps(nil, logger, nil)
	server.AddReceivingMiddleware(windows.InjectDepsMiddleware(deps))
	inv.RegisterTools(ctx, server, deps)

	// The two guardrail tools are registered unconditionally by RunStdio, so they
	// are part of the served manifest and must be scored too.
	kill := guardrails.NewKillSwitch(nil)
	statusTool, statusHandler := guardrails.StatusTool(
		func() guardrails.Decision { return guardrails.Decision{} },
		func() guardrails.ServerStatus { return guardrails.ServerStatus{} },
		kill,
	)
	server.AddTool(statusTool, statusHandler)
	killTool, killHandler := guardrails.KillTool(func(string) {})
	server.AddTool(killTool, killHandler)

	ctx, cancel := context.WithTimeout(ctx, captureTimeout)
	defer cancel()

	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		return in, fmt.Errorf("connect server: %w", err)
	}
	defer func() { _ = ss.Close() }()

	client := mcp.NewClient(&mcp.Implementation{Name: "spec-check", Version: cfg.Version}, nil)
	cs, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		return in, fmt.Errorf("connect client: %w", err)
	}
	defer func() { _ = cs.Close() }()

	initResult := cs.InitializeResult()
	if initResult == nil {
		return in, fmt.Errorf("no initialize result captured") //nolint:err113 // local sentinel not needed
	}

	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		return in, fmt.Errorf("list tools: %w", err)
	}

	if in.HandshakeResult, err = json.Marshal(initResult); err != nil {
		return in, fmt.Errorf("marshal handshake result: %w", err)
	}
	if initResult.Capabilities != nil {
		if in.Capabilities, err = json.Marshal(initResult.Capabilities); err != nil {
			return in, fmt.Errorf("marshal capabilities: %w", err)
		}
	}
	if in.ToolsListResult, err = json.Marshal(tools); err != nil {
		return in, fmt.Errorf("marshal tools/list result: %w", err)
	}

	in.NegotiatedVersion = initResult.ProtocolVersion
	in.DeclaredCapabilities = declaredCapabilities(in.Capabilities)
	in.ImplementedMethods = implementedMethods(in.DeclaredCapabilities)
	return in, nil
}

// declaredCapabilities lists the non-empty capability keys the server advertises,
// read back off the wire so it cannot drift from what clients see.
func declaredCapabilities(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil
	}
	out := make([]string, 0, len(obj))
	for k, v := range obj {
		if len(v) == 0 || string(v) == "null" {
			continue
		}
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// capabilityMethods maps a declared server capability to the JSON-RPC methods it
// obliges the server to serve. Used to derive the implemented method surface from
// the advertised capabilities, so adding a capability updates the score without a
// separate hand-maintained list.
var capabilityMethods = map[string][]string{
	"tools":       {"tools/list", "tools/call"},
	"resources":   {"resources/list", "resources/read", "resources/templates/list"},
	"prompts":     {"prompts/list", "prompts/get"},
	"completions": {"completion/complete"},
}

func implementedMethods(capabilities []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range capabilities {
		for _, m := range capabilityMethods[c] {
			if !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	sort.Strings(out)
	return out
}
