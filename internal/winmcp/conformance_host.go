//go:build windows && (amd64 || arm64) && conformance

// This file exists only under the `conformance` build tag. `go build ./...`
// does not compile it, so the released binary has no HTTP listener and remains
// stdio-only — the posture the guardrail threat model is written against.
//
// It exists because the official MCP conformance suite
// (github.com/modelcontextprotocol/conformance) can only reach a server over
// HTTP: `--url` is a required option of its `server` command and there is no
// stdio path. Proving conformance therefore requires an endpoint the harness can
// connect to, and this is the smallest one that still serves the real thing.

package winmcp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/windows-mcp-server/internal/desktop"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/audit"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/contain"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/enforce"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/policy"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/signals"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/status"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/watch"
	"github.com/deploymenttheory/windows-mcp-server/pkg/windows"
)

// ConformanceConfig configures the loopback host.
type ConformanceConfig struct {
	// Addr is the listen address. It must be a loopback address.
	Addr string
	// Path is the HTTP path the MCP endpoint is served on.
	Path string
	// Fixtures registers the named tools, resources and prompts the conformance
	// suite requires in order to exercise tools/call, resources/read and
	// prompts/get at all (see conformance_fixtures.go).
	//
	// This is the difference between the suite's two passes. Without it the run
	// measures the manifest this server actually ships; with it the run measures
	// how our handler-to-wire path behaves, at the cost of no longer being the
	// shipped manifest. Recording them separately is what keeps both claims honest.
	Fixtures bool
}

// shutdownGrace bounds the wait for in-flight requests when the context ends, so
// a hung stream cannot leave the CI job running to its timeout.
const shutdownGrace = 5 * time.Second

// RunConformanceHost serves this server's MCP surface over Streamable HTTP on
// loopback so the official conformance suite can connect to it.
//
// What makes the evidence meaningful is that the surface is built by
// newMCPSurface and wrapped in the same middleware chain as RunStdio, in the same
// order: inject-deps and cache hints from the shared constructor, then audit,
// rug-pull and the policy engine. Only the transport differs.
//
// Three deliberate differences from a production run, each to avoid measuring
// something other than protocol conformance:
//
//   - The policy engine runs under the built-in default policy, which evaluates
//     and records but refuses nothing. The engine has to be in the chain — a
//     conformance result gathered without it would describe a server nobody runs
//     — but a policy that refused calls partway through would report its own
//     refusals as protocol failures.
//   - The desktop engine is best-effort. It is created when the environment can
//     host one, so resources/read returns real state; where it cannot, the server
//     still serves, because most of the suite needs no engine and losing the run
//     to obtain one would be a bad trade.
//   - Handler panics are recovered rather than fatal. Finishing the run and
//     reporting is the whole job here; see recoverMiddleware.
func RunConformanceHost(ctx context.Context, cfg Config, hostCfg ConformanceConfig) error {
	if err := requireLoopback(hostCfg.Addr); err != nil {
		return err
	}
	// Logs go to stderr: stdout carries the bound URL for the harness runner.
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	server, err := buildConformanceServer(ctx, cfg, hostCfg.Fixtures, logger)
	if err != nil {
		return err
	}

	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{
			// Protocol 2026-07-28 removed protocol-level sessions (SEP-2567), and the
			// suite's stateless scenarios exercise exactly that. Leaving sessions on
			// would make the server answer a sessionless client with session
			// machinery it is no longer allowed to use.
			Stateless: true,
			Logger:    logger,
			// DNS-rebinding protection is left at its default (on). The suite has a
			// scenario for it precisely because a localhost server without HTTPS or
			// auth is the case that needs it, so disabling it here would be
			// disabling the thing under test.
		})

	mux := http.NewServeMux()
	mux.Handle(hostCfg.Path, handler)

	var lc net.ListenConfig
	listener, err := lc.Listen(ctx, "tcp", hostCfg.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", hostCfg.Addr, err)
	}
	url := fmt.Sprintf("http://%s%s", listener.Addr().String(), hostCfg.Path)
	// The bound URL on stdout is the runner's contract: with :0 the port is only
	// known here, and the harness needs it to build --url.
	fmt.Fprintln(os.Stdout, url)
	logger.Info("conformance host listening", "url", url, "stateless", true)

	httpServer := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- httpServer.Serve(listener) }()

	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
		// Deliberately NOT derived from ctx: ctx is already cancelled, and a
		// cancelled context makes Shutdown abandon in-flight requests immediately.
		// The grace period is the point — the suite's last response should finish
		// before the process exits, or the run's own results are the casualty.
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil { //nolint:contextcheck // see above
			return fmt.Errorf("shutdown: %w", err)
		}
		return nil
	}
}

// buildConformanceServer assembles the server the host serves. It is separate
// from the transport so a test can drive the same object over an in-memory
// transport and compare its manifest with the stdio one.
func buildConformanceServer(
	ctx context.Context, cfg Config, fixturesEnabled bool, logger *slog.Logger,
) (*mcp.Server, error) {
	inv, personaInstructions, err := buildInventory(cfg, false)
	if err != nil {
		return nil, fmt.Errorf("build inventory: %w", err)
	}

	// A real engine when the runner can host one, so resources/read returns real
	// desktop state and the suite's caching checks measure something. It is
	// best-effort: a headless or UIA-less environment must degrade to a nil engine
	// rather than refusing to serve, because most of the suite needs no engine at
	// all and losing the whole run to get one would be a bad trade.
	dsk, err := desktop.New(logger, desktop.Options{}) //nolint:contextcheck // owns its lifetime
	if err != nil {
		logger.Warn("no desktop engine for the conformance host; "+
			"engine-backed resources will report an error rather than data", "error", err)
		dsk = nil
	}

	deps := windows.NewBaseDeps(dsk, logger, nil).WithEnforceHTTPS(enforceHTTPS(cfg))
	surface := newMCPSurface(cfg, inv, personaInstructions, deps)
	server := surface.Server

	// Outermost, so nothing a handler does can take the process down.
	//
	// This is not defensive padding. Without it, one handler dereferencing a nil
	// engine killed the host mid-suite, and every scenario after that point
	// reported "fetch failed" — indistinguishable, in the results, from a server
	// that answered wrongly. A conformance run whose failures might mean "the
	// server is not there" is not evidence of anything.
	server.AddReceivingMiddleware(recoverMiddleware(logger))

	// The transparency services, as RunStdio wires them. A trip here logs and
	// records rather than actuating containment: the conformance host has no
	// desktop to contain, and a kill mid-suite would destroy the evidence.
	audit := audit.NewAuditLog(&conformanceAuditSink{logger: logger})
	rugpull := watch.NewRugPull(func(reason string) {
		logger.Error("guardrail.rugpull", "reason", reason)
	}, audit)

	server.AddReceivingMiddleware(audit.Middleware())
	server.AddReceivingMiddleware(rugpull.Middleware())
	server.AddReceivingMiddleware(rugpull.PromptMiddleware())
	server.AddReceivingMiddleware(rugpull.ResourceMiddleware())
	server.AddReceivingMiddleware(rugpull.DiscoverMiddleware())

	// The policy engine under the built-in default: present, evaluating and
	// recording, refusing nothing. The suite must meet the same middleware chain a
	// real session does — otherwise the conformance evidence describes a server
	// nobody runs — but a policy that refused calls would report the refusals as
	// protocol failures.
	engine := policy.NewEngine(policy.Default(), newGuardrailRegistry(cfg, logger), nil,
		func() *signals.Env { return &signals.Env{Sys: &conformanceProbe{}, Logger: logger} })
	server.AddReceivingMiddleware(enforce.Middleware(engine, enforce.EnforcerDeps{
		Audit:  audit,
		Logger: logger,
	}))

	inv.RegisterAll(ctx, server, deps)
	engine.SetIndex(newToolIndex(ctx, inv))

	kill := contain.NewKillSwitch(nil)
	statusTool, statusHandler := status.StatusTool(
		func() signals.Decision { return signals.Decision{} },
		func() status.ServerStatus { return status.ServerStatus{} },
		kill,
	)
	server.AddTool(statusTool, statusHandler)
	killTool, killHandler := status.KillTool(func(string) {})
	server.AddTool(killTool, killHandler)

	// Baselines are pinned after the fixtures are registered, over what the server
	// will actually serve. Pinning the product manifest and then adding fixtures
	// would trip the rug-pull detector on the suite's first tools/list — correctly,
	// since the manifest really would have changed after the baseline.
	fixtures := registerConformanceFixtures(server, fixturesEnabled)

	tools := append(invMCPTools(ctx, inv), statusTool, killTool)
	rugpull.SetBaseline(append(tools, fixtures.Tools...))
	rugpull.SetPromptBaseline(append(invMCPPrompts(ctx, inv), fixtures.Prompts...))
	rugpull.SetResourceBaseline(append(invMCPResources(ctx, inv), fixtures.Resources...))
	rugpull.SetDiscoverBaseline(surface.Capabilities, surface.Instructions)

	return server, nil
}

// requireLoopback refuses any address that is not loopback.
//
// This host has no authentication and no authorization: it is a test fixture that
// serves the full tool manifest of a desktop-automation server. Binding it to a
// routable interface would publish that manifest, and the ability to call it, to
// the network. The check is here rather than in the CLI so no future caller can
// route around it.
func requireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("parse listen address %q: %w", addr, err)
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("conformance host refuses to bind %q: loopback only", addr) //nolint:err113 // one-off guard
	}
	return nil
}

// recoverMiddleware turns a panicking handler into a JSON-RPC error instead of a
// dead process.
//
// It belongs on the conformance host and not on the stdio server. Here the whole
// point is to finish the run and produce results, so one broken handler must not
// cost the evidence for every scenario after it — a run whose failures might mean
// "the server is not there" proves nothing. A production session makes the
// opposite trade: a panic there means the engine's state is unknown, and driving
// a desktop from an unknown state is worse than stopping.
func recoverMiddleware(logger *slog.Logger) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (res mcp.Result, err error) {
			defer func() {
				if r := recover(); r != nil {
					logger.Error("handler panicked", "method", method, "panic", r,
						"stack", string(debug.Stack()))
					res = nil
					err = &jsonrpc.Error{
						Code:    jsonrpc.CodeInternalError,
						Message: fmt.Sprintf("handler for %s panicked: %v", method, r),
					}
				}
			}()
			return next(ctx, method, req)
		}
	}
}

// conformanceProbe satisfies signals.SystemProbe without a desktop engine.
//
// The conformance host creates no engine — the suite never drives the real
// desktop — so the default policy's signals have nothing to read. Every method
// returns a zero value, which makes run-context report a non-interactive session
// and therefore fail. Under the default policy that is a warning and nothing
// more, which is the intended outcome: the middleware is exercised on every
// request, and no request is refused.
type conformanceProbe struct{}

func (*conformanceProbe) RunShell(context.Context, string) (string, error) { return "", nil }
func (*conformanceProbe) DomainSKU() (signals.DomainSKU, error) {
	return signals.DomainSKU{}, nil
}
func (*conformanceProbe) RunContext() signals.RunContext { return signals.RunContext{} }
func (*conformanceProbe) DeviceIdentity() signals.DeviceIdentity {
	return signals.DeviceIdentity{Hostname: "conformance-host"}
}
func (*conformanceProbe) IsAdmin() bool { return false }

// conformanceAuditSink writes the hash-chained audit entries to the logger, so a
// conformance run leaves the same transparency trail a real session would and the
// entries land in the workflow log next to the harness output.
type conformanceAuditSink struct{ logger *slog.Logger }

func (s *conformanceAuditSink) Write(e audit.AuditEntry) error {
	s.logger.Info("audit", "seq", e.Seq, "event", e.Event, "hash", e.EntryHash)
	return nil
}
func (s *conformanceAuditSink) Flush() error { return nil }
func (s *conformanceAuditSink) Close() error { return nil }
