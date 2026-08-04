//go:build windows && (amd64 || arm64)

package winmcp

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/windows-mcp-server/pkg/windows"
)

// recordingMiddleware appends name to order when a request passes through it.
// refuse makes it answer without calling next, standing in for a policy denial.
func recordingMiddleware(mu *sync.Mutex, order *[]string, name string, refuse bool) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method == "tools/list" {
				mu.Lock()
				*order = append(*order, name)
				mu.Unlock()
			}
			if refuse && method == "tools/list" {
				return nil, errors.New("refused by policy")
			}
			return next(ctx, method, req)
		}
	}
}

// newTestSurface builds a surface with no desktop engine, which is enough to
// exercise the middleware chain: nothing here reaches the OS.
func newTestSurface(t *testing.T) *mcpSurface {
	t.Helper()
	cfg := Config{Version: "test"}
	inv, personaInstructions, err := buildInventory(cfg, false)
	if err != nil {
		t.Fatalf("build inventory: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return newMCPSurface(cfg, inv, personaInstructions, windows.NewBaseDeps(nil, logger, nil))
}

// listOnce runs one tools/list against the server, ignoring whether it succeeded
// — a refused call is the interesting case.
func listOnce(t *testing.T, server *mcp.Server) {
	t.Helper()
	ctx := context.Background()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ss.Close() }()

	client := mcp.NewClient(&mcp.Implementation{Name: "order-test", Version: "test"}, nil)
	cs, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cs.Close() }()

	_, _ = cs.ListTools(ctx, nil)
}

// TestReceivingMiddlewareRunsOutermostFirst pins the order installReceiving
// produces. It is a regression test for a real inversion: the layers were added
// one AddReceivingMiddleware call at a time, and because each call wraps the
// chain built so far, the LAST middleware added became the outermost. The policy
// engine ended up outside the audit layer.
func TestReceivingMiddlewareRunsOutermostFirst(t *testing.T) {
	var mu sync.Mutex
	var order []string

	surface := newTestSurface(t)
	surface.installReceiving(
		recordingMiddleware(&mu, &order, "audit", false),
		recordingMiddleware(&mu, &order, "rugpull", false),
		recordingMiddleware(&mu, &order, "enforce", false),
	)
	listOnce(t, surface.Server)

	mu.Lock()
	defer mu.Unlock()
	want := []string{"audit", "rugpull", "enforce"}
	if len(order) != len(want) {
		t.Fatalf("middleware order = %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("middleware order = %v, want %v", order, want)
		}
	}
}

// TestOuterMiddlewareObservesRefusedRequests is the property the ordering exists
// for. The audit layer must record a call the policy engine refuses — those
// refusals are exactly what an investigator needs, and the inverted chain
// dropped them: no tool.call entry was ever written for a denied call.
func TestOuterMiddlewareObservesRefusedRequests(t *testing.T) {
	var mu sync.Mutex
	var order []string

	surface := newTestSurface(t)
	surface.installReceiving(
		recordingMiddleware(&mu, &order, "audit", false),
		recordingMiddleware(&mu, &order, "enforce", true), // refuses, never calls next
	)
	listOnce(t, surface.Server)

	mu.Lock()
	defer mu.Unlock()
	if len(order) == 0 || order[0] != "audit" {
		t.Fatalf("audit did not observe the refused request: order = %v", order)
	}
	if len(order) != 2 || order[1] != "enforce" {
		t.Fatalf("expected the refusal to happen inside audit: order = %v", order)
	}
}
