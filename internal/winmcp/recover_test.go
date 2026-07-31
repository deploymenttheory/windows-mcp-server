//go:build windows && (amd64 || arm64) && conformance

package winmcp

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestRecoverMiddlewareKeepsTheHostAlive is the regression guard for a run that
// produced 73 failures from one bug.
//
// A resources/read handler dereferenced a nil desktop engine, the panic took the
// whole host down, and every scenario after that point reported "fetch failed".
// In the results those are indistinguishable from a server that answered wrongly,
// so the run looked like a catastrophic protocol failure and was actually a dead
// process. Recovering turns one broken handler into one failed check.
func TestRecoverMiddlewareKeepsTheHostAlive(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	var reached int

	next := func(_ context.Context, method string, _ mcp.Request) (mcp.Result, error) {
		reached++
		if method == "resources/read" {
			var dead *struct{ field int }
			_ = dead.field // the shape of the original crash: a nil dereference
		}
		return &mcp.CallToolResult{}, nil
	}
	handler := recoverMiddleware(logger)(next)
	req := &mcp.ServerRequest[mcp.Params]{Params: &mcp.ReadResourceParams{URI: "windows://desktop/displays"}}

	res, err := handler(context.Background(), "resources/read", req)
	if err == nil {
		t.Fatalf("a panicking handler must surface as an error, got result %T", res)
	}
	if res != nil {
		t.Errorf("want a nil result alongside the error, got %T", res)
	}
	var wire *jsonrpc.Error
	if !errors.As(err, &wire) {
		t.Fatalf("want a JSON-RPC error, got %T: %v", err, err)
	}
	if wire.Code != jsonrpc.CodeInternalError {
		t.Errorf("code = %d, want %d (InternalError)", wire.Code, jsonrpc.CodeInternalError)
	}
	if !strings.Contains(wire.Message, "resources/read") {
		t.Errorf("the error should name the method that panicked, got %q", wire.Message)
	}

	// The point of the whole exercise: the next request still works.
	if _, err := handler(context.Background(), "tools/list", req); err != nil {
		t.Fatalf("the host must keep serving after a panic: %v", err)
	}
	if reached != 2 {
		t.Errorf("handler reached %d times, want 2", reached)
	}
}

// TestConformanceHostToleratesNoDesktopEngine covers the environment the CI
// runner may actually present. The host must build and serve whether or not a
// desktop engine could be created.
func TestConformanceHostToleratesNoDesktopEngine(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := buildConformanceServer(context.Background(), Config{Toolsets: []string{"all"}}, false, logger)
	if err != nil {
		t.Fatalf("the conformance host must build regardless of engine availability: %v", err)
	}
	if server == nil {
		t.Fatal("no server built")
	}
}
