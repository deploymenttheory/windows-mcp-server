//go:build windows && (amd64 || arm64)

// Package windows defines the Windows-automation MCP tools and the glue that
// binds them to the domain-agnostic pkg/inventory registry. Tool handlers
// retrieve their dependencies from the request context (injected once at
// startup, or per-request for an HTTP transport) via InjectDepsMiddleware and
// MustDepsFromContext, mirroring github-mcp-server's dependency-injection
// design.
package windows

import (
	"context"
	"errors"
	"log/slog"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/windows-mcp-server/internal/desktop"
	"github.com/deploymenttheory/windows-mcp-server/pkg/inventory"
)

// depsContextKey is the private context key under which ToolDependencies are
// stored. A private type prevents collisions with other packages.
type depsContextKey struct{}

// ErrDepsNotInContext is returned/panicked when ToolDependencies are missing
// from the context.
var ErrDepsNotInContext = errors.New("ToolDependencies not found in context; use ContextWithDeps to inject")

// ToolDependencies is the interface tool handlers use to reach shared services.
// It is an interface so different transports can supply different
// implementations (a single shared instance for stdio, or per-request
// instances for HTTP).
type ToolDependencies interface {
	// Desktop returns the Windows automation engine (UIA, input, screenshots,
	// window management). Handlers submit work to it; it owns the COM STA thread.
	Desktop() *desktop.Desktop

	// Logger returns the structured logger, optionally enriched with
	// request-scoped fields from ctx.
	Logger(ctx context.Context) *slog.Logger

	// IsFeatureEnabled reports whether a named feature flag is enabled.
	IsFeatureEnabled(ctx context.Context, flagName string) bool

	// Credentials returns the non-secret registry of credentials installed at
	// init: names, targets, usernames, and classes. It deliberately cannot expose
	// a secret — the plaintext never leaves the desktop engine, so no tool handler
	// is able to return one.
	Credentials() []desktop.CredentialInfo
}

// BaseDeps is the standard ToolDependencies implementation for the local
// (stdio) server. It holds pre-created, process-lifetime services.
type BaseDeps struct {
	desktop        *desktop.Desktop
	logger         *slog.Logger
	featureChecker inventory.FeatureFlagChecker
	credentials    []desktop.CredentialInfo
}

// Compile-time assertion that BaseDeps satisfies ToolDependencies.
var _ ToolDependencies = (*BaseDeps)(nil)

// NewBaseDeps constructs a BaseDeps.
func NewBaseDeps(dsk *desktop.Desktop, logger *slog.Logger, featureChecker inventory.FeatureFlagChecker) *BaseDeps {
	if logger == nil {
		logger = slog.Default()
	}
	return &BaseDeps{desktop: dsk, logger: logger, featureChecker: featureChecker}
}

// WithCredentials records the credentials installed at init, so the Credentials
// tool can list what is available. Returns the receiver for chaining.
func (d *BaseDeps) WithCredentials(creds []desktop.CredentialInfo) *BaseDeps {
	d.credentials = creds
	return d
}

// Desktop implements ToolDependencies.
func (d *BaseDeps) Desktop() *desktop.Desktop { return d.desktop }

// Credentials implements ToolDependencies.
func (d *BaseDeps) Credentials() []desktop.CredentialInfo { return d.credentials }

// Logger implements ToolDependencies.
func (d *BaseDeps) Logger(_ context.Context) *slog.Logger { return d.logger }

// IsFeatureEnabled implements ToolDependencies.
func (d *BaseDeps) IsFeatureEnabled(ctx context.Context, flagName string) bool {
	if d.featureChecker == nil || flagName == "" {
		return false
	}
	enabled, err := d.featureChecker(ctx, flagName)
	if err != nil {
		d.logger.Warn("feature flag check failed", "flag", flagName, "error", err)
		return false
	}
	return enabled
}

// InjectDepsMiddleware returns MCP receiving middleware that injects the given
// dependencies into the context of every request, so tool handlers can read
// them via MustDepsFromContext instead of capturing them in closures.
func InjectDepsMiddleware(deps ToolDependencies) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			return next(ContextWithDeps(ctx, deps), method, req)
		}
	}
}

// ContextWithDeps returns a copy of ctx carrying the given dependencies.
func ContextWithDeps(ctx context.Context, deps ToolDependencies) context.Context {
	return context.WithValue(ctx, depsContextKey{}, deps)
}

// DepsFromContext retrieves ToolDependencies from ctx, reporting whether they
// were present.
func DepsFromContext(ctx context.Context) (ToolDependencies, bool) {
	deps, ok := ctx.Value(depsContextKey{}).(ToolDependencies)
	return deps, ok
}

// MustDepsFromContext retrieves ToolDependencies from ctx, panicking if absent.
// Use it in handlers where dependencies are required.
func MustDepsFromContext(ctx context.Context) ToolDependencies {
	deps, ok := DepsFromContext(ctx)
	if !ok {
		panic(ErrDepsNotInContext)
	}
	return deps
}

// NewTool creates a ServerTool whose typed handler receives dependencies pulled
// from the request context. This avoids allocating a closure per tool at
// registration time. Ensure InjectDepsMiddleware is installed so deps are
// present when handlers run.
func NewTool[In any, Out any](
	toolset inventory.ToolsetMetadata,
	tool mcp.Tool,
	handler func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest, args In) (*mcp.CallToolResult, Out, error),
) inventory.ServerTool {
	return inventory.NewServerToolWithContextHandler(tool, toolset, func(ctx context.Context, req *mcp.CallToolRequest, args In) (*mcp.CallToolResult, Out, error) {
		deps := MustDepsFromContext(ctx)
		return handler(ctx, deps, req, args)
	})
}

// NewToolFromHandler creates a ServerTool from a raw handler that receives
// dependencies from context. Use it when the handler needs the raw request
// rather than typed, pre-unmarshaled arguments.
func NewToolFromHandler(
	toolset inventory.ToolsetMetadata,
	tool mcp.Tool,
	handler func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error),
) inventory.ServerTool {
	return inventory.NewServerTool(tool, toolset, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		deps := MustDepsFromContext(ctx)
		return handler(ctx, deps, req)
	})
}
