//go:build windows && (amd64 || arm64)

// Package windows defines the Windows-automation MCP tools and the glue that
// binds them to the shared inventory registry. Tool handlers retrieve their
// dependencies from the request context via the toolkit's InjectDepsMiddleware
// and MustDepsFromContext, mirroring github-mcp-server's dependency-injection
// design. The platform-agnostic half of the dependency set, the argument
// accessors and the result constructors live in mcp-server-core/toolkit; this
// file is the Windows-specific shim over them.
package windows

import (
	"context"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/mcp-server-core/inventory"
	"github.com/deploymenttheory/mcp-server-core/toolkit"
	"github.com/deploymenttheory/windows-mcp-server/internal/desktop"
)

// ToolDependencies is the interface tool handlers use to reach shared services.
// It is the shared toolkit contract plus the Windows engine.
type ToolDependencies interface {
	toolkit.ToolDependencies
	// Desktop returns the Windows automation engine (UIA, input, screenshots,
	// window management). Handlers submit work to it; it owns the COM STA thread.
	Desktop() *desktop.Desktop
}

// BaseDeps is the standard ToolDependencies implementation for the local
// (stdio) server: the shared base plus the engine.
type BaseDeps struct {
	*toolkit.BaseDeps
	desktop *desktop.Desktop
}

// Compile-time assertion that BaseDeps satisfies ToolDependencies.
var _ ToolDependencies = (*BaseDeps)(nil)

// NewBaseDeps constructs a BaseDeps. The path normaliser is the Windows one, so
// protected-path matching folds the spellings NTFS folds.
func NewBaseDeps(dsk *desktop.Desktop, logger *slog.Logger, featureChecker inventory.FeatureFlagChecker) *BaseDeps {
	return &BaseDeps{
		BaseDeps: toolkit.NewBaseDeps(logger, featureChecker).WithPathNormalizer(NormalizePath),
		desktop:  dsk,
	}
}

// Desktop implements ToolDependencies.
func (d *BaseDeps) Desktop() *desktop.Desktop { return d.desktop }

// NormalizePath renders a path in the one form protected-path matching
// compares, so the same file cannot be reached under a different spelling.
//
// Windows accepts several names for one file that filepath.Clean does not fold
// together, and each was a way past the guard:
//
//	\\?\C:\...          the extended-length prefix. Clean preserves it and
//	                    os.OpenFile honours it, so it never equalled the
//	                    stored path.
//	C:\file.txt::$DATA  the default data stream, which is the file itself.
//	C:\file.txt.        a trailing dot, which Windows strips when opening.
//	C:\file.txt         a trailing space, likewise.
//
// All four normalize to the same string, so one rule covers them.
//
// Deliberately still not folded, and the reason this stays a guardrail rather
// than a sandbox: 8.3 short names (PROGRA~1), hard links, and UNC-to-self
// (\\localhost\C$\...) all reach the file under another name. Closing those needs
// the path opened and compared by file ID, which is a larger change; the
// shell toolset reaches these files with no check at all, which is why it
// requires an explicit acknowledgement.
func NormalizePath(path string) string {
	p := strings.ToLower(strings.TrimSpace(path))

	// The extended-length prefix, in both its plain and UNC forms.
	const extPrefix = `\\?\`
	const extUNCPrefix = `\\?\unc\`
	switch {
	case strings.HasPrefix(p, extUNCPrefix):
		p = `\\` + p[len(extUNCPrefix):]
	case strings.HasPrefix(p, extPrefix):
		p = p[len(extPrefix):]
	}

	// An explicit data stream names the same bytes as the file itself.
	if i := strings.Index(p, "::$"); i >= 0 {
		p = p[:i]
	}

	p = filepath.Clean(p)

	// Windows ignores trailing dots and spaces when opening a path; Clean does not.
	return strings.TrimRight(p, ". ")
}

// NewToolFromHandler creates a ServerTool from a raw handler that receives
// dependencies from context.
func NewToolFromHandler(
	toolset inventory.ToolsetMetadata,
	tool mcp.Tool,
	handler func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error),
) inventory.ServerTool {
	return toolkit.NewToolFromHandler[ToolDependencies](toolset, tool, handler)
}

// MustDepsFromContext retrieves ToolDependencies from ctx, panicking if absent.
func MustDepsFromContext(ctx context.Context) ToolDependencies {
	return toolkit.MustDepsFromContext[ToolDependencies](ctx)
}

// Result constructors and argument accessors, re-exported so the tool files
// read as they always have.
var (
	ContextWithDeps           = toolkit.ContextWithDeps
	NewToolResultText         = toolkit.NewToolResultText
	NewToolResultTextf        = toolkit.NewToolResultTextf
	NewToolResultError        = toolkit.NewToolResultError
	NewToolResultErrorf       = toolkit.NewToolResultErrorf
	NewToolResultErrorFromErr = toolkit.NewToolResultErrorFromErr
	NewToolResultImage        = toolkit.NewToolResultImage
	ArgsMap                   = toolkit.ArgsMap
	RequiredString            = toolkit.RequiredString
	OptionalString            = toolkit.OptionalString
	OptionalInt               = toolkit.OptionalInt
	OptionalFloat             = toolkit.OptionalFloat
	OptionalBool              = toolkit.OptionalBool
	OptionalStringEnum        = toolkit.OptionalStringEnum
	OptionalIntSlice          = toolkit.OptionalIntSlice
)
