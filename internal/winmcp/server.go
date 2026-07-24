//go:build windows && (amd64 || arm64)

// Package winmcp wires the Windows automation engine and tool inventory into an
// MCP server and runs it over a transport. It is the bootstrap layer between
// the cobra CLI (cmd/windows-mcp-server) and the domain package (pkg/windows).
package winmcp

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/windows-mcp-server/internal/desktop"
	"github.com/deploymenttheory/windows-mcp-server/pkg/inventory"
	"github.com/deploymenttheory/windows-mcp-server/pkg/windows"
)

// Config controls how the server is assembled and which tools it exposes.
type Config struct {
	// Version is reported in the MCP server implementation info.
	Version string

	// Persona, if set, selects a built-in preset (see windows.Personas) that
	// determines the toolset selection and read-only default. Explicit Toolsets
	// / ReadOnly settings override the persona.
	Persona string

	// Toolsets is the toolset selection (values accepted by
	// Builder.WithToolsets, including "all"/"default"). When nil and no persona
	// is set, the default toolsets are used.
	Toolsets []string
	// Tools is an additive allow-list of individual tools that bypass toolset
	// filtering.
	Tools []string
	// ExcludeTools is a deny-list applied last.
	ExcludeTools []string
	// ReadOnly, when true, exposes only read-only tools.
	ReadOnly bool
	// readOnlySet records whether ReadOnly was explicitly provided, so a persona
	// default is not silently overridden by the zero value.
	readOnlySet bool

	// LogFile, if set, directs debug logs to this file; otherwise info-level
	// logs go to stderr. stdout is reserved for the MCP stdio transport.
	LogFile string

	// Overlay enables visual-feedback overlays (green hue around the focused
	// window, orange flash at click points) for screen capture and video.
	Overlay bool

	// RecordDir, when set, records the whole session to a video file in this
	// directory so every session is tracked. RecordFPS and RecordCodec tune it.
	RecordDir   string
	RecordFPS   int
	RecordCodec string
}

// SetReadOnly records an explicit read-only choice (distinguishing it from the
// zero value so it can override a persona default).
func (c *Config) SetReadOnly(v bool) {
	c.ReadOnly = v
	c.readOnlySet = true
}

// RunStdio builds the server and serves the MCP protocol over stdio until the
// context is cancelled or the client disconnects.
func RunStdio(ctx context.Context, cfg Config) error {
	logger, cleanup, err := newLogger(cfg.LogFile)
	if err != nil {
		return err
	}
	defer cleanup()

	dsk, err := desktop.New(logger, desktop.Options{
		Overlay: cfg.Overlay,
		Record: desktop.RecorderOptions{
			Dir:   cfg.RecordDir,
			FPS:   cfg.RecordFPS,
			Codec: cfg.RecordCodec,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to start desktop engine: %w", err)
	}
	defer func() { _ = dsk.Close() }()

	inv, personaInstructions, err := buildInventory(cfg)
	if err != nil {
		return err
	}
	for _, unknown := range inv.UnrecognizedToolsets() {
		logger.Warn("unrecognized toolset requested", "toolset", unknown)
	}

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "windows-mcp-server",
		Title:   "Windows MCP Server",
		Version: cfg.Version,
	}, &mcp.ServerOptions{
		Instructions: combineInstructions(personaInstructions, inv.Instructions()),
	})

	deps := windows.NewBaseDeps(dsk, logger, nil)
	// Inject dependencies into the context of every request so tool handlers
	// retrieve them via context rather than registration-time closures.
	server.AddReceivingMiddleware(windows.InjectDepsMiddleware(deps))

	inv.RegisterTools(ctx, server, deps)

	logger.Info("starting windows-mcp-server over stdio",
		"version", cfg.Version,
		"enabled_toolsets", toolsetIDs(inv.EnabledToolsets()),
	)

	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil {
		return fmt.Errorf("server run: %w", err)
	}
	return nil
}

// buildInventory applies persona, toolset, read-only, and allow/deny
// configuration to the full tool manifest. It also returns the selected
// persona's instructions (empty when no persona is selected).
func buildInventory(cfg Config) (*inventory.Inventory, string, error) {
	toolsets := cfg.Toolsets
	readOnly := cfg.ReadOnly
	var personaInstructions string

	if cfg.Persona != "" {
		persona, ok := windows.LookupPersona(cfg.Persona)
		if !ok {
			return nil, "", fmt.Errorf("unknown persona %q", cfg.Persona)
		}
		personaInstructions = persona.Instructions
		// Explicit --toolsets overrides the persona's selection.
		if toolsets == nil {
			toolsets = persona.Toolsets
		}
		// Explicit --read-only overrides the persona default.
		if !cfg.readOnlySet {
			readOnly = persona.ReadOnly
		}
	}

	inv, err := windows.NewInventory().
		WithToolsets(toolsets).
		WithReadOnly(readOnly).
		WithTools(cfg.Tools).
		WithExcludeTools(cfg.ExcludeTools).
		WithServerInstructions().
		Build()
	if err != nil {
		return nil, "", fmt.Errorf("failed to build tool inventory: %w", err)
	}
	return inv, personaInstructions, nil
}

// combineInstructions joins the persona guidance and the toolset-derived
// instructions, omitting empty parts.
func combineInstructions(parts ...string) string {
	var nonEmpty []string
	for _, p := range parts {
		if p != "" {
			nonEmpty = append(nonEmpty, p)
		}
	}
	return strings.Join(nonEmpty, "\n\n")
}

func toolsetIDs(tss []inventory.ToolsetMetadata) []string {
	ids := make([]string, len(tss))
	for i, ts := range tss {
		ids[i] = string(ts.ID)
	}
	return ids
}

// newLogger returns a structured logger writing to logFile (debug level) or, if
// empty, to stderr (info level). stdout is never used, so it stays clean for
// the MCP stdio transport.
func newLogger(logFile string) (*slog.Logger, func(), error) {
	var w io.Writer = os.Stderr
	level := slog.LevelInfo
	cleanup := func() {}

	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to open log file %q: %w", logFile, err)
		}
		w = f
		level = slog.LevelDebug
		cleanup = func() { _ = f.Close() }
	}

	logger := slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level}))
	return logger, cleanup, nil
}
