//go:build windows && (amd64 || arm64)

package windows

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/windows-mcp-server/pkg/inventory"
)

// Resource URIs. Fixed rather than templated: each addresses one piece of
// already-captured state, so there is nothing to parameterize.
const (
	uriSnapshot  = "windows://desktop/snapshot"
	uriDisplays  = "windows://desktop/displays"
	uriSystem    = "windows://system/info"
	uriRecording = "windows://session/recording"
)

// AllResources returns the full fixed-URI resource manifest.
//
// Every resource is a read-only view of state the engine already holds, and each
// is attached to a toolset that also contains tools. That matters:
// AvailableToolsets, EnabledToolsets and the instructions generator all iterate
// tools only, so a toolset introduced solely by a resource would be invisible to
// them.
func AllResources() []inventory.ServerResource {
	return []inventory.ServerResource{
		// screen
		SnapshotResource(),
		DisplaysResource(),
		RecordingResource(),

		// diagnostics
		SystemInfoResource(),
	}
}

// NewResourceFromHandler builds a fixed-URI resource whose handler receives
// ToolDependencies from the request context.
//
// The deps argument the inventory passes at registration is ignored, exactly as
// it is for tools: InjectDepsMiddleware is receiving middleware over every MCP
// method, so the context is the real injection path for resources too.
func NewResourceFromHandler(
	toolset inventory.ToolsetMetadata,
	resource mcp.Resource,
	handler func(ctx context.Context, deps ToolDependencies, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error),
) inventory.ServerResource {
	return inventory.NewServerResource(toolset, resource, func(any) mcp.ResourceHandler {
		return func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			return handler(ctx, MustDepsFromContext(ctx), req)
		}
	})
}

// textResult wraps plain text as a resource read result.
func textResult(uri, mime, text string) *mcp.ReadResourceResult {
	return &mcp.ReadResourceResult{
		Contents: []*mcp.ResourceContents{{URI: uri, MIMEType: mime, Text: text}},
	}
}

// jsonResult marshals v as a JSON resource read result.
func jsonResult(uri string, v any) (*mcp.ReadResourceResult, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("render %s: %w", uri, err)
	}
	return textResult(uri, "application/json", string(b)), nil
}

// SnapshotResource exposes the most recent Snapshot without taking a new one.
//
// Deliberately the *cached* state: reading a resource should not drive the
// desktop. A client that wants fresh perception calls the Snapshot tool, which is
// the action; this is the record of what that action last produced.
func SnapshotResource() inventory.ServerResource {
	return NewResourceFromHandler(
		ToolsetScreen,
		mcp.Resource{
			Name:        "desktop-snapshot",
			Title:       "Latest desktop snapshot",
			URI:         uriSnapshot,
			MIMEType:    "text/plain",
			Description: "The most recent Snapshot: foreground window, open windows, and the labeled interactive-element tree. Reading this does not capture a new snapshot — call the Snapshot tool for that.",
		},
		func(_ context.Context, deps ToolDependencies, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			state := deps.Desktop().LastState()
			if state == nil {
				return textResult(uriSnapshot, "text/plain",
					"No snapshot has been taken yet. Call the Snapshot tool first."), nil
			}
			return textResult(uriSnapshot, "text/plain", formatSnapshot(state)), nil
		},
	)
}

// DisplaysResource exposes the connected displays.
func DisplaysResource() inventory.ServerResource {
	return NewResourceFromHandler(
		ToolsetScreen,
		mcp.Resource{
			Name:        "displays",
			Title:       "Connected displays",
			URI:         uriDisplays,
			MIMEType:    "application/json",
			Description: "Connected displays with bounds, work area, DPI and scale percentage, for translating coordinates.",
		},
		func(_ context.Context, deps ToolDependencies, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			displays, err := deps.Desktop().Displays()
			if err != nil {
				return nil, fmt.Errorf("enumerate displays: %w", err)
			}
			return jsonResult(uriDisplays, displays)
		},
	)
}

// RecordingResource exposes session-recording status — the read-only half of the
// Recording tool, whose "mark" mode is a write and stays a tool.
func RecordingResource() inventory.ServerResource {
	return NewResourceFromHandler(
		ToolsetScreen,
		mcp.Resource{
			Name:        "session-recording",
			Title:       "Session recording status",
			URI:         uriRecording,
			MIMEType:    "application/json",
			Description: "Whether the session is being recorded, and the video/marker paths, frame count and duration.",
		},
		func(_ context.Context, deps ToolDependencies, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			status, active := deps.Desktop().RecordingStatus()
			if !active {
				return jsonResult(uriRecording, map[string]any{"recording": false})
			}
			return jsonResult(uriRecording, status)
		},
	)
}

// SystemInfoResource exposes the OS/hardware inventory.
func SystemInfoResource() inventory.ServerResource {
	return NewResourceFromHandler(
		ToolsetDiagnostics,
		mcp.Resource{
			Name:        "system-info",
			Title:       "System information",
			URI:         uriSystem,
			MIMEType:    "application/json",
			Description: "OS, hardware, memory and disk inventory for this machine, via WMI.",
		},
		func(_ context.Context, deps ToolDependencies, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			info, err := deps.Desktop().GetSystemInfo()
			if err != nil {
				return nil, fmt.Errorf("read system info: %w", err)
			}
			return jsonResult(uriSystem, info)
		},
	)
}
