//go:build windows && (amd64 || arm64)

package windows

import "github.com/deploymenttheory/windows-mcp-server/pkg/inventory"

// AllTools returns the full manifest of Windows automation tools with their
// toolset membership. This is the single source of truth for what the server
// can expose; the inventory Builder filters it down per toolset selection,
// read-only mode, persona, and allow/deny lists.
//
// Tools are grouped by toolset for readability. The list grows as feature
// parity with the Python Windows-MCP project is completed.
func AllTools() []inventory.ServerTool {
	return []inventory.ServerTool{
		// screen toolset
		Snapshot(),
		Screenshot(),
		DisplayInventory(),
		Recording(),

		// apps toolset
		App(),

		// interaction toolset
		Click(),
		Type(),
		Invoke(),
		GetText(),
		Scroll(),
		Move(),
		Shortcut(),
		Wait(),
		WaitFor(),
		MultiSelect(),
		MultiEdit(),

		// system toolset
		Clipboard(),
		Process(),
		Registry(),
		Notification(),

		// shell toolset
		PowerShell(),

		// filesystem toolset
		FileSystem(),

		// web toolset
		Scrape(),

		// diagnostics toolset (1st-line support)
		SystemInfo(),
		Service(),

		// credentials
		Credentials(),

		// testing toolset (QA)
		Assert(),
		CaptureEvidence(),
	}
}

// ToolToolsets maps each tool's name to its toolset ID. Callers that need to
// reason about a tool's membership use it — for example, to detect a --tools
// entry that escapes a persona's toolset selection via the additional-tools
// bypass. GuardrailStatus and Kill are absent because they belong to no toolset
// and are served unconditionally.
func ToolToolsets() map[string]string {
	tools := AllTools()
	m := make(map[string]string, len(tools))
	for _, t := range tools {
		m[t.Tool.Name] = string(t.Toolset.ID)
	}
	return m
}

// NewInventory builds an inventory Builder seeded with the full tool manifest.
// Callers apply persona/toolset/read-only configuration and call Build.
func NewInventory() *inventory.Builder {
	return inventory.NewBuilder().
		SetTools(AllTools()).
		SetFixedResources(AllResources()).
		SetPrompts(AllPrompts())
}
