//go:build windows && (amd64 || arm64)

package windows

import (
	"github.com/deploymenttheory/mcp-server-core/inventory"
	"github.com/deploymenttheory/mcp-server-core/toolkit"
)

// Scrape fetches a web page and extracts its readable text. The
// implementation is platform-neutral and lives in mcp-server-core; this binds
// it to the web toolset under this server's user agent.
func Scrape() inventory.ServerTool {
	return toolkit.ScrapeTool[ToolDependencies](ToolsetWeb, "windows-mcp-server/scrape")
}
