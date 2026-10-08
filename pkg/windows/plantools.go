//go:build windows && (amd64 || arm64)

package windows

import (
	"github.com/deploymenttheory/mcp-server-core/inventory"
	"github.com/deploymenttheory/mcp-server-core/toolkit"
)

// Plan and Apply are the plan-and-apply tools: propose a whole sequence of tool
// calls for adjudication, then run the approved plan verbatim. The
// implementation is platform-neutral and lives in mcp-server-core; this binds
// it to the planning toolset.
func Plan() inventory.ServerTool  { return toolkit.PlanTool[ToolDependencies](ToolsetPlanning) }
func Apply() inventory.ServerTool { return toolkit.ApplyTool[ToolDependencies](ToolsetPlanning) }
