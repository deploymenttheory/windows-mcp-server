//go:build windows && (amd64 || arm64)

package winmcp

import (
	"context"
	"strings"
	"testing"
)

// TestPlanningToolsetServesPlanAndApply pins that the planning toolset serves
// the two plan-and-apply tools, and that their schemas serialize into a real
// tools/list, since CaptureSurface runs one. The planner's own behaviour is
// pinned in mcp-server-core.
func TestPlanningToolsetServesPlanAndApply(t *testing.T) {
	captured, err := CaptureSurface(context.Background(), Config{Toolsets: []string{"planning"}})
	if err != nil {
		t.Fatalf("CaptureSurface: %v", err)
	}
	served := string(captured.ToolsListResult)
	for _, name := range []string{"Plan", "Apply"} {
		if !strings.Contains(served, `"`+name+`"`) {
			t.Errorf("%s should be served under the planning toolset", name)
		}
	}
}
