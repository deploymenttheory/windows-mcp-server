//go:build windows && (amd64 || arm64)

package winmcp

import (
	"context"
	"encoding/json"
	"testing"
)

// TestToolsListOrderIsDeterministic pins the SHOULD that protocol 2026-07-28
// added: servers should return tools/list in a deterministic order, so clients
// can cache the manifest and so an LLM prompt built from it hits the prompt cache.
//
// The order is stable today because pkg/inventory keeps tools in a slice and the
// SDK sorts by name. Neither is guaranteed by anything but this test — a map
// anywhere in the registration path would reintroduce Go's randomized iteration
// order and quietly cost every downstream cache.
func TestToolsListOrderIsDeterministic(t *testing.T) {
	names := func() []string {
		surface, err := CaptureSurface(context.Background(), Config{Toolsets: []string{"all"}})
		if err != nil {
			t.Fatal(err)
		}
		var payload struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		}
		if err := json.Unmarshal(surface.ToolsListResult, &payload); err != nil {
			t.Fatal(err)
		}
		out := make([]string, len(payload.Tools))
		for i, tool := range payload.Tools {
			out[i] = tool.Name
		}
		return out
	}

	first := names()
	if len(first) == 0 {
		t.Fatal("no tools served")
	}
	// Repeated across independent server constructions: map iteration order varies
	// per process *and* per map, so one extra capture is enough to expose it.
	for i := 0; i < 3; i++ {
		next := names()
		if len(next) != len(first) {
			t.Fatalf("capture %d served %d tools, want %d", i, len(next), len(first))
		}
		for j := range first {
			if next[j] != first[j] {
				t.Fatalf("tools/list order is not deterministic: position %d was %q, now %q",
					j, first[j], next[j])
			}
		}
	}
}
