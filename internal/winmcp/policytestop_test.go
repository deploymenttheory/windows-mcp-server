//go:build windows && (amd64 || arm64)

package winmcp

import (
	"path/filepath"
	"testing"
)

// TestShippedPolicyFixturesPass runs the committed example fixtures, so the
// documents that demonstrate the verb are also known to hold. The fixture
// runner itself is pinned in mcp-server-core.
func TestShippedPolicyFixturesPass(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "policy", "examples", "tests", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no example fixtures found")
	}
	reports, err := TestPolicy(paths)
	if err != nil {
		t.Fatalf("TestPolicy: %v", err)
	}
	for _, r := range reports {
		for _, c := range r.Cases {
			if !c.OK {
				t.Errorf("%s / %s: %s", filepath.Base(r.Fixture), c.Name, c.Detail)
			}
		}
	}
}
