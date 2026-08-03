package journeys

import (
	"os"
	"path/filepath"
	"testing"
)

// TestShippedExampleJourneysCompile keeps the examples runnable: a journey that
// fails to parse, validate or compile is worse than none, since it breaks at the
// moment someone copies it as a starting point.
func TestShippedExampleJourneysCompile(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "journeys", "examples", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no example journeys found")
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			raw, err := os.ReadFile(path) //nolint:gosec // test-controlled path
			if err != nil {
				t.Fatal(err)
			}
			j, err := Parse(raw)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if err := j.Validate(); err != nil {
				t.Fatalf("validate: %v", err)
			}
			doc, err := Compile(j, "test")
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			if len(doc.Steps) < len(j.Steps) {
				t.Errorf("compiled to %d plan steps, fewer than %d journey steps", len(doc.Steps), len(j.Steps))
			}
		})
	}
}
