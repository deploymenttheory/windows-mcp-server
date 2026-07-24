//go:build windows && (amd64 || arm64)

package windows

import (
	"testing"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/deploymenttheory/windows-mcp-server/pkg/inventory"
)

// TestAllToolsValid asserts every tool in the manifest is well-formed: unique
// name, non-empty description, a toolset, an object input schema, and a handler.
func TestAllToolsValid(t *testing.T) {
	tools := AllTools()
	if len(tools) == 0 {
		t.Fatal("AllTools() is empty")
	}
	seen := map[string]bool{}
	for _, st := range tools {
		name := st.Tool.Name
		if name == "" {
			t.Error("tool with empty name")
			continue
		}
		if seen[name] {
			t.Errorf("duplicate tool name %q", name)
		}
		seen[name] = true

		if st.Tool.Description == "" {
			t.Errorf("%s: empty description", name)
		}
		if st.Toolset.ID == "" {
			t.Errorf("%s: no toolset", name)
		}
		if !st.HasHandler() {
			t.Errorf("%s: no handler", name)
		}
		schema, ok := st.Tool.InputSchema.(*jsonschema.Schema)
		if !ok || schema == nil {
			t.Errorf("%s: input schema is not *jsonschema.Schema", name)
			continue
		}
		if schema.Type != "object" {
			t.Errorf("%s: input schema type = %q, want object", name, schema.Type)
		}
	}
}

// TestExpectedToolCount guards against accidental tool loss/addition.
func TestExpectedToolCount(t *testing.T) {
	const want = 26
	if got := len(AllTools()); got != want {
		t.Errorf("tool count = %d, want %d (update this test intentionally)", got, want)
	}
}

// TestPersonasReferenceRealToolsets ensures each persona's toolsets exist in the
// manifest, so a persona can never silently resolve to an unknown toolset.
func TestPersonasReferenceRealToolsets(t *testing.T) {
	inv, err := NewInventory().WithToolsets([]string{"all"}).Build()
	if err != nil {
		t.Fatal(err)
	}
	valid := map[inventory.ToolsetID]bool{}
	for _, id := range inv.ToolsetIDs() {
		valid[id] = true
	}
	for id, persona := range Personas {
		for _, ts := range persona.Toolsets {
			if !valid[inventory.ToolsetID(ts)] {
				t.Errorf("persona %q references unknown toolset %q", id, ts)
			}
		}
	}
}

// TestPersonasHaveGuidance asserts every persona carries instructions and a
// non-empty toolset selection, so it is a complete "tooling collection".
func TestPersonasHaveGuidance(t *testing.T) {
	if len(Personas) == 0 {
		t.Fatal("no personas defined")
	}
	for id, p := range Personas {
		if p.Instructions == "" {
			t.Errorf("persona %q has no instructions", id)
		}
		if len(p.Toolsets) == 0 {
			t.Errorf("persona %q has no toolsets", id)
		}
	}
}

// TestReadOnlyToolsAreSafe asserts tools we expect to be read-only are annotated
// as such (so --read-only and read-only personas expose them).
func TestReadOnlyToolsAreSafe(t *testing.T) {
	readOnly := map[string]bool{
		"Snapshot": true, "Screenshot": true, "DisplayInventory": true,
		"Wait": true, "WaitFor": true, "Scrape": true, "GetText": true,
		"Assert": true, "CaptureEvidence": true, "SystemInfo": true,
	}
	for _, st := range AllTools() {
		if readOnly[st.Tool.Name] && !st.IsReadOnly() {
			t.Errorf("%s should be read-only", st.Tool.Name)
		}
	}
}

// TestDestructiveToolsAreWrite asserts powerful tools are not marked read-only.
func TestDestructiveToolsAreWrite(t *testing.T) {
	for _, st := range AllTools() {
		switch st.Tool.Name {
		case "PowerShell", "Registry", "FileSystem", "Process":
			if st.IsReadOnly() {
				t.Errorf("%s must not be read-only", st.Tool.Name)
			}
		}
	}
}
