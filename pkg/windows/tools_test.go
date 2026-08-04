//go:build windows && (amd64 || arm64)

package windows

import (
	"strings"
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
	// 35 since LaunchExecutable was split out of App's launch_executable mode, so
	// arbitrary code execution sits in the shell toolset rather than in apps.
	const want = 35
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
		"Plan": true, "EventLog": true, "Network": true,
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
		case "PowerShell", "Registry", "FileSystem", "Process", "Credentials", "Apply", "ScheduledTask", "Package":
			if st.IsReadOnly() {
				t.Errorf("%s must not be read-only", st.Tool.Name)
			}
		}
	}
}

// TestCredentialsToolNeverReturnsSecrets is a guard on the tool's core security
// property. The Credentials tool must expose no mode that reads a secret back, so
// a future "get"/"read" mode cannot be added without deliberately editing this
// test — and the description must state the guarantee so the model does not try.
func TestCredentialsToolNeverReturnsSecrets(t *testing.T) {
	var tool *inventory.ServerTool
	for i := range AllTools() {
		if AllTools()[i].Tool.Name == "Credentials" {
			tool = &AllTools()[i]
			break
		}
	}
	if tool == nil {
		t.Fatal("Credentials tool not found in the manifest")
	}

	modeProp := tool.Tool.InputSchema.(*jsonschema.Schema).Properties["mode"]
	if modeProp == nil {
		t.Fatal("Credentials has no mode property")
	}
	allowed := map[string]bool{"list": true, "verify": true, "inject": true}
	for _, v := range modeProp.Enum {
		s, ok := v.(string)
		if !ok {
			t.Errorf("non-string mode enum value %v", v)
			continue
		}
		if !allowed[s] {
			t.Errorf("Credentials mode %q is not an approved mode; a secret-reading mode "+
				"would put plaintext into the model's context", s)
		}
	}
	if len(modeProp.Enum) != len(allowed) {
		t.Errorf("mode enum has %d values, want exactly %d", len(modeProp.Enum), len(allowed))
	}
	if !strings.Contains(tool.Tool.Description, "cannot be read") {
		t.Error("Credentials description must state that secrets cannot be read")
	}
}

// TestAllResourcesValid mirrors TestAllToolsValid for the resource manifest.
func TestAllResourcesValid(t *testing.T) {
	seen := map[string]bool{}
	uris := map[string]bool{}
	for _, r := range AllResources() {
		switch {
		case r.Resource.Name == "":
			t.Error("resource with empty name")
		case r.Resource.URI == "":
			t.Errorf("resource %q has no URI", r.Resource.Name)
		case r.Resource.Description == "":
			t.Errorf("resource %q has no description", r.Resource.Name)
		case r.Toolset.ID == "":
			t.Errorf("resource %q has no toolset", r.Resource.Name)
		case !r.HasHandler():
			t.Errorf("resource %q has no handler", r.Resource.Name)
		}
		if seen[r.Resource.Name] {
			t.Errorf("duplicate resource name %q", r.Resource.Name)
		}
		if uris[r.Resource.URI] {
			t.Errorf("duplicate resource URI %q", r.Resource.URI)
		}
		seen[r.Resource.Name], uris[r.Resource.URI] = true, true

		if !strings.HasPrefix(r.Resource.URI, "windows://") {
			t.Errorf("resource %q URI %q should use the windows:// scheme", r.Resource.Name, r.Resource.URI)
		}
	}
}

// TestAllPromptsValid mirrors it for prompts, and checks required arguments are
// declared so a client can prompt the user for them.
func TestAllPromptsValid(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range AllPrompts() {
		switch {
		case p.Prompt.Name == "":
			t.Error("prompt with empty name")
		case p.Prompt.Description == "":
			t.Errorf("prompt %q has no description", p.Prompt.Name)
		case p.Toolset.ID == "":
			t.Errorf("prompt %q has no toolset", p.Prompt.Name)
		case p.Handler == nil:
			t.Errorf("prompt %q has no handler", p.Prompt.Name)
		}
		if seen[p.Prompt.Name] {
			t.Errorf("duplicate prompt name %q", p.Prompt.Name)
		}
		seen[p.Prompt.Name] = true

		for _, a := range p.Prompt.Arguments {
			if a.Name == "" {
				t.Errorf("prompt %q has an unnamed argument", p.Prompt.Name)
			}
			if a.Description == "" {
				t.Errorf("prompt %q argument %q has no description", p.Prompt.Name, a.Name)
			}
		}
	}
}

// TestResourcesAndPromptsUseToolBearingToolsets guards a subtle inventory trap:
// AvailableToolsets, EnabledToolsets and the instructions generator all iterate
// tools only, so a toolset introduced solely by a resource or prompt would be
// invisible to them.
func TestResourcesAndPromptsUseToolBearingToolsets(t *testing.T) {
	withTools := map[inventory.ToolsetID]bool{}
	for _, st := range AllTools() {
		withTools[st.Toolset.ID] = true
	}
	for _, r := range AllResources() {
		if !withTools[r.Toolset.ID] {
			t.Errorf("resource %q uses toolset %q which contains no tools; it would be "+
				"invisible to AvailableToolsets/EnabledToolsets", r.Resource.Name, r.Toolset.ID)
		}
	}
	for _, p := range AllPrompts() {
		if !withTools[p.Toolset.ID] {
			t.Errorf("prompt %q uses toolset %q which contains no tools", p.Prompt.Name, p.Toolset.ID)
		}
	}
}

// TestPromptsReusePersonaGuidance pins the single-source-of-truth rule: prompt
// text is built from Personas[...].Instructions rather than restating it, so the
// two cannot drift.
func TestPromptsReusePersonaGuidance(t *testing.T) {
	if got := personaGuidance("business-user"); got == "" {
		t.Fatal("personaGuidance returned empty for a real persona")
	}
	if got := personaGuidance("no-such-persona"); got != "" {
		t.Errorf("unknown persona should yield empty guidance, got %q", got)
	}
}

// TestExecutionPrimitivesAreAnnotatedDestructive pins the annotations policy
// rules match on. Each of these tools can cause or drive arbitrary execution, and
// each was previously unannotated -- so a rule matching `annotation: destructive`
// (as policy/examples/secure.json and enterprise.json both do, for hardware
// posture, rate limiting and require_plan) silently did not cover them.
//
// App launches an arbitrary executable. Type and Shortcut are universal write
// primitives, and win+r followed by Type is arbitrary execution without ever
// calling PowerShell. MultiEdit amplifies Type. Credentials types a live secret.
func TestExecutionPrimitivesAreAnnotatedDestructive(t *testing.T) {
	want := map[string]bool{
		"App": true, "Type": true, "Shortcut": true, "MultiEdit": true, "Credentials": true,
	}
	seen := map[string]bool{}
	for _, tool := range AllTools() {
		if !want[tool.Tool.Name] {
			continue
		}
		seen[tool.Tool.Name] = true
		a := tool.Tool.Annotations
		if a == nil || a.DestructiveHint == nil || !*a.DestructiveHint {
			t.Errorf("%s must carry DestructiveHint: policy rules and rate limits match on it, "+
				"so without it this tool is outside every destructive gate", tool.Tool.Name)
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("%s is no longer in the manifest; update this test deliberately", name)
		}
	}
}

// TestRecordingIsNotReadOnly guards a tool that writes while claiming not to.
// mode=mark appends a model-supplied label to the session file, so annotated
// read-only it was served even under --read-only and no destructive rule or rate
// limit applied to it.
func TestRecordingIsNotReadOnly(t *testing.T) {
	for _, tool := range AllTools() {
		if tool.Tool.Name != "Recording" {
			continue
		}
		if tool.Tool.Annotations != nil && tool.Tool.Annotations.ReadOnlyHint {
			t.Error("Recording mode=mark writes to the session file; it must not be annotated read-only")
		}
		return
	}
	t.Error("Recording is no longer in the manifest; update this test deliberately")
}

// TestArbitraryExecutionIsNotInADefaultToolset pins where code execution lives.
//
// launch_executable used to be a mode of App, in the Default: true apps toolset
// carried by every persona -- including business-user, whose instructions promise
// "no shell, registry, or file-system access". A persona documented as having no
// shell could therefore start cmd.exe.
func TestArbitraryExecutionIsNotInADefaultToolset(t *testing.T) {
	execTools := map[string]bool{"PowerShell": true, "LaunchExecutable": true}
	found := 0
	for _, tool := range AllTools() {
		if !execTools[tool.Tool.Name] {
			continue
		}
		found++
		if tool.Toolset.Default {
			t.Errorf("%s is in the default toolset %q; arbitrary code execution must be opt-in",
				tool.Tool.Name, tool.Toolset.ID)
		}
		if tool.Toolset.ID != ToolsetShell.ID {
			t.Errorf("%s is in toolset %q, want %q so one decision covers all code execution",
				tool.Tool.Name, tool.Toolset.ID, ToolsetShell.ID)
		}
	}
	if found != len(execTools) {
		t.Errorf("found %d of %d execution tools; update this test deliberately", found, len(execTools))
	}
}

// TestAppNoLongerExecutesByPath keeps the mode from being reintroduced on the
// tool that every persona carries.
func TestAppNoLongerExecutesByPath(t *testing.T) {
	for _, tool := range AllTools() {
		if tool.Tool.Name != "App" {
			continue
		}
		schema, ok := tool.Tool.InputSchema.(*jsonschema.Schema)
		if !ok || schema == nil {
			t.Fatal("App input schema is not *jsonschema.Schema")
		}
		if props := schema.Properties; props != nil {
			for _, banned := range []string{"executable", "cwd"} {
				if _, ok := props[banned]; ok {
					t.Errorf("App accepts %q again; execution by path belongs to LaunchExecutable "+
						"in the shell toolset", banned)
				}
			}
		}
		return
	}
	t.Error("App is no longer in the manifest; update this test deliberately")
}
