package inventory

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// makeTool builds a test ServerTool in the given toolset with a no-op handler.
func makeTool(name string, toolset ToolsetMetadata, readOnly bool) ServerTool {
	return NewServerTool(
		mcp.Tool{
			Name:        name,
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: readOnly},
		},
		toolset,
		func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) { return nil, nil },
	)
}

var (
	tsDefaultA = ToolsetMetadata{ID: "alpha", Description: "Alpha", Default: true}
	tsDefaultB = ToolsetMetadata{ID: "bravo", Description: "Bravo", Default: true}
	tsOptional = ToolsetMetadata{ID: "charlie", Description: "Charlie"}
)

func sampleTools() []ServerTool {
	return []ServerTool{
		makeTool("a_read", tsDefaultA, true),
		makeTool("a_write", tsDefaultA, false),
		makeTool("b_read", tsDefaultB, true),
		makeTool("c_write", tsOptional, false),
	}
}

func toolNames(tools []ServerTool) []string {
	names := make([]string, len(tools))
	for i, t := range tools {
		names[i] = t.Tool.Name
	}
	return names
}

func TestDefaultToolsetsOnly(t *testing.T) {
	inv, err := NewBuilder().SetTools(sampleTools()).Build()
	if err != nil {
		t.Fatal(err)
	}
	got := toolNames(inv.AvailableTools(context.Background()))
	want := []string{"a_read", "a_write", "b_read"} // charlie is not default
	if !slices.Equal(got, want) {
		t.Errorf("default toolsets: got %v, want %v", got, want)
	}
}

func TestAllToolsets(t *testing.T) {
	inv, err := NewBuilder().SetTools(sampleTools()).WithToolsets([]string{"all"}).Build()
	if err != nil {
		t.Fatal(err)
	}
	got := toolNames(inv.AvailableTools(context.Background()))
	want := []string{"a_read", "a_write", "b_read", "c_write"}
	if !slices.Equal(got, want) {
		t.Errorf("all toolsets: got %v, want %v", got, want)
	}
}

func TestSpecificToolset(t *testing.T) {
	inv, err := NewBuilder().SetTools(sampleTools()).WithToolsets([]string{"charlie"}).Build()
	if err != nil {
		t.Fatal(err)
	}
	got := toolNames(inv.AvailableTools(context.Background()))
	if !slices.Equal(got, []string{"c_write"}) {
		t.Errorf("charlie only: got %v", got)
	}
}

func TestReadOnlyFilter(t *testing.T) {
	inv, err := NewBuilder().SetTools(sampleTools()).WithToolsets([]string{"all"}).WithReadOnly(true).Build()
	if err != nil {
		t.Fatal(err)
	}
	got := toolNames(inv.AvailableTools(context.Background()))
	want := []string{"a_read", "b_read"}
	if !slices.Equal(got, want) {
		t.Errorf("read-only: got %v, want %v", got, want)
	}
}

func TestExcludeTools(t *testing.T) {
	inv, err := NewBuilder().SetTools(sampleTools()).WithToolsets([]string{"all"}).WithExcludeTools([]string{"a_write"}).Build()
	if err != nil {
		t.Fatal(err)
	}
	got := toolNames(inv.AvailableTools(context.Background()))
	if slices.Contains(got, "a_write") {
		t.Errorf("a_write should be excluded, got %v", got)
	}
}

func TestAdditionalToolsBypassToolset(t *testing.T) {
	// Enable only "alpha", but additionally allow c_write (in disabled charlie).
	inv, err := NewBuilder().SetTools(sampleTools()).
		WithToolsets([]string{"alpha"}).
		WithTools([]string{"c_write"}).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	got := toolNames(inv.AvailableTools(context.Background()))
	if !slices.Contains(got, "c_write") {
		t.Errorf("c_write should be included via WithTools, got %v", got)
	}
}

// TestReadOnlyFiltersAdditionalTools pins that --tools bypasses toolset membership
// but NOT the read-only filter, which sits ahead of the bypass: a write tool named
// in WithTools is still dropped under WithReadOnly. Otherwise --read-only would be
// a suggestion any --tools entry could escape.
func TestReadOnlyFiltersAdditionalTools(t *testing.T) {
	inv, err := NewBuilder().SetTools(sampleTools()).
		WithToolsets([]string{"alpha"}).
		WithReadOnly(true).
		WithTools([]string{"c_write"}). // c_write is destructive; charlie is disabled
		Build()
	if err != nil {
		t.Fatal(err)
	}
	got := toolNames(inv.AvailableTools(context.Background()))
	if slices.Contains(got, "c_write") {
		t.Errorf("a write tool added via WithTools must still be filtered under WithReadOnly, got %v", got)
	}
	if !slices.Contains(got, "a_read") {
		t.Errorf("read-only tools should remain, got %v", got)
	}
}

func TestUnknownAdditionalToolErrors(t *testing.T) {
	_, err := NewBuilder().SetTools(sampleTools()).WithTools([]string{"does_not_exist"}).Build()
	if !errors.Is(err, ErrUnknownTools) {
		t.Errorf("expected ErrUnknownTools, got %v", err)
	}
}

func TestEmptyToolsetsEnablesNone(t *testing.T) {
	inv, err := NewBuilder().SetTools(sampleTools()).WithToolsets([]string{}).Build()
	if err != nil {
		t.Fatal(err)
	}
	if got := inv.AvailableTools(context.Background()); len(got) != 0 {
		t.Errorf("empty toolsets should enable none, got %v", toolNames(got))
	}
}

func TestUnrecognizedToolsets(t *testing.T) {
	inv, err := NewBuilder().SetTools(sampleTools()).WithToolsets([]string{"alpha", "nope"}).Build()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(inv.UnrecognizedToolsets(), "nope") {
		t.Errorf("expected 'nope' unrecognized, got %v", inv.UnrecognizedToolsets())
	}
}

func TestFeatureFlagGating(t *testing.T) {
	tools := sampleTools()
	// Gate a_write behind a feature flag that is off.
	tools[1].FeatureFlagEnable = "beta_feature"
	checker := func(_ context.Context, flag string) (bool, error) {
		return flag != "beta_feature", nil // beta_feature is disabled
	}
	inv, err := NewBuilder().SetTools(tools).WithToolsets([]string{"all"}).WithFeatureChecker(checker).Build()
	if err != nil {
		t.Fatal(err)
	}
	got := toolNames(inv.AvailableTools(context.Background()))
	if slices.Contains(got, "a_write") {
		t.Errorf("a_write should be gated off, got %v", got)
	}
}

func TestDefaultToolsetIDs(t *testing.T) {
	inv, err := NewBuilder().SetTools(sampleTools()).Build()
	if err != nil {
		t.Fatal(err)
	}
	ids := inv.DefaultToolsetIDs()
	if !slices.Contains(ids, ToolsetID("alpha")) || !slices.Contains(ids, ToolsetID("bravo")) {
		t.Errorf("expected alpha+bravo as defaults, got %v", ids)
	}
	if slices.Contains(ids, ToolsetID("charlie")) {
		t.Errorf("charlie should not be a default, got %v", ids)
	}
}

func TestDeterministicOrdering(t *testing.T) {
	inv, err := NewBuilder().SetTools(sampleTools()).WithToolsets([]string{"all"}).Build()
	if err != nil {
		t.Fatal(err)
	}
	// Sorted by toolset ID then name.
	got := toolNames(inv.AvailableTools(context.Background()))
	want := []string{"a_read", "a_write", "b_read", "c_write"}
	if !slices.Equal(got, want) {
		t.Errorf("ordering: got %v, want %v", got, want)
	}
}
