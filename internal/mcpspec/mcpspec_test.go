package mcpspec

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"testing"
)

// schemaDir is the vendored schema tree, relative to this package.
func schemaDir() string { return filepath.Join("..", "..", "schema") }

func TestLoadManifest(t *testing.T) {
	m, err := LoadManifest(schemaDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Versions) < 2 {
		t.Fatalf("expected several vendored revisions, got %v", m.Versions)
	}
	if !slices.IsSorted(m.Versions) {
		t.Errorf("versions must be sorted (ISO dates sort chronologically): %v", m.Versions)
	}
	if got := m.Newest(); got != m.Versions[len(m.Versions)-1] {
		t.Errorf("Newest() = %q", got)
	}
	if got := m.RevisionsBehind(m.Newest()); got != 0 {
		t.Errorf("newest revision should be 0 behind, got %d", got)
	}
	if got := m.RevisionsBehind(m.Versions[0]); got != len(m.Versions)-1 {
		t.Errorf("oldest revision should be %d behind, got %d", len(m.Versions)-1, got)
	}
	if got := m.RevisionsBehind("1999-01-01"); got != -1 {
		t.Errorf("unknown revision should report -1, got %d", got)
	}
}

// TestEveryVendoredSchemaResolves is the load-bearing test: every revision must
// parse and every definition a check depends on must actually resolve. It covers
// both schema layouts in the vendored set (draft-07/definitions for the early
// revisions, 2020-12/$defs for the later ones).
func TestEveryVendoredSchemaResolves(t *testing.T) {
	m, err := LoadManifest(schemaDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range m.Versions {
		t.Run(v, func(t *testing.T) {
			spec, err := Load(schemaDir(), v)
			if err != nil {
				t.Fatal(err)
			}
			if spec.Draft() == "" {
				t.Error("revision declares no $schema dialect")
			}
			if spec.DefCount() == 0 {
				t.Fatal("no definitions loaded")
			}
			// Tool and ListToolsResult exist in every MCP revision to date; if that
			// ever stops being true the dimension skips rather than fails, but the
			// resolve path still has to work here.
			for _, def := range []string{"Tool", "ListToolsResult"} {
				if !spec.Has(def) {
					t.Fatalf("revision does not define %s", def)
				}
				if err := spec.Validate(def, map[string]any{}); err == nil {
					t.Errorf("%s: empty object should fail validation (required fields)", def)
				} else if errors.Is(err, ErrNoDefinitions) {
					t.Errorf("%s: resolve failed: %v", def, err)
				}
			}
			if got := spec.ServerMethods(); len(got) == 0 {
				t.Error("no server methods derived from ClientRequest union")
			}
			if got := spec.ServerCapabilityKeys(); len(got) == 0 {
				t.Error("no server capability keys derived from ServerCapabilities")
			}
		})
	}
}

// TestServerMethodsAreServerSide guards the ClientRequest-union derivation: it
// must yield methods a server implements and never client-implemented ones.
func TestServerMethodsAreServerSide(t *testing.T) {
	m, err := LoadManifest(schemaDir())
	if err != nil {
		t.Fatal(err)
	}
	spec, err := Load(schemaDir(), m.Newest())
	if err != nil {
		t.Fatal(err)
	}
	methods := spec.ServerMethods()

	for _, want := range []string{"tools/list", "tools/call"} {
		if !slices.Contains(methods, want) {
			t.Errorf("server methods missing %q: %v", want, methods)
		}
	}
	// Client-implemented methods must not appear.
	for _, unwanted := range []string{"sampling/createMessage", "roots/list", "elicitation/create"} {
		if slices.Contains(methods, unwanted) {
			t.Errorf("client-side method %q leaked into server methods", unwanted)
		}
	}
}

// TestMissingDefIsReportedNotFatal covers the revision-drift path.
func TestMissingDefIsReportedNotFatal(t *testing.T) {
	spec, err := Parse("test", []byte(`{"$defs":{"Thing":{"type":"object"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	err = spec.Validate("Nope", map[string]any{})
	var missing *MissingDefError
	if !errors.As(err, &missing) {
		t.Fatalf("want MissingDefError, got %v", err)
	}
	if missing.Def != "Nope" || missing.Version != "test" {
		t.Errorf("unexpected MissingDefError contents: %+v", missing)
	}
	if _, ok := spec.FirstPresent("Nope", "Thing"); !ok {
		t.Error("FirstPresent should fall through to the defined name")
	}
}

func TestParseRejectsSchemaWithoutDefinitions(t *testing.T) {
	if _, err := Parse("test", []byte(`{"type":"object"}`)); !errors.Is(err, ErrNoDefinitions) {
		t.Errorf("want ErrNoDefinitions, got %v", err)
	}
}

// TestEvaluateScoresAndSkips exercises the scoring maths, including that a
// skipped dimension leaves the denominator rather than scoring zero.
func TestEvaluateScoresAndSkips(t *testing.T) {
	m, err := LoadManifest(schemaDir())
	if err != nil {
		t.Fatal(err)
	}
	spec, err := Load(schemaDir(), m.Newest())
	if err != nil {
		t.Fatal(err)
	}

	// A minimal but genuinely valid tools/list result.
	toolsList := json.RawMessage(`{"tools":[{"name":"Ping","description":"d","inputSchema":{"type":"object"}}]}`)
	rep := Evaluate(spec, Input{
		ToolsListResult:      toolsList,
		ImplementedMethods:   []string{"tools/list", "tools/call"},
		DeclaredCapabilities: []string{"tools"},
		NegotiatedVersion:    m.Newest(),
		Manifest:             m,
	})

	if rep.Score <= 0 || rep.Score > 100 {
		t.Fatalf("score out of range: %d", rep.Score)
	}
	if rep.ApplicableWeight <= 0 || rep.ApplicableWeight > 100 {
		t.Errorf("applicable weight out of range: %d", rep.ApplicableWeight)
	}
	if rep.RevisionsBehind != 0 {
		t.Errorf("negotiating newest should be 0 behind, got %d", rep.RevisionsBehind)
	}

	byID := map[string]Dimension{}
	for _, d := range rep.Dimensions {
		byID[d.ID] = d
	}
	if d := byID["tool-schema"]; d.Skipped || d.Score != 100 {
		t.Errorf("valid tool should score 100, got %+v (findings: %+v)", d, rep.Findings)
	}
	if d := byID["protocol-currency"]; d.Score != 100 {
		t.Errorf("currency on newest should be 100, got %+v", d)
	}
	// Nothing was captured for these, so they must skip, not score zero.
	for _, id := range []string{"handshake-result", "server-capabilities"} {
		if d := byID[id]; !d.Skipped {
			t.Errorf("%s should skip when nothing was captured, got %+v", id, d)
		}
	}
	// Skipped weight must be excluded from the denominator.
	if rep.ApplicableWeight != weightToolSchema+weightListToolsResult+weightMethodSurface+weightCurrency {
		t.Errorf("applicable weight should exclude skipped dimensions, got %d", rep.ApplicableWeight)
	}
	if rep.Markdown() == "" {
		t.Error("Markdown() returned empty")
	}
}

// TestEvaluateFlagsInvalidTool proves the tool dimension actually catches a
// malformed tool rather than passing everything.
func TestEvaluateFlagsInvalidTool(t *testing.T) {
	m, err := LoadManifest(schemaDir())
	if err != nil {
		t.Fatal(err)
	}
	spec, err := Load(schemaDir(), m.Newest())
	if err != nil {
		t.Fatal(err)
	}

	// Missing the required inputSchema, and name is the wrong type.
	bad := json.RawMessage(`{"tools":[{"name":123}]}`)
	rep := Evaluate(spec, Input{ToolsListResult: bad, Manifest: m})

	byID := map[string]Dimension{}
	for _, d := range rep.Dimensions {
		byID[d.ID] = d
	}
	d := byID["tool-schema"]
	if d.Skipped {
		t.Fatal("dimension should have run")
	}
	if d.Passed != 0 || d.Score != 0 {
		t.Errorf("malformed tool must not pass: %+v", d)
	}
	if len(rep.Findings) == 0 {
		t.Error("a malformed tool must produce a finding")
	}
}

func TestCurrencyHalvesPerRevisionBehind(t *testing.T) {
	m := &Manifest{Versions: []string{"a", "b", "c", "d"}}
	for _, tc := range []struct {
		negotiated string
		want       int
	}{
		{"d", 100}, {"c", 50}, {"b", 25}, {"a", 12},
	} {
		r := &Report{NegotiatedVersion: tc.negotiated, NewestPublished: m.Newest(), RevisionsBehind: m.RevisionsBehind(tc.negotiated)}
		if got := currencyDimension(r); got.Score != tc.want {
			t.Errorf("negotiated %q: score = %d, want %d", tc.negotiated, got.Score, tc.want)
		}
	}
}
