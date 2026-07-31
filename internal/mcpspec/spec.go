// Package mcpspec loads the vendored Model Context Protocol JSON Schemas and
// validates wire JSON against them.
//
// The authority on conformance is the official suite at
// github.com/modelcontextprotocol/conformance, run against the server from the
// compliance workflow; see internal/mcpconf for the reporting side.
//
// Two jobs remain here:
//
//   - a fast, offline, pass/fail validation of the served surface against the
//     newest vendored revision, so `go test` still catches a broken tool schema on
//     a machine with no Node installed (see winmcp's capture test); and
//   - the revision manifest, which the compliance workflow uses to notice that
//     upstream has published a revision newer than the one we run against.
//
// Lookups are driven by what a revision's schema actually defines rather than by
// hardcoded definition names, because the protocol restructures between
// revisions: 2026-07-28, for example, removes InitializeRequest/InitializeResult
// entirely in favour of server/discover. FirstPresent exists for exactly that, so
// a caller can name the equivalent definitions and let the revision decide.
//
// The package is platform-agnostic (no build tag), so it is testable in isolation.
package mcpspec

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
)

// ManifestFile is the vendored revision manifest, relative to the schema dir.
const ManifestFile = "versions.json"

// SchemaFile is the schema document within each revision directory.
const SchemaFile = "schema.json"

// ErrNoDefinitions is returned for a schema document with neither $defs nor
// definitions — i.e. not a recognizable MCP schema.
var ErrNoDefinitions = errors.New("schema has neither $defs nor definitions")

// MissingDefError reports a definition the loaded revision does not declare.
// Callers treat this as "check not applicable to this revision", not a failure.
type MissingDefError struct {
	Version string
	Def     string
}

func (e *MissingDefError) Error() string {
	return fmt.Sprintf("schema %s does not define %q", e.Version, e.Def)
}

// Manifest is the vendored revision list.
type Manifest struct {
	Source   string   `json:"source"`
	Note     string   `json:"note"`
	Versions []string `json:"versions"`
}

// LoadManifest reads the revision manifest from dir. Versions are returned
// sorted, which for ISO-8601 revision names is also chronological order.
func LoadManifest(dir string) (*Manifest, error) {
	b, err := os.ReadFile(filepath.Join(dir, ManifestFile))
	if err != nil {
		return nil, fmt.Errorf("read schema manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parse schema manifest: %w", err)
	}
	if len(m.Versions) == 0 {
		return nil, errors.New("schema manifest lists no versions")
	}
	sort.Strings(m.Versions)
	return &m, nil
}

// Newest returns the most recent vendored revision.
func (m *Manifest) Newest() string { return m.Versions[len(m.Versions)-1] }

// Index returns the position of version in the revision list, or -1.
func (m *Manifest) Index(version string) int {
	for i, v := range m.Versions {
		if v == version {
			return i
		}
	}
	return -1
}

// RevisionsBehind reports how many released revisions newer than version exist.
// It returns -1 when version is not a known revision.
func (m *Manifest) RevisionsBehind(version string) int {
	i := m.Index(version)
	if i < 0 {
		return -1
	}
	return len(m.Versions) - 1 - i
}

// Spec is one loaded MCP schema revision, ready to validate instances against.
type Spec struct {
	Version string

	root    *jsonschema.Schema
	defsKey string // "$defs" (2020-12 revisions) or "definitions" (draft-07 ones)
	defs    map[string]*jsonschema.Schema
	cache   map[string]*jsonschema.Resolved
}

// Load reads dir/<version>/schema.json.
func Load(dir, version string) (*Spec, error) {
	b, err := os.ReadFile(filepath.Join(dir, version, SchemaFile))
	if err != nil {
		return nil, fmt.Errorf("read schema %s: %w", version, err)
	}
	return Parse(version, b)
}

// Parse builds a Spec from a raw schema document. Both the draft-07 /
// "definitions" and the 2020-12 / "$defs" layouts used across MCP revisions are
// accepted.
func Parse(version string, raw []byte) (*Spec, error) {
	var root jsonschema.Schema
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("parse schema %s: %w", version, err)
	}
	s := &Spec{Version: version, root: &root, cache: map[string]*jsonschema.Resolved{}}
	switch {
	case len(root.Defs) > 0:
		s.defsKey, s.defs = "$defs", root.Defs
	case len(root.Definitions) > 0:
		s.defsKey, s.defs = "definitions", root.Definitions
	default:
		return nil, fmt.Errorf("schema %s: %w", version, ErrNoDefinitions)
	}
	return s, nil
}

// Draft reports the JSON Schema dialect the revision declares.
func (s *Spec) Draft() string { return s.root.Schema }

// DefCount returns the number of definitions in the revision.
func (s *Spec) DefCount() int { return len(s.defs) }

// Has reports whether the revision declares the named definition.
func (s *Spec) Has(def string) bool { _, ok := s.defs[def]; return ok }

// FirstPresent returns the first of names the revision declares, and whether any
// matched. It lets a check name the equivalent definitions across revisions
// (e.g. InitializeResult, then DiscoverResult) instead of hardcoding one.
func (s *Spec) FirstPresent(names ...string) (string, bool) {
	for _, n := range names {
		if s.Has(n) {
			return n, true
		}
	}
	return "", false
}

// Validate checks a decoded JSON instance against the named definition.
func (s *Spec) Validate(def string, instance any) error {
	r, err := s.resolve(def)
	if err != nil {
		return err
	}
	return r.Validate(instance)
}

// ValidateJSON checks raw wire JSON against the named definition.
func (s *Spec) ValidateJSON(def string, raw []byte) error {
	var instance any
	if err := json.Unmarshal(raw, &instance); err != nil {
		return fmt.Errorf("decode instance: %w", err)
	}
	return s.Validate(def, instance)
}

// resolve builds (and caches) a schema rooted at the named definition. The whole
// definition map is carried on the wrapper so intra-schema $refs still resolve.
func (s *Spec) resolve(def string) (*jsonschema.Resolved, error) {
	if r, ok := s.cache[def]; ok {
		return r, nil
	}
	if !s.Has(def) {
		return nil, &MissingDefError{Version: s.Version, Def: def}
	}
	wrapper := &jsonschema.Schema{
		Schema: s.root.Schema, // preserve the dialect: draft-07 vs 2020-12
		Ref:    "#/" + s.defsKey + "/" + def,
	}
	if s.defsKey == "$defs" {
		wrapper.Defs = s.defs
	} else {
		wrapper.Definitions = s.defs
	}
	r, err := wrapper.Resolve(&jsonschema.ResolveOptions{})
	if err != nil {
		return nil, fmt.Errorf("resolve %s/%s: %w", s.Version, def, err)
	}
	s.cache[def] = r
	return r, nil
}

// ServerMethods returns the JSON-RPC methods the revision expects a *server* to
// implement. It is derived from the ClientRequest union — the requests a client
// sends — so it stays correct as revisions add and remove methods, and it
// excludes client-implemented methods such as sampling/createMessage.
func (s *Spec) ServerMethods() []string {
	union, ok := s.defs["ClientRequest"]
	if !ok {
		return nil
	}
	var out []string
	for _, member := range union.AnyOf {
		def := s.defs[s.defName(member.Ref)]
		if def == nil {
			continue
		}
		if m := methodConst(def); m != "" {
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out
}

// ServerCapabilityKeys returns the capability keys the revision defines on
// ServerCapabilities.
func (s *Spec) ServerCapabilityKeys() []string {
	caps, ok := s.defs["ServerCapabilities"]
	if !ok {
		return nil
	}
	out := make([]string, 0, len(caps.Properties))
	for k := range caps.Properties {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// defName extracts the definition name from an intra-schema $ref.
func (s *Spec) defName(ref string) string {
	prefix := "#/" + s.defsKey + "/"
	return strings.TrimPrefix(ref, prefix)
}

// methodConst reads the const value of a request definition's "method" property,
// looking through allOf composition when the revision nests it.
func methodConst(def *jsonschema.Schema) string {
	if m, ok := constString(def.Properties["method"]); ok {
		return m
	}
	for _, part := range def.AllOf {
		if m, ok := constString(part.Properties["method"]); ok {
			return m
		}
	}
	return ""
}

func constString(s *jsonschema.Schema) (string, bool) {
	if s == nil || s.Const == nil {
		return "", false
	}
	v, ok := (*s.Const).(string)
	return v, ok
}
