package mcpspec

import (
	"encoding/json"
	"fmt"
)

// Input is the observed MCP surface to score. Every field carrying protocol
// shape is raw wire JSON: what a client actually receives, captured from a real
// session, rather than a re-marshalling of our internal Go types.
type Input struct {
	// ToolsListResult is the tools/list result as served.
	ToolsListResult json.RawMessage
	// HandshakeResult is the initialize (or, from 2026-07-28, server/discover)
	// result as served. Optional.
	HandshakeResult json.RawMessage
	// Capabilities is the serverCapabilities object as served. Optional.
	Capabilities json.RawMessage
	// ImplementedMethods lists the JSON-RPC methods this server actually serves.
	ImplementedMethods []string
	// DeclaredCapabilities lists the capability keys this server declares.
	DeclaredCapabilities []string
	// NegotiatedVersion is the protocol revision the server negotiated.
	NegotiatedVersion string
	// Manifest is the vendored revision list, used for currency scoring.
	Manifest *Manifest
}

// Dimension weights. They sum to 100; skipped dimensions drop out of the
// denominator so a revision that removes a feature cannot depress the score.
const (
	weightToolSchema      = 40
	weightListToolsResult = 15
	weightMethodSurface   = 15
	weightHandshake       = 10
	weightCapabilities    = 10
	weightCurrency        = 10
)

// Evaluate scores the observed surface against one schema revision.
func Evaluate(spec *Spec, in Input) *Report {
	r := &Report{
		SchemaVersion:     spec.Version,
		SchemaDraft:       spec.Draft(),
		NegotiatedVersion: in.NegotiatedVersion,
		RevisionsBehind:   -1,
	}
	if in.Manifest != nil {
		r.NewestPublished = in.Manifest.Newest()
		r.RevisionsBehind = in.Manifest.RevisionsBehind(in.NegotiatedVersion)
	}

	r.MethodSurface = newSurface(spec.ServerMethods(), in.ImplementedMethods)
	r.CapabilitySurface = newSurface(spec.ServerCapabilityKeys(), in.DeclaredCapabilities)

	r.Dimensions = []Dimension{
		toolSchemaDimension(spec, in, r),
		singleInstanceDimension(spec, r, dimSpec{
			id:      "list-tools-result",
			title:   "tools/list result conforms",
			weight:  weightListToolsResult,
			defs:    []string{"ListToolsResult"},
			payload: in.ToolsListResult,
		}),
		methodSurfaceDimension(r),
		singleInstanceDimension(spec, r, dimSpec{
			id:     "handshake-result",
			title:  "Handshake result conforms",
			weight: weightHandshake,
			// The handshake was restructured in 2026-07-28: initialize is replaced
			// by server/discover. Name both and use whichever the revision defines.
			defs:    []string{"InitializeResult", "DiscoverResult"},
			payload: in.HandshakeResult,
		}),
		singleInstanceDimension(spec, r, dimSpec{
			id:      "server-capabilities",
			title:   "Server capabilities conform",
			weight:  weightCapabilities,
			defs:    []string{"ServerCapabilities"},
			payload: in.Capabilities,
		}),
		currencyDimension(r),
	}

	r.finalize()
	return r
}

// toolsListPayload is the slice of the tools/list result we need for per-tool
// validation and naming.
type toolsListPayload struct {
	Tools []json.RawMessage `json:"tools"`
}

// toolSchemaDimension validates every served tool against the revision's Tool
// definition. This is the heaviest dimension: it is where the project's own
// hand-written InputSchemas and annotations are actually checked.
func toolSchemaDimension(spec *Spec, in Input, r *Report) Dimension {
	d := Dimension{ID: "tool-schema", Title: "Tool definitions conform", Weight: weightToolSchema}

	if !spec.Has("Tool") {
		d.Skipped, d.SkipReason = true, "revision does not define Tool"
		return d
	}
	if len(in.ToolsListResult) == 0 {
		d.Skipped, d.SkipReason = true, "no tools/list result captured"
		return d
	}

	var payload toolsListPayload
	if err := json.Unmarshal(in.ToolsListResult, &payload); err != nil {
		d.Detail = "could not decode tools/list result"
		r.Findings = append(r.Findings, Finding{
			Dimension: d.ID, Subject: "tools/list", Problem: err.Error(),
		})
		return d
	}
	if len(payload.Tools) == 0 {
		d.Skipped, d.SkipReason = true, "server served no tools"
		return d
	}

	d.Total = len(payload.Tools)
	for _, raw := range payload.Tools {
		name := toolName(raw)
		if err := spec.ValidateJSON("Tool", raw); err != nil {
			r.Findings = append(r.Findings, Finding{
				Dimension: d.ID, Subject: name, Problem: err.Error(),
			})
			continue
		}
		d.Passed++
	}
	d.Score = pct(d.Passed, d.Total)
	d.Detail = fmt.Sprintf("%d of %d tools valid", d.Passed, d.Total)
	return d
}

// dimSpec describes a dimension that validates one whole instance.
type dimSpec struct {
	id      string
	title   string
	weight  int
	defs    []string // candidate definition names, in preference order
	payload json.RawMessage
}

func singleInstanceDimension(spec *Spec, r *Report, ds dimSpec) Dimension {
	d := Dimension{ID: ds.id, Title: ds.title, Weight: ds.weight}

	def, ok := spec.FirstPresent(ds.defs...)
	if !ok {
		d.Skipped = true
		d.SkipReason = fmt.Sprintf("revision defines none of %v", ds.defs)
		return d
	}
	if len(ds.payload) == 0 {
		d.Skipped, d.SkipReason = true, "no "+def+" captured"
		return d
	}

	d.Total = 1
	if err := spec.ValidateJSON(def, ds.payload); err != nil {
		r.Findings = append(r.Findings, Finding{Dimension: d.ID, Subject: def, Problem: err.Error()})
		d.Detail = "does not validate against " + def
		return d
	}
	d.Passed, d.Score = 1, 100
	d.Detail = "validates against " + def
	return d
}

// methodSurfaceDimension scores how much of the revision's server-side method
// surface this server implements, derived from the ClientRequest union.
func methodSurfaceDimension(r *Report) Dimension {
	d := Dimension{ID: "method-surface", Title: "Server method coverage", Weight: weightMethodSurface}
	s := r.MethodSurface
	if len(s.Defined) == 0 {
		d.Skipped, d.SkipReason = true, "revision defines no ClientRequest union"
		return d
	}
	d.Passed, d.Total, d.Score = len(s.Present), len(s.Defined), s.Coverage
	d.Detail = fmt.Sprintf("%d of %d server methods implemented", len(s.Present), len(s.Defined))
	return d
}

// currencyDimension scores how current the negotiated revision is. Each released
// revision behind halves the score, so falling further behind keeps costing but
// never dominates the total.
func currencyDimension(r *Report) Dimension {
	d := Dimension{ID: "protocol-currency", Title: "Protocol revision currency", Weight: weightCurrency}

	switch {
	case r.NegotiatedVersion == "":
		d.Skipped, d.SkipReason = true, "negotiated revision unknown"
	case r.RevisionsBehind < 0:
		d.Detail = fmt.Sprintf("negotiated %q is not a known released revision", r.NegotiatedVersion)
	case r.RevisionsBehind == 0:
		d.Score, d.Detail = 100, "negotiating the newest published revision"
	default:
		d.Score = 100 >> r.RevisionsBehind
		d.Detail = fmt.Sprintf("%d released revision(s) behind %s", r.RevisionsBehind, r.NewestPublished)
	}
	return d
}

func toolName(raw json.RawMessage) string {
	var t struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(raw, &t); err != nil || t.Name == "" {
		return "<unnamed>"
	}
	return t.Name
}

func pct(passed, total int) int {
	if total == 0 {
		return 0
	}
	return 100 * passed / total
}
