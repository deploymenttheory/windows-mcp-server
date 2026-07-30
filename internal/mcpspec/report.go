package mcpspec

import (
	"fmt"
	"slices"
	"strings"
)

// Report is the scored conformance result for one protocol revision.
type Report struct {
	// SchemaVersion is the revision scored against.
	SchemaVersion string `json:"schema_version"`
	// SchemaDraft is the JSON Schema dialect that revision declares.
	SchemaDraft string `json:"schema_draft,omitempty"`
	// NegotiatedVersion is the revision the server actually negotiates.
	NegotiatedVersion string `json:"negotiated_version,omitempty"`
	// NewestPublished is the most recent vendored revision.
	NewestPublished string `json:"newest_published,omitempty"`
	// RevisionsBehind counts released revisions newer than the negotiated one.
	RevisionsBehind int `json:"revisions_behind"`
	// ConformanceScore is the weighted score, 0-100, over applicable *conformance*
	// dimensions. This is the number to gate on: 100 means everything the server
	// actually serves validates against this revision.
	ConformanceScore int `json:"conformance_score"`
	// ConformanceWeight is the total weight of non-skipped conformance dimensions.
	ConformanceWeight int `json:"conformance_weight"`
	// Coverage summarizes optional-feature breadth. Informational only — MCP does
	// not require a server to implement prompts, resources or completions.
	Coverage   CoverageSummary `json:"coverage"`
	Dimensions []Dimension     `json:"dimensions"`
	Findings   []Finding       `json:"findings,omitempty"`
	// MethodSurface details spec-defined server methods against implemented ones.
	MethodSurface Surface `json:"method_surface"`
	// CapabilitySurface details spec-defined capability keys against declared ones.
	CapabilitySurface Surface `json:"capability_surface"`
}

// Dimension kinds. Only KindConformance contributes to ConformanceScore.
const (
	KindConformance = "conformance"
	KindCoverage    = "coverage"
)

// CoverageSummary reports optional-feature breadth, separately from conformance.
type CoverageSummary struct {
	MethodsImplemented   int `json:"methods_implemented"`
	MethodsDefined       int `json:"methods_defined"`
	MethodsPct           int `json:"methods_pct"`
	CapabilitiesDeclared int `json:"capabilities_declared"`
	CapabilitiesDefined  int `json:"capabilities_defined"`
	CapabilitiesPct      int `json:"capabilities_pct"`
}

// Dimension is one scored axis.
type Dimension struct {
	ID string `json:"id"`
	// Kind is KindConformance or KindCoverage; only the former is scored.
	Kind   string `json:"kind"`
	Title  string `json:"title"`
	Weight int    `json:"weight"`
	// Score is 0-100 for this dimension.
	Score int `json:"score"`
	// Passed and Total are populated for count-based dimensions.
	Passed int `json:"passed,omitempty"`
	Total  int `json:"total,omitempty"`
	// Skipped marks a dimension the revision does not support; it is excluded
	// from the score denominator and SkipReason says why.
	Skipped    bool   `json:"skipped,omitempty"`
	SkipReason string `json:"skip_reason,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

// Finding is a single concrete conformance defect.
type Finding struct {
	Dimension string `json:"dimension"`
	Subject   string `json:"subject"`
	Problem   string `json:"problem"`
}

// Surface compares what a revision defines against what this server provides.
type Surface struct {
	Defined  []string `json:"defined"`
	Present  []string `json:"present"`
	Missing  []string `json:"missing"`
	Unknown  []string `json:"unknown,omitempty"`
	Coverage int      `json:"coverage"`
}

// newSurface diffs a spec-defined set against what the server provides.
// Anything the server provides that the revision does not define lands in
// Unknown — which is how a server running ahead of (or behind) the scored
// revision shows up rather than being silently ignored.
func newSurface(defined, provided []string) Surface {
	definedSet := map[string]bool{}
	for _, d := range defined {
		definedSet[d] = true
	}
	providedSet := map[string]bool{}
	for _, p := range provided {
		providedSet[p] = true
	}

	s := Surface{Defined: sortedCopy(defined)}
	for _, d := range s.Defined {
		if providedSet[d] {
			s.Present = append(s.Present, d)
		} else {
			s.Missing = append(s.Missing, d)
		}
	}
	for _, p := range sortedCopy(provided) {
		if !definedSet[p] {
			s.Unknown = append(s.Unknown, p)
		}
	}
	if len(s.Defined) > 0 {
		s.Coverage = 100 * len(s.Present) / len(s.Defined)
	}
	return s
}

func sortedCopy(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return out
}

// finalize computes the conformance score over applicable conformance dimensions,
// and summarizes coverage separately.
func (r *Report) finalize() {
	var weighted, total int
	for _, d := range r.Dimensions {
		if d.Skipped || d.Kind != KindConformance {
			continue
		}
		total += d.Weight
		weighted += d.Weight * d.Score
	}
	r.ConformanceWeight = total
	if total > 0 {
		r.ConformanceScore = weighted / total
	}

	r.Coverage = CoverageSummary{
		MethodsImplemented:   len(r.MethodSurface.Present),
		MethodsDefined:       len(r.MethodSurface.Defined),
		MethodsPct:           r.MethodSurface.Coverage,
		CapabilitiesDeclared: len(r.CapabilitySurface.Present),
		CapabilitiesDefined:  len(r.CapabilitySurface.Defined),
		CapabilitiesPct:      r.CapabilitySurface.Coverage,
	}
}

// Markdown renders the report for a workflow job summary or a committed doc.
func (r *Report) Markdown() string {
	var b strings.Builder

	fmt.Fprintf(&b, "# MCP spec compliance — `%s`\n\n", r.SchemaVersion)
	fmt.Fprintf(&b, "**Conformance: %d/100** (over %d applicable weight) — everything the server serves validates.\n\n",
		r.ConformanceScore, r.ConformanceWeight)
	fmt.Fprintf(&b, "**Coverage: %d%% of server methods (%d/%d), %d%% of capabilities (%d/%d)** — informational; "+
		"MCP does not require prompts, resources or completions.\n\n",
		r.Coverage.MethodsPct, r.Coverage.MethodsImplemented, r.Coverage.MethodsDefined,
		r.Coverage.CapabilitiesPct, r.Coverage.CapabilitiesDeclared, r.Coverage.CapabilitiesDefined)

	fmt.Fprintf(&b, "| | |\n|---|---|\n")
	fmt.Fprintf(&b, "| Scored against | `%s` (%s) |\n", r.SchemaVersion, r.SchemaDraft)
	if r.NegotiatedVersion != "" {
		fmt.Fprintf(&b, "| Server negotiates | `%s` |\n", r.NegotiatedVersion)
	}
	if r.NewestPublished != "" {
		fmt.Fprintf(&b, "| Newest published | `%s` |\n", r.NewestPublished)
	}
	if r.RevisionsBehind >= 0 {
		fmt.Fprintf(&b, "| Revisions behind | %d |\n", r.RevisionsBehind)
	}
	b.WriteString("\n## Dimensions\n\n")
	b.WriteString("| Dimension | Kind | Weight | Score | Detail |\n|---|---|---:|---:|---|\n")
	for _, d := range r.Dimensions {
		score := fmt.Sprintf("%d", d.Score)
		detail := d.Detail
		if d.Skipped {
			score = "n/a"
			detail = "skipped — " + d.SkipReason
		}
		weight := fmt.Sprintf("%d", d.Weight)
		if d.Kind == KindCoverage {
			weight = "—" // reported, not scored
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", d.Title, d.Kind, weight, score, detail)
	}

	b.WriteString("\n## Server method surface\n\n")
	writeSurface(&b, r.MethodSurface, "methods")
	b.WriteString("\n## Server capability surface\n\n")
	writeSurface(&b, r.CapabilitySurface, "capabilities")

	if len(r.Findings) > 0 {
		b.WriteString("\n## Findings\n\n")
		b.WriteString("| Dimension | Subject | Problem |\n|---|---|---|\n")
		for _, f := range r.Findings {
			fmt.Fprintf(&b, "| %s | `%s` | %s |\n", f.Dimension, f.Subject, oneLine(f.Problem))
		}
	}
	return b.String()
}

func writeSurface(b *strings.Builder, s Surface, plural string) {
	fmt.Fprintf(b, "Coverage **%d%%** (%d of %d defined %s).\n\n", s.Coverage, len(s.Present), len(s.Defined), plural)
	if len(s.Present) > 0 {
		fmt.Fprintf(b, "- Implemented: %s\n", code(s.Present))
	}
	if len(s.Missing) > 0 {
		fmt.Fprintf(b, "- Not implemented: %s\n", code(s.Missing))
	}
	if len(s.Unknown) > 0 {
		fmt.Fprintf(b, "- Not in this revision: %s\n", code(s.Unknown))
	}
}

func code(items []string) string {
	out := make([]string, len(items))
	for i, s := range items {
		out[i] = "`" + s + "`"
	}
	return strings.Join(out, ", ")
}

// oneLine flattens a validation error for table rendering, and truncates it:
// JSON Schema errors can run to hundreds of characters.
func oneLine(s string) string {
	s = strings.Join(strings.Fields(strings.ReplaceAll(s, "|", "\\|")), " ")
	const max = 300
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
