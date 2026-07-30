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
	// Score is the weighted conformance score, 0-100, over applicable dimensions.
	Score int `json:"score"`
	// ApplicableWeight is the total weight of non-skipped dimensions.
	ApplicableWeight int         `json:"applicable_weight"`
	Dimensions       []Dimension `json:"dimensions"`
	Findings         []Finding   `json:"findings,omitempty"`
	// MethodSurface details spec-defined server methods against implemented ones.
	MethodSurface Surface `json:"method_surface"`
	// CapabilitySurface details spec-defined capability keys against declared ones.
	CapabilitySurface Surface `json:"capability_surface"`
}

// Dimension is one scored conformance axis.
type Dimension struct {
	ID     string `json:"id"`
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

// finalize computes the weighted score over applicable dimensions.
func (r *Report) finalize() {
	var weighted, total int
	for _, d := range r.Dimensions {
		if d.Skipped {
			continue
		}
		total += d.Weight
		weighted += d.Weight * d.Score
	}
	r.ApplicableWeight = total
	if total == 0 {
		r.Score = 0
		return
	}
	r.Score = weighted / total
}

// Markdown renders the report for a workflow job summary or a committed doc.
func (r *Report) Markdown() string {
	var b strings.Builder

	fmt.Fprintf(&b, "# MCP spec compliance — `%s`\n\n", r.SchemaVersion)
	fmt.Fprintf(&b, "**Score: %d/100** (over %d applicable weight)\n\n", r.Score, r.ApplicableWeight)

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
	b.WriteString("| Dimension | Weight | Score | Detail |\n|---|---:|---:|---|\n")
	for _, d := range r.Dimensions {
		score := fmt.Sprintf("%d", d.Score)
		detail := d.Detail
		if d.Skipped {
			score = "n/a"
			detail = "skipped — " + d.SkipReason
		}
		fmt.Fprintf(&b, "| %s | %d | %s | %s |\n", d.Title, d.Weight, score, detail)
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
