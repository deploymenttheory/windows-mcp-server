// Package mcpconf reads the results of the official Model Context Protocol
// conformance suite (github.com/modelcontextprotocol/conformance) and renders
// them as the project's committed compliance report.
//
// It deliberately does not score anything. The suite is the authority on whether
// this server conforms; its verdict is per-check pass or fail, gated by a
// baseline of expected failures and communicated through its own exit code. This
// package's whole job is to turn that verdict into something a human can read and
// a workflow can commit, so the evidence is legible without re-running the suite.
//
// It replaced a scorer written in this repository that graded the server's wire
// objects against vendored schemas and reported 100/100. That number was
// self-marked. Reintroducing a percentage here — even one derived from the
// official checks — would recreate exactly the problem the change removed, so
// counts and statuses are all that is reported.
//
// The package is platform-agnostic (no build tag): it reads JSON files and emits
// text, so it is unit-testable without a Windows host.
package mcpconf

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
)

// ErrUnrecognizedResults reports a results file whose shape the suite no longer
// matches. It is an error rather than an empty result on purpose: zero checks
// would render as a clean run.
var ErrUnrecognizedResults = errors.New("unrecognized conformance results format")

// Check statuses emitted by the suite, from its ConformanceCheck type.
const (
	StatusSuccess = "SUCCESS"
	StatusFailure = "FAILURE"
	StatusWarning = "WARNING"
	StatusSkipped = "SKIPPED"
	StatusInfo    = "INFO"
)

// Check is one conformance check as the suite writes it to checks.json.
//
// The fields mirror the suite's own type; unknown fields are ignored so a suite
// upgrade that adds one cannot break parsing. Only what the report needs is
// modelled.
//
// The camelCase tags are the suite's wire format, not this project's convention.
// Renaming them to snake_case would simply stop the file parsing.
//
//nolint:tagliatelle // decodes the conformance suite's output; its field names, not ours
type Check struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      string `json:"status"`
	// ErrorMessage is present on a failure and is the single most useful field
	// in the file, so it is carried into the report verbatim.
	ErrorMessage string `json:"errorMessage,omitempty"`
	// Source records which spec revision or extension introduced the scenario.
	Source *Source `json:"source,omitempty"`
}

// Source is a scenario's applicability window, as the suite records it.
//
//nolint:tagliatelle // decodes the conformance suite's output; its field names, not ours
type Source struct {
	IntroducedIn string `json:"introducedIn,omitempty"`
	RemovedIn    string `json:"removedIn,omitempty"`
	ExtensionID  string `json:"extensionId,omitempty"`
}

// Pass is one invocation of the suite: a set of checks plus the provenance that
// makes them evidence rather than an assertion.
type Pass struct {
	// Name distinguishes the passes — "product" for the manifest this server
	// ships, "fixtures" for the run that adds the suite's named fixtures.
	Name string `json:"name"`
	// Description says, in one line, what this pass proves.
	Description string `json:"description"`
	// SpecVersion is the protocol revision the suite was run at.
	SpecVersion string `json:"spec_version"`
	// HarnessVersion is the exact npm version of the suite. Pinned, because the
	// verdict is only reproducible against a known harness.
	HarnessVersion string `json:"harness_version"`
	// Baseline names the expected-failures file the run was gated against.
	Baseline string  `json:"baseline,omitempty"`
	Checks   []Check `json:"checks"`
}

// Report is the committed record: every pass, with the provenance of the run.
type Report struct {
	// ServerVersion and Commit tie the result to a specific build.
	ServerVersion string `json:"server_version,omitempty"`
	Commit        string `json:"commit,omitempty"`
	// GeneratedAt is supplied by the caller rather than read from the clock, so
	// the workflow controls it and the report is reproducible.
	GeneratedAt string `json:"generated_at,omitempty"`
	// RunURL links back to the workflow run that produced the checks.
	RunURL string  `json:"run_url,omitempty"`
	Passes []*Pass `json:"passes"`
}

// Tally counts a pass's checks by status.
type Tally struct {
	Success int `json:"success"`
	Failure int `json:"failure"`
	Warning int `json:"warning"`
	Skipped int `json:"skipped"`
	Info    int `json:"info"`
	Total   int `json:"total"`
}

// Tally counts the checks in a pass.
func (p *Pass) Tally() Tally {
	var t Tally
	for _, c := range p.Checks {
		t.Total++
		switch c.Status {
		case StatusSuccess:
			t.Success++
		case StatusFailure:
			t.Failure++
		case StatusWarning:
			t.Warning++
		case StatusSkipped:
			t.Skipped++
		case StatusInfo:
			t.Info++
		}
	}
	return t
}

// Failures returns the failed checks, sorted by id for a stable report.
func (p *Pass) Failures() []Check {
	var out []Check
	for _, c := range p.Checks {
		if c.Status == StatusFailure {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// LoadChecks reads a checks.json written by the suite.
//
// The suite writes a bare JSON array. An object wrapping a "checks" array is
// accepted too, so a future change to the output shape degrades to a clear error
// rather than a silent empty result.
func LoadChecks(path string) ([]Check, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // a results file path supplied by the operator
	if err != nil {
		return nil, fmt.Errorf("read conformance checks: %w", err)
	}
	var checks []Check
	if err := json.Unmarshal(raw, &checks); err == nil {
		return checks, nil
	}
	// An object is accepted only if it actually carries a "checks" key. Decoding
	// leniently would turn an unrecognised shape into zero checks, which renders
	// as a clean run — the one failure mode this report must never have.
	var wrapped map[string]json.RawMessage
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return nil, fmt.Errorf("parse conformance checks %s: %w", path, err)
	}
	inner, ok := wrapped["checks"]
	if !ok {
		return nil, fmt.Errorf("%w: %s has neither a top-level array nor a \"checks\" key",
			ErrUnrecognizedResults, path)
	}
	if err := json.Unmarshal(inner, &checks); err != nil {
		return nil, fmt.Errorf("parse conformance checks %s: %w", path, err)
	}
	return checks, nil
}

// Badge is a shields.io endpoint payload (schemaVersion 1), committed to the
// repository so the README can render the latest CI result without a third-party
// service holding the state.
//
//nolint:tagliatelle // shields.io's endpoint schema; its field names, not ours
type Badge struct {
	SchemaVersion int    `json:"schemaVersion"`
	Label         string `json:"label"`
	Message       string `json:"message"`
	Color         string `json:"color"`
}

// BadgeFor summarises one pass for the README badge.
//
// The figure is the suite's own tally — the share of checks that ran and passed —
// not a grade this project awards itself. That distinction is why the markdown
// report still carries no score: a percentage there would invite reading it as an
// overall verdict, whereas a badge is understood to be a summary and links to the
// report that qualifies it.
//
// Skipped and informational checks are excluded from the denominator. A scenario
// the revision does not apply to should not count for or against us, which is the
// same reason the suite reports it as skipped rather than failed.
//
// Note the denominator still includes checks that are failing *by design* and
// listed in the baseline — for the product pass, the scenarios needing the suite's
// fixtures. Excluding those would let the badge read 100% while the baseline grew,
// which is exactly the kind of self-flattery this whole change removed.
func (r *Report) BadgeFor(passName string) Badge {
	badge := Badge{SchemaVersion: 1, Label: "MCP conformance"}

	var pass *Pass
	for _, p := range r.Passes {
		if p.Name == passName {
			pass = p
			break
		}
	}
	if pass == nil {
		badge.Message, badge.Color = "not measured", "lightgrey"
		return badge
	}

	t := pass.Tally()
	ran := t.Success + t.Failure
	if ran == 0 {
		badge.Message, badge.Color = pass.SpecVersion+" · no checks ran", "lightgrey"
		return badge
	}
	pct := 100 * t.Success / ran
	badge.Message = fmt.Sprintf("%s · %d%% (%d/%d)", pass.SpecVersion, pct, t.Success, ran)
	badge.Color = badgeColor(pct)
	return badge
}

func badgeColor(pct int) string {
	switch {
	case pct >= 95:
		return "brightgreen"
	case pct >= 85:
		return "green"
	case pct >= 70:
		return "yellowgreen"
	case pct >= 50:
		return "yellow"
	default:
		return "red"
	}
}

// Markdown renders the committed report.
func (r *Report) Markdown() string {
	var b strings.Builder

	b.WriteString("# MCP conformance\n\n")
	b.WriteString("Produced by the official conformance suite, " +
		"[modelcontextprotocol/conformance](https://github.com/modelcontextprotocol/conformance), " +
		"run against this server over loopback HTTP. Each check is pass or fail; the run is gated " +
		"on a committed baseline of expected failures.\n\n")

	b.WriteString("| | |\n|---|---|\n")
	writeRow(&b, "Server version", r.ServerVersion)
	writeRow(&b, "Commit", r.Commit)
	writeRow(&b, "Generated", r.GeneratedAt)
	if r.RunURL != "" {
		fmt.Fprintf(&b, "| Workflow run | %s |\n", r.RunURL)
	}
	b.WriteString("\n## Summary\n\n")
	b.WriteString("| Pass | Spec | Harness | Passed | Failed | Warned | Skipped |\n")
	b.WriteString("|---|---|---|---:|---:|---:|---:|\n")
	for _, p := range r.Passes {
		t := p.Tally()
		fmt.Fprintf(&b, "| %s | `%s` | `%s` | %d | %d | %d | %d |\n",
			p.Name, p.SpecVersion, p.HarnessVersion, t.Success, t.Failure, t.Warning, t.Skipped)
	}

	for _, p := range r.Passes {
		fmt.Fprintf(&b, "\n## Pass: %s\n\n", p.Name)
		if p.Description != "" {
			fmt.Fprintf(&b, "%s\n\n", p.Description)
		}
		if p.Baseline != "" {
			fmt.Fprintf(&b, "Gated against `%s`; a failure not listed there fails the build, "+
				"and so does an entry there that has started passing.\n\n", p.Baseline)
		}
		failures := p.Failures()
		if len(failures) == 0 {
			fmt.Fprintf(&b, "No unexpected failures across %d checks.\n", p.Tally().Total)
			continue
		}
		b.WriteString("| Check | Problem |\n|---|---|\n")
		for _, c := range failures {
			fmt.Fprintf(&b, "| `%s` | %s |\n", c.ID, oneLine(c.ErrorMessage))
		}
	}
	return b.String()
}

func writeRow(b *strings.Builder, label, value string) {
	if value == "" {
		return
	}
	fmt.Fprintf(b, "| %s | `%s` |\n", label, value)
}

// oneLine flattens a check's error for table rendering and truncates it: suite
// errors can carry a whole JSON payload.
func oneLine(s string) string {
	if s == "" {
		return "—"
	}
	s = strings.Join(strings.Fields(strings.ReplaceAll(s, "|", "\\|")), " ")
	const maxLen = 300
	if len(s) > maxLen {
		return s[:maxLen] + "…"
	}
	return s
}
