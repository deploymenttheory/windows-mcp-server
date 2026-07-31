package mcpconf

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadChecksAcceptsTheSuiteArray(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "checks.json")
	// The shape the suite actually writes: a bare array.
	const payload = `[
	  {"id":"tools-list","name":"tools/list","status":"SUCCESS","source":{"introducedIn":"2025-06-18"}},
	  {"id":"caching","name":"caching","status":"FAILURE","errorMessage":"ttlMs missing"}
	]`
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	checks, err := LoadChecks(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != 2 {
		t.Fatalf("want 2 checks, got %d", len(checks))
	}
	if checks[1].ErrorMessage != "ttlMs missing" {
		t.Errorf("error message not carried through: %q", checks[1].ErrorMessage)
	}
}

// TestLoadChecksSurfacesAShapeChange guards the failure mode that would matter:
// a suite upgrade changing the output shape must be an error, not an empty
// result that renders as "no failures".
func TestLoadChecksSurfacesAShapeChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "checks.json")
	if err := os.WriteFile(path, []byte(`{"results":{"unexpected":true}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	checks, err := LoadChecks(path)
	if err == nil {
		t.Fatalf("an unrecognised results shape must be an error, not %d checks; "+
			"zero checks renders as a clean run", len(checks))
	}
	if !errors.Is(err, ErrUnrecognizedResults) {
		t.Errorf("want ErrUnrecognizedResults, got %v", err)
	}
}

func TestTallyAndFailures(t *testing.T) {
	p := &Pass{Checks: []Check{
		{ID: "a", Status: StatusSuccess},
		{ID: "c", Status: StatusFailure, ErrorMessage: "second"},
		{ID: "b", Status: StatusFailure, ErrorMessage: "first"},
		{ID: "d", Status: StatusSkipped},
		{ID: "e", Status: StatusWarning},
		{ID: "f", Status: StatusInfo},
	}}
	got := p.Tally()
	want := Tally{Success: 1, Failure: 2, Warning: 1, Skipped: 1, Info: 1, Total: 6}
	if got != want {
		t.Errorf("tally = %+v, want %+v", got, want)
	}
	failures := p.Failures()
	if len(failures) != 2 || failures[0].ID != "b" || failures[1].ID != "c" {
		t.Errorf("failures must be sorted by id for a stable report, got %+v", failures)
	}
}

// TestMarkdownReportsNoScore is the guard on the point of this package. The
// self-marked 0-100 score is what this replaced; a percentage creeping back into
// the headline would undo that.
func TestMarkdownReportsNoScore(t *testing.T) {
	r := &Report{
		ServerVersion: "1.2.3",
		Commit:        "abc1234",
		Passes: []*Pass{{
			Name:           "product",
			SpecVersion:    "2026-07-28",
			HarnessVersion: "0.2.0-alpha.10",
			Baseline:       "conformance/baseline-product.yml",
			Checks: []Check{
				{ID: "tools-list", Status: StatusSuccess},
				{ID: "caching", Status: StatusFailure, ErrorMessage: "ttlMs was absent"},
			},
		}},
	}
	md := r.Markdown()

	for _, want := range []string{"2026-07-28", "0.2.0-alpha.10", "abc1234", "caching", "ttlMs was absent"} {
		if !strings.Contains(md, want) {
			t.Errorf("report omits %q:\n%s", want, md)
		}
	}
	// No numeric score anywhere. The prose may say there isn't one; a figure would
	// be the regression.
	for _, banned := range []string{"/100", "%"} {
		if strings.Contains(md, banned) {
			t.Errorf("report contains %q — conformance is pass/fail, not a score:\n%s", banned, md)
		}
	}
}

func TestBadgeReportsTheSuitesOwnTally(t *testing.T) {
	r := &Report{Passes: []*Pass{{
		Name:        "product",
		SpecVersion: "2026-07-28",
		Checks: []Check{
			{ID: "a", Status: StatusSuccess},
			{ID: "b", Status: StatusSuccess},
			{ID: "c", Status: StatusSuccess},
			{ID: "d", Status: StatusFailure},
			// Skipped and informational checks must not move the figure: a scenario
			// the revision does not apply to counts neither for nor against us.
			{ID: "e", Status: StatusSkipped},
			{ID: "f", Status: StatusInfo},
		},
	}}}
	badge := r.BadgeFor("product")
	if badge.SchemaVersion != 1 {
		t.Errorf("shields endpoint requires schemaVersion 1, got %d", badge.SchemaVersion)
	}
	if want := "2026-07-28 · 75% (3/4)"; badge.Message != want {
		t.Errorf("message = %q, want %q", badge.Message, want)
	}
	if badge.Color != "yellowgreen" {
		t.Errorf("color = %q, want yellowgreen for 75%%", badge.Color)
	}
}

// TestBadgeForAnUnmeasuredPassIsNotGreen guards the failure that would matter on
// a README: a missing or empty result must never render as a healthy badge.
func TestBadgeForAnUnmeasuredPassIsNotGreen(t *testing.T) {
	cases := map[string]*Report{
		"no such pass": {Passes: []*Pass{{Name: "fixtures", SpecVersion: "2026-07-28"}}},
		"no checks":    {Passes: []*Pass{{Name: "product", SpecVersion: "2026-07-28"}}},
		"no passes":    {},
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			badge := r.BadgeFor("product")
			if badge.Color != "lightgrey" {
				t.Errorf("color = %q, want lightgrey; an unmeasured badge must not look healthy", badge.Color)
			}
			if strings.Contains(badge.Message, "%") {
				t.Errorf("message = %q, want no figure when nothing was measured", badge.Message)
			}
		})
	}
}

// TestMarkdownDoesNotHideFailuresBehindAnEmptyPass checks the opposite mistake:
// a pass whose checks failed to load must not render as a clean run.
func TestMarkdownDoesNotHideFailuresBehindAnEmptyPass(t *testing.T) {
	r := &Report{Passes: []*Pass{{Name: "product", SpecVersion: "2026-07-28"}}}
	if md := r.Markdown(); !strings.Contains(md, "No unexpected failures across 0 checks") {
		t.Errorf("an empty pass must say so explicitly rather than read as a pass:\n%s", md)
	}
}
