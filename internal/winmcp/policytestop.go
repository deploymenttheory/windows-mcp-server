//go:build windows && (amd64 || arm64)

package winmcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/policy"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/policy/policytest"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/signals"
)

// ErrBadFixtureStatus reports a device signal status that is not pass/fail/error.
var ErrBadFixtureStatus = errors.New("fixture device status must be pass, fail or error")

// A policy-test fixture is a policy document, a fixture device state, and a list
// of tool calls with their asserted verdicts. It turns a policy from something
// only a live session can exercise into something CI can, so a rule change that
// drops a requirement fails a test rather than a call in the field.

type policyTestFixture struct {
	// Policy is the document to evaluate, relative to the fixture file (empty uses
	// the built-in default).
	Policy string `json:"policy"`
	// Device is the fixture signal state: signal id -> "pass" | "fail" | "error".
	Device map[string]string `json:"device"`
	Cases  []policyTestCase  `json:"cases"`
}

type policyTestCase struct {
	Name   string           `json:"name"`
	Call   policyTestCall   `json:"call"`
	Expect policyTestExpect `json:"expect"`
}

type policyTestCall struct {
	Tool        string `json:"tool"`
	Toolset     string `json:"toolset"`
	Annotations struct {
		ReadOnly    bool `json:"read_only"`
		Destructive bool `json:"destructive"`
		OpenWorld   bool `json:"open_world"`
	} `json:"annotations"`
}

type policyTestExpect struct {
	// Severity is the verdict the case asserts: allow, warn, deny or kill. Required.
	// It is the effective severity after the policy's mode is applied, so a test
	// against an audit-mode policy asserts the capped verdict — which is the truth
	// of what that policy does.
	Severity string `json:"severity"`
	// FailedSignals, when present, must equal the exact set of signals that failed.
	FailedSignals []string `json:"failed_signals,omitempty"`
	// Rules, when present, must each appear among the rules that matched.
	Rules []string `json:"rules,omitempty"`
}

// PolicyTestReport is the result of running one fixture file.
type PolicyTestReport struct {
	Fixture string                 `json:"fixture"`
	Cases   []PolicyTestCaseResult `json:"cases"`
}

// PolicyTestCaseResult is the outcome of one asserted call.
type PolicyTestCaseResult struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// Passed reports whether every case in the report held.
func (r PolicyTestReport) Passed() bool {
	for _, c := range r.Cases {
		if !c.OK {
			return false
		}
	}
	return true
}

// TestPolicy runs every fixture and returns a report per file. The returned error
// is for I/O or malformed fixtures only; a failed assertion is a non-OK case, so
// one run reports every mismatch rather than stopping at the first.
func TestPolicy(cfg Config, fixturePaths []string) ([]PolicyTestReport, error) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	known := newGuardrailRegistry(cfg, logger).IDs()

	reports := make([]PolicyTestReport, 0, len(fixturePaths))
	for _, path := range fixturePaths {
		rep, err := runPolicyFixture(path, known)
		if err != nil {
			return nil, err
		}
		reports = append(reports, rep)
	}
	return reports, nil
}

func runPolicyFixture(path string, known []string) (PolicyTestReport, error) {
	rep := PolicyTestReport{Fixture: path}

	raw, err := os.ReadFile(path)
	if err != nil {
		return rep, fmt.Errorf("read fixture: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var fx policyTestFixture
	if err := dec.Decode(&fx); err != nil {
		return rep, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}

	// The policy path is relative to the fixture file, so a fixture is runnable
	// from any working directory.
	devicePolicy := policy.Default()
	if fx.Policy != "" {
		policyPath := fx.Policy
		if !filepath.IsAbs(policyPath) {
			policyPath = filepath.Join(filepath.Dir(path), policyPath)
		}
		devicePolicy, err = policy.Load(policyPath, known)
		if err != nil {
			return rep, fmt.Errorf("%s: %w", filepath.Base(path), err)
		}
	}

	states, err := fixtureStates(fx.Device)
	if err != nil {
		return rep, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	// A fixture lists only the signals it is exercising; every other signal the
	// policy declares defaults to passing, so a case reads as "this device is
	// healthy except for the named signals".
	for id := range devicePolicy.Signals {
		if _, ok := states[id]; !ok {
			states[id] = signals.Pass
		}
	}

	for _, c := range fx.Cases {
		rep.Cases = append(rep.Cases, evaluateCase(devicePolicy, states, c))
	}
	return rep, nil
}

func fixtureStates(device map[string]string) (map[string]signals.Status, error) {
	states := make(map[string]signals.Status, len(device))
	for id, v := range device {
		switch signals.Status(v) {
		case signals.Pass, signals.Fail, signals.Error:
			states[id] = signals.Status(v)
		default:
			return nil, fmt.Errorf("%w: signal %q has status %q", ErrBadFixtureStatus, id, v)
		}
	}
	return states, nil
}

func evaluateCase(
	devicePolicy *policy.Policy,
	states map[string]signals.Status,
	c policyTestCase,
) PolicyTestCaseResult {
	facts := policy.ToolFacts{
		Name:        c.Call.Tool,
		Toolset:     c.Call.Toolset,
		ReadOnly:    c.Call.Annotations.ReadOnly,
		Destructive: c.Call.Annotations.Destructive,
		OpenWorld:   c.Call.Annotations.OpenWorld,
	}
	index := policytest.StaticIndex{c.Call.Tool: facts}
	engine := policytest.NewEngine(devicePolicy, index, states)
	v := engine.Evaluate(context.Background(), engine.SubjectForTool("tools/call", c.Call.Tool))

	res := PolicyTestCaseResult{Name: c.Name, OK: true}

	if got := v.Severity.String(); got != c.Expect.Severity {
		return failCase(res, fmt.Sprintf("severity = %s, want %s", got, c.Expect.Severity))
	}
	if c.Expect.FailedSignals != nil {
		if got, want := failedSignalSet(v), toSet(c.Expect.FailedSignals); !equalSets(got, want) {
			return failCase(res, fmt.Sprintf("failed signals = %v, want %v", sortedSet(got), sortedSet(want)))
		}
	}
	for _, name := range c.Expect.Rules {
		// The verdict records rules as display labels (`rule "managed-device"`); a
		// fixture names the bare rule, so compare against the same label form.
		if !containsStr(v.Rules, fmt.Sprintf("rule %q", name)) {
			return failCase(res, fmt.Sprintf("rule %q did not match (matched: %v)", name, v.Rules))
		}
	}
	return res
}

func failCase(res PolicyTestCaseResult, detail string) PolicyTestCaseResult {
	res.OK = false
	res.Detail = detail
	return res
}

func failedSignalSet(v policy.Verdict) map[string]bool {
	out := map[string]bool{}
	for _, f := range v.Failures {
		out[f.Signal] = true
	}
	return out
}

func toSet(xs []string) map[string]bool {
	out := make(map[string]bool, len(xs))
	for _, x := range xs {
		out[x] = true
	}
	return out
}

func equalSets(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func sortedSet(s map[string]bool) []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func containsStr(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
