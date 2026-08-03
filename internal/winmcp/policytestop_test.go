//go:build windows && (amd64 || arm64)

package winmcp

import (
	"os"
	"path/filepath"
	"testing"
)

// TestShippedPolicyFixturesPass runs the committed example fixtures, so the
// documents that demonstrate the verb are also known to hold.
func TestShippedPolicyFixturesPass(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "policy", "examples", "tests", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no example fixtures found")
	}
	reports, err := TestPolicy(Config{}, paths)
	if err != nil {
		t.Fatalf("TestPolicy: %v", err)
	}
	for _, r := range reports {
		for _, c := range r.Cases {
			if !c.OK {
				t.Errorf("%s / %s: %s", filepath.Base(r.Fixture), c.Name, c.Detail)
			}
		}
	}
}

const fixtureEnforcePolicy = `{
  "version": 1, "mode": "enforce",
  "signals": { "run-context": { "ttl": "0s" } },
  "rules": [ { "name": "r", "match": { "toolset": "*" }, "require": ["run-context"], "on_fail": "deny" } ]
}`

// writeFixture writes a policy and a fixture referencing it by basename into a
// fresh directory, returning the fixture path.
func writeFixture(t *testing.T, fixtureJSON string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pol.json"), []byte(fixtureEnforcePolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "fixture.json")
	if err := os.WriteFile(path, []byte(fixtureJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPolicyReportsPassAndFail(t *testing.T) {
	path := writeFixture(t, `{
	  "policy": "pol.json",
	  "device": { "run-context": "fail" },
	  "cases": [
	    { "name": "denied", "call": { "tool": "X", "toolset": "any" },
	      "expect": { "severity": "deny", "failed_signals": ["run-context"], "rules": ["r"] } },
	    { "name": "wrong-severity", "call": { "tool": "X", "toolset": "any" },
	      "expect": { "severity": "allow" } },
	    { "name": "wrong-signals", "call": { "tool": "X", "toolset": "any" },
	      "expect": { "severity": "deny", "failed_signals": ["bitlocker"] } }
	  ]
	}`)

	reports, err := TestPolicy(Config{}, []string{path})
	if err != nil {
		t.Fatalf("TestPolicy: %v", err)
	}
	cases := reports[0].Cases
	if !cases[0].OK {
		t.Errorf("case 'denied' should hold: %s", cases[0].Detail)
	}
	if cases[1].OK {
		t.Error("case 'wrong-severity' should fail: policy denies, fixture expects allow")
	}
	if cases[2].OK {
		t.Error("case 'wrong-signals' should fail: the failed-signal set does not match")
	}
	if reports[0].Passed() {
		t.Error("a report with failing cases must not report Passed")
	}
}

func TestPolicyRejectsBadDeviceStatus(t *testing.T) {
	path := writeFixture(t, `{
	  "policy": "pol.json",
	  "device": { "run-context": "maybe" },
	  "cases": []
	}`)
	if _, err := TestPolicy(Config{}, []string{path}); err == nil {
		t.Error("a device status other than pass/fail/error should be rejected")
	}
}

func TestPolicyRejectsUnknownFixtureField(t *testing.T) {
	path := writeFixture(t, `{ "policy": "pol.json", "device": {}, "cases": [], "typo": true }`)
	if _, err := TestPolicy(Config{}, []string{path}); err == nil {
		t.Error("an unknown fixture field should be rejected (DisallowUnknownFields)")
	}
}
