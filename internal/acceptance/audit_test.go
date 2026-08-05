//go:build windows && (amd64 || arm64)

package acceptance

import (
	"fmt"
	"strings"
	"testing"
)

// The audit chain on a real machine: a chain that seals on a clean exit, a sealed
// chain that catches a removed tail, an unsealed chain that cannot, and a keyed
// chain that carries its MACs.
//
// A unit test reaches the chain logic but not the conditions that produce these
// states — a process killed rather than shut down, and a file edited underneath a
// verifier that has already run.

const auditDir = remoteDir + `\audit`

// auditPolicy puts the chain in a directory, which is what gives each session its
// own file and a cross-session manifest to check against. Everything else stays
// at its default: these tests are about the record, not about enforcement.
func auditPolicy() map[string]any {
	return map[string]any{
		"version": 1,
		"transparency": map[string]any{
			"audit_destination": auditDir,
		},
	}
}

// runSealedSession starts a stdio session with standard input already closed, so
// it configures itself, records that, and exits cleanly through its normal
// shutdown path — which is what writes the seal.
func runSealedSession(t *testing.T, h *harness, policyPath string) string {
	t.Helper()
	before := len(h.sessionStamps(auditDir))
	if _, err := h.guestServer("stdio", "--policy-config", policyPath); err != nil {
		// A stdio server exiting on a closed stdin is not an error condition, but
		// the exit code depends on how the shell reports it; the assertion that
		// matters is that a new session file appeared.
		t.Logf("stdio session returned: %v", err)
	}
	stamps := h.sessionStamps(auditDir)
	if len(stamps) <= before {
		t.Fatalf("no new session file appeared in %s (had %d, now %d)", auditDir, before, len(stamps))
	}
	return stamps[len(stamps)-1]
}

// TestCleanSessionSeals is the baseline the rest of this file depends on. It runs
// first so that a broken guest is distinguishable from a broken chain.
func TestCleanSessionSeals(t *testing.T) {
	h := newHarness(t)
	policy := h.writePolicy("audit-policy.json", auditPolicy())
	stamp := runSealedSession(t, h, policy)

	out, err := h.guestServer("audit", "verify", auditDir)
	if err != nil {
		t.Fatalf("verifying a clean chain should succeed: %v\n%s", err, out)
	}
	if !contains(out, "SEALED") {
		t.Errorf("a cleanly-exited session should be marked SEALED, got:\n%s", out)
	}
	if !contains(out, stamp) {
		t.Errorf("the report should name session %s:\n%s", stamp, out)
	}

	// And --strict, which fails on any unsealed session, should also pass.
	if out, err := h.guestServer("audit", "verify", auditDir, "--strict"); err != nil {
		t.Errorf("--strict should pass when every session is sealed: %v\n%s", err, out)
	}
}

// TestSealedSessionDetectsTruncation: a sealed session's head is recorded in the
// manifest, which the session file cannot rewrite, so removing the tail leaves
// the two inconsistent and verification fails.
func TestSealedSessionDetectsTruncation(t *testing.T) {
	h := newHarness(t)
	policy := h.writePolicy("audit-policy.json", auditPolicy())
	stamp := runSealedSession(t, h, policy)

	sessionFile := fmt.Sprintf(`%s\session-%s.audit.jsonl`, auditDir, stamp)
	before := h.countLines(sessionFile)
	if before < 2 {
		t.Fatalf("need at least two entries to remove one, got %d", before)
	}
	h.truncateLines(sessionFile, before-1)

	out, err := h.guestServer("audit", "verify", auditDir)
	if err == nil {
		t.Errorf("removing the tail of a SEALED session must fail verification, got:\n%s", out)
	}
	if !contains(out, stamp) {
		t.Errorf("the failure should name the session it found the problem in:\n%s", out)
	}
}

// TestUnsealedSessionIsLoudButUndetected pins the current behaviour of an
// unsealed session, which is reported but not detected.
//
// A killed process writes no seal, so there is no recorded head to compare a
// truncated chain against, and any prefix of a valid chain is itself valid. The
// verifier therefore marks the session UNSEALED, warns what a missing seal does
// not prove, and fails only under --strict.
//
// This is asserted as it stands rather than as it should be. Detection is open as
// S12; when a checkpointed head lands, plain verify starts failing here and this
// test is what changes.
func TestUnsealedSessionIsLoudButUndetected(t *testing.T) {
	h := newHarness(t)
	policy := h.writePolicy("audit-policy.json", auditPolicy())

	stamp := h.hardKilledSession(t, policy)
	sessionFile := fmt.Sprintf(`%s\session-%s.audit.jsonl`, auditDir, stamp)

	out := h.guestExec(fmt.Sprintf(`Get-Content -LiteralPath '%s' | Select-String -Pattern 'seal' -Quiet`, sessionFile))
	if strings.Contains(strings.ToLower(out), "true") {
		t.Skip("the hard kill still managed to seal; nothing to assert about an unsealed session")
	}

	before := h.countLines(sessionFile)
	if before < 2 {
		t.Fatalf("need at least two entries to remove one, got %d", before)
	}
	h.truncateLines(sessionFile, before-1)

	// Loud.
	plain, plainErr := h.guestServer("audit", "verify", auditDir)
	if !contains(plain, "UNSEALED") {
		t.Errorf("an unsealed session must be marked UNSEALED, got:\n%s", plain)
	}

	// But not detected — the whole reason S12 is still open.
	if plainErr != nil {
		t.Errorf("plain verify is not expected to detect truncation of an unsealed session yet; "+
			"if S12 has landed, this test is what should change:\n%s", plain)
	}

	// And --strict is what an evidence collector should use.
	strict, strictErr := h.guestServer("audit", "verify", auditDir, "--strict")
	if strictErr == nil {
		t.Errorf("--strict must fail on an unsealed session, got:\n%s", strict)
	}
}

// TestKeyedChainCarriesItsMAC: with a key, entries are provably written by a key
// holder rather than merely internally consistent.
func TestKeyedChainCarriesItsMAC(t *testing.T) {
	h := newHarness(t)
	policy := h.writePolicy("audit-policy.json", auditPolicy())

	const key = "acceptance-suite-audit-key"
	h.guestExec(fmt.Sprintf(`$env:WINDOWS_MCP_AUDIT_KEY='%s'; `+
		`'' | & '%s' stdio --policy-config '%s' 2>&1 | Out-Null`, key, remoteExe, policy))

	stamps := h.sessionStamps(auditDir)
	if len(stamps) == 0 {
		t.Fatal("no session produced")
	}
	sessionFile := fmt.Sprintf(`%s\session-%s.audit.jsonl`, auditDir, stamps[len(stamps)-1])

	if raw := h.readGuestFile(sessionFile); !contains(raw, `"mac"`) {
		t.Errorf("a keyed chain's entries should carry a MAC:\n%s", firstLines(raw, 3))
	}

	out := h.guestExec(fmt.Sprintf(
		`$env:WINDOWS_MCP_AUDIT_KEY='%s'; & '%s' audit verify '%s' --key-env WINDOWS_MCP_AUDIT_KEY 2>&1 | Out-String`,
		key, remoteExe, auditDir))
	if contains(out, "BROKEN") {
		t.Errorf("verification with the right key should pass:\n%s", out)
	}
}

// --- helpers that reach into the guest's filesystem -----------------------

// countLines returns the number of lines in an in-guest file.
func (h *harness) countLines(remotePath string) int {
	h.t.Helper()
	out := h.guestExec(fmt.Sprintf(
		`(Get-Content -LiteralPath '%s' | Measure-Object -Line).Lines`, remotePath))
	var n int
	if _, err := fmt.Sscanf(strings.TrimSpace(lastLine(out)), "%d", &n); err != nil {
		h.t.Fatalf("counting lines of %s: %v (output %q)", remotePath, err, out)
	}
	return n
}

// truncateLines rewrites an in-guest file with only its first n lines: dropping
// the tail, which is the edit the chain is meant to resist.
func (h *harness) truncateLines(remotePath string, n int) {
	h.t.Helper()
	h.guestExec(fmt.Sprintf(
		`$lines = Get-Content -LiteralPath '%s' | Select-Object -First %d; `+
			`Set-Content -LiteralPath '%s' -Value $lines`, remotePath, n, remotePath))
}

// hardKilledSession starts a session and terminates it without letting it run its
// shutdown path, which is how a session comes to have no seal. The kill ladder's
// Shutdown rung produces the same state by construction.
func (h *harness) hardKilledSession(t *testing.T, policyPath string) string {
	t.Helper()
	before := h.sessionStamps(auditDir)
	h.guestExec(fmt.Sprintf(
		`$p = Start-Process -FilePath '%s' -ArgumentList 'stdio','--policy-config','%s' `+
			`-PassThru -WindowStyle Hidden; `+
			`Start-Sleep -Seconds 5; `+
			`Stop-Process -Id $p.Id -Force; `+
			`Start-Sleep -Seconds 2`, remoteExe, policyPath))

	after := h.sessionStamps(auditDir)
	if len(after) <= len(before) {
		t.Fatalf("the hard-killed session produced no audit file (had %d, now %d)", len(before), len(after))
	}
	return after[len(after)-1]
}

// firstLines renders the head of a blob for a failure message.
func firstLines(s string, n int) string {
	lines := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
