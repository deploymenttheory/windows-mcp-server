//go:build windows && (amd64 || arm64)

// Package acceptance drives the shipped binary against a disposable Windows
// guest, to test the things CI structurally cannot see.
//
// The Windows runner compiles everything and runs the pure-logic suites, and
// then skips: "cannot start desktop engine in this environment", "no displays
// reported (headless)", "set WINDOWS_MCP_GLOBAL_BLOCK_TEST=1 to run the tests
// that make this machine default-deny". The desktop engine, the guardrails that
// need elevation, and the audit chain's behaviour under a hard kill are verified
// today only by reading them — and the last time this server was driven against a
// real guest, it confirmed every fix from a code review and found four things the
// review had not.
//
// The guest is managed by weave (github.com/deploymenttheory/guestweave-windows),
// which runs VMs on the Host Compute Service. The dependency is the CLI, not the
// module: weave is pre-alpha and its internals are not importable, so the contract
// here is `weave.exe` on PATH and nothing else.
//
// Gated: set WINDOWS_MCP_ACC=1 to run. Everything below skips otherwise, on every
// machine including CI — a harness that runs by accident is worse than none,
// because these tests revert snapshots and hard-kill processes.
//
// See docs/acceptance-testing.md for building the golden image.
package acceptance

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// Environment gates and knobs.
const (
	// gateEnv must be "1" or every test here skips.
	gateEnv = "WINDOWS_MCP_ACC"
	// guestEnv names the weave VM to drive; snapshotEnv the snapshot to revert to.
	guestEnv    = "WINDOWS_MCP_ACC_GUEST"
	snapshotEnv = "WINDOWS_MCP_ACC_SNAPSHOT"
	// keepEnv leaves the guest running after the suite, for inspecting a failure.
	keepEnv = "WINDOWS_MCP_ACC_KEEP"

	defaultGuest    = "acc"
	defaultSnapshot = "golden"

	// remoteDir is where the golden image expects the binary and the run's state.
	// It is inside the guest, so a revert takes the whole thing away.
	remoteDir = `C:\acc`
	remoteExe = remoteDir + `\windows-mcp-server.exe`
)

// bootTimeout bounds how long we wait for the guest to answer over SSH after a
// revert. A reverted running snapshot resumes into the captured instant, so this
// is usually seconds rather than a boot.
const bootTimeout = 3 * time.Minute

// harness owns one acceptance run against one guest.
type harness struct {
	t        *testing.T
	exe      string // the server binary, built on the host for this run
	guest    string
	snapshot string
}

// newHarness gates the suite, builds the binary under test, and returns the guest
// to its golden snapshot so every run starts from the same machine.
//
// Reverting rather than cleaning up is deliberate: these tests hard-kill a
// process and tamper with files on disk, and a test that fails halfway would
// otherwise leave the next one running against wreckage.
func newHarness(t *testing.T) *harness {
	t.Helper()
	if os.Getenv(gateEnv) != "1" {
		t.Skipf("set %s=1 to run the acceptance suite (it drives a real VM)", gateEnv)
	}
	if _, err := exec.LookPath("weave"); err != nil {
		t.Fatalf("weave.exe is not on PATH: %v\nSee docs/acceptance-testing.md", err)
	}

	h := &harness{
		t:        t,
		guest:    envOr(guestEnv, defaultGuest),
		snapshot: envOr(snapshotEnv, defaultSnapshot),
	}

	h.exe = filepath.Join(t.TempDir(), "windows-mcp-server.exe")
	build := exec.Command("go", "build", "-o", h.exe, "github.com/deploymenttheory/windows-mcp-server/cmd/windows-mcp-server")
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the binary under test: %v\n%s", err, out)
	}

	h.resetGuest()
	h.push(h.exe, remoteExe)

	t.Cleanup(func() {
		if os.Getenv(keepEnv) == "1" {
			t.Logf("%s=1: leaving %s running for inspection (weave console %s)", keepEnv, h.guest, h.guest)
			return
		}
		if _, err := h.tryWeave("stop", h.guest); err != nil {
			t.Logf("stopping the guest failed (not fatal): %v", err)
		}
	})
	return h
}

// resetGuest reverts to the golden snapshot, boots, and waits for SSH.
func (h *harness) resetGuest() {
	h.t.Helper()
	h.t.Logf("reverting %s to snapshot %q", h.guest, h.snapshot)
	h.weave("snapshot", "revert", h.guest, h.snapshot)
	h.weave("run", h.guest, "--detach")
	h.waitForGuest()
	// The golden image has no run directory: it is created per run so a revert
	// genuinely clears the previous run's audit files and bundles.
	h.guestExec(fmt.Sprintf(`New-Item -ItemType Directory -Force -Path '%s' | Out-Null`, remoteDir))
}

// waitForGuest blocks until the guest answers a trivial command.
func (h *harness) waitForGuest() {
	h.t.Helper()
	deadline := time.Now().Add(bootTimeout)
	for {
		if _, err := h.tryGuestExec(`Write-Output ready`); err == nil {
			return
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("%s did not answer over SSH within %s", h.guest, bootTimeout)
		}
		time.Sleep(5 * time.Second)
	}
}

// weave runs a weave verb, failing the test on a non-zero exit.
func (h *harness) weave(args ...string) string {
	h.t.Helper()
	out, err := h.tryWeave(args...)
	if err != nil {
		h.t.Fatalf("weave %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func (h *harness) tryWeave(args ...string) (string, error) {
	cmd := exec.Command("weave", args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// guestExec runs a PowerShell script inside the guest, failing on a non-zero
// exit. Use tryGuestExec where a failure is the thing being asserted.
func (h *harness) guestExec(script string) string {
	h.t.Helper()
	out, err := h.tryGuestExec(script)
	if err != nil {
		h.t.Fatalf("in-guest command failed: %v\nscript:\n%s\noutput:\n%s", err, script, out)
	}
	return out
}

// tryGuestExec runs a PowerShell script in the guest and returns its combined
// output and error.
//
// The script goes over as -EncodedCommand, the same base64 UTF-16LE trick the
// server uses for its own PowerShell invocations: it removes every layer of
// quoting between here, the SSH command line, and the guest's shell, which is
// otherwise a reliable source of tests that fail for reasons unrelated to the
// thing under test.
func (h *harness) tryGuestExec(script string) (string, error) {
	return h.tryWeave("ssh", h.guest, "powershell", "-NoProfile", "-NonInteractive",
		"-EncodedCommand", encodePowerShell(script))
}

// guestServer runs the binary under test inside the guest and returns its output.
// Standard input is closed immediately, so a stdio session starts, records its
// startup, and exits cleanly — which is enough to produce a sealed chain.
func (h *harness) guestServer(args ...string) (string, error) {
	quoted := make([]string, 0, len(args))
	for _, a := range args {
		quoted = append(quoted, "'"+strings.ReplaceAll(a, "'", "''")+"'")
	}
	return h.tryGuestExec(fmt.Sprintf(
		`$ErrorActionPreference='Continue'; '' | & '%s' %s 2>&1 | Out-String`,
		remoteExe, strings.Join(quoted, " ")))
}

// push copies a local file into the guest.
//
// weave has no cp verb, but it already has the primitive — internal/ssh has an
// SFTP upload that `weave agent install` uses — so exposing `weave cp` is the
// clean fix and this is the stopgap until it exists. The payload is streamed as
// base64 on standard input rather than embedded in the command, because a ~20 MB
// binary does not fit on a command line.
func (h *harness) push(localPath, remotePath string) {
	h.t.Helper()
	raw, err := os.ReadFile(localPath) //nolint:gosec // a test-controlled path
	if err != nil {
		h.t.Fatalf("read %s: %v", localPath, err)
	}

	script := fmt.Sprintf(
		`$b64 = [Console]::In.ReadToEnd(); `+
			`[IO.File]::WriteAllBytes('%s', [Convert]::FromBase64String($b64)); `+
			`Write-Output ((Get-Item '%s').Length)`, remotePath, remotePath)

	cmd := exec.Command("weave", "ssh", h.guest, "powershell", "-NoProfile", "-NonInteractive",
		"-EncodedCommand", encodePowerShell(script))
	cmd.Stdin = strings.NewReader(base64.StdEncoding.EncodeToString(raw))
	out, err := cmd.CombinedOutput()
	if err != nil {
		h.t.Fatalf("push %s -> %s: %v\n%s\n\n"+
			"If this failed because `weave ssh` does not forward standard input, the fix is a "+
			"`weave cp` verb in guestweave-windows: internal/ssh/upload.go already implements "+
			"the SFTP upload it would use.", localPath, remotePath, err, out)
	}
	if got := strings.TrimSpace(lastLine(string(out))); got != fmt.Sprint(len(raw)) {
		h.t.Fatalf("push %s: guest reported %s bytes, sent %d", remotePath, got, len(raw))
	}
}

// readGuestFile returns the contents of a file in the guest.
func (h *harness) readGuestFile(remotePath string) string {
	h.t.Helper()
	return h.guestExec(fmt.Sprintf(`Get-Content -Raw -LiteralPath '%s'`, remotePath))
}

// guestFileExists reports whether a path exists in the guest.
func (h *harness) guestFileExists(remotePath string) bool {
	h.t.Helper()
	out := h.guestExec(fmt.Sprintf(`if (Test-Path -LiteralPath '%s') { 'yes' } else { 'no' }`, remotePath))
	return strings.Contains(out, "yes")
}

// writePolicy writes a policy document into the guest and returns its path.
func (h *harness) writePolicy(name string, doc map[string]any) string {
	h.t.Helper()
	blob, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		h.t.Fatalf("marshal policy: %v", err)
	}
	path := remoteDir + `\` + name
	h.guestExec(fmt.Sprintf(
		`[IO.File]::WriteAllBytes('%s', [Convert]::FromBase64String('%s'))`,
		path, base64.StdEncoding.EncodeToString(blob)))
	return path
}

// sessionStamps lists the session stamps present in an in-guest audit directory,
// which is how a test finds the session it just produced without guessing the
// clock.
func (h *harness) sessionStamps(auditDir string) []string {
	h.t.Helper()
	out := h.guestExec(fmt.Sprintf(
		`Get-ChildItem -LiteralPath '%s' -Filter 'session-*.audit.jsonl' | `+
			`ForEach-Object { $_.BaseName -replace '^session-','' -replace '\.audit$','' }`, auditDir))
	var stamps []string
	for line := range strings.SplitSeq(out, "\n") {
		if s := strings.TrimSpace(line); s != "" {
			stamps = append(stamps, s)
		}
	}
	return stamps
}

// b64 renders a blob for embedding in a PowerShell FromBase64String call.
func b64(blob []byte) string { return base64.StdEncoding.EncodeToString(blob) }

// singleQuote renders a string as a PowerShell single-quoted literal, which
// interpolates nothing — the only quoting that is safe for author-supplied text.
func singleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// mustReadLocal reads a file on the host, for pushing into the guest.
func mustReadLocal(t *testing.T, path string) []byte {
	t.Helper()
	blob, err := os.ReadFile(path) //nolint:gosec // a test-controlled repo path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return blob
}

// encodePowerShell renders a script as base64 UTF-16LE for -EncodedCommand.
func encodePowerShell(script string) string {
	units := utf16.Encode([]rune(script))
	buf := make([]byte, 0, len(units)*2)
	for _, u := range units {
		buf = append(buf, byte(u), byte(u>>8))
	}
	return base64.StdEncoding.EncodeToString(buf)
}

// lastLine returns the last non-empty line of s.
func lastLine(s string) string {
	lines := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) != "" {
			return lines[i]
		}
	}
	return ""
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// contains is a readability helper for asserting on guest output.
func contains(haystack, needle string) bool {
	return bytes.Contains([]byte(haystack), []byte(needle))
}
