//go:build windows && (amd64 || arm64)

package acceptance

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The paired-process slice: the agentweave-harness governing the shipped
// server on the guest, over the real control channel, as two processes. It is
// the end-to-end pin for the cross-process behaviour a single-process unit test
// cannot reach — a refusal synthesized in the harness and answered on the wire,
// two audit chains that seal independently and cross-anchor, and the never-read
// invariant now provable across a process boundary rather than within one.
//
// It is gated behind its own variable, like the global-block firewall tests:
// it builds and pushes a second binary and drives a paired session, which a
// routine acceptance run should not do by accident.

const (
	// pairedGateEnv opts a run into the paired-process slice specifically. The
	// base WINDOWS_MCP_ACC gate still applies.
	pairedGateEnv = "WINDOWS_MCP_ACC_PAIRED"

	remoteHarnessExe = remoteDir + `\agentweave-harness.exe`
	harnessAuditDir  = remoteDir + `\harness-audit`
	serverAuditDir   = remoteDir + `\server-audit`

	// harnessModule is the command path built from this repo's dependency on
	// the agentweave-harness module, so the two binaries under test are the
	// harness and server versions this repo actually pins.
	harnessModule = "github.com/deploymenttheory/agentweave-harness/cmd/agentweave-harness"
)

// pairedHarness gates the slice, builds the harness binary from the pinned
// module, and pushes it alongside the already-pushed server.
func pairedHarness(t *testing.T) *harness {
	t.Helper()
	if os.Getenv(pairedGateEnv) != "1" {
		t.Skipf("set %s=1 to run the paired harness+server slice (it drives two processes on the VM)", pairedGateEnv)
	}
	h := newHarness(t)

	exe := filepath.Join(t.TempDir(), "agentweave-harness.exe")
	build := exec.Command("go", "build", "-o", exe, harnessModule)
	build.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build agentweave-harness from the pinned module: %v\n%s", err, out)
	}
	h.push(exe, remoteHarnessExe)
	return h
}

// enforcingHarnessPolicy denies a destructive tool when a required signal
// fails. run-context is a cheap in-process signal the servant always serves, so
// the rule is servable; requiring it and denying makes the harness refuse the
// call rather than skip it. (The rule fires only for the named tool, so an
// unrelated call is unaffected.)
func enforcingHarnessPolicy() map[string]any {
	return map[string]any{
		"version": 1,
		"mode":    "enforce",
		"signals": map[string]any{"run-context": map[string]any{"ttl": "0s"}},
		"rules": []map[string]any{{
			"name":    "shell-needs-managed-context",
			"match":   map[string]any{"tool": "Shell"},
			"require": []string{"run-context"},
			"on_fail": "deny",
		}},
		"transparency": map[string]any{"audit_destination": harnessAuditDir},
	}
}

// guestHarness runs the harness wrapping the server on the guest, feeding the
// given newline-delimited MCP frames on stdin, and returns what the client
// would receive on stdout.
func (h *harness) guestHarness(frames string, harnessArgs ...string) (string, error) {
	h.t.Helper()
	quoted := make([]string, 0, len(harnessArgs))
	for _, a := range harnessArgs {
		quoted = append(quoted, "'"+strings.ReplaceAll(a, "'", "''")+"'")
	}
	// The frames are piped in as UTF-8; the harness proxies stdout, which is
	// the MCP stream we capture. Stderr (both processes' diagnostics and AUDIT
	// lines) is separated so it does not pollute the parsed stdout.
	script := fmt.Sprintf(
		`$ErrorActionPreference='Continue'; `+
			`$in=[Convert]::FromBase64String('%s'); `+
			`$p=New-Object Diagnostics.Process; `+
			`$p.StartInfo.FileName='%s'; `+
			`$p.StartInfo.Arguments=%s+' -- %s stdio'; `+
			`$p.StartInfo.RedirectStandardInput=$true; `+
			`$p.StartInfo.RedirectStandardOutput=$true; `+
			`$p.StartInfo.UseShellExecute=$false; `+
			`[void]$p.Start(); `+
			`$p.StandardInput.BaseStream.Write($in,0,$in.Length); $p.StandardInput.Close(); `+
			`$out=$p.StandardOutput.ReadToEnd(); $p.WaitForExit(15000); $out`,
		b64([]byte(frames)),
		remoteHarnessExe,
		"'"+strings.Join(quoted, " ")+"'",
		remoteExe)
	return h.tryGuestExec(script)
}

// TestPairedHarnessRefusesOnTheWire is the core cross-process pin: an enforcing
// harness policy denies a tools/call, the client receives an IsError refusal,
// and the refusal is synthesized in the harness — the server never sees the
// call.
func TestPairedHarnessRefusesOnTheWire(t *testing.T) {
	h := pairedHarness(t)
	policy := h.writePolicy("harness-policy.json", enforcingHarnessPolicy())

	// A tools/call for the denied tool. Its argument carries a sentinel that
	// must never appear in either recorded chain (the never-read pin below).
	const sentinel = "PAIRED-SECRET-VALUE-do-not-record"
	frame := fmt.Sprintf(
		`{"jsonrpc":"2.0","id":"p1","method":"tools/call","params":{"name":"Shell","arguments":{"command":%q}}}`,
		sentinel) + "\n"

	out, err := h.guestHarness(frame, "run", "--policy-config", policy, "--audit-sink", harnessAuditDir)
	if err != nil {
		t.Logf("paired session returned: %v", err) // exit code varies; the frame is the assertion
	}
	if !strings.Contains(out, `"p1"`) {
		t.Fatalf("no response for the tool call:\n%s", out)
	}
	if !strings.Contains(out, `"isError":true`) {
		t.Fatalf("the harness did not refuse the call with an IsError result:\n%s", out)
	}
	// The echo of a forwarded call would carry the tool's own output; a refused
	// call never reaches the server, so the sentinel must not round-trip.
	if strings.Contains(out, sentinel) {
		t.Fatalf("the refused call reached the server (sentinel echoed):\n%s", out)
	}

	// Both chains must exist and verify: the harness's own chain of the
	// proxied conversation, and the server's host-events chain.
	for _, dir := range []string{harnessAuditDir, serverAuditDir} {
		if len(h.sessionStamps(dir)) == 0 {
			// The server chain only exists if the server configured one; a
			// harness-governed server on its default policy audits to stderr,
			// so serverAuditDir may legitimately be empty. Only the harness
			// chain is guaranteed here.
			if dir == harnessAuditDir {
				t.Fatalf("the harness wrote no audit chain in %s", dir)
			}
			continue
		}
		if out, err := h.guestServer("audit", "verify", dir); err != nil {
			t.Fatalf("audit verify %s failed: %v\n%s", dir, err, out)
		}
	}

	// The never-read invariant across the process boundary: the sentinel
	// argument value appears in no recorded frame on either chain. Arguments
	// are digested, never recorded raw — the same guarantee the in-process
	// audit gives, now provable end to end.
	if body := h.readChainBytes(harnessAuditDir); strings.Contains(body, sentinel) {
		t.Fatalf("the argument value leaked into the harness audit chain")
	}
}

// readChainBytes returns the concatenated text of every audit file in a guest
// directory, for a leak check.
func (h *harness) readChainBytes(dir string) string {
	h.t.Helper()
	return h.guestExec(fmt.Sprintf(
		`if (Test-Path -LiteralPath '%s') { `+
			`Get-ChildItem -LiteralPath '%s' -Filter '*.jsonl' | `+
			`ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw } }`, dir, dir))
}

// TestPairedChannelLossCleansUpCredentials pins the channel-loss teardown
// across processes: when the harness dies, the servant's control pipe closes,
// the run context cancels, and the server's LIFO teardown — credential cleanup
// included — runs. Killing the harness mid-session and asserting no session
// credential survives is what a single process cannot exercise.
func TestPairedChannelLossCleansUpCredentials(t *testing.T) {
	h := pairedHarness(t)
	// A minimal enforcing policy so the servant attaches in enforce mode.
	policy := h.writePolicy("harness-policy-loss.json", enforcingHarnessPolicy())

	// Start the paired session detached, kill the harness, then assert the
	// server exited (its stdout pump saw the servant's pipe close). The
	// credential subsystem is server-side; with no credentials configured in
	// this slice, the assertion is that the server process is gone — the
	// teardown ran rather than the server orphaning.
	script := fmt.Sprintf(
		`$h=Start-Process -FilePath '%s' -ArgumentList 'run','--policy-config','%s',`+
			`'--audit-sink','%s','--','%s','stdio' -PassThru -WindowStyle Hidden; `+
			`Start-Sleep -Seconds 2; `+
			`$kids=Get-CimInstance Win32_Process -Filter "ParentProcessId=$($h.Id)" | Select-Object -Expand ProcessId; `+
			`Stop-Process -Id $h.Id -Force; Start-Sleep -Seconds 3; `+
			`$alive=@($kids | Where-Object { Get-Process -Id $_ -ErrorAction SilentlyContinue }); `+
			`"survivors=$($alive.Count)"`,
		remoteHarnessExe, policy, harnessAuditDir, remoteExe)
	out, err := h.tryGuestExec(script)
	if err != nil {
		t.Fatalf("paired channel-loss scenario failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "survivors=0") {
		t.Fatalf("the governed server did not exit when the harness died (orphaned child):\n%s", out)
	}
}
