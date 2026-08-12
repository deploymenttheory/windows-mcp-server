//go:build windows && (amd64 || arm64)

// Package acceptance drives the shipped binary against a disposable Windows
// guest. It covers what a CI runner cannot: the desktop engine, which needs an
// interactive session; the guardrails that need elevation; and the audit chain's
// behaviour when a process is killed rather than shut down.
//
// The guest is managed by weave (github.com/deploymenttheory/guestweave-windows),
// which runs VMs on the Host Compute Service. The dependency is the CLI, not the
// module: weave's internals are not importable, so the contract is `weave.exe` on
// PATH.
//
// Gated on WINDOWS_MCP_ACC=1. These tests revert snapshots and kill processes, so
// they must never run unattended.
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
	"slices"
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
	// weaveEnv names the weave binary. weave is pre-alpha and normally run from a
	// build tree rather than installed, so being on PATH is the exception.
	weaveEnv = "WINDOWS_MCP_ACC_WEAVE"

	defaultGuest    = "acc"
	defaultSnapshot = "golden"

	// remoteDir is where the golden image expects the binary and the run's state.
	// It is inside the guest, so a revert takes the whole thing away.
	remoteDir = `C:\acc`
	remoteExe = remoteDir + `\windows-mcp-server.exe`

	// interactiveRunner is the console-session command runner provision.ps1
	// installs. PowerShell over SSH lands in session 0, which has no desktop.
	interactiveRunner = remoteDir + `\run-interactive.ps1`
)

// bootTimeout bounds how long we wait for the guest to answer over SSH after a
// revert. The golden snapshot is taken with the guest stopped, so this is a cold
// boot: measured at about 30 seconds, with headroom for a slower host.
//
// The snapshot must be a stopped one. A snapshot of a running guest captures RAM
// and resumes into that instant, and a guest resumed that way comes back with no
// network at all — not merely no sshd, but unreachable by ping, while weave still
// reports the VM running and still resolves its address.
const bootTimeout = 5 * time.Minute

// harness owns one acceptance run against one guest.
type harness struct {
	t        *testing.T
	exe      string // the server binary, built on the host for this run
	weaveExe string // the weave CLI driving the guest
	guest    string
	snapshot string

	// interactive records whether the guest carries the console-session runner,
	// probed once per run rather than per scenario.
	interactive bool

	// keyFile and ip are the file-transfer path. weave authenticates to the guest
	// with a password and forwards no standard input, so a binary cannot be piped
	// through `weave ssh`; scp against the guest's own sshd is the way in, and it
	// needs a key because there is no non-interactive password prompt on Windows.
	keyFile string
	ip      string
}

// newHarness gates the suite, builds the binary under test, and reverts the guest
// to its golden snapshot.
//
// Isolation is by revert rather than by cleanup because the scenarios kill
// processes and tamper with files: a test that fails partway through cannot be
// relied on to undo its own damage.
func newHarness(t *testing.T) *harness {
	t.Helper()
	if os.Getenv(gateEnv) != "1" {
		t.Skipf("set %s=1 to run the acceptance suite (it drives a real VM)", gateEnv)
	}

	h := &harness{
		t:        t,
		weaveExe: resolveWeave(t),
		guest:    envOr(guestEnv, defaultGuest),
		snapshot: envOr(snapshotEnv, defaultSnapshot),
	}
	// Before the build, and before anything is stopped or reverted: a name that
	// does not exist should cost a second and name the alternatives.
	h.preflightGuest()

	h.exe = filepath.Join(t.TempDir(), "windows-mcp-server.exe")
	build := exec.Command("go", "build", "-o", h.exe, "github.com/deploymenttheory/windows-mcp-server/cmd/windows-mcp-server")
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the binary under test: %v\n%s", err, out)
	}

	h.resetGuest()
	h.bootstrapTransfer()
	h.push(h.exe, remoteExe)

	// Probed once, here, so an unprovisioned image is diagnosed as such rather
	// than reported one scenario at a time as an unexplained skip.
	h.interactive = h.guestFileExists(interactiveRunner)
	if !h.interactive {
		t.Logf("%s is absent: the scenarios that drive the UI will skip. Run "+
			"acceptance/guest/provision.ps1 inside %s and re-take the %q snapshot.",
			interactiveRunner, h.guest, h.snapshot)
	}

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

// resolveWeave locates the weave CLI: the explicit override first, then PATH,
// then the places a `go install` or a packaged build leaves it.
//
// The suite's entire contract with weave is this one binary, so not finding it is
// the most likely way a run fails, and the message names every place looked
// rather than only asserting PATH.
func resolveWeave(t *testing.T) string {
	t.Helper()
	if v := os.Getenv(weaveEnv); v != "" {
		if _, err := os.Stat(v); err != nil {
			t.Fatalf("%s=%s: %v", weaveEnv, v, err)
		}
		return v
	}
	if p, err := exec.LookPath("weave"); err == nil {
		return p
	}

	tried := make([]string, 0, 4)
	for _, dir := range weaveSearchDirs() {
		p := filepath.Join(dir, "weave.exe")
		tried = append(tried, p)
		if _, err := os.Stat(p); err == nil {
			t.Logf("weave is not on PATH; using %s", p)
			return p
		}
	}
	t.Fatalf("weave.exe is not on PATH, and is not at any of:\n  %s\n"+
		"Set %s to its full path (e.g. %s=D:\\weave\\weave.exe).\n"+
		"See docs/acceptance-testing.md", strings.Join(tried, "\n  "), weaveEnv, weaveEnv)
	return ""
}

// weaveSearchDirs are the conventional install locations, tried only after PATH.
func weaveSearchDirs() []string {
	var dirs []string
	if gobin := os.Getenv("GOBIN"); gobin != "" {
		dirs = append(dirs, gobin)
	}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, "go", "bin"))
	}
	for _, env := range []string{"LOCALAPPDATA", "ProgramFiles"} {
		if v := os.Getenv(env); v != "" {
			dirs = append(dirs, filepath.Join(v, "weave"))
		}
	}
	return dirs
}

// preflightGuest checks the guest and snapshot exist before the suite stops,
// reverts or builds anything.
//
// Without it a name that does not exist first surfaces as a failed revert several
// steps in, reported as weave's error rather than as the list of names that
// actually answers the question.
func (h *harness) preflightGuest() {
	h.t.Helper()

	out, err := h.tryWeave("list", "--quiet")
	if err != nil {
		h.t.Fatalf("weave list: %v\n%s", err, out)
	}
	names := vmNames(out)
	if !slices.Contains(names, h.guest) {
		h.t.Fatalf("no weave VM named %q. This host has: %s.\n"+
			"Set %s to one of them, or build a guest per docs/acceptance-testing.md.",
			h.guest, orNone(names), guestEnv)
	}

	out, err = h.tryWeave("snapshot", "list", h.guest)
	if err != nil {
		h.t.Fatalf("weave snapshot list %s: %v\n%s", h.guest, err, out)
	}
	snaps := snapshotNames(out)
	if !slices.Contains(snaps, h.snapshot) {
		h.t.Fatalf("%s has no snapshot %q. It has: %s.\n"+
			"Set %s, or take one with the guest stopped and provisioned:\n"+
			"  weave snapshot create %s %s -d \"windows-mcp acceptance baseline\"\n"+
			"See docs/acceptance-testing.md — a snapshot of a running guest resumes with no network.",
			h.guest, h.snapshot, orNone(snaps), snapshotEnv, h.guest, h.snapshot)
	}
	h.t.Logf("driving weave VM %s (snapshot %s) via %s", h.guest, h.snapshot, h.weaveExe)
}

// vmNames reads `weave list --quiet`, which prints one name per line.
func vmNames(out string) []string {
	return nonEmptyLines(out)
}

// snapshotNames reads the names out of `weave snapshot list`. That verb has no
// --format, so its table is parsed: a header row, then one snapshot per line with
// the current one marked by a trailing asterisk.
func snapshotNames(table string) []string {
	var names []string
	for _, line := range nonEmptyLines(table) {
		name, _, _ := strings.Cut(line, " ")
		if name == "" || name == "NAME" {
			continue
		}
		names = append(names, strings.TrimSuffix(name, "*"))
	}
	return names
}

// resetGuest reverts to the golden snapshot, boots, and waits for SSH.
func (h *harness) resetGuest() {
	h.t.Helper()
	// weave reverts stopped VMs only. Between tests the guest is already stopped,
	// because each harness's cleanup stops it — but the first test of a run finds
	// it in whatever state the last thing to touch it left, so the suite would only
	// work from a state it happened to produce itself. A stop that fails because
	// the guest is already stopped is the expected case, not an error.
	if _, err := h.tryWeave("stop", h.guest); err != nil {
		h.t.Logf("stopping %s before the revert: %v (expected when it was already stopped)", h.guest, err)
	}
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
			h.t.Fatalf("%s did not answer over SSH within %s. If the guest is running and has "+
				"an address but does not respond to ping, the golden snapshot was taken while "+
				"the guest was running: a RAM snapshot resumes with no network. Re-take it "+
				"with the guest stopped.", h.guest, bootTimeout)
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
	cmd := exec.Command(h.weaveExe, args...)
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
// The script travels as -EncodedCommand (base64 UTF-16LE), as the server's own
// PowerShell invocations do, so no quoting has to survive the Go string, the SSH
// command line and the guest's shell.
func (h *harness) tryGuestExec(script string) (string, error) {
	out, err := h.tryWeave("ssh", h.guest, "powershell", "-NoProfile", "-NonInteractive",
		"-EncodedCommand", encodePowerShell(guestPrologue+script))
	return stripProgressRecords(out), err
}

// guestPrologue silences PowerShell's progress stream.
//
// Standard error is redirected over SSH, and a redirected PowerShell serializes
// its non-output streams as CLIXML rather than rendering them. The first command
// after a cold boot emits a "Preparing modules for first use" progress record,
// which arrives in the combined output as a one-line XML blob — indistinguishable
// from the command's own value to anything reading the last line, which is how
// push's size check once compared a file length against an <Objs> document.
const guestPrologue = `$ProgressPreference='SilentlyContinue'; `

// stripProgressRecords removes serialized progress records from guest output.
//
// The prologue prevents them, so this is the second line of defence: it drops
// only progress objects, because a CLIXML error record is a diagnostic and a test
// asserting on a failure needs to keep it.
func stripProgressRecords(out string) string {
	if !strings.Contains(out, `S="progress"`) {
		return out
	}
	var kept []string
	for line := range strings.SplitSeq(strings.ReplaceAll(out, "\r\n", "\n"), "\n") {
		// The serializer announces itself with a "#< CLIXML" header line before the
		// document, so dropping only the document would leave that behind as the
		// last non-empty line — the same failure with a shorter blob.
		trimmed := strings.TrimSpace(line)
		if trimmed == "#< CLIXML" || strings.Contains(line, `S="progress"`) {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
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

// bootstrapTransfer opens a file-transfer path to the guest: an ephemeral key
// pair, its public half installed in the guest, and the guest's address.
//
// The key is installed per run rather than baked into the golden snapshot, so no
// long-lived credential sits in an image, and it is authorised through
// administrators_authorized_keys because the guest account is an administrator —
// Windows OpenSSH ignores an admin's ~/.ssh/authorized_keys, and rejects the file
// unless its ACL grants only Administrators and SYSTEM.
func (h *harness) bootstrapTransfer() {
	h.t.Helper()
	for _, tool := range []string{"ssh-keygen", "scp", "ssh"} {
		if _, err := exec.LookPath(tool); err != nil {
			h.t.Fatalf("%s is not on PATH; the OpenSSH client is required to push files: %v", tool, err)
		}
	}

	dir := h.t.TempDir()
	h.keyFile = filepath.Join(dir, "acc_id_ed25519")
	gen := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-f", h.keyFile, "-C", "windows-mcp-acc")
	if out, err := gen.CombinedOutput(); err != nil {
		h.t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}
	pub, err := os.ReadFile(h.keyFile + ".pub")
	if err != nil {
		h.t.Fatalf("read generated public key: %v", err)
	}

	h.guestExec(fmt.Sprintf(
		`$f='C:\ProgramData\ssh\administrators_authorized_keys'; `+
			`Set-Content -LiteralPath $f -Value %s -Encoding ASCII; `+
			`icacls $f /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F' | Out-Null`,
		singleQuote(strings.TrimSpace(string(pub)))))

	h.ip = strings.TrimSpace(lastLine(h.weave("ip", h.guest, "--wait", "120")))
	if h.ip == "" {
		h.t.Fatal("could not resolve the guest's address")
	}
}

// push copies a local file into the guest over scp.
//
// weave has no cp verb and `weave ssh` does not forward standard input, so a
// binary can be neither piped nor passed on a command line; scp against the
// guest's own sshd is what remains. A `weave cp` over the SFTP upload in weave's
// internal/ssh would replace all of this.
func (h *harness) push(localPath, remotePath string) {
	h.t.Helper()
	if h.keyFile == "" {
		h.t.Fatal("push called before bootstrapTransfer")
	}
	// scp wants a forward-slashed remote path even on Windows.
	dest := fmt.Sprintf("weave@%s:%s", h.ip, strings.ReplaceAll(remotePath, `\`, "/"))
	args := append(h.sshOpts(), localPath, dest)
	if out, err := exec.Command("scp", args...).CombinedOutput(); err != nil {
		h.t.Fatalf("scp %s -> %s: %v\n%s", localPath, dest, err, out)
	}

	want, err := os.Stat(localPath)
	if err != nil {
		h.t.Fatalf("stat %s: %v", localPath, err)
	}
	raw := h.guestExec(fmt.Sprintf(`(Get-Item -LiteralPath '%s').Length`, remotePath))
	got := strings.TrimSpace(lastLine(raw))
	if got != fmt.Sprint(want.Size()) {
		h.t.Fatalf("push %s: guest reports %q bytes, sent %d\nfull output:\n%s",
			remotePath, got, want.Size(), raw)
	}
}

// sshOpts are the non-interactive options every ssh/scp call needs. The guest is
// disposable and reverted before each run, so its host key changes and pinning it
// would only produce a mismatch to suppress.
func (h *harness) sshOpts() []string {
	return []string{
		"-i", h.keyFile,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=" + os.DevNull,
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=20",
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

// requireInteractive skips unless the guest carries the console-session runner.
// Without it there is no route to a desktop, and the test would fail on the
// absence of UIA rather than on the behaviour under test.
func (h *harness) requireInteractive(t *testing.T) {
	t.Helper()
	if !h.interactive {
		t.Skipf("%s is not in the %q snapshot of %s: run acceptance/guest/provision.ps1 "+
			"in the guest and re-take it. See docs/acceptance-testing.md",
			interactiveRunner, h.snapshot, h.guest)
	}
}

// listGuestFiles names the files matching a filter in an in-guest directory.
//
// A missing directory lists nothing, for the same reason sessionStamps tolerates
// one: the callers are asserting that a run produced output, and that assertion
// should report the absence in its own words rather than being pre-empted by a
// PowerShell PathNotFound.
func (h *harness) listGuestFiles(dir, filter string) string {
	h.t.Helper()
	return h.guestExec(fmt.Sprintf(
		`if (Test-Path -LiteralPath '%s') { `+
			`Get-ChildItem -LiteralPath '%s' -Filter '%s' | ForEach-Object { $_.Name } }`,
		dir, dir, filter))
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
//
// A missing directory answers "none". It is the state of every freshly reverted
// guest — the server creates the destination when it writes the first entry — and
// callers count the stamps before a run to tell which one is theirs, so treating
// its absence as an error would fail every test on its first question.
func (h *harness) sessionStamps(auditDir string) []string {
	h.t.Helper()
	out := h.guestExec(fmt.Sprintf(
		`if (Test-Path -LiteralPath '%s') { `+
			`Get-ChildItem -LiteralPath '%s' -Filter 'session-*.audit.jsonl' | `+
			`ForEach-Object { $_.BaseName -replace '^session-','' -replace '\.audit$','' } }`,
		auditDir, auditDir))
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

// nonEmptyLines splits CLI output into trimmed, non-blank lines.
func nonEmptyLines(s string) []string {
	var out []string
	for line := range strings.SplitSeq(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		if t := strings.TrimSpace(line); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// orNone renders a list for a diagnostic, so an empty one reads as a fact rather
// than as a truncated sentence.
func orNone(items []string) string {
	if len(items) == 0 {
		return "(none)"
	}
	return strings.Join(items, ", ")
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
