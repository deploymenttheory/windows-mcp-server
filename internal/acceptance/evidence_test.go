//go:build windows && (amd64 || arm64)

package acceptance

import (
	"fmt"
	"strings"
	"testing"
)

// The evidence bundle is the artifact handed to an auditor, and its documented
// promise has two halves that are easy to conflate: every member is checked
// against the manifest (integrity), and the manifest is signed by a key published
// out of band (provenance). A bundle with no key is still hash-verifiable; a
// bundle verified against the wrong key proves nothing about who made it.
//
// These tests exercise both halves, and the three ways a bundle can be wrong,
// against a real archive on a real machine.

const (
	keyDir     = remoteDir + `\keys`
	bundlePath = remoteDir + `\session.evidence.zip`
)

// sealBundle produces a signed bundle for a session and returns the public key.
func sealBundle(t *testing.T, h *harness, stamp string) string {
	t.Helper()
	if out, err := h.guestServer("evidence", "keygen", "--out", keyDir); err != nil {
		t.Fatalf("evidence keygen: %v\n%s", err, out)
	}
	pub := strings.TrimSpace(h.readGuestFile(keyDir + `\evidence.pub`))
	if pub == "" {
		t.Fatal("keygen produced no public key")
	}

	if out, err := h.guestServer("evidence", "bundle",
		"--dir", auditDir, "--session", stamp,
		"--out", bundlePath, "--key-file", keyDir+`\evidence.key`); err != nil {
		t.Fatalf("evidence bundle: %v\n%s", err, out)
	}
	if !h.guestFileExists(bundlePath) {
		t.Fatalf("no bundle at %s", bundlePath)
	}
	return pub
}

// TestEvidenceBundleRoundTrip is the positive case: seal, then verify against the
// key you expect.
func TestEvidenceBundleRoundTrip(t *testing.T) {
	h := newHarness(t)
	policy := h.writePolicy("audit-policy.json", auditPolicy())
	stamp := runSealedSession(t, h, policy)
	pub := sealBundle(t, h, stamp)

	out, err := h.guestServer("evidence", "verify", bundlePath, "--pubkey", pub)
	if err != nil {
		t.Fatalf("a freshly sealed bundle should verify against its own key: %v\n%s", err, out)
	}
	if !contains(out, "verdicts.json") && !contains(out, "audit/") {
		t.Logf("verify output (for reference):\n%s", out)
	}
}

// TestTamperedMemberFailsVerification: the manifest records a SHA-256 per member,
// so editing one is caught whether or not the bundle is signed.
func TestTamperedMemberFailsVerification(t *testing.T) {
	h := newHarness(t)
	policy := h.writePolicy("audit-policy.json", auditPolicy())
	stamp := runSealedSession(t, h, policy)
	pub := sealBundle(t, h, stamp)

	h.rewriteZipEntry(bundlePath, "verdicts.json", `[{"tampered":true}]`)

	out, err := h.guestServer("evidence", "verify", bundlePath, "--pubkey", pub)
	if err == nil {
		t.Errorf("a tampered member must fail verification, got:\n%s", out)
	}
}

// TestDroppedMemberFailsVerification: removing a member is as much a lie as
// editing one, and the manifest enumerates what should be there.
func TestDroppedMemberFailsVerification(t *testing.T) {
	h := newHarness(t)
	policy := h.writePolicy("audit-policy.json", auditPolicy())
	stamp := runSealedSession(t, h, policy)
	pub := sealBundle(t, h, stamp)

	h.deleteZipEntry(bundlePath, "verdicts.json")

	out, err := h.guestServer("evidence", "verify", bundlePath, "--pubkey", pub)
	if err == nil {
		t.Errorf("a dropped member must fail verification, got:\n%s", out)
	}
}

// TestWrongKeyFailsWhileTheBundleStillHashVerifies is the integrity/provenance
// distinction made concrete: the archive is intact, and it is still not the
// archive you were promised.
func TestWrongKeyFailsWhileTheBundleStillHashVerifies(t *testing.T) {
	h := newHarness(t)
	policy := h.writePolicy("audit-policy.json", auditPolicy())
	stamp := runSealedSession(t, h, policy)
	sealBundle(t, h, stamp)

	// A different key, minted the same way.
	const otherDir = remoteDir + `\keys-other`
	if out, err := h.guestServer("evidence", "keygen", "--out", otherDir); err != nil {
		t.Fatalf("second keygen: %v\n%s", err, out)
	}
	other := strings.TrimSpace(h.readGuestFile(otherDir + `\evidence.pub`))

	if out, err := h.guestServer("evidence", "verify", bundlePath, "--pubkey", other); err == nil {
		t.Errorf("verifying against a key that did not sign the bundle must fail, got:\n%s", out)
	}

	// Without a key the same archive still verifies: every member matches the
	// manifest. That is integrity without provenance, exactly as documented.
	if out, err := h.guestServer("evidence", "verify", bundlePath); err != nil {
		t.Errorf("an untampered bundle should still hash-verify with no key: %v\n%s", err, out)
	}
}

// TestJourneyArtifactsReachTheBundle is the end-to-end proof of the evidence work:
// a journey run writes an OTLP/JSON record and real screenshots, and both are
// sealed and hash-covered alongside the chain.
//
// It is the one scenario here that needs the desktop engine, so it needs the
// console session — a journey cannot run in session 0, where there is no desktop
// to automate.
func TestJourneyArtifactsReachTheBundle(t *testing.T) {
	h := newHarness(t)
	h.requireInteractive(t)

	evidenceRoot := remoteDir + `\evidence-root`
	policy := h.writePolicy("journey-policy.json", map[string]any{
		"version": 1,
		"transparency": map[string]any{
			"audit_destination": auditDir,
			"evidence_dir":      evidenceRoot,
		},
	})

	journeyPath := remoteDir + `\notepad-smoke.json`
	h.pushBytes(mustReadLocal(t, `..\..\journeys\examples\notepad-smoke.json`), journeyPath)

	out := h.runInteractive(fmt.Sprintf(`& '%s' journey run '%s' --policy-config '%s' --json`,
		remoteExe, journeyPath, policy))
	if !contains(out, `"passed"`) {
		t.Fatalf("the journey produced no report:\n%s", out)
	}
	if contains(out, `"passed": false`) || contains(out, `"passed":false`) {
		t.Fatalf("the journey did not pass on the guest:\n%s", out)
	}

	// The run record and at least one image.
	records := h.guestExec(fmt.Sprintf(
		`Get-ChildItem -LiteralPath '%s\journeys' -Filter '*.otlp.json' | ForEach-Object { $_.Name }`, evidenceRoot))
	if strings.TrimSpace(records) == "" {
		t.Error("the run wrote no OTLP/JSON run record")
	}
	images := h.guestExec(fmt.Sprintf(
		`Get-ChildItem -LiteralPath '%s\evidence' -Filter '*.png' | ForEach-Object { $_.Name }`, evidenceRoot))
	if strings.TrimSpace(images) == "" {
		t.Error("the run captured no images; screenshot persistence is not working on a real desktop")
	}

	// And they are sealed and verifiable.
	stamps := h.sessionStamps(auditDir)
	if len(stamps) == 0 {
		t.Fatal("the journey run produced no audit session")
	}
	stamp := stamps[len(stamps)-1]
	pub := sealBundle(t, h, stamp)

	listing := h.zipEntries(bundlePath)
	for _, want := range []string{"journeys/", "evidence/"} {
		if !contains(listing, want) {
			t.Errorf("the bundle should carry %s members:\n%s", want, listing)
		}
	}
	if out, err := h.guestServer("evidence", "verify", bundlePath, "--pubkey", pub); err != nil {
		t.Errorf("a bundle carrying journey artifacts should verify: %v\n%s", err, out)
	}

	// The journey's own verdict should be in the summary a reviewer opens first.
	verdicts := h.zipEntryText(bundlePath, "verdicts.json")
	if !contains(verdicts, "journey.finished") {
		t.Errorf("verdicts.json should carry the journey's verdict:\n%s", firstLines(verdicts, 20))
	}
}

// --- guest-side helpers ---------------------------------------------------

// requireInteractive skips unless the golden image's console-session runner is
// present. Without it there is no way to reach a desktop, and a journey test that
// silently ran in session 0 would fail for the wrong reason.
func (h *harness) requireInteractive(t *testing.T) {
	t.Helper()
	if !h.guestFileExists(interactiveRunner) {
		t.Skipf("no interactive runner at %s in the golden image; see docs/acceptance-testing.md",
			interactiveRunner)
	}
}

// interactiveRunner is the console-session command runner the golden image
// installs. PowerShell over SSH lands in session 0, which has no desktop.
const interactiveRunner = remoteDir + `\run-interactive.ps1`

// runInteractive runs a command in the guest's console session and returns its
// output.
func (h *harness) runInteractive(command string) string {
	h.t.Helper()
	return h.guestExec(fmt.Sprintf(
		`& '%s' -Command %s -TimeoutSec 300`, interactiveRunner, singleQuote(command)))
}

// pushBytes writes a blob into the guest.
func (h *harness) pushBytes(blob []byte, remotePath string) {
	h.t.Helper()
	h.guestExec(fmt.Sprintf(`[IO.File]::WriteAllBytes('%s', [Convert]::FromBase64String('%s'))`,
		remotePath, b64(blob)))
}

// zipEntries lists an archive's members.
func (h *harness) zipEntries(remotePath string) string {
	h.t.Helper()
	return h.guestExec(fmt.Sprintf(
		`Add-Type -AssemblyName System.IO.Compression.FileSystem; `+
			`$z=[IO.Compression.ZipFile]::OpenRead('%s'); `+
			`$z.Entries | ForEach-Object { $_.FullName }; $z.Dispose()`, remotePath))
}

// zipEntryText returns one member's contents.
func (h *harness) zipEntryText(remotePath, entry string) string {
	h.t.Helper()
	return h.guestExec(fmt.Sprintf(
		`Add-Type -AssemblyName System.IO.Compression.FileSystem; `+
			`$z=[IO.Compression.ZipFile]::OpenRead('%s'); `+
			`$e=$z.Entries | Where-Object { $_.FullName -eq '%s' }; `+
			`$r=New-Object IO.StreamReader($e.Open()); $r.ReadToEnd(); $r.Dispose(); $z.Dispose()`,
		remotePath, entry))
}

// rewriteZipEntry replaces a member's contents in place, leaving the manifest
// untouched — which is exactly what a tamperer would do.
func (h *harness) rewriteZipEntry(remotePath, entry, content string) {
	h.t.Helper()
	h.guestExec(fmt.Sprintf(
		`Add-Type -AssemblyName System.IO.Compression.FileSystem; `+
			`$z=[IO.Compression.ZipFile]::Open('%s','Update'); `+
			`$e=$z.Entries | Where-Object { $_.FullName -eq '%s' }; `+
			`$s=$e.Open(); $s.SetLength(0); `+
			`$w=New-Object IO.StreamWriter($s); $w.Write(%s); $w.Flush(); $w.Dispose(); `+
			`$z.Dispose()`, remotePath, entry, singleQuote(content)))
}

// deleteZipEntry removes a member.
func (h *harness) deleteZipEntry(remotePath, entry string) {
	h.t.Helper()
	h.guestExec(fmt.Sprintf(
		`Add-Type -AssemblyName System.IO.Compression.FileSystem; `+
			`$z=[IO.Compression.ZipFile]::Open('%s','Update'); `+
			`($z.Entries | Where-Object { $_.FullName -eq '%s' }).Delete(); `+
			`$z.Dispose()`, remotePath, entry))
}
