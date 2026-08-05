//go:build windows && (amd64 || arm64)

package acceptance

import (
	"fmt"
	"testing"
)

// The journey recorder's capture path cannot be automated, and that is a
// security property rather than a gap.
//
// internal/desktop/journeyhook_windows.go drops every keyboard event carrying
// LLKHF_INJECTED, so input synthesised with SendInput is ignored. That filter
// exists because a recorder that captured injected input would capture an
// agent's credential injection — whose entire design is that the secret is typed
// and never written down. Driving the recorder from a test would mean adding a
// switch to turn that filter off, which is a worse thing to have in the codebase
// than an untested path.
//
// So this test does the part a machine can do — get a guest to a ready desktop
// with the recorder running — and then stops and tells a human exactly what to
// do. It turns roadmap item A from an afternoon into five minutes.

// TestRecorderManualPrep prepares the guest for the manual recorder check.
// It is skipped unless explicitly asked for, because it ends with a VM waiting
// for a person and would otherwise hang an unattended run.
func TestRecorderManualPrep(t *testing.T) {
	if envOr("WINDOWS_MCP_ACC_RECORDER", "") != "1" {
		t.Skip("set WINDOWS_MCP_ACC_RECORDER=1 to prepare the guest for the manual recorder check")
	}
	h := newHarness(t)
	h.requireInteractive(t)

	out := remoteDir + `\recorded.json`
	h.guestExec(fmt.Sprintf(`Remove-Item -LiteralPath '%s' -ErrorAction SilentlyContinue`, out))

	// Start the recorder in the console session and do not wait for it: it runs
	// until the human presses F9.
	h.guestExec(fmt.Sprintf(
		`Start-Process -FilePath '%s' -ArgumentList 'journey','record','--out','%s','--name','manual-check' `+
			`-WindowStyle Hidden`, interactiveRunner, out))

	t.Log(recorderInstructions(h.guest, out))
	t.Log("when you have finished, run TestRecorderManualVerify against the same guest " +
		"with WINDOWS_MCP_ACC_KEEP=1 still set")
}

// TestRecorderManualVerify checks the file a human just recorded. Split from the
// prep so the guest is not reverted between the two.
func TestRecorderManualVerify(t *testing.T) {
	if envOr("WINDOWS_MCP_ACC_RECORDER", "") != "1" {
		t.Skip("set WINDOWS_MCP_ACC_RECORDER=1 to verify a manually recorded journey")
	}
	h := &harness{t: t, guest: envOr(guestEnv, defaultGuest), snapshot: envOr(snapshotEnv, defaultSnapshot)}

	out := remoteDir + `\recorded.json`
	if !h.guestFileExists(out) {
		t.Fatalf("no recorded journey at %s — run TestRecorderManualPrep first", out)
	}
	doc := h.readGuestFile(out)

	// The security guarantee first, because it is the one that matters most and
	// the one a tired reviewer skips.
	if contains(doc, "hunter2") {
		t.Errorf("THE RECORDED JOURNEY CONTAINS THE TYPED PASSWORD. This is the redaction "+
			"guarantee failing on a real desktop:\n%s", doc)
	}
	if !contains(doc, "enter_credential") {
		t.Errorf("no enter_credential step: the password field was not detected, so redaction "+
			"either did not fire or fired as something else:\n%s", doc)
	}

	// Then the things this phase added, neither of which has run against a real
	// accessibility tree before.
	if !contains(doc, "automation_id") {
		t.Logf("no automation_id in the draft — either the app exposes none, or the ladder " +
			"is not reaching it. Check against the app you drove.")
	}
	for _, want := range []string{`"verb": "invoke"`, `"verb": "toggle"`, `"verb": "select"`} {
		if contains(doc, want) {
			t.Logf("pattern-driven verb inference produced %s", want)
		}
	}
	if !contains(doc, "assertions") {
		t.Errorf("no assertions in the draft: F8 marking did not produce anything:\n%s", doc)
	}

	t.Logf("recorded journey:\n%s", doc)
}

func recorderInstructions(guest, out string) string {
	return fmt.Sprintf(`
The recorder is running on %[1]s. Open its console and drive it:

    weave console %[1]s

In the guest, with the recorder capturing:

  1. Open an application with named controls (Notepad, or anything with a
     toolbar). Click several NAMED controls, not blank areas.
  2. Click a checkbox or a list item if one is available — those exercise the
     pattern-driven verb inference (toggle / select) that has never run against
     a real tree.
  3. Type some ordinary text into a normal field.
  4. Type the literal password hunter2 into a PASSWORD field. Any masked field
     will do. This is the redaction check.
  5. Point at a control that shows a value and press F8. That is the assertion
     mark: it should record what the control currently reads.
  6. Press F9 to stop.

The draft lands at %[2]s in the guest.

Then run:

    go test ./internal/acceptance/ -run TestRecorderManualVerify -v

What it checks, and what you should read for yourself:

  - the string hunter2 appears NOWHERE in the file (the redaction guarantee)
  - a step with verb enter_credential marks where the password went
  - clicks on named controls carry a selector, preferring automation_id
  - a checkbox recorded as toggle, a list item as select — not as click
  - the F8 mark produced an assertion with the observed value filled in
`, guest, out)
}
