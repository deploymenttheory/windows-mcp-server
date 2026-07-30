//go:build windows && (amd64 || arm64)

package desktop

import (
	"strings"
	"testing"
)

// TestToastCommandTypeLoadsAreIntact pins the two WinRT type-load statements.
//
// They are written as concatenated fragments to stay inside the line limit, so a
// dropped space or a fragment joined in the wrong order would produce a script
// that no longer loads the type — and Notify logs its failure rather than
// returning it, so the toast would simply stop appearing with nothing to see.
func TestToastCommandTypeLoadsAreIntact(t *testing.T) {
	got := toastCommand("Title", "Body")

	for _, want := range []string{
		"[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null;",
		"[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null;",
		"$t = New-Object Windows.UI.Notifications.ToastNotification $xml;",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("toast command is missing %q\ngot: %s", want, got)
		}
	}
}

// TestToastCommandEscapesSingleQuotes: the whole toast XML reaches PowerShell
// inside a single-quoted literal, so no bare apostrophe may survive. Two
// mechanisms cover it — operator text is XML-escaped to &apos;, and the quotes
// the template itself contains are doubled — and both must hold, because
// guardrail titles and messages are operator-authored free text.
func TestToastCommandEscapesSingleQuotes(t *testing.T) {
	got := toastCommand("Dafydd's PC", "it's blocked")

	if strings.Contains(got, "Dafydd's") || strings.Contains(got, "it's") {
		t.Errorf("a bare apostrophe would close the PowerShell literal early: %s", got)
	}
	for _, want := range []string{"Dafydd&apos;s PC", "it&apos;s blocked", "template=''ToastGeneric''"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in the command, got: %s", want, got)
		}
	}
}

// TestToastCommandEscapesMarkup keeps operator text from breaking the toast XML.
func TestToastCommandEscapesMarkup(t *testing.T) {
	got := toastCommand("<b>", "a & b")
	if strings.Contains(got, "<b>") {
		t.Error("title markup was not escaped")
	}
	if !strings.Contains(got, "&lt;b&gt;") || !strings.Contains(got, "a &amp; b") {
		t.Errorf("expected escaped markup, got: %s", got)
	}
}
