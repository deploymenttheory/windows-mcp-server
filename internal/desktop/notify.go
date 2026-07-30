//go:build windows && (amd64 || arm64)

package desktop

import (
	"context"
	"strings"
	"time"
)

// Notify shows a best-effort Windows toast notification (WinRT via Windows
// PowerShell 5.1). Used by the guardrails layer to surface run-context
// auto-limiting and policy actions. Failures are logged, not returned.
func (d *Desktop) Notify(ctx context.Context, title, message string) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if _, err := d.RunWindowsPowerShell(ctx, toastCommand(title, message), 15*time.Second); err != nil {
		d.logger.Warn("guardrail notification failed", "error", err)
	}
}

// toastCommand builds the PowerShell that raises the toast. It is separated from
// Notify so the emitted script can be asserted without a desktop: the WinRT type
// loads are spelled across string concatenations to stay inside the line limit,
// and a mistake there would fail silently — Notify logs rather than returns.
func toastCommand(title, message string) string {
	esc := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;", "'", "&apos;")
	toast := "<toast><visual><binding template='ToastGeneric'><text>" +
		esc.Replace(title) + "</text><text>" + esc.Replace(message) +
		"</text></binding></visual></toast>"
	appID := `{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe`
	q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

	return "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, " +
		"ContentType = WindowsRuntime] | Out-Null;" +
		"[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, " +
		"ContentType = WindowsRuntime] | Out-Null;" +
		"$xml = New-Object Windows.Data.Xml.Dom.XmlDocument;$xml.LoadXml(" + q(toast) + ");" +
		"$t = New-Object Windows.UI.Notifications.ToastNotification $xml;" +
		"[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier(" + q(appID) + ").Show($t)"
}
