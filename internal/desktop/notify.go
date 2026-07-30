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
	esc := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;", "'", "&apos;")
	toast := "<toast><visual><binding template='ToastGeneric'><text>" +
		esc.Replace(title) + "</text><text>" + esc.Replace(message) +
		"</text></binding></visual></toast>"
	appID := `{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe`
	q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

	cmd := "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null;" +
		"[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null;" +
		"$xml = New-Object Windows.Data.Xml.Dom.XmlDocument;$xml.LoadXml(" + q(toast) + ");" +
		"$t = New-Object Windows.UI.Notifications.ToastNotification $xml;" +
		"[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier(" + q(appID) + ").Show($t)"

	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if _, err := d.RunWindowsPowerShell(ctx, cmd, 15*time.Second); err != nil {
		d.logger.Warn("guardrail notification failed", "error", err)
	}
}
