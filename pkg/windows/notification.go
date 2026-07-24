//go:build windows && (amd64 || arm64)

package windows

import (
	"context"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/windows-mcp-server/pkg/inventory"
)

// xmlEscape escapes text for inclusion in XML/toast content.
func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;", "'", "&apos;")
	return r.Replace(s)
}

// Notification shows a Windows toast notification. It uses Windows PowerShell
// 5.1 because the WinRT toast APIs are not available in PowerShell 7.
func Notification() inventory.ServerTool {
	return NewToolFromHandler(
		ToolsetSystem,
		mcp.Tool{
			Name:        "Notification",
			Description: "Show a Windows toast notification with a title and message.",
			Annotations: &mcp.ToolAnnotations{Title: "Show notification", ReadOnlyHint: false},
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"title":   {Type: "string", Description: "Notification title."},
					"message": {Type: "string", Description: "Notification body text."},
					"app_id":  {Type: "string", Description: "AppUserModelID to attribute the toast to (default: PowerShell)."},
				},
				Required: []string{"title", "message"},
			},
		},
		func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args, err := ArgsMap(req)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			title, err := RequiredString(args, "title")
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			message, err := RequiredString(args, "message")
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			appID := OptionalString(args, "app_id", "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe")

			toastXML := "<toast><visual><binding template='ToastGeneric'>" +
				"<text>" + xmlEscape(title) + "</text>" +
				"<text>" + xmlEscape(message) + "</text>" +
				"</binding></visual></toast>"

			command := "" +
				"[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null;" +
				"[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null;" +
				"$xml = New-Object Windows.Data.Xml.Dom.XmlDocument;" +
				"$xml.LoadXml(" + psQuote(toastXML) + ");" +
				"$toast = New-Object Windows.UI.Notifications.ToastNotification $xml;" +
				"[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier(" + psQuote(appID) + ").Show($toast);" +
				"'OK'"

			res, err := deps.Desktop().RunWindowsPowerShell(ctx, command, 20*time.Second)
			if err != nil {
				return NewToolResultErrorFromErr("notification failed", err), nil
			}
			if res.ExitCode != 0 {
				return NewToolResultErrorf("notification failed (exit %d):\n%s", res.ExitCode, strings.TrimSpace(res.Output)), nil
			}
			return NewToolResultTextf("Notification shown: %q", title), nil
		},
	)
}
