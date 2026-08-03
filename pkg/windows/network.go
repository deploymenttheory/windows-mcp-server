//go:build windows && (amd64 || arm64)

package windows

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/windows-mcp-server/pkg/inventory"
)

// Network reports adapter, DNS and IP configuration, and tests connectivity to a
// host. Read-only, but open-world: the "test" mode reaches the network directly
// and so is not constrained by the egress proxy — an honest residual.
func Network() inventory.ServerTool {
	openWorld := true
	return NewToolFromHandler(
		ToolsetDiagnostics,
		mcp.Tool{
			Name: "Network",
			Description: "Inspect networking and test connectivity. mode=adapters lists network adapters; " +
				"mode=dns shows configured DNS servers; mode=config shows IP configuration; mode=test runs " +
				"Test-NetConnection to a host (optionally a port). Read-only. Note: mode=test reaches the " +
				"network directly and is not routed through the egress proxy.",
			Annotations: &mcp.ToolAnnotations{
				Title:         "Network diagnostics",
				ReadOnlyHint:  true,
				OpenWorldHint: &openWorld,
			},
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"mode": {Type: "string", Enum: []any{"adapters", "dns", "config", "test"}, Description: "Operation."},
					"host": {Type: "string", Description: "Target host or IP (required for mode=test)."},
					"port": {Type: "integer", Description: "TCP port to test (mode=test); omit for an ICMP ping."},
				},
				Required: []string{"mode"},
			},
		},
		func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args, err := ArgsMap(req)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			mode, err := OptionalStringEnum(args, "mode", "", "adapters", "dns", "config", "test")
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}

			var command string
			switch mode {
			case "adapters":
				command = "Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, " +
					"@{n='LinkSpeed';e={$_.LinkSpeed}}, MacAddress | ConvertTo-Json -Depth 3 -AsArray"
			case "dns":
				command = "Get-DnsClientServerAddress -AddressFamily IPv4 | " +
					"Select-Object InterfaceAlias, @{n='Servers';e={$_.ServerAddresses -join ', '}} | " +
					"ConvertTo-Json -Depth 3 -AsArray"
			case "config":
				command = "Get-NetIPConfiguration | Select-Object InterfaceAlias, " +
					"@{n='IPv4';e={($_.IPv4Address.IPAddress) -join ', '}}, " +
					"@{n='Gateway';e={($_.IPv4DefaultGateway.NextHop) -join ', '}}, " +
					"@{n='DNS';e={($_.DNSServer.ServerAddresses) -join ', '}} | ConvertTo-Json -Depth 4 -AsArray"
			case "test":
				host, err := RequiredString(args, "host")
				if err != nil {
					return NewToolResultError(err.Error()), nil
				}
				// The host is embedded as a single-quoted PowerShell literal so it cannot
				// break out of the Test-NetConnection argument into a command.
				cmd := "Test-NetConnection -ComputerName " + psQuote(host)
				port, err := OptionalInt(args, "port", 0)
				if err != nil {
					return NewToolResultError(err.Error()), nil
				}
				if port > 0 {
					cmd += fmt.Sprintf(" -Port %d", clampInt(port, 1, 65535))
				}
				command = "$ProgressPreference='SilentlyContinue'; " + cmd +
					" | Select-Object ComputerName, RemoteAddress, RemotePort, " +
					"TcpTestSucceeded, PingSucceeded | ConvertTo-Json -Depth 3"
			}

			res, err := deps.Desktop().RunPowerShell(ctx, command, 60*time.Second)
			if err != nil {
				return NewToolResultErrorFromErr("network query failed", err), nil
			}
			out := strings.TrimSpace(res.Output)
			if res.TimedOut {
				return NewToolResultErrorf("network query timed out"), nil
			}
			if res.ExitCode != 0 {
				return NewToolResultErrorf("network query failed: %s", out), nil
			}
			if out == "" {
				return NewToolResultText("(no output)"), nil
			}
			return NewToolResultText(out), nil
		},
	)
}
