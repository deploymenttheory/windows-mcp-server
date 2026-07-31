//go:build windows && (amd64 || arm64) && conformance

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/deploymenttheory/windows-mcp-server/internal/winmcp"
)

// addConformanceCommand registers `conformance-serve`, which exists only in a
// build tagged `conformance`.
func addConformanceCommand(root *cobra.Command) { root.AddCommand(conformanceServeCmd()) }

func conformanceServeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "conformance-serve",
		Short: "Serve the MCP surface over loopback HTTP for the official conformance suite",
		Long: "conformance-serve exposes this server's MCP surface over Streamable HTTP on a " +
			"loopback address so that github.com/modelcontextprotocol/conformance can connect " +
			"to it — its `server` mode requires --url and has no stdio path.\n\n" +
			"The surface is built by the same code as `stdio` and wrapped in the same middleware " +
			"chain, so evidence gathered here describes the shipped server. Only the transport " +
			"differs.\n\n" +
			"This subcommand does not exist in a released binary.\n\n" +
			"The bound URL is printed to stdout, so `--addr 127.0.0.1:0` can be used to take an " +
			"ephemeral port and read back the address to pass to the harness.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			v := viperFor(cmd)

			cfg := winmcp.Config{Version: version}
			cfg.Persona = v.GetString("persona")
			// Serve every tool by default. A tool in a non-default toolset is just as
			// much part of what this project ships, and just as able to serve a
			// non-conformant schema.
			cfg.Toolsets = splitCSV(v.GetString("toolsets"))
			if len(cfg.Toolsets) == 0 && cfg.Persona == "" {
				cfg.Toolsets = []string{"all"}
			}
			if cmd.Flags().Changed("read-only") {
				cfg.SetReadOnly(v.GetBool("read-only"))
			}
			cfg.EnforceHTTPS = v.GetBool("enforce-https")

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			return winmcp.RunConformanceHost(ctx, cfg, winmcp.ConformanceConfig{
				Addr:     v.GetString("addr"),
				Path:     v.GetString("path"),
				Fixtures: v.GetBool("fixtures"),
			})
		},
	}

	f := cmd.Flags()
	f.String("addr", "127.0.0.1:3001", "Loopback address to listen on. Use :0 for an ephemeral port.")
	f.String("path", "/mcp", "HTTP path to serve the MCP endpoint on.")
	f.Bool("fixtures", false,
		"Register the conformance suite's named fixture tools, resources and prompts. Off serves "+
			"the manifest this server actually ships (the product pass); on lets the suite exercise "+
			"tools/call, resources/read and prompts/get (the depth pass).")
	f.String("toolsets", "", "Comma-separated toolsets to serve (default: all toolsets).")
	f.String("persona", "", "Serve the manifest a persona would serve.")
	f.Bool("read-only", false, "Serve the read-only manifest.")
	f.Bool("enforce-https", false, "Refuse plaintext http:// targets, as --security does.")
	return cmd
}
