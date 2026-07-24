//go:build windows && (amd64 || arm64)

// Command windows-mcp-server is an MCP server that bridges AI agents to the
// Windows desktop: UI Automation, synthetic input, screenshots, window and
// application control, PowerShell, and system state.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/deploymenttheory/windows-mcp-server/internal/winmcp"
	"github.com/deploymenttheory/windows-mcp-server/pkg/windows"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "windows-mcp-server",
		Short: "MCP server for Windows desktop automation",
		Long: "windows-mcp-server exposes Windows desktop automation (UI Automation, input, " +
			"screenshots, window/app control, PowerShell, and system state) as MCP tools, " +
			"grouped into toolsets and selectable per persona.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(stdioCmd())
	root.AddCommand(personasCmd())
	return root
}

func stdioCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stdio",
		Short: "Start the MCP server over stdio",
		RunE: func(cmd *cobra.Command, _ []string) error {
			v := viperFor(cmd)

			cfg := winmcp.Config{
				Version:      version,
				Persona:      v.GetString("persona"),
				Toolsets:     splitCSV(v.GetString("toolsets")),
				Tools:        splitCSV(v.GetString("tools")),
				ExcludeTools: splitCSV(v.GetString("exclude-tools")),
				LogFile:      v.GetString("log-file"),
				Overlay:      v.GetBool("overlay"),
				RecordDir:    v.GetString("record-dir"),
				RecordFPS:    v.GetInt("record-fps"),
				RecordCodec:  v.GetString("record-codec"),
			}
			// Only treat --read-only as set when the flag was explicitly changed,
			// so a persona's default read-only stance is not overridden by the
			// flag's zero value.
			if cmd.Flags().Changed("read-only") {
				cfg.SetReadOnly(v.GetBool("read-only"))
			}

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return winmcp.RunStdio(ctx, cfg)
		},
	}

	f := cmd.Flags()
	f.String("toolsets", "", "Comma-separated toolsets to enable (e.g. screen,interaction,apps). Special: 'all', 'default'.")
	f.String("tools", "", "Comma-separated individual tools to additionally enable (bypasses toolset filtering).")
	f.String("exclude-tools", "", "Comma-separated tools to exclude (applied last).")
	f.Bool("read-only", false, "Expose only read-only tools.")
	f.String("persona", "", "Persona preset selecting toolsets and read-only stance (see 'personas' subcommand).")
	f.String("log-file", "", "Write debug logs to this file (default: info logs to stderr).")
	f.Bool("overlay", false, "Show visual-feedback overlays: a green hue around the focused window and an orange flash at click points (for screen capture / video).")
	f.String("record-dir", "", "Record the whole session to a video file in this directory (one file per session), so every session is tracked.")
	f.Int("record-fps", 4, "Session recording frame rate (frames per second).")
	f.String("record-codec", "h264", "Session recording codec: h264 or h265 (via ffmpeg if available; smaller files), or mjpeg (pure-Go, no dependency, larger files).")
	return cmd
}

func personasCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "personas",
		Short: "List the available persona presets",
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			for _, id := range []string{"first-line-support", "qa-test-engineer", "business-user"} {
				p, ok := windows.LookupPersona(id)
				if !ok {
					continue
				}
				fmt.Fprintf(out, "%s\n  %s\n  toolsets: %s (read-only: %t)\n\n",
					p.ID, p.Description, strings.Join(p.Toolsets, ", "), p.ReadOnly)
			}
			return nil
		},
	}
}

// viperFor binds a command's flags to viper with the WINDOWS_MCP_ env prefix, so
// every flag (e.g. --read-only) has an env-var equivalent (WINDOWS_MCP_READ_ONLY).
func viperFor(cmd *cobra.Command) *viper.Viper {
	v := viper.New()
	v.SetEnvPrefix("WINDOWS_MCP")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv()
	_ = v.BindPFlags(cmd.Flags())
	return v
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
