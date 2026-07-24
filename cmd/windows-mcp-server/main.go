//go:build windows && (amd64 || arm64)

// Command windows-mcp-server is an MCP server that bridges AI agents to the
// Windows desktop: UI Automation, synthetic input, screenshots, window and
// application control, PowerShell, and system state.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
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
	root.AddCommand(checkCmd())
	root.AddCommand(personasCmd())
	return root
}

// guardrailConfigFrom maps the shared guardrail/graph flags to a Config.
func guardrailConfigFrom(v *viper.Viper) winmcp.Config {
	return winmcp.Config{
		RunContext:            v.GetString("run-context"),
		Guardrails:            v.GetString("guardrails"),
		EnterpriseGuardrails:  v.GetBool("enterprise-guardrails"),
		Guardrail:             v.GetStringSlice("guardrail"),
		GuardrailsInterval:    v.GetDuration("guardrails-interval"),
		GuardrailsStatusAddr:  v.GetString("guardrails-status-addr"),
		GuardrailsStatusToken: v.GetString("guardrails-status-token"),
		GuardrailsControlDir:  v.GetString("guardrails-control-dir"),
		GuardrailsBypass:      v.GetBool("guardrails-bypass"),
		CircuitBreaker:        v.GetBool("circuit-breaker"),
		GraphTenant:           v.GetString("graph-tenant"),
		GraphClientID:         v.GetString("graph-client-id"),
		GraphClientSecret:     v.GetString("graph-client-secret"),
		RemotePolicyToken:     v.GetString("remote-policy-token"),
	}
}

// addGuardrailFlags registers the guardrail/admission and tier-2 remote flags on
// a command, shared by `stdio` and `check`.
func addGuardrailFlags(f *pflag.FlagSet) {
	f.String("run-context", "user", "Expected process context: 'user' (default) or 'system'. Validated against the token; personas require user. SYSTEM disables desktop-automation tools.")
	f.String("guardrails", "off", "Guardrail mode: off, audit (evaluate + log only), or enforce (refuse to run if policy fails).")
	f.Bool("enterprise-guardrails", false, "Shortcut for --guardrails=enforce with the enterprise preset (MDM-enrolled + Entra-joined + run-context=user).")
	f.StringSlice("guardrail", nil, "Additional guardrails to require, repeatable: id or id=arg (e.g. secure-boot, bitlocker, vbs, device-allowlist=C:\\allow.txt).")
	f.Duration("guardrails-interval", 60*time.Second, "Continuous re-evaluation interval; if posture fails the session self-terminates (0 disables).")
	f.String("guardrails-status-addr", "", "Loopback HTTP address for the guardrail status/may-run endpoint (e.g. 127.0.0.1:8177). Empty disables.")
	f.String("guardrails-status-token", "", "Bearer token required by the status endpoint.")
	f.String("guardrails-control-dir", "", "Directory watched for a 'kill' sentinel file that stops the session. Empty disables.")
	f.Bool("guardrails-bypass", false, "Break-glass: skip guardrail checks (logged prominently).")
	f.Bool("circuit-breaker", false, "Enable the inline destructive-action circuit breaker (auto-on in enforce mode).")
	f.String("graph-tenant", "", "Entra tenant ID for Graph device-compliance checks (Entra + Intune).")
	f.String("graph-client-id", "", "Entra app (client) ID with Device.Read.All + DeviceManagementManagedDevices.Read.All.")
	f.String("graph-client-secret", "", "Client secret for the Graph app registration (prefer the environment/vault).")
	f.String("remote-policy-token", "", "Bearer token presented to a remote-policy=<url> may-run endpoint.")
}

// checkCmd evaluates the guardrail set once and prints the decision document,
// without starting the server. Useful as a device-posture dry-run for operators
// and CI, and — when run elevated — to exercise the TPM platform attestation.
func checkCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Evaluate device guardrails once and print the decision document",
		RunE: func(cmd *cobra.Command, _ []string) error {
			v := viperFor(cmd)
			cfg := guardrailConfigFrom(v)
			cfg.Version = version
			cfg.LogFile = v.GetString("log-file")

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			decision, err := winmcp.EvaluateGuardrails(ctx, cfg)
			if err != nil {
				return err
			}
			out, err := json.MarshalIndent(decision, "", "  ")
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), string(out))
			if !decision.Admit {
				os.Exit(2) // non-zero so CI/operators can gate on posture
			}
			return nil
		},
	}
	addGuardrailFlags(cmd.Flags())
	cmd.Flags().String("log-file", "", "Write debug logs to this file (default: info logs to stderr).")
	return cmd
}

func stdioCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stdio",
		Short: "Start the MCP server over stdio",
		RunE: func(cmd *cobra.Command, _ []string) error {
			v := viperFor(cmd)

			cfg := guardrailConfigFrom(v)
			cfg.Version = version
			cfg.Persona = v.GetString("persona")
			cfg.Toolsets = splitCSV(v.GetString("toolsets"))
			cfg.Tools = splitCSV(v.GetString("tools"))
			cfg.ExcludeTools = splitCSV(v.GetString("exclude-tools"))
			cfg.LogFile = v.GetString("log-file")
			cfg.Overlay = v.GetBool("overlay")
			cfg.RecordDir = v.GetString("record-dir")
			cfg.RecordFPS = v.GetInt("record-fps")
			cfg.RecordCodec = v.GetString("record-codec")
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

	// Guardrails / admission control (shared with `check`).
	addGuardrailFlags(f)
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
