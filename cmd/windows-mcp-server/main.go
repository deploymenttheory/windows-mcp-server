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

// guardrailConfigFrom maps the four-layer security flags to a Config, shared by
// `stdio` and `check`.
func guardrailConfigFrom(v *viper.Viper) winmcp.Config {
	return winmcp.Config{
		// Layer 1: pre-flight
		Security:            v.GetBool("security"),
		WithMDM:             v.GetBool("with-mdm"),
		WithLoggedOnAccount: v.GetString("with-logged-on-account"),
		WithUserContext:     v.GetBool("with-user-context"),
		IsNotAdmin:          v.GetBool("is-not-admin"),
		RunContext:          v.GetString("run-context"),
		// Layer 2: in-flight
		GuardrailsInterval:   v.GetDuration("inflight-interval"),
		GuardrailsControlDir: v.GetString("inflight-control-dir"),
		// Layer 3: guardrails
		Guardrails:       v.GetString("guardrails"),
		Guardrail:        v.GetStringSlice("guardrail"),
		CircuitBreaker:   v.GetBool("circuit-breaker"),
		CircuitWindow:    v.GetDuration("circuit-window"),
		CircuitThreshold: v.GetInt("circuit-threshold"),
		// Layer 4: transparency
		WithVideoSessionRecording: v.GetString("with-video-session-recording"),
		WithLogging:               v.GetString("with-logging"),
		HeartbeatInterval:         v.GetDuration("heartbeat-interval"),
		// Kill switch — triggers
		WithKillSwitch:     v.GetBool("with-kill-switch"),
		KillOnPostureDrift: v.GetBool("kill-on-posture-drift"),
		KillOnCircuitTrip:  v.GetBool("kill-on-circuit-trip"),
		KillOnRugpull:      v.GetBool("kill-on-rugpull"),
		KillOnHeartbeatGap: v.GetBool("kill-on-heartbeat-gap"),
		// Kill switch — actions
		KillActionIsolate:       v.GetBool("kill-action-isolate"),
		KillActionKillProcs:     v.GetBool("kill-action-kill-procs"),
		KillActionProcNames:     v.GetStringSlice("kill-action-proc-names"),
		KillActionLock:          v.GetBool("kill-action-lock"),
		KillActionShutdown:      v.GetBool("kill-action-shutdown"),
		KillActionShutdownDelay: v.GetDuration("kill-action-shutdown-delay"),
		// Status + legacy
		GuardrailsStatusAddr:  v.GetString("guardrails-status-addr"),
		GuardrailsStatusToken: v.GetString("guardrails-status-token"),
		GuardrailsBypass:      v.GetBool("guardrails-bypass"),
		EnterpriseGuardrails:  v.GetBool("enterprise-guardrails"),
		// Tier-2 (parked)
		EnableTier2:       v.GetBool("enable-tier2"),
		GraphTenant:       v.GetString("graph-tenant"),
		GraphClientID:     v.GetString("graph-client-id"),
		GraphClientSecret: v.GetString("graph-client-secret"),
		RemotePolicyToken: v.GetString("remote-policy-token"),
	}
}

// addGuardrailFlags registers the four-layer security flags, grouped, shared by
// `stdio` and `check`. All bind to WINDOWS_MCP_* env vars via viperFor.
func addGuardrailFlags(f *pflag.FlagSet) {
	addPreflightFlags(f)
	addInflightFlags(f)
	addGuardrailPolicyFlags(f)
	addTransparencyFlags(f)
	addKillSwitchFlags(f)
	addTier2Flags(f)
}

// addPreflightFlags — Layer 1: checks evaluated once at startup.
func addPreflightFlags(f *pflag.FlagSet) {
	f.Bool("security", false, "Master switch: enforce pre-flight checks and force-on all transparency services (audit log, heartbeat, rug-pull detection, on-screen banner, recording).")
	f.Bool("with-mdm", false, "Pre-flight: require the device to be MDM-enrolled.")
	f.String("with-logged-on-account", "", "Pre-flight: require the interactive user to match this regex.")
	f.Bool("with-user-context", false, "Pre-flight: require an interactive user context (not SYSTEM / Session 0).")
	f.Bool("is-not-admin", false, "Pre-flight: require the interactive user to NOT be a local administrator.")
	f.String("run-context", "user", "Expected process context: 'user' (default) or 'system'. SYSTEM disables desktop-automation tools.")
}

// addInflightFlags — Layer 2: continuous polling (status/heartbeat/rug-pull are force-on).
func addInflightFlags(f *pflag.FlagSet) {
	f.Duration("inflight-interval", 60*time.Second, "In-flight posture re-evaluation cadence; posture drift self-terminates the session (0 disables drift re-eval).")
	f.String("inflight-control-dir", "", "Directory watched for a 'kill' sentinel file that stops the session. Empty disables.")
}

// addGuardrailPolicyFlags — Layer 3: inline tool-call policy.
func addGuardrailPolicyFlags(f *pflag.FlagSet) {
	f.String("guardrails", "off", "Guardrail mode: off, audit (log only), or enforce (block on failure). Forced to enforce by --security or any pre-flight check.")
	f.StringSlice("guardrail", nil, "Additional guardrails to require, repeatable: id or id=arg (e.g. secure-boot, bitlocker, vbs, device-allowlist=C:\\allow.txt).")
	f.Bool("circuit-breaker", false, "Inline destructive-action circuit breaker (auto-on in enforce mode).")
	f.Duration("circuit-window", 0, "Circuit-breaker sliding window (0 = default 10s).")
	f.Int("circuit-threshold", 0, "Sensitive tool calls within the window before tripping (0 = default 3).")
}

// addTransparencyFlags — Layer 4: always-on transparency (forced on by --security).
func addTransparencyFlags(f *pflag.FlagSet) {
	f.String("with-video-session-recording", "", "Record the session to a video file in this directory (implies recording capture).")
	f.String("with-logging", "", "Audit-log sink target: empty/'stderr' for stderr JSONL, or a file path for append-only hash-chained JSONL.")
	f.Duration("heartbeat-interval", 30*time.Second, "Heartbeat cadence written to the audit chain (also the gap watchdog basis).")
	f.String("guardrails-status-addr", "", "Loopback HTTP address for the always-on status/may-run endpoint (e.g. 127.0.0.1:8177). Empty disables.")
	f.String("guardrails-status-token", "", "Bearer token required by the status endpoint.")
	f.Bool("guardrails-bypass", false, "Break-glass: skip pre-flight checks (logged prominently).")
	f.Bool("enterprise-guardrails", false, "Legacy alias: enforce mode + the enterprise preset.")
}

// addKillSwitchFlags — kill switch triggers and (opt-in) actions, configured separately.
func addKillSwitchFlags(f *pflag.FlagSet) {
	f.Bool("with-kill-switch", false, "Arm the kill switch.")
	f.Bool("kill-on-posture-drift", true, "Trigger: kill on in-flight posture drift.")
	f.Bool("kill-on-circuit-trip", true, "Trigger: kill when the circuit breaker trips.")
	f.Bool("kill-on-rugpull", true, "Trigger: kill on tool-manifest mutation (rug pull).")
	f.Bool("kill-on-heartbeat-gap", true, "Trigger: kill on a heartbeat gap.")
	f.Bool("kill-action-isolate", true, "Action: isolate the device (firewall block-all) on kill. Requires elevation.")
	f.Bool("kill-action-kill-procs", false, "Action: terminate --kill-action-proc-names on kill. Requires elevation.")
	f.StringSlice("kill-action-proc-names", nil, "Process image names to terminate when --kill-action-kill-procs is set.")
	f.Bool("kill-action-lock", false, "Action: lock the workstation on kill.")
	f.Bool("kill-action-shutdown", false, "Action: shut the device down on kill. Requires elevation.")
	f.Duration("kill-action-shutdown-delay", 0, "Delay before shutdown when --kill-action-shutdown is set.")
}

// addTier2Flags — parked authoritative remote checks (not wired unless --enable-tier2).
func addTier2Flags(f *pflag.FlagSet) {
	f.Bool("enable-tier2", false, "Wire the parked tier-2 remote checks (Graph / remote may-run PDP).")
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
