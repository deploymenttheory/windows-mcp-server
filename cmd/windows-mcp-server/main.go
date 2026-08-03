//go:build windows && (amd64 || arm64)

// Command windows-mcp-server is an MCP server that bridges AI agents to the
// Windows desktop: UI Automation, synthetic input, screenshots, window and
// application control, PowerShell, and system state.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/audit"
	"github.com/deploymenttheory/windows-mcp-server/internal/mcpconf"
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
	root.AddCommand(policyCmd())
	root.AddCommand(auditCmd())
	root.AddCommand(personasCmd())
	root.AddCommand(conformanceReportCmd())
	// Adds `conformance-serve` only under the `conformance` build tag. The
	// released binary has no HTTP listener; see conformance_cmd.go.
	addConformanceCommand(root)
	return root
}

// guardrailConfigFrom maps the security flags to a Config.
//
// There is one flag left. Everything else the subsystem needs comes from the
// policy document, which RunStdio loads.
func guardrailConfigFrom(v *viper.Viper) winmcp.Config {
	return winmcp.Config{PolicyConfig: v.GetString("policy-config")}
}

// addGuardrailFlags registers the flags that configure the security subsystem.
//
// There is one: the path to the policy document. Everything the subsystem does —
// which device signals are read and how often, which rules cover which tools,
// what a failure does, what trips the kill switch and what it actuates, where the
// audit chain is written — lives in that document instead of in flags.
//
// The reason is that the questions are relational, and flags cannot express a
// relation. "PowerShell requires MDM enrolment but taking a screenshot does not"
// has no spelling as a set of booleans; as a rule with a match and a requirement
// it is one line. Every flag that used to live here maps to a field in the
// document — see docs/policy-config.md for the table.
func addGuardrailFlags(f *pflag.FlagSet) {
	f.String("policy-config", "", "Path to the device-policy JSON document. Omit to use the built-in "+
		"default, which evaluates every declared signal and records every verdict but refuses nothing. "+
		"Validate one with `policy validate`; see which rules cover a tool with `policy explain`.")
}

// policyCmd groups the three questions an operator asks about device policy:
// is this document valid, what does this device look like right now, and why was
// that call refused.
func policyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Inspect the device policy: validate a document, check this device, explain a tool",
		Long: "The policy engine decides every tool call against live device signals. These " +
			"subcommands answer the three questions that come up around it, without starting a server.\n\n" +
			"With no --policy-config they operate on the built-in default: the engine present, every " +
			"declared signal evaluated and every verdict recorded, nothing refused.",
	}
	cmd.AddCommand(policyValidateCmd(), policyCheckCmd(), policyExplainCmd())
	return cmd
}

// auditCmd groups operations on the tamper-evident audit chain. Today there is
// one: verify. It exists because the chain is only worth as much as the ability
// to check it, and until now that check lived only as a Go API under internal/.
func auditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Inspect the tamper-evident audit chain",
		Long: "The audit chain records what a session did, each entry committing to the previous " +
			"entry's hash. These subcommands check that record without starting a server.",
	}
	cmd.AddCommand(auditVerifyCmd())
	return cmd
}

// auditVerifyCmd verifies a session file or a directory of them.
func auditVerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify <file|dir>",
		Short: "Verify a session audit file, or a directory of them linked by a manifest",
		Long: "verify checks a hash chain end to end. Given a single session-*.audit.jsonl file it " +
			"verifies that one chain. Given a directory (the audit_sink target in directory mode) it " +
			"verifies the manifest chain, each session file, and that every sealed session's head " +
			"matches its manifest record — so a dropped or rewritten session is caught.\n\n" +
			"With --key-env naming an environment variable that holds the same key the server ran " +
			"with (WINDOWS_MCP_AUDIT_KEY), it also checks every entry's HMAC, proving the chain was " +
			"written by a key holder and not just internally consistent.\n\n" +
			"Exits 1 on any integrity problem, reporting all of them.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			info, err := os.Stat(path)
			if err != nil {
				return fmt.Errorf("audit verify: %w", err)
			}
			out := cmd.OutOrStdout()

			var key []byte
			if env, _ := cmd.Flags().GetString("key-env"); env != "" {
				v := os.Getenv(env)
				if v == "" {
					return fmt.Errorf("audit verify: %s is empty; nothing to verify the MAC against", env)
				}
				key = []byte(v)
			}

			if info.IsDir() {
				rep, err := audit.VerifyDir(path, key)
				if err != nil {
					return fmt.Errorf("audit verify: %w", err)
				}
				fmt.Fprint(out, rep.String())
				if !rep.OK() {
					os.Exit(1)
				}
				return nil
			}

			entries, err := audit.VerifyFile(path, key)
			if err != nil {
				fmt.Fprintf(out, "BROKEN  %s: %v\n", path, err)
				os.Exit(1)
			}
			fmt.Fprintf(out, "ok  %s: %d entries, chain intact\n", path, len(entries))
			return nil
		},
	}
	cmd.Flags().String("key-env", "", "Name of an environment variable holding the audit HMAC key; "+
		"when set, entry MACs are verified in addition to the hash chain.")
	return cmd
}

// policyValidateCmd checks a document without touching the device, so it runs in
// CI on a machine with no TPM and no domain.
func policyValidateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate a policy document against this build's signal set",
		Long: "validate parses the document, rejects unknown fields, and checks that every signal " +
			"it names is one this build can evaluate and that every rule requires a declared signal.\n\n" +
			"It reads no device state, so it is safe to run anywhere. Exits 1 on any problem, and " +
			"reports all of them at once rather than one per run.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			v := viperFor(cmd)
			cfg := winmcp.Config{Version: version, PolicyConfig: v.GetString("policy-config")}

			policy, err := winmcp.ValidatePolicy(cfg)
			if err != nil {
				return err
			}
			source := cfg.PolicyConfig
			if source == "" {
				source = "(built-in default)"
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"ok  %s\n    mode=%s  signals=%v  rules=%d  rate_limits=%d\n",
				source, policy.Mode, policy.SignalIDs(), len(policy.Rules), len(policy.RateLimits))
			return nil
		},
	}
	addPolicyConfigFlag(cmd.Flags())
	return cmd
}

// policyCheckCmd evaluates the device now and prints the decision document.
func policyCheckCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Evaluate every declared signal against this device and print the decision",
		Long: "check reads every signal the policy declares, live and cache-bypassed, then applies " +
			"the startup-scoped rules and prints the decision document.\n\n" +
			"It is deliberately slow: dsregcmd, WMI and tpmtool all run. That is the point of a " +
			"diagnostic, and it is why the request path caches instead.\n\n" +
			"Exits 2 when the device is not admitted, so CI and operators can gate on posture.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			v := viperFor(cmd)
			cfg := winmcp.Config{
				Version:      version,
				PolicyConfig: v.GetString("policy-config"),
				LogFile:      v.GetString("log-file"),
			}

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			decision, err := winmcp.EvaluatePolicy(ctx, cfg)
			if err != nil {
				return err
			}
			out, err := json.MarshalIndent(decision, "", "  ")
			if err != nil {
				return fmt.Errorf("render decision: %w", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), string(out))
			if !decision.Admit {
				os.Exit(2)
			}
			return nil
		},
	}
	addPolicyConfigFlag(cmd.Flags())
	cmd.Flags().String("log-file", "", "Write debug logs to this file (default: info logs to stderr).")
	return cmd
}

// policyExplainCmd answers "why was that refused". Without it a denial in the
// field is unattributable, and the first instinct is to disable the engine.
func policyExplainCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "explain",
		Short: "Show which rules cover a tool and what they require",
		Long: "explain reports every rule that covers a tool, what each requires, and what it does " +
			"on failure.\n\n" +
			"It evaluates nothing, so it can be run on a machine other than the one that refused the " +
			"call, and answers instantly.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			v := viperFor(cmd)
			tool := v.GetString("tool")
			if tool == "" {
				return errNoToolNamed
			}
			cfg := winmcp.Config{
				Version:      version,
				PolicyConfig: v.GetString("policy-config"),
				Persona:      v.GetString("persona"),
				Toolsets:     splitCSV(v.GetString("toolsets")),
			}
			// Explain against the whole manifest by default: a tool the current
			// selection happens to exclude is still a tool the operator may be
			// asking about.
			if len(cfg.Toolsets) == 0 && cfg.Persona == "" {
				cfg.Toolsets = []string{"all"}
			}

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			cov, err := winmcp.ExplainPolicy(ctx, cfg, tool)
			if err != nil {
				return err
			}
			if v.GetString("format") == "json" {
				out, err := json.MarshalIndent(cov, "", "  ")
				if err != nil {
					return fmt.Errorf("render coverage: %w", err)
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(out))
				return nil
			}
			printCoverage(cmd.OutOrStdout(), cov)
			return nil
		},
	}
	addPolicyConfigFlag(cmd.Flags())
	f := cmd.Flags()
	f.String("tool", "", "Tool name to explain (required).")
	f.String("format", "text", "Output format: text or json.")
	f.String("toolsets", "", "Toolsets to resolve the tool against (default: all).")
	f.String("persona", "", "Resolve against the manifest a persona would serve.")
	return cmd
}

// errNoToolNamed is returned when `policy explain` is run without --tool.
var errNoToolNamed = errors.New("no tool named: use --tool <name>")

func printCoverage(w io.Writer, cov winmcp.PolicyCoverage) {
	fmt.Fprintf(w, "tool: %s\n", cov.Tool)
	if !cov.Known {
		fmt.Fprintf(w, "  not in the served manifest — only rules matching every tool can cover it\n")
	} else {
		fmt.Fprintf(w, "  toolset=%s read-only=%t destructive=%t open-world=%t\n",
			cov.Facts.Toolset, cov.Facts.ReadOnly, cov.Facts.Destructive, cov.Facts.OpenWorld)
	}
	if len(cov.Rules) == 0 {
		fmt.Fprintf(w, "\nno rule covers this tool: calls to it are never refused by policy\n")
		return
	}
	fmt.Fprintf(w, "\ncovered by %d rule(s):\n", len(cov.Rules))
	for _, r := range cov.Rules {
		fmt.Fprintf(w, "  %-24s requires %-40v on failure: %s\n", r.Name, r.Requires, r.OnFail)
	}
	fmt.Fprintf(w, "\nsignals that must pass: %v\n", cov.Signals)
}

// addPolicyConfigFlag adds the flag every policy subcommand takes.
func addPolicyConfigFlag(f *pflag.FlagSet) {
	f.String("policy-config", "", "Path to the device-policy JSON document. Omit for the built-in default.")
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
			cfg.RecordFPS = v.GetInt("record-fps")
			cfg.RecordCodec = v.GetString("record-codec")
			cfg.CredentialsFile = v.GetString("credentials-file")
			// Read-only is only applied when the operator actually asked for it,
			// so the flag's zero value cannot override a persona's own read-only
			// stance. "Asked for it" has to include the environment as well as
			// the command line: WINDOWS_MCP_READ_ONLY is the documented
			// equivalent of the flag, and gating on Changed() alone silently
			// ignored it — the operator would believe the server was read-only
			// when it was not.
			if cmd.Flags().Changed("read-only") || os.Getenv("WINDOWS_MCP_READ_ONLY") != "" {
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
	f.Int("record-fps", 4, "Session recording frame rate (frames per second). Whether a session is "+
		"recorded, and where, is set by transparency.recording_dir in the policy document.")
	f.String("record-codec", "h264", "Session recording codec: h264 or h265 (via ffmpeg if available; smaller files), or mjpeg (pure-Go, no dependency, larger files).")
	f.String("credentials-file", "", "JSON file of credentials to install into the Windows Credential Manager at init, "+
		"for app/web/SSO sign-in. Enables the 'credentials' toolset. Secrets are never accepted as flags or "+
		"returned to the agent, and are removed from the store when the session ends.")

	// Guardrails / admission control (shared with `check`).
	addGuardrailFlags(f)
	return cmd
}

// conformanceReportCmd renders the results of the official MCP conformance suite
// into the committed compliance report.
//
// It replaced `spec-check`, which scored this server's wire objects against
// vendored schemas and reported a number out of 100. That number was marked by
// the same project it graded. The suite at
// github.com/modelcontextprotocol/conformance is now the authority: the
// compliance workflow runs it against the loopback conformance host and this
// command turns its checks.json output into something readable and committable.
//
// It does not gate. The suite already does, via --expected-failures and its own
// exit code, and reimplementing that here would be a second opinion on a question
// that has an authoritative answer.
func conformanceReportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "conformance-report",
		Short: "Render official MCP conformance suite results as the compliance report",
		Long: "conformance-report reads one or more checks.json files produced by " +
			"github.com/modelcontextprotocol/conformance and renders them as markdown or JSON.\n\n" +
			"Each --pass is name=path/to/checks.json. Two passes are expected: `product`, run " +
			"against the manifest this server ships, and `fixtures`, run with the suite's named " +
			"fixture tools registered so tools/call, resources/read and prompts/get are exercised " +
			"at all.\n\n" +
			"No score is emitted: conformance is per-check pass or fail, gated by the suite.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			v := viperFor(cmd)

			report := &mcpconf.Report{
				ServerVersion: version,
				Commit:        v.GetString("commit"),
				GeneratedAt:   v.GetString("generated-at"),
				RunURL:        v.GetString("run-url"),
			}
			specVersion := v.GetString("spec-version")
			harness := v.GetString("harness-version")

			for _, spec := range v.GetStringSlice("pass") {
				name, path, ok := strings.Cut(spec, "=")
				if !ok {
					return fmt.Errorf("--pass %q must be name=path/to/checks.json", spec)
				}
				checks, err := mcpconf.LoadChecks(path)
				if err != nil {
					return err
				}
				report.Passes = append(report.Passes, &mcpconf.Pass{
					Name:           name,
					Description:    passDescriptions[name],
					SpecVersion:    specVersion,
					HarnessVersion: harness,
					Baseline:       v.GetString("baseline-" + name),
					Checks:         checks,
				})
			}
			if len(report.Passes) == 0 {
				return errNoPasses
			}

			// The badge is written before the report so a bad --format cannot leave
			// the README pointing at a stale figure while the report is regenerated.
			if badgeOut := v.GetString("badge-out"); badgeOut != "" {
				badge, err := json.MarshalIndent(report.BadgeFor(v.GetString("badge-pass")), "", "  ")
				if err != nil {
					return fmt.Errorf("marshal badge: %w", err)
				}
				if err := os.WriteFile(badgeOut, append(badge, '\n'), 0o644); err != nil { //nolint:gosec // a badge is not a secret
					return fmt.Errorf("write badge: %w", err)
				}
			}

			rendered, err := renderConformanceReport(report, v.GetString("format"))
			if err != nil {
				return err
			}
			if out := v.GetString("out"); out != "" {
				if err := os.WriteFile(out, []byte(rendered), 0o644); err != nil { //nolint:gosec // a report is not a secret
					return fmt.Errorf("write report: %w", err)
				}
				return nil
			}
			fmt.Fprint(cmd.OutOrStdout(), rendered)
			return nil
		},
	}

	f := cmd.Flags()
	f.StringSlice("pass", nil, "A suite run to include, as name=path/to/checks.json. Repeatable.")
	f.String("spec-version", "2026-07-28", "Protocol revision the suite was run at.")
	f.String("harness-version", "", "Exact npm version of the conformance suite that produced the results.")
	f.String("baseline-product", "", "Expected-failures file the product pass was gated against.")
	f.String("baseline-fixtures", "", "Expected-failures file the fixtures pass was gated against.")
	f.String("commit", "", "Commit the tested binary was built from.")
	f.String("generated-at", "", "Timestamp for the report; supplied by the caller so the output is reproducible.")
	f.String("run-url", "", "Link to the workflow run that produced the results.")
	f.String("format", "markdown", "Output format: markdown or json.")
	f.String("out", "", "Write the report to this file instead of stdout.")
	f.String("badge-out", "", "Also write a shields.io endpoint badge to this file.")
	f.String("badge-pass", "product", "Which pass the badge summarises.")
	return cmd
}

// errNoPasses is returned when no results were supplied. Rendering an empty
// report would read as a server with nothing wrong with it.
var errNoPasses = errors.New("no --pass results supplied")

// passDescriptions says what each pass proves, so the committed report explains
// itself without reference to the workflow that produced it.
var passDescriptions = map[string]string{
	"product": "Run against the manifest this server actually ships. Scenarios needing the suite's " +
		"named fixtures cannot execute here and are listed in the baseline; what this pass covers is " +
		"the transport and wire conformance that the 2026-07-28 revision is about.",
	"fixtures": "Run with the suite's fixture tools, resources and prompts registered, so tools/call, " +
		"resources/read, resources/templates/list and prompts/get are exercised through the real " +
		"middleware and result constructors. The fixtures exist only under the `conformance` build " +
		"tag and are never present in a released binary.",
}

func renderConformanceReport(r *mcpconf.Report, format string) (string, error) {
	switch format {
	case "json":
		b, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			return "", fmt.Errorf("marshal report: %w", err)
		}
		return string(b) + "\n", nil
	case "", "markdown", "md":
		return r.Markdown(), nil
	default:
		return "", fmt.Errorf("unknown --format %q (want markdown or json)", format)
	}
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
