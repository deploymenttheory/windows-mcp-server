package plan

import (
	"fmt"
	"strconv"
	"strings"
)

// DeriveTargets returns the targets a step's tool provably touches, read from its
// arguments, and whether the tool's blast radius is underivable (PowerShell — an
// arbitrary script). Deriving the targets independently of what the agent declares
// is what stops a plan from understating its own reach: the manifest shows what
// the tool will do, not what the agent said it would.
//
// It is keyed on tool name and argument keys — the same vocabulary a policy rule
// matches on — so it stays free of any dependency on the tool implementations.
func DeriveTargets(s Step) (targets []Target, undeclarable bool) {
	mode := strArg(s.Args, "mode")
	switch s.Tool {
	case "FileSystem":
		return fileTargets(s.Args, mode), false
	case "Registry":
		return registryTargets(s.Args, mode), false
	case "Process":
		return processTargets(s.Args, mode), false
	case "App":
		return appTargets(s.Args, mode), false
	case "PowerShell":
		// An arbitrary command: its reach cannot be read from its arguments. Flag
		// it so the manifest says as much rather than implying it touches nothing.
		return []Target{{Kind: KindShell, Name: "PowerShell command", Verb: VerbExecute}}, true
	case "Network":
		return networkTargets(s.Args, mode), false
	case "ScheduledTask":
		return scheduledTaskTargets(s.Args, mode), false
	case "Package":
		return packageTargets(s.Args, mode), false

	// The UI tools. Without these a plan built out of desktop interaction derived
	// nothing at all, so its manifest showed an empty change list and every step
	// rendered as non-destructive — not merely uninformative but wrong, since a
	// click is what presses "Delete" and a key chord is arbitrary execution.
	case "Click", "Move":
		return []Target{{KindUI, uiTargetName(s.Args, "pointer"), clickVerb(s.Args)}}, false
	case "Type", "MultiEdit":
		return []Target{{KindUI, uiTargetName(s.Args, "focused field"), VerbWrite}}, false
	case "Invoke":
		return []Target{{KindUI, uiTargetName(s.Args, "element"), invokeVerb(s.Args)}}, false
	case "MultiSelect":
		return []Target{{KindUI, uiTargetName(s.Args, "selection"), VerbWrite}}, false
	case "Shortcut":
		// A chord is reach into the shell, not a click: win+r is arbitrary
		// execution, which is why Shortcut is annotated destructive.
		return []Target{{KindUI, "keyboard: " + strArg(s.Args, "shortcut"), VerbExecute}}, false
	case "Scroll", "GetText", "Assert":
		return []Target{{KindUI, uiTargetName(s.Args, "screen"), VerbRead}}, false
	case "Snapshot", "Screenshot", "CaptureEvidence":
		return []Target{{KindUI, "screen", VerbRead}}, false
	case "Credentials":
		return credentialTargets(s.Args, mode), false

	default:
		return nil, false
	}
}

// uiTargetName names the element a UI step acts on, reading the selector keys in
// stability order — the automation id, then the accessible name, then the raw
// coordinate. fallback names the target when the step carries no selector at all,
// which is legitimate: typing goes to whatever holds focus.
func uiTargetName(args map[string]any, fallback string) string {
	if id := strArg(args, "automation_id"); id != "" {
		return id
	}
	if name := strArg(args, "name"); name != "" {
		return name
	}
	if loc, ok := args["loc"].([]any); ok && len(loc) == 2 {
		return fmt.Sprintf("(%v,%v)", loc[0], loc[1])
	}
	if loc, ok := args["loc"].([]int); ok && len(loc) == 2 {
		return fmt.Sprintf("(%d,%d)", loc[0], loc[1])
	}
	return fallback
}

// clickVerb reads how far a pointer step reaches. Zero clicks is a hover: the
// pointer moves over a control and nothing is pressed, so it observes rather than
// acts.
func clickVerb(args map[string]any) TargetVerb {
	if n := strArg(args, "clicks"); n == "0" {
		return VerbRead
	}
	return VerbInvoke
}

// invokeVerb reads how far an Invoke step reaches from its action: setting a
// value or changing a selection writes, while activating or expanding does not.
func invokeVerb(args map[string]any) TargetVerb {
	switch strArg(args, "action") {
	case "set_value", "toggle", "select":
		return VerbWrite
	default: // invoke, expand, collapse
		return VerbInvoke
	}
}

// credentialTargets derives the reach of a Credentials step. Only inject touches
// the UI — it types a secret into a field; list and verify report on what is
// installed and name no element.
func credentialTargets(args map[string]any, mode string) []Target {
	if mode != "inject" {
		return nil
	}
	name := strArg(args, "automation_id")
	if name == "" {
		name = strArg(args, "name_target")
	}
	if name == "" {
		name = "focused field"
	}
	return []Target{{KindUI, name, VerbWrite}}
}

// packageTargets derives the reach of a Package step: install creates a package,
// uninstall removes one, named by the winget id or the MSI path. list and search
// touch nothing installed and derive nothing.
func packageTargets(args map[string]any, mode string) []Target {
	name := strArg(args, "id")
	if name == "" {
		name = strArg(args, "msi")
	}
	if name == "" {
		return nil
	}
	switch mode {
	case "install":
		return []Target{{KindPackage, name, VerbCreate}}
	case "uninstall":
		return []Target{{KindPackage, name, VerbDelete}}
	default: // list, search
		return nil
	}
}

// scheduledTaskTargets derives the reach of a ScheduledTask step: a task named by
// the step, at a verb matching the mode. list has no single named task, so it
// derives nothing.
func scheduledTaskTargets(args map[string]any, mode string) []Target {
	name := strArg(args, "name")
	if name == "" {
		return nil
	}
	switch mode {
	case "create":
		return []Target{{KindTask, name, VerbCreate}}
	case "delete":
		return []Target{{KindTask, name, VerbDelete}}
	case "run":
		return []Target{{KindTask, name, VerbExecute}}
	case "enable", "disable":
		return []Target{{KindTask, name, VerbWrite}}
	case "get":
		return []Target{{KindTask, name, VerbRead}}
	default: // list
		return nil
	}
}

// networkTargets derives the reach of a Network step. Only mode=test leaves the
// machine — it reaches a host — so it is the only mode that names a target; the
// inspection modes touch nothing outside the local configuration.
func networkTargets(args map[string]any, mode string) []Target {
	if mode != "test" {
		return nil
	}
	host := strArg(args, "host")
	if host == "" {
		return nil
	}
	return []Target{{KindHost, host, VerbReach}}
}

func fileTargets(args map[string]any, mode string) []Target {
	path := strArg(args, "path")
	if path == "" {
		return nil
	}
	switch mode {
	case "write":
		return []Target{{KindFile, path, VerbWrite}}
	case "delete":
		return []Target{{KindFile, path, VerbDelete}}
	case "copy":
		return withDest(args, Target{KindFile, path, VerbRead}, VerbWrite)
	case "move":
		// A move removes the source, so the source is written, not merely read.
		return withDest(args, Target{KindFile, path, VerbWrite}, VerbWrite)
	default: // read, list, search, info
		return []Target{{KindFile, path, VerbRead}}
	}
}

func withDest(args map[string]any, src Target, destVerb TargetVerb) []Target {
	out := []Target{src}
	if dest := strArg(args, "destination"); dest != "" {
		out = append(out, Target{KindFile, dest, destVerb})
	}
	return out
}

func registryTargets(args map[string]any, mode string) []Target {
	path := strArg(args, "path")
	if path == "" {
		return nil
	}
	switch mode {
	case "set":
		return []Target{{KindRegistry, path, VerbWrite}}
	case "delete":
		return []Target{{KindRegistry, path, VerbDelete}}
	default: // get, list
		return []Target{{KindRegistry, path, VerbRead}}
	}
}

func processTargets(args map[string]any, mode string) []Target {
	if mode != "kill" {
		return []Target{{KindProcess, "process list", VerbRead}}
	}
	name := strArg(args, "name")
	if pid := strArg(args, "pid"); pid != "" && pid != "0" {
		name = "pid:" + pid
	}
	if name == "" {
		name = "process"
	}
	return []Target{{KindProcess, name, VerbKill}}
}

func appTargets(args map[string]any, mode string) []Target {
	name := strArg(args, "name")
	if name == "" {
		return nil
	}
	// A URL-shaped name is a navigation to the default browser, not a UI action.
	if strings.Contains(name, "://") {
		host := name
		if i := strings.Index(name, "://"); i >= 0 {
			host = name[i+3:]
		}
		if j := strings.IndexAny(host, "/:"); j >= 0 {
			host = host[:j]
		}
		return []Target{{KindHost, host, VerbReach}}
	}
	switch mode {
	case "launch", "launch_executable":
		return []Target{{KindUI, name, VerbCreate}}
	default: // switch, resize
		return []Target{{KindUI, name, VerbInvoke}}
	}
}

// strArg reads a string argument, tolerating the value types Claude Desktop
// coerces (a bool or number stringified). A missing or non-scalar value is "".
func strArg(args map[string]any, key string) string {
	v, ok := args[key]
	if !ok {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case int:
		return strconv.Itoa(x)
	default:
		return ""
	}
}
