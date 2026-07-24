package windows

import "github.com/deploymenttheory/windows-mcp-server/pkg/inventory"

// Toolset metadata. Each tool declares membership in exactly one of these. The
// Default flag marks toolsets included when the caller asks for the "default"
// configuration (or passes no --toolsets selection). These groupings are also
// the building blocks of the persona presets below.
var (
	// ToolsetScreen: read-only perception of the desktop.
	ToolsetScreen = inventory.ToolsetMetadata{
		ID:          "screen",
		Description: "Read-only perception of the desktop: UI-tree snapshots, screenshots, and display inventory.",
		Default:     true,
		Icon:        "device-desktop",
	}
	// ToolsetInteraction: synthetic input and UI interaction.
	ToolsetInteraction = inventory.ToolsetMetadata{
		ID:          "interaction",
		Description: "Mouse and keyboard interaction: click, type, scroll, move, shortcuts, waits, and multi-element actions.",
		Default:     true,
		Icon:        "pointer",
	}
	// ToolsetApps: application and window lifecycle.
	ToolsetApps = inventory.ToolsetMetadata{
		ID:          "apps",
		Description: "Launch, switch, resize, and manage applications and windows.",
		Default:     true,
		Icon:        "browser",
	}
	// ToolsetSystem: local system state and objects.
	ToolsetSystem = inventory.ToolsetMetadata{
		ID:          "system",
		Description: "Local system operations: process list/kill, clipboard, registry, and notifications.",
		Default:     true,
		Icon:        "gear",
	}
	// ToolsetShell: arbitrary PowerShell execution (powerful; non-default).
	ToolsetShell = inventory.ToolsetMetadata{
		ID:          "shell",
		Description: "Execute arbitrary PowerShell commands. Powerful and potentially destructive; disabled by default.",
		Icon:        "terminal",
	}
	// ToolsetFilesystem: file operations (non-default).
	ToolsetFilesystem = inventory.ToolsetMetadata{
		ID:          "filesystem",
		Description: "Read, write, copy, move, delete, list, and search files. Disabled by default.",
		Icon:        "file-directory",
	}
	// ToolsetWeb: web scraping (non-default).
	ToolsetWeb = inventory.ToolsetMetadata{
		ID:          "web",
		Description: "Fetch and extract web page content, optionally via the active browser's DOM. Disabled by default.",
		Icon:        "globe",
	}
	// ToolsetDiagnostics: system diagnostics for support workflows (non-default).
	ToolsetDiagnostics = inventory.ToolsetMetadata{
		ID:          "diagnostics",
		Description: "System diagnostics: OS/hardware inventory and Windows service control, for support and troubleshooting. Disabled by default.",
		Icon:        "pulse",
	}
	// ToolsetTesting: assertions and evidence capture for QA (non-default).
	ToolsetTesting = inventory.ToolsetMetadata{
		ID:          "testing",
		Description: "UI test assertions and evidence capture, for authoring and running automated tests. Disabled by default.",
		Icon:        "beaker",
	}
)

// Persona is a named preset that resolves to a toolset selection and a
// read-only default. Personas make the toolset engine's persona goal concrete:
// each is simply a fixed WithToolsets configuration a caller can select with a
// single flag, rather than enumerating toolsets by hand.
type Persona struct {
	// ID is the persona's selector value (e.g. "first-line-support").
	ID string
	// Description explains who the persona is for.
	Description string
	// Toolsets is the toolset selection this persona enables (values accepted by
	// Builder.WithToolsets, including "all"/"default").
	Toolsets []string
	// ReadOnly is the persona's default read-only stance. A caller may still
	// override it explicitly.
	ReadOnly bool
	// Instructions is guidance injected into the MCP server's Instructions so
	// the agent adopts this persona's workflow and mindset.
	Instructions string
}

// Personas is the registry of built-in personas.
//
// These are intentionally coarse starting points for the persona work; the tool
// surface each one exposes will be tuned once feature parity is proven. They
// demonstrate that persona = (toolset selection + read-only stance) over the
// same underlying tool manifest.
var Personas = map[string]Persona{
	"first-line-support": {
		ID:          "first-line-support",
		Description: "1st-line support engineer: perceive and drive the desktop, manage apps and system state, run diagnostics, and control services.",
		Toolsets:    []string{"screen", "interaction", "apps", "system", "shell", "diagnostics"},
		ReadOnly:    false,
		Instructions: "You are assisting a 1st-line support engineer troubleshooting a Windows machine. " +
			"Diagnose before you act: take a Snapshot to see the desktop, and use SystemInfo, Process, and Service " +
			"to gather state before making changes. Use PowerShell for deeper diagnostics. Before any destructive or " +
			"disruptive action (killing a process, stopping a service, editing the registry), state what you will do " +
			"and why. Report findings and the steps you took in clear, non-jargon language the end user can follow.",
	},
	"qa-test-engineer": {
		ID:          "qa-test-engineer",
		Description: "QA test engineer: full desktop automation for authoring and running UI tests, with assertions, evidence capture, filesystem, and web access.",
		Toolsets:    []string{"screen", "interaction", "apps", "system", "filesystem", "web", "testing"},
		ReadOnly:    false,
		Instructions: "You are automating and verifying UI tests as a QA engineer. Work deterministically: take a " +
			"Snapshot before each interaction and target elements by their label rather than raw coordinates, since " +
			"labels are stable across DPI, theme, and window position. Verify every expected outcome with Assert or " +
			"WaitFor, and treat a failed Assert as a test failure to report — do not silently continue. Capture " +
			"evidence with CaptureEvidence at key steps and on failure. Re-Snapshot after the UI changes.",
	},
	"business-user": {
		ID: "business-user",
		Description: "Business end-user & user-journey testing: drive everyday applications and browse the web through " +
			"the real UI, verify outcomes, and capture evidence — without shell, registry, or file-system access.",
		Toolsets: []string{"screen", "interaction", "apps", "web", "testing"},
		ReadOnly: false,
		Instructions: "You are driving a Windows device as a business end-user, to complete everyday tasks and to test " +
			"user journeys through the real application UI. Work one observable step at a time: take a Snapshot, act on " +
			"an element by its label (Click, Type, or the UIA actions Invoke/SetValue/Toggle/Select), then verify the " +
			"result with Assert or WaitFor before moving on — treat a failed Assert as a failed journey step and report " +
			"it. Prefer the UIA actions (Invoke/SetValue) over raw Click/Type where available: they are more reliable and " +
			"do not depend on window focus. Capture evidence with CaptureEvidence at key steps and on failure. You have " +
			"no shell, registry, or file-system access — stay within the open applications and browser. " +
			"Note: the Windows sign-in screen, lock screen, and UAC elevation prompts run on a protected desktop that " +
			"cannot be automated; assume you are already in an unlocked, signed-in session. Explain each step in plain " +
			"language and confirm before anything a user might not expect (submitting forms, deleting content, closing apps).",
	},
}

// LookupPersona returns the named persona and whether it exists.
func LookupPersona(id string) (Persona, bool) {
	p, ok := Personas[id]
	return p, ok
}
