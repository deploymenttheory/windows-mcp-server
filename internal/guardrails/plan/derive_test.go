package plan

import (
	"reflect"
	"testing"
)

func TestDeriveTargets(t *testing.T) {
	for _, tc := range []struct {
		name         string
		step         Step
		want         []Target
		undeclarable bool
	}{
		{
			"filesystem read",
			Step{Tool: "FileSystem", Args: map[string]any{"mode": "read", "path": `C:\a`}},
			[]Target{{KindFile, `C:\a`, VerbRead}}, false,
		},
		{
			"filesystem write",
			Step{Tool: "FileSystem", Args: map[string]any{"mode": "write", "path": `C:\a`}},
			[]Target{{KindFile, `C:\a`, VerbWrite}}, false,
		},
		{
			"filesystem copy names both files",
			Step{Tool: "FileSystem", Args: map[string]any{"mode": "copy", "path": `C:\a`, "destination": `C:\b`}},
			[]Target{{KindFile, `C:\a`, VerbRead}, {KindFile, `C:\b`, VerbWrite}}, false,
		},
		{
			"filesystem move writes the source",
			Step{Tool: "FileSystem", Args: map[string]any{"mode": "move", "path": `C:\a`, "destination": `C:\b`}},
			[]Target{{KindFile, `C:\a`, VerbWrite}, {KindFile, `C:\b`, VerbWrite}}, false,
		},
		{
			"registry set is a write",
			Step{Tool: "Registry", Args: map[string]any{"mode": "set", "path": `HKCU:\Software\X`}},
			[]Target{{KindRegistry, `HKCU:\Software\X`, VerbWrite}}, false,
		},
		{
			"process kill by pid",
			Step{Tool: "Process", Args: map[string]any{"mode": "kill", "pid": float64(1234)}},
			[]Target{{KindProcess, "pid:1234", VerbKill}}, false,
		},
		{
			"app launch creates a ui",
			Step{Tool: "App", Args: map[string]any{"mode": "launch", "name": "notepad"}},
			[]Target{{KindUI, "notepad", VerbCreate}}, false,
		},
		{
			"app launching a url reaches a host",
			Step{Tool: "App", Args: map[string]any{"mode": "launch", "name": "https://example.com/path"}},
			[]Target{{KindHost, "example.com", VerbReach}}, false,
		},
		{
			"powershell is undeclarable",
			Step{Tool: "PowerShell", Args: map[string]any{"command": "Remove-Item x"}},
			[]Target{{KindShell, "PowerShell command", VerbExecute}}, true,
		},
		{
			"network test reaches a host",
			Step{Tool: "Network", Args: map[string]any{"mode": "test", "host": "example.com"}},
			[]Target{{KindHost, "example.com", VerbReach}}, false,
		},
		{
			"network inspection touches nothing outside the machine",
			Step{Tool: "Network", Args: map[string]any{"mode": "adapters"}},
			nil, false,
		},
		{
			"scheduled task create names the task",
			Step{Tool: "ScheduledTask", Args: map[string]any{"mode": "create", "name": "Nightly"}},
			[]Target{{KindTask, "Nightly", VerbCreate}}, false,
		},
		{
			"scheduled task delete is a delete",
			Step{Tool: "ScheduledTask", Args: map[string]any{"mode": "delete", "name": "Nightly"}},
			[]Target{{KindTask, "Nightly", VerbDelete}}, false,
		},
		{
			"scheduled task list derives nothing",
			Step{Tool: "ScheduledTask", Args: map[string]any{"mode": "list"}},
			nil, false,
		},
		{
			"package install creates a package",
			Step{Tool: "Package", Args: map[string]any{"mode": "install", "id": "Vendor.App"}},
			[]Target{{KindPackage, "Vendor.App", VerbCreate}}, false,
		},
		{
			"package uninstall removes a package",
			Step{Tool: "Package", Args: map[string]any{"mode": "uninstall", "id": "Vendor.App"}},
			[]Target{{KindPackage, "Vendor.App", VerbDelete}}, false,
		},
		{
			"package search derives nothing",
			Step{Tool: "Package", Args: map[string]any{"mode": "search", "query": "editor"}},
			nil, false,
		},
		{
			// Snapshot used to stand in here, back when no UI tool derived anything.
			// It now derives a read of the screen, so the case needs a name no tool
			// has — which is the thing actually being checked.
			"an unknown tool derives nothing",
			Step{Tool: "NoSuchTool"},
			nil, false,
		},
		{
			"a click derives what it presses",
			Step{Tool: "Click", Args: map[string]any{"name": "Delete", "clicks": 1}},
			[]Target{{KindUI, "Delete", VerbInvoke}}, false,
		},
		{
			"a hover reads rather than acts",
			Step{Tool: "Click", Args: map[string]any{"name": "Delete", "clicks": 0}},
			[]Target{{KindUI, "Delete", VerbRead}}, false,
		},
		{
			"an automation id names the target over the accessible name",
			Step{Tool: "Click", Args: map[string]any{"automation_id": "btnDel", "name": "Delete"}},
			[]Target{{KindUI, "btnDel", VerbInvoke}}, false,
		},
		{
			// A chord is reach into the shell: win+r is arbitrary execution.
			"a shortcut executes",
			Step{Tool: "Shortcut", Args: map[string]any{"shortcut": "win+r"}},
			[]Target{{KindUI, "keyboard: win+r", VerbExecute}}, false,
		},
		{
			"setting a value writes",
			Step{Tool: "Invoke", Args: map[string]any{"name": "Amount", "action": "set_value"}},
			[]Target{{KindUI, "Amount", VerbWrite}}, false,
		},
		{
			"invoking does not",
			Step{Tool: "Invoke", Args: map[string]any{"name": "Submit", "action": "invoke"}},
			[]Target{{KindUI, "Submit", VerbInvoke}}, false,
		},
		{
			"typing with no target writes to whatever holds focus",
			Step{Tool: "Type", Args: map[string]any{"text": "hello"}},
			[]Target{{KindUI, "focused field", VerbWrite}}, false,
		},
		{
			"injecting a credential writes into the field",
			Step{Tool: "Credentials", Args: map[string]any{"mode": "inject", "name_target": "Password"}},
			[]Target{{KindUI, "Password", VerbWrite}}, false,
		},
		{
			"listing credentials touches no element",
			Step{Tool: "Credentials", Args: map[string]any{"mode": "list"}},
			nil, false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, undeclarable := DeriveTargets(tc.step)
			if undeclarable != tc.undeclarable {
				t.Errorf("undeclarable = %v, want %v", undeclarable, tc.undeclarable)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("targets = %+v, want %+v", got, tc.want)
			}
		})
	}
}
