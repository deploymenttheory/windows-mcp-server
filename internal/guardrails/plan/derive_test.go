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
			"an unknown tool derives nothing",
			Step{Tool: "Snapshot"},
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
