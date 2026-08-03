package plan

import (
	"strings"
	"testing"
)

func TestRenderChangeManifest(t *testing.T) {
	d, _ := doc(
		Step{Name: "read config", Tool: "FileSystem", Args: map[string]any{"mode": "read", "path": `C:\app\config.json`}},
		Step{Name: "wipe temp", Tool: "FileSystem", Args: map[string]any{"mode": "delete", "path": `C:\temp\x`}},
		Step{Tool: "PowerShell", Args: map[string]any{"command": "Restart-Service Spooler"}},
	).WithID()

	out := d.Render()

	for _, want := range []string{
		"read config [FileSystem]",
		`file     read    C:\app\config.json`,
		"wipe temp [FileSystem]",
		"⚠ destructive",
		"PowerShell",
		"⚠ undeclarable blast radius",
		"file: ",
		"shell: ",
		"2 of 3 step(s) destructive",
		"1 with an undeclarable blast radius",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("manifest missing %q\n---\n%s", want, out)
		}
	}
}
