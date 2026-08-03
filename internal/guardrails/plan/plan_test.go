package plan

import (
	"errors"
	"testing"
)

func doc(steps ...Step) Document {
	return Document{Version: SchemaVersion, Steps: steps}
}

func TestComputeIDIsStableAndContentBound(t *testing.T) {
	d := doc(
		Step{Tool: "FileSystem", Args: map[string]any{"mode": "read", "path": `C:\a.txt`}},
		Step{Tool: "PowerShell", Args: map[string]any{"command": "Get-Process"}},
	)

	id1, err := d.ComputeID()
	if err != nil {
		t.Fatal(err)
	}
	id2, _ := d.ComputeID()
	if id1 != id2 {
		t.Errorf("ComputeID is not stable for the same content: %s vs %s", id1, id2)
	}

	// Setting PlanID must not change the hash (it is excluded from the canonical form).
	withID, _ := d.WithID()
	if got, _ := withID.ComputeID(); got != id1 {
		t.Errorf("PlanID must be excluded from its own hash: %s vs %s", got, id1)
	}

	// Argument map order must not matter — encoding/json sorts keys.
	reordered := doc(
		Step{Tool: "FileSystem", Args: map[string]any{"path": `C:\a.txt`, "mode": "read"}},
		Step{Tool: "PowerShell", Args: map[string]any{"command": "Get-Process"}},
	)
	if got, _ := reordered.ComputeID(); got != id1 {
		t.Errorf("argument order changed the id: %s vs %s", got, id1)
	}

	// Changing a step must change the id.
	changed := doc(
		Step{Tool: "FileSystem", Args: map[string]any{"mode": "delete", "path": `C:\a.txt`}},
		Step{Tool: "PowerShell", Args: map[string]any{"command": "Get-Process"}},
	)
	if got, _ := changed.ComputeID(); got == id1 {
		t.Error("changing a step did not change the id")
	}
}

func TestValidateRejectsUnderstatedTargets(t *testing.T) {
	// The tool writes the file, but the step declares only a read — hiding reach.
	d := doc(Step{
		Tool:    "FileSystem",
		Args:    map[string]any{"mode": "write", "path": `C:\secret.txt`},
		Targets: []Target{{KindFile, `C:\secret.txt`, VerbRead}},
	})
	err := d.Validate()
	if !errors.Is(err, ErrUnderstatedTargets) {
		t.Fatalf("understated targets should be rejected, got %v", err)
	}
}

func TestValidateAcceptsCoveringAndAbsentDeclarations(t *testing.T) {
	// Declaring nothing is fine — the derivation stands in.
	if err := doc(Step{Tool: "FileSystem", Args: map[string]any{"mode": "write", "path": `C:\a`}}).Validate(); err != nil {
		t.Errorf("a step that declares no targets should validate: %v", err)
	}
	// Declaring a target at least as mutating as the derived one is fine.
	ok := doc(Step{
		Tool:    "FileSystem",
		Args:    map[string]any{"mode": "write", "path": `C:\a`},
		Targets: []Target{{KindFile, `C:\a`, VerbWrite}},
	})
	if err := ok.Validate(); err != nil {
		t.Errorf("a covering declaration should validate: %v", err)
	}
}

func TestValidateRejectsBadVersionAndEmptyTool(t *testing.T) {
	if err := (Document{Version: 999}).Validate(); !errors.Is(err, ErrPlanVersion) {
		t.Error("an unsupported version should be rejected")
	}
	if err := doc(Step{Tool: ""}).Validate(); err == nil {
		t.Error("a step with no tool should be rejected")
	}
}

func TestDestructiveAndUndeclarableFlags(t *testing.T) {
	read := Step{Tool: "FileSystem", Args: map[string]any{"mode": "read", "path": `C:\a`}}
	if read.Destructive() {
		t.Error("a read step is not destructive")
	}
	del := Step{Tool: "FileSystem", Args: map[string]any{"mode": "delete", "path": `C:\a`}}
	if !del.Destructive() {
		t.Error("a delete step is destructive")
	}
	shell := Step{Tool: "PowerShell", Args: map[string]any{"command": "x"}}
	if !shell.Undeclarable() || !shell.Destructive() {
		t.Error("a shell step is undeclarable and treated as destructive")
	}
}
