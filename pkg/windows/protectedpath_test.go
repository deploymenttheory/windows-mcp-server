//go:build windows && (amd64 || arm64)

package windows

import "testing"

// TestProtectedPathFoldsWindowsSpellings is a regression test for the ways one
// file could be reached under a name the guard did not recognise.
//
// Matching was strings.ToLower(filepath.Clean(...)), which leaves the
// extended-length prefix in place, keeps an explicit data stream, and preserves
// trailing dots and spaces that Windows strips when opening. Each was a way to
// truncate the audit log or read the credentials file straight past the check.
func TestProtectedPathFoldsWindowsSpellings(t *testing.T) {
	const target = `C:\ProgramData\windows-mcp\audit\session.jsonl`
	p := protect(target, "the audit log", false, true, true)

	equivalent := []string{
		target,
		`c:\programdata\windows-mcp\audit\session.jsonl`,        // case
		`\\?\C:\ProgramData\windows-mcp\audit\session.jsonl`,     // extended-length prefix
		`C:\ProgramData\windows-mcp\audit\session.jsonl::$DATA`, // default data stream
		`C:\ProgramData\windows-mcp\audit\session.jsonl.`,       // trailing dot
		`C:\ProgramData\windows-mcp\audit\session.jsonl `,       // trailing space
		`C:\ProgramData\windows-mcp\.\audit\session.jsonl`,      // uncleaned
		`C:\ProgramData\windows-mcp\other\..\audit\session.jsonl`,
	}
	for _, spelling := range equivalent {
		if !p.Covers(NormalizePath(spelling)) {
			t.Errorf("%s reaches the protected file but is not covered", spelling)
		}
	}

	different := []string{
		`C:\ProgramData\windows-mcp\audit\other.jsonl`,
		`C:\ProgramData\windows-mcp\audit\session.jsonl.bak`,
		`C:\ProgramData\windows-mcp\audit`,
	}
	for _, other := range different {
		if p.Covers(NormalizePath(other)) {
			t.Errorf("%s is a different file and must not be covered", other)
		}
	}
}

// TestProtectedTreeFoldsSpellings covers the directory form, which is how the
// kill-switch control directory and a directory audit destination are protected.
func TestProtectedTreeFoldsSpellings(t *testing.T) {
	p := protect(`C:\ProgramData\windows-mcp\control`, "the control directory", true, true, true)

	inside := []string{
		`C:\ProgramData\windows-mcp\control\kill`,
		`\\?\C:\ProgramData\windows-mcp\control\kill`,
		`C:\ProgramData\windows-mcp\control\nested\deep\file`,
		`C:\ProgramData\windows-mcp\control`,
	}
	for _, path := range inside {
		if !p.Covers(NormalizePath(path)) {
			t.Errorf("%s is inside the protected tree but is not covered", path)
		}
	}
	if p.Covers(NormalizePath(`C:\ProgramData\windows-mcp\controlled\file`)) {
		t.Error("a sibling whose name merely shares a prefix must not be covered")
	}
}
