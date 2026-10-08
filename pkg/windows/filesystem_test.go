//go:build windows && (amd64 || arm64)

package windows

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/mcp-server-core/toolkit"
)

// protect builds a ProtectedPath matched the Windows way.
func protect(path, label string, tree, denyRead, denyWrite bool) toolkit.ProtectedPath {
	return toolkit.NewProtectedPath(NormalizePath, path, label, tree, denyRead, denyWrite)
}

func TestFileSystemRefusesProtectedPaths(t *testing.T) {
	creds := `C:\secrets\creds.json`
	auditDir := `C:\ProgramData\windows-mcp\audit\`
	deps := NewBaseDeps(nil, nil, nil)
	deps.WithProtectedPaths([]toolkit.ProtectedPath{
		protect(creds, "the credentials file", false, true, true),
		protect(auditDir, "the audit log", true, false, true),
	})
	fs := FileSystem()

	// The credentials file is refused for read (a read is plaintext into context)
	// and for write, before any disk access.
	for _, mode := range []string{"read", "write"} {
		res := callTool(t, fs, deps, map[string]any{"mode": mode, "path": creds, "content": "x"})
		if !res.IsError || !strings.Contains(resultText(res), "credentials file") {
			t.Errorf("%s of the credentials file should be refused: isErr=%v text=%q",
				mode, res.IsError, resultText(res))
		}
	}

	// An audit session file is readable but not writable/deletable.
	auditFile := auditDir + `session-x.audit.jsonl`
	if res := callTool(t, fs, deps, map[string]any{"mode": "delete", "path": auditFile}); !res.IsError ||
		!strings.Contains(resultText(res), "audit log") {
		t.Errorf("delete of an audit file should be refused: %q", resultText(res))
	}
}

// TestFileSystemAllowsUnprotectedPaths confirms the guard does not block ordinary
// work: a write to an unrelated path succeeds.
func TestFileSystemAllowsUnprotectedPaths(t *testing.T) {
	deps := NewBaseDeps(nil, nil, nil)
	deps.WithProtectedPaths([]toolkit.ProtectedPath{
		protect(`C:\secrets\creds.json`, "the credentials file", false, true, true),
	})
	fs := FileSystem()

	target := filepath.Join(t.TempDir(), "note.txt")
	res := callTool(t, fs, deps, map[string]any{"mode": "write", "path": target, "content": "hello"})
	if res.IsError {
		t.Fatalf("write to an unprotected path should succeed: %q", resultText(res))
	}
	if got, _ := os.ReadFile(target); string(got) != "hello" {
		t.Errorf("file content = %q, want hello", got)
	}
}
