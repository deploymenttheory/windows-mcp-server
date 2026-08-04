//go:build windows && (amd64 || arm64)

package windows

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/windows-mcp-server/pkg/inventory"
)

// maxFileReadBytes caps how much a single read returns.
const maxFileReadBytes = 1 << 20 // 1 MiB

// protectedPathChecker is the optional capability the FileSystem tool uses to
// refuse touching a guardrail path (the audit log, the credentials file, the
// policy document). BaseDeps implements it; a fake that does not is simply
// unrestricted, which is correct for tests that never install guardrail paths.
type protectedPathChecker interface {
	ProtectedPathViolation(absPath string, write bool) (reason string, denied bool)
}

// checkProtected returns a tool error result when deps protects absPath against
// the requested access, or nil to proceed.
func checkProtected(deps ToolDependencies, absPath string, write bool) *mcp.CallToolResult {
	pc, ok := deps.(protectedPathChecker)
	if !ok {
		return nil
	}
	if reason, denied := pc.ProtectedPathViolation(absPath, write); denied {
		return NewToolResultError(reason)
	}
	return nil
}

// resolvePath resolves a possibly-relative path against the user's Desktop
// folder (matching the Python implementation's convention).
func resolvePath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("path is required")
	}
	if filepath.IsAbs(path) {
		return filepath.Clean(path), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot resolve home directory: %w", err)
	}
	return filepath.Join(home, "Desktop", path), nil
}

// FileSystem reads, writes, and manages files. Relative paths resolve against
// the user's Desktop.
func FileSystem() inventory.ServerTool {
	destructive, openWorld := true, true
	return NewToolFromHandler(
		ToolsetFilesystem,
		mcp.Tool{
			Name: "FileSystem",
			Description: "Read, write, copy, move, delete, list, search, and stat files and directories. " +
				"Relative paths resolve against the user's Desktop. Modes: read, write, copy, move, delete, list, search, info.",
			Annotations: &mcp.ToolAnnotations{
				Title:           "File system operations",
				ReadOnlyHint:    false,
				DestructiveHint: &destructive,
				// Open-world: a UNC path reads from or writes to another host, which is
				// network egress outside the proxy and the allowlist.
				OpenWorldHint: &openWorld,
			},
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"mode":        {Type: "string", Enum: []any{"read", "write", "copy", "move", "delete", "list", "search", "info"}, Description: "Operation."},
					"path":        {Type: "string", Description: "Target path (relative to Desktop unless absolute)."},
					"destination": {Type: "string", Description: "Destination path (copy/move)."},
					"content":     {Type: "string", Description: "Content to write (write mode)."},
					"append":      {Type: "boolean", Description: "Append instead of overwrite (write mode)."},
					"pattern":     {Type: "string", Description: "Glob pattern (search mode), e.g. *.txt."},
					"recursive":   {Type: "boolean", Description: "Recurse into subdirectories (search mode)."},
				},
				Required: []string{"mode", "path"},
			},
		},
		func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args, err := ArgsMap(req)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			mode, err := OptionalStringEnum(args, "mode", "", "read", "write", "copy", "move", "delete", "list", "search", "info")
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			path, err := RequiredString(args, "path")
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			abs, err := resolvePath(path)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}

			switch mode {
			case "read":
				if r := checkProtected(deps, abs, false); r != nil {
					return r, nil
				}
				return fsRead(abs)
			case "write":
				if r := checkProtected(deps, abs, true); r != nil {
					return r, nil
				}
				return fsWrite(abs, OptionalString(args, "content", ""), OptionalBool(args, "append", false))
			case "list":
				if r := checkProtected(deps, abs, false); r != nil {
					return r, nil
				}
				return fsList(abs)
			case "info":
				if r := checkProtected(deps, abs, false); r != nil {
					return r, nil
				}
				return fsInfo(abs)
			case "delete":
				if r := checkProtected(deps, abs, true); r != nil {
					return r, nil
				}
				return fsDelete(abs)
			case "copy", "move":
				dest := OptionalString(args, "destination", "")
				if dest == "" {
					return NewToolResultError("destination is required"), nil
				}
				absDest, err := resolvePath(dest)
				if err != nil {
					return NewToolResultError(err.Error()), nil
				}
				// A move removes the source, so the source is a write; a copy only
				// reads it. The destination is always written.
				if r := checkProtected(deps, abs, mode == "move"); r != nil {
					return r, nil
				}
				if r := checkProtected(deps, absDest, true); r != nil {
					return r, nil
				}
				return fsCopyMove(abs, absDest, mode == "move")
			case "search":
				if r := checkProtected(deps, abs, false); r != nil {
					return r, nil
				}
				return fsSearch(abs, OptionalString(args, "pattern", "*"), OptionalBool(args, "recursive", false))
			default:
				return NewToolResultError("invalid mode"), nil
			}
		},
	)
}

func fsRead(path string) (*mcp.CallToolResult, error) {
	info, err := os.Stat(path)
	if err != nil {
		return NewToolResultErrorFromErr("stat failed", err), nil
	}
	if info.IsDir() {
		return NewToolResultError("path is a directory; use mode=list"), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return NewToolResultErrorFromErr("read failed", err), nil
	}
	truncated := false
	if len(data) > maxFileReadBytes {
		data = data[:maxFileReadBytes]
		truncated = true
	}
	out := string(data)
	if truncated {
		out += fmt.Sprintf("\n\n[truncated at %d bytes]", maxFileReadBytes)
	}
	return NewToolResultText(out), nil
}

func fsWrite(path, content string, appendMode bool) (*mcp.CallToolResult, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return NewToolResultErrorFromErr("failed to create parent directory", err), nil
	}
	flag := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	verb := "Wrote"
	if appendMode {
		flag = os.O_CREATE | os.O_WRONLY | os.O_APPEND
		verb = "Appended to"
	}
	f, err := os.OpenFile(path, flag, 0o644)
	if err != nil {
		return NewToolResultErrorFromErr("open failed", err), nil
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(content); err != nil {
		return NewToolResultErrorFromErr("write failed", err), nil
	}
	return NewToolResultTextf("%s %s (%d bytes).", verb, path, len(content)), nil
}

func fsList(path string) (*mcp.CallToolResult, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return NewToolResultErrorFromErr("list failed", err), nil
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IsDir() != entries[j].IsDir() {
			return entries[i].IsDir()
		}
		return entries[i].Name() < entries[j].Name()
	})
	var b strings.Builder
	fmt.Fprintf(&b, "%s (%d entries):\n", path, len(entries))
	for _, e := range entries {
		info, _ := e.Info()
		kind := "file"
		size := int64(0)
		if e.IsDir() {
			kind = "dir "
		} else if info != nil {
			size = info.Size()
		}
		fmt.Fprintf(&b, "  [%s] %-40s %10d\n", kind, e.Name(), size)
	}
	return NewToolResultText(b.String()), nil
}

func fsInfo(path string) (*mcp.CallToolResult, error) {
	info, err := os.Stat(path)
	if err != nil {
		return NewToolResultErrorFromErr("stat failed", err), nil
	}
	kind := "file"
	if info.IsDir() {
		kind = "directory"
	}
	return NewToolResultTextf("Path: %s\nType: %s\nSize: %d bytes\nModified: %s\nMode: %s",
		path, kind, info.Size(), info.ModTime().Format("2006-01-02 15:04:05"), info.Mode()), nil
}

func fsDelete(path string) (*mcp.CallToolResult, error) {
	if err := os.RemoveAll(path); err != nil {
		return NewToolResultErrorFromErr("delete failed", err), nil
	}
	return NewToolResultTextf("Deleted %s.", path), nil
}

func fsCopyMove(src, dest string, move bool) (*mcp.CallToolResult, error) {
	if move {
		if err := os.Rename(src, dest); err != nil {
			return NewToolResultErrorFromErr("move failed", err), nil
		}
		return NewToolResultTextf("Moved %s -> %s.", src, dest), nil
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return NewToolResultErrorFromErr("copy read failed", err), nil
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return NewToolResultErrorFromErr("copy mkdir failed", err), nil
	}
	if err := os.WriteFile(dest, data, 0o644); err != nil {
		return NewToolResultErrorFromErr("copy write failed", err), nil
	}
	return NewToolResultTextf("Copied %s -> %s (%d bytes).", src, dest, len(data)), nil
}

func fsSearch(root, pattern string, recursive bool) (*mcp.CallToolResult, error) {
	var matches []string
	walk := func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() {
			if !recursive && p != root {
				return fs.SkipDir
			}
			return nil
		}
		if ok, _ := filepath.Match(pattern, d.Name()); ok {
			matches = append(matches, p)
		}
		return nil
	}
	if err := filepath.WalkDir(root, walk); err != nil {
		return NewToolResultErrorFromErr("search failed", err), nil
	}
	if len(matches) == 0 {
		return NewToolResultTextf("No files matching %q under %s.", pattern, root), nil
	}
	return NewToolResultTextf("%d match(es) for %q:\n%s", len(matches), pattern, strings.Join(matches, "\n")), nil
}
