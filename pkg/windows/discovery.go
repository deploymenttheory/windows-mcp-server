//go:build windows && (amd64 || arm64)

package windows

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	winapi "golang.org/x/sys/windows"

	"github.com/deploymenttheory/windows-mcp-server/internal/desktop"
	"github.com/deploymenttheory/windows-mcp-server/pkg/inventory"
)

const (
	maxIndexedSearchResults     = 100
	defaultIndexedSearchResults = 25
	indexedSearchTimeout        = 15 * time.Second
	defaultOverviewEntries      = 10
	maxOverviewEntries          = 50
)

// indexedSearchItem is deliberately limited to metadata. FileSearch never
// reads file contents; it asks Windows Search for indexed name/path metadata.
type indexedSearchItem struct {
	Path     string `json:"path"`
	Kind     string `json:"kind"`
	Size     *int64 `json:"size"`
	Modified string `json:"modified"`
}

// FileSearch searches the Windows Search SystemIndex for file and folder names.
// It is separate from FileSystem so read-only inventories can expose indexed
// discovery without exposing the mutating filesystem tool.
func FileSearch() inventory.ServerTool {
	destructive, openWorld := false, false
	return NewToolFromHandler(
		ToolsetFilesystem,
		mcp.Tool{
			Name: "FileSearch",
			Description: "Search the local Windows Search index for file and folder names without reading or changing contents. " +
				"Results are metadata from the index and may lag the live filesystem. " +
				"The optional scope is a local folder; relative paths resolve against the user's Desktop.",
			Annotations: &mcp.ToolAnnotations{
				Title:           "Indexed file and folder search",
				ReadOnlyHint:    true,
				DestructiveHint: &destructive,
				OpenWorldHint:   &openWorld,
			},
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"query": {Type: "string", Description: "Text substring to match against indexed item names."},
					"scope": {Type: "string", Description: "Optional local folder scope. Relative paths resolve against Desktop."},
					"kind":  {Type: "string", Enum: []any{"all", "file", "folder"}, Description: "Return files, folders, or both (default: all)."},
					"limit": {Type: "integer", Description: "Maximum results, capped at 100 (default: 25)."},
				},
				Required: []string{"query"},
			},
		},
		func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args, err := ArgsMap(req)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			query, err := RequiredString(args, "query")
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			kind, err := OptionalStringEnum(args, "kind", "all", "all", "file", "folder")
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			limit, err := OptionalInt(args, "limit", defaultIndexedSearchResults)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			if limit < 1 {
				return NewToolResultError("parameter limit must be at least 1"), nil
			}
			limit = clampInt(limit, 1, maxIndexedSearchResults)

			scopePath := ""
			scopeURI := "file:"
			if scope := strings.TrimSpace(OptionalString(args, "scope", "")); scope != "" {
				scopePath, err = resolveLocalFolder(scope)
				if err != nil {
					return NewToolResultError(err.Error()), nil
				}
				if r := checkProtected(deps, scopePath, false); r != nil {
					return r, nil
				}
				scopeURI = searchScopeURI(scopePath)
			}

			sql, err := buildWindowsSearchSQL(query, scopeURI, kind, limit)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			items, err := runIndexedSearch(ctx, deps.Desktop(), sql)
			if err != nil {
				return NewToolResultErrorFromErr("Windows Search failed", err), nil
			}
			visible := items[:0]
			for _, item := range items {
				if item.Path != "" && isProtectedRead(deps, item.Path) {
					continue
				}
				visible = append(visible, item)
			}
			return NewToolResultText(renderIndexedSearch(query, scopePath, kind, visible)), nil
		},
	)
}

// FolderOverview reports drive capacity and immediate directory entries. It
// intentionally does not recursively walk folders or calculate recursive size.
func FolderOverview() inventory.ServerTool {
	destructive, openWorld := false, false
	return NewToolFromHandler(
		ToolsetFilesystem,
		mcp.Tool{
			Name: "FolderOverview",
			Description: "Return a compact read-only overview of a local folder or all local drives: capacity when available, " +
				"immediate file/folder counts, and a bounded child sample. It does not recursively walk or modify anything.",
			Annotations: &mcp.ToolAnnotations{
				Title:           "Folder and drive overview",
				ReadOnlyHint:    true,
				DestructiveHint: &destructive,
				OpenWorldHint:   &openWorld,
			},
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"path":        {Type: "string", Description: "Optional local folder or drive. Relative paths resolve against Desktop; omitted means all local drives."},
					"max_entries": {Type: "integer", Description: "Maximum child names shown per folder, capped at 50 (default: 10)."},
				},
			},
		},
		func(_ context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args, err := ArgsMap(req)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			maxEntries, err := OptionalInt(args, "max_entries", defaultOverviewEntries)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			if maxEntries < 1 {
				return NewToolResultError("parameter max_entries must be at least 1"), nil
			}
			maxEntries = clampInt(maxEntries, 1, maxOverviewEntries)

			rawPath := strings.TrimSpace(OptionalString(args, "path", ""))
			if rawPath != "" {
				path, err := resolveLocalFolder(rawPath)
				if err != nil {
					return NewToolResultError(err.Error()), nil
				}
				if r := checkProtected(deps, path, false); r != nil {
					return r, nil
				}
				overview, err := folderOverviewForPath(path, maxEntries)
				if err != nil {
					return NewToolResultErrorFromErr("folder overview failed", err), nil
				}
				return NewToolResultText(renderFolderOverviews([]folderOverview{overview})), nil
			}

			paths, err := logicalDrivePaths()
			if err != nil {
				return NewToolResultErrorFromErr("logical drive enumeration failed", err), nil
			}
			overviews := make([]folderOverview, 0, len(paths))
			for _, path := range paths {
				overview, overviewErr := folderOverviewForPath(path, maxEntries)
				if overviewErr == nil {
					overviews = append(overviews, overview)
				}
			}
			if len(overviews) == 0 {
				return NewToolResultError("no accessible local drives"), nil
			}
			return NewToolResultText(renderFolderOverviews(overviews)), nil
		},
	)
}

func resolveLocalFolder(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if len(raw) == 2 && raw[1] == ':' {
		raw += string(filepath.Separator)
	}
	path, err := resolvePath(raw)
	if err != nil {
		return "", err
	}
	if isUNCPath(path) {
		return "", fmt.Errorf("UNC paths are not supported by local discovery tools")
	}
	driveType, err := driveTypeForPath(path)
	if err != nil {
		return "", err
	}
	if driveType == winapi.DRIVE_REMOTE {
		return "", fmt.Errorf("network-mapped drives are not supported by local discovery tools")
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("folder does not exist: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("scope must be a folder")
	}
	return filepath.Clean(path), nil
}

func isUNCPath(path string) bool {
	return strings.HasPrefix(path, `\\`) || strings.HasPrefix(path, `//`)
}

func searchScopeURI(path string) string {
	return "file:" + filepath.ToSlash(filepath.Clean(path))
}

func sqlLiteral(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}

func buildWindowsSearchSQL(query, scopeURI, kind string, limit int) (string, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return "", fmt.Errorf("query is required")
	}
	for _, r := range query {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("query contains unsupported control characters")
		}
	}
	if scopeURI == "" {
		scopeURI = "file:"
	}
	if limit < 1 {
		return "", fmt.Errorf("limit must be at least 1")
	}
	limit = clampInt(limit, 1, maxIndexedSearchResults)

	var kindPredicate string
	switch kind {
	case "all":
	case "file":
		kindPredicate = " AND System.ItemType <> 'Directory'"
	case "folder":
		kindPredicate = " AND System.ItemType = 'Directory'"
	default:
		return "", fmt.Errorf("kind must be one of all, file, folder")
	}

	// LIKE is supported for the indexed System.ItemName property and gives the
	// discovery tool substring semantics. Escape LIKE metacharacters so a caller
	// searching for a literal percent or underscore does not broaden the query.
	pattern := `%` + escapeWindowsSearchLike(query) + `%`
	nameMatch := `System.ItemName LIKE '` + sqlLiteral(pattern) + `'`
	return fmt.Sprintf(
		"SELECT TOP %d System.ItemPathDisplay, System.ItemType, System.Size, System.DateModified FROM SystemIndex WHERE SCOPE='%s' AND %s%s ORDER BY System.Search.Rank DESC, System.ItemPathDisplay ASC",
		limit, sqlLiteral(scopeURI), nameMatch, kindPredicate,
	), nil
}

func escapeWindowsSearchLike(value string) string {
	var b strings.Builder
	for _, r := range value {
		switch r {
		case '%':
			b.WriteString("[%]")
		case '_':
			b.WriteString("[_]")
		case '[':
			b.WriteString("[[]")
		case ']':
			b.WriteString("[]]")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func indexedSearchScript(sql string) string {
	var ps PSScript
	sqlValue := ps.Arg(sql)
	return ps.Script(`$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$connection = New-Object System.Data.OleDb.OleDbConnection
$connection.ConnectionString = "Provider=Search.CollatorDSO.1;Extended Properties='Application=Windows';"
$connection.Open()
try {
  $command = $connection.CreateCommand()
  $command.CommandText = ` + sqlValue + `
  $reader = $command.ExecuteReader()
  $items = @()
  $pathOrdinal = $reader.GetOrdinal('System.ItemPathDisplay')
  $typeOrdinal = $reader.GetOrdinal('System.ItemType')
  $sizeOrdinal = $reader.GetOrdinal('System.Size')
  $modifiedOrdinal = $reader.GetOrdinal('System.DateModified')
  try {
    while ($reader.Read()) {
      if ($reader.IsDBNull($pathOrdinal)) { continue }
      $pathValue = [string]$reader.GetValue($pathOrdinal)
      if ([string]::IsNullOrWhiteSpace($pathValue)) { continue }
      $typeValue = ''
      if (-not $reader.IsDBNull($typeOrdinal)) { $typeValue = [string]$reader.GetValue($typeOrdinal) }
      $kindValue = 'file'
      if ($typeValue -eq 'Directory') { $kindValue = 'folder' }
      $sizeValue = $null
      if (-not $reader.IsDBNull($sizeOrdinal)) { $sizeValue = [int64]$reader.GetValue($sizeOrdinal) }
      $modifiedValue = $null
      if (-not $reader.IsDBNull($modifiedOrdinal)) { $modifiedValue = ([datetime]$reader.GetValue($modifiedOrdinal)).ToString('o', [Globalization.CultureInfo]::InvariantCulture) }
      $items += [pscustomobject]@{ path = $pathValue; kind = $kindValue; size = $sizeValue; modified = $modifiedValue }
    }
  } finally {
    $reader.Close()
  }
} finally {
  $connection.Close()
}
ConvertTo-Json -InputObject $items -Compress`)
}

func runIndexedSearch(ctx context.Context, dsk *desktop.Desktop, sql string) ([]indexedSearchItem, error) {
	if dsk == nil {
		return nil, fmt.Errorf("desktop engine is unavailable")
	}
	result, err := dsk.RunWindowsPowerShell(ctx, indexedSearchScript(sql), indexedSearchTimeout)
	if err != nil {
		return nil, err
	}
	if result.TimedOut {
		return nil, fmt.Errorf("query timed out after %s", indexedSearchTimeout)
	}
	if result.ExitCode != 0 {
		return nil, fmt.Errorf("query process exited %d: %s", result.ExitCode, trimOutput(result.Output))
	}
	return parseIndexedSearchOutput(result.Output)
}

func parseIndexedSearchOutput(output string) ([]indexedSearchItem, error) {
	lines := strings.Split(output, "\n")
	var lastErr error
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(strings.TrimPrefix(lines[i], "\ufeff"))
		if line == "" || !strings.HasPrefix(line, "[") {
			continue
		}
		var items []indexedSearchItem
		if err := json.Unmarshal([]byte(line), &items); err != nil {
			lastErr = err
			continue
		}
		return items, nil
	}
	if lastErr != nil {
		return nil, fmt.Errorf("invalid Windows Search JSON: %w", lastErr)
	}
	return nil, fmt.Errorf("Windows Search returned no JSON result")
}

func isProtectedRead(deps ToolDependencies, path string) bool {
	checker, ok := deps.(protectedPathChecker)
	if !ok {
		return false
	}
	_, denied := checker.ProtectedPathViolation(path, false)
	return denied
}

func renderIndexedSearch(query, scope, kind string, items []indexedSearchItem) string {
	if len(items) == 0 {
		where := "all local indexed locations"
		if scope != "" {
			where = scope
		}
		return fmt.Sprintf("No indexed %s matching %q under %s.", kindLabel(kind), query, where)
	}
	where := "all local indexed locations"
	if scope != "" {
		where = scope
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Indexed %s search for %q under %s (%d result(s); index may lag the filesystem):\n", kindLabel(kind), query, where, len(items))
	for _, item := range items {
		fmt.Fprintf(&b, "  [%s] %s", item.Kind, item.Path)
		if item.Size != nil && *item.Size >= 0 {
			fmt.Fprintf(&b, " — %s", formatDiscoveryBytes(uint64(*item.Size)))
		}
		if item.Modified != "" {
			fmt.Fprintf(&b, " — modified %s", item.Modified)
		}
		b.WriteByte('\n')
	}
	return strings.TrimSuffix(b.String(), "\n")
}

func kindLabel(kind string) string {
	switch kind {
	case "file":
		return "file"
	case "folder":
		return "folder"
	default:
		return "file/folder"
	}
}

type folderOverview struct {
	path         string
	fileCount    int
	folderCount  int
	entries      []folderOverviewEntry
	totalBytes   uint64
	freeBytes    uint64
	hasDiskSpace bool
}

type folderOverviewEntry struct {
	name string
	kind string
	size int64
}

func logicalDrivePaths() ([]string, error) {
	mask, err := winapi.GetLogicalDrives()
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, 4)
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) != 0 {
			path := fmt.Sprintf("%c:%c", 'A'+i, filepath.Separator)
			driveType, typeErr := driveTypeForPath(path)
			if typeErr == nil && driveType != winapi.DRIVE_REMOTE {
				paths = append(paths, path)
			}
		}
	}
	return paths, nil
}

func driveTypeForPath(path string) (uint32, error) {
	volume := filepath.VolumeName(path)
	if volume == "" {
		return 0, fmt.Errorf("path has no local volume")
	}
	root, err := winapi.UTF16PtrFromString(volume + string(filepath.Separator))
	if err != nil {
		return 0, err
	}
	driveType := winapi.GetDriveType(root)
	if driveType == winapi.DRIVE_UNKNOWN {
		return 0, fmt.Errorf("unable to determine drive type for %s", path)
	}
	return driveType, nil
}

func folderOverviewForPath(path string, maxEntries int) (folderOverview, error) {
	info, err := os.Stat(path)
	if err != nil {
		return folderOverview{}, err
	}
	if !info.IsDir() {
		return folderOverview{}, fmt.Errorf("path is not a folder")
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return folderOverview{}, err
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IsDir() != entries[j].IsDir() {
			return entries[i].IsDir()
		}
		return entries[i].Name() < entries[j].Name()
	})
	overview := folderOverview{path: filepath.Clean(path)}
	for _, entry := range entries {
		if entry.IsDir() {
			overview.folderCount++
		} else {
			overview.fileCount++
		}
		if len(overview.entries) >= maxEntries {
			continue
		}
		entryInfo, infoErr := entry.Info()
		size := int64(0)
		if infoErr == nil && !entry.IsDir() {
			size = entryInfo.Size()
		}
		kind := "file"
		if entry.IsDir() {
			kind = "folder"
		}
		overview.entries = append(overview.entries, folderOverviewEntry{name: entry.Name(), kind: kind, size: size})
	}
	if total, free, spaceErr := diskSpaceForPath(path); spaceErr == nil {
		overview.totalBytes, overview.freeBytes, overview.hasDiskSpace = total, free, true
	}
	return overview, nil
}

func diskSpaceForPath(path string) (uint64, uint64, error) {
	volume := filepath.VolumeName(path)
	if volume == "" {
		return 0, 0, fmt.Errorf("path has no local volume")
	}
	root, err := winapi.UTF16PtrFromString(volume + string(filepath.Separator))
	if err != nil {
		return 0, 0, err
	}
	var free, total, totalFree uint64
	if err := winapi.GetDiskFreeSpaceEx(root, &free, &total, &totalFree); err != nil {
		return 0, 0, err
	}
	return total, free, nil
}

func renderFolderOverviews(overviews []folderOverview) string {
	var b strings.Builder
	b.WriteString("Folder/drive overview (immediate entries only):\n")
	for _, overview := range overviews {
		fmt.Fprintf(&b, "\n%s\n", overview.path)
		if overview.hasDiskSpace {
			used := uint64(0)
			if overview.totalBytes >= overview.freeBytes {
				used = overview.totalBytes - overview.freeBytes
			}
			fmt.Fprintf(&b, "  Capacity: %s total, %s used, %s free\n",
				formatDiscoveryBytes(overview.totalBytes), formatDiscoveryBytes(used), formatDiscoveryBytes(overview.freeBytes))
		} else {
			b.WriteString("  Capacity: unavailable\n")
		}
		fmt.Fprintf(&b, "  Immediate entries: %d file(s), %d folder(s)\n", overview.fileCount, overview.folderCount)
		for _, entry := range overview.entries {
			if entry.kind == "folder" {
				fmt.Fprintf(&b, "  [folder] %q\n", entry.name)
			} else {
				fmt.Fprintf(&b, "  [file]   %q (%s)\n", entry.name, formatDiscoveryBytes(uint64(maxInt64(entry.size, 0))))
			}
		}
		remaining := overview.fileCount + overview.folderCount - len(overview.entries)
		if remaining > 0 {
			fmt.Fprintf(&b, "  ... %d more immediate entries\n", remaining)
		}
	}
	return strings.TrimSuffix(b.String(), "\n")
}

func maxInt64(value, fallback int64) int64 {
	if value < fallback {
		return fallback
	}
	return value
}

func formatDiscoveryBytes(bytes uint64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	}
	value := float64(bytes)
	units := []string{"KiB", "MiB", "GiB", "TiB", "PiB"}
	for _, unit := range units {
		value /= 1024
		if value < 1024 || unit == units[len(units)-1] {
			return fmt.Sprintf("%.1f %s", value, unit)
		}
	}
	return fmt.Sprintf("%d B", bytes)
}

func trimOutput(output string) string {
	output = strings.TrimSpace(output)
	if len(output) > 512 {
		return output[:512] + "..."
	}
	return output
}
