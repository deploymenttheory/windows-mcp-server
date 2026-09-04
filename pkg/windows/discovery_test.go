//go:build windows && (amd64 || arm64)

package windows

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/deploymenttheory/windows-mcp-server/internal/desktop"
	"github.com/deploymenttheory/windows-mcp-server/pkg/inventory"
)

func TestDiscoveryToolsAreReadOnly(t *testing.T) {
	for _, tool := range []inventory.ServerTool{FileSearch(), FolderOverview()} {
		if !tool.IsReadOnly() {
			t.Errorf("%s must be annotated read-only", tool.Tool.Name)
		}
		if annotations := tool.Tool.Annotations; annotations != nil && annotations.DestructiveHint != nil && *annotations.DestructiveHint {
			t.Errorf("%s must not be annotated destructive", tool.Tool.Name)
		}
	}
}

func TestReadOnlyFilesystemInventoryIncludesDiscovery(t *testing.T) {
	inv, err := NewInventory().
		WithToolsets([]string{"filesystem"}).
		WithReadOnly(true).
		Build()
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]bool{}
	for _, tool := range inv.AvailableTools(t.Context()) {
		got[tool.Tool.Name] = true
	}
	for _, name := range []string{"FileSearch", "FolderOverview"} {
		if !got[name] {
			t.Errorf("read-only filesystem inventory is missing %s", name)
		}
	}
	if got["FileSystem"] {
		t.Error("read-only filesystem inventory must not expose the mutating FileSystem tool")
	}
}

func TestFileSearchSchema(t *testing.T) {
	schema, ok := FileSearch().Tool.InputSchema.(*jsonschema.Schema)
	if !ok || schema == nil {
		t.Fatal("FileSearch schema is not *jsonschema.Schema")
	}
	if len(schema.Required) != 1 || schema.Required[0] != "query" {
		t.Fatalf("FileSearch required = %v, want [query]", schema.Required)
	}
	if got := schema.Properties["kind"].Enum; len(got) != 3 {
		t.Fatalf("FileSearch kind enum = %v, want all/file/folder", got)
	}
	if schema.Properties["limit"] == nil || schema.Properties["scope"] == nil {
		t.Fatal("FileSearch schema must expose scope and limit")
	}
}

func TestFileSearchRejectsEmptyQueryBeforeDesktopAccess(t *testing.T) {
	res := callTool(t, FileSearch(), NewBaseDeps(nil, nil, nil), map[string]any{"query": ""})
	if !res.IsError || !strings.Contains(resultText(res), "required parameter query is empty") {
		t.Fatalf("empty query result = isError:%v text:%q", res.IsError, resultText(res))
	}
}

func TestDiscoveryRejectsUNCPaths(t *testing.T) {
	deps := NewBaseDeps(nil, nil, nil)
	for _, tool := range []inventory.ServerTool{FileSearch(), FolderOverview()} {
		args := map[string]any{"path": `\\server\share`}
		if tool.Tool.Name == "FileSearch" {
			delete(args, "path")
			args["scope"] = `\\server\share`
			args["query"] = "report"
		}
		res := callTool(t, tool, deps, args)
		if !res.IsError || !strings.Contains(resultText(res), "UNC paths") {
			t.Errorf("%s UNC result = isError:%v text:%q", tool.Tool.Name, res.IsError, resultText(res))
		}
	}
}

func TestBuildWindowsSearchSQLIsBoundedAndEscaped(t *testing.T) {
	sql, err := buildWindowsSearchSQL(`O'Brien; DROP TABLE`, `file:C:/Users/Ivan/Documents`, "file", maxIndexedSearchResults+1)
	if err != nil {
		t.Fatal(err)
	}
	checks := []string{
		"SELECT TOP 100",
		`SCOPE='file:C:/Users/Ivan/Documents'`,
		`System.ItemName LIKE '%O''Brien; DROP TABLE%'`,
		"System.ItemType <> 'Directory'",
		"ORDER BY System.Search.Rank DESC",
	}
	for _, want := range checks {
		if !strings.Contains(sql, want) {
			t.Errorf("SQL missing %q:\n%s", want, sql)
		}
	}
}

func TestIndexedSearchScriptBindsSQLAsData(t *testing.T) {
	sql := `SELECT TOP 1 System.ItemPathDisplay FROM SystemIndex WHERE CONTAINS(System.ItemName, '"x"')`
	script := indexedSearchScript(sql)
	if strings.Contains(script, sql) {
		t.Error("indexed search SQL must not be interpolated into PowerShell source")
	}
	if !strings.Contains(script, "FromBase64String") || !strings.Contains(script, "$wmcpA0") {
		t.Errorf("indexed search script is missing a data binding:\n%s", script)
	}
}

func TestParseIndexedSearchOutputSkipsPowerShellStartupNoise(t *testing.T) {
	items, err := parseIndexedSearchOutput(`#< CLIXML
<Objs Version="1.1.0.1"></Objs>
[{"path":"C:\\Users\\Ivan\\Desktop\\report.txt","kind":"file","size":12,"modified":"2026-09-05T00:00:00Z"}]`)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Path != `C:\Users\Ivan\Desktop\report.txt` || items[0].Size == nil || *items[0].Size != 12 {
		t.Fatalf("parsed items = %+v", items)
	}
}

func TestFolderOverviewReportsImmediateChildren(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "one.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "subdir"), 0o755); err != nil {
		t.Fatal(err)
	}

	res := callTool(t, FolderOverview(), NewBaseDeps(nil, nil, nil), map[string]any{
		"path":        root,
		"max_entries": 5,
	})
	if res.IsError {
		t.Fatalf("FolderOverview failed: %q", resultText(res))
	}
	text := resultText(res)
	for _, want := range []string{"Immediate entries", "1 file(s)", "1 folder(s)", "one.txt", "subdir"} {
		if !strings.Contains(text, want) {
			t.Errorf("FolderOverview output missing %q:\n%s", want, text)
		}
	}
}

func TestFormatDiscoveryBytes(t *testing.T) {
	for _, tc := range []struct {
		bytes uint64
		want  string
	}{
		{0, "0 B"},
		{1024, "1.0 KiB"},
		{1024 * 1024, "1.0 MiB"},
	} {
		if got := formatDiscoveryBytes(tc.bytes); got != tc.want {
			t.Errorf("formatDiscoveryBytes(%d) = %q, want %q", tc.bytes, got, tc.want)
		}
	}
}

func TestIndexedSearchProvider(t *testing.T) {
	if os.Getenv("WINDOWS_MCP_RUN_INTEGRATION") != "1" {
		t.Skip("set WINDOWS_MCP_RUN_INTEGRATION=1 to query the live Windows Search provider")
	}
	dsk, err := desktop.New(nil, desktop.Options{})
	if err != nil {
		t.Skipf("desktop engine unavailable: %v", err)
	}
	defer dsk.Close()

	sql, err := buildWindowsSearchSQL("Desktop", `file:C:/Users/ivang`, "all", 5)
	if err != nil {
		t.Fatal(err)
	}
	items, err := runIndexedSearch(context.Background(), dsk, sql)
	if err != nil {
		t.Fatalf("live Windows Search query failed: %v", err)
	}
	if len(items) == 0 {
		t.Log("Windows Search provider is available but returned no indexed Desktop matches")
	}
	res := callTool(t, FileSearch(), NewBaseDeps(dsk, nil, nil), map[string]any{
		"query": "Desktop",
		"scope": `C:\Users\ivang`,
		"limit": 5,
	})
	if res.IsError {
		t.Fatalf("FileSearch handler failed against live provider: %q", resultText(res))
	}
}
