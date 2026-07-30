//go:build windows && (amd64 || arm64)

package windows

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/windows-mcp-server/internal/desktop"
	"github.com/deploymenttheory/windows-mcp-server/pkg/inventory"
)

// fakeDeps is a ToolDependencies stand-in, usable ONLY for handler paths that
// return before touching the desktop engine.
//
// A nil Desktop() is NOT a safety net. Several engine methods never dereference
// their receiver — LaunchApp shells out via RunPowerShell, which only builds an
// exec.Cmd — so a handler that reaches the engine with a nil *Desktop will really
// launch the application rather than panic. Only assert on paths that are blocked
// before the engine call; test the allow side against the gate helpers directly.
type fakeDeps struct {
	enforceHTTPS bool
	creds        []desktop.CredentialInfo
}

func (f fakeDeps) Desktop() *desktop.Desktop                     { return nil }
func (f fakeDeps) Logger(context.Context) *slog.Logger           { return slog.Default() }
func (f fakeDeps) IsFeatureEnabled(context.Context, string) bool { return false }
func (f fakeDeps) Credentials() []desktop.CredentialInfo         { return f.creds }
func (f fakeDeps) EnforceHTTPS() bool                            { return f.enforceHTTPS }

// compile-time assertion that the fake keeps up with the interface
var _ ToolDependencies = fakeDeps{}

// callTool invokes a tool's handler directly with the given arguments.
func callTool(t *testing.T, st inventory.ServerTool, deps ToolDependencies, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: st.Tool.Name, Arguments: raw}}
	// Handler takes deps, but the context-based constructors ignore that argument
	// and read deps from the context — which is the real injection path.
	res, err := st.Handler(deps)(ContextWithDeps(context.Background(), deps), req)
	if err != nil {
		t.Fatalf("handler returned a Go error (reserved for infrastructure failure): %v", err)
	}
	return res
}

func resultText(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

// TestAppLaunchBlocksPlaintextURL is the App-launch half of Enforce HTTPS.
// `Start-Process http://example.com` hands the URL to the default browser, so a
// URL-shaped app name is a navigation and has to be gated.
func TestAppLaunchBlocksPlaintextURL(t *testing.T) {
	app := App()
	deps := fakeDeps{enforceHTTPS: true}

	for _, name := range []string{
		"http://example.com",
		"HTTP://example.com/path",
	} {
		res := callTool(t, app, deps, map[string]any{"mode": "launch", "name": name})
		if !res.IsError {
			t.Errorf("launch %q should be blocked", name)
			continue
		}
		text := resultText(res)
		if !strings.Contains(text, "Enforce HTTPS") {
			t.Errorf("blocked message should name the setting, got %q", text)
		}
		if !strings.Contains(text, "https://") {
			t.Errorf("blocked message should tell the model to retry over https, got %q", text)
		}
	}
}

// TestAppLaunchGateDecision covers the allow side of the App-launch gate without
// invoking the handler.
//
// The handler cannot be used here: anything the gate permits goes on to
// Start-Process and really launches an application (an earlier version of this
// test opened a browser tab). So the decision the handler makes is asserted
// against the same two helpers it composes.
func TestAppLaunchGateDecision(t *testing.T) {
	// blocked mirrors the condition in App()'s launch branch.
	blocked := func(name string, enforce bool) bool {
		scheme, isURL := urlSchemeIfURL(name)
		return isURL && scheme == "http" && enforce
	}

	for _, tc := range []struct {
		name    string
		enforce bool
		want    bool
	}{
		{"http://example.com", true, true},   // plaintext + enforcing = blocked
		{"HTTP://example.com", true, true},   // case-insensitive
		{"https://example.com", true, false}, // https passes the gate
		{"http://example.com", false, false}, // setting off = unchanged behaviour
		{"notepad", true, false},             // ordinary app name is not a URL
		{"msedge", true, false},
		{"C:\\Windows\\System32\\notepad.exe", true, false},
	} {
		if got := blocked(tc.name, tc.enforce); got != tc.want {
			t.Errorf("blocked(%q, enforce=%t) = %t, want %t", tc.name, tc.enforce, got, tc.want)
		}
	}
}

func TestEnforceHTTPSSchemeIsErrorsIsMatchable(t *testing.T) {
	err := validateScrapeURL("http://example.com", true)
	if !errors.Is(err, ErrPlaintextHTTP) {
		t.Errorf("want ErrPlaintextHTTP, got %v", err)
	}
}
