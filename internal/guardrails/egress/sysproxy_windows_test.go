//go:build windows && (amd64 || arm64)

package egress

import (
	"os"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/registry"
)

// The WinINET settings are per-user and need no elevation, but writing them
// still changes how every browser on the machine reaches the network. That is
// worth an explicit opt-in even though it is far less drastic than the firewall
// work:
//
//	set WINDOWS_MCP_SYSPROXY_TEST=1
//	go test ./internal/guardrails/egress/ -run TestSystemProxy -v -count=1
//
// The test restores whatever it found, including restoring "the value was not
// there" by deleting rather than blanking.
const sysProxyTestEnv = "WINDOWS_MCP_SYSPROXY_TEST"

func requireSysProxyOptIn(t *testing.T) {
	t.Helper()
	if strings.ToLower(strings.TrimSpace(os.Getenv(sysProxyTestEnv))) != "1" {
		t.Skipf("set %s=1 to run the tests that change this user's WinINET proxy settings", sysProxyTestEnv)
	}
}

func readProxyValues(t *testing.T) (enable uint32, hadEnable bool, server string, hadServer bool) {
	t.Helper()
	key, closeKey, err := openInternetSettings(registry.KEY_QUERY_VALUE)
	if err != nil {
		t.Fatalf("open WinINET settings: %v", err)
	}
	defer closeKey()
	enable, hadEnable = queryDWord(key, "ProxyEnable")
	server, hadServer = queryString(key, "ProxyServer")
	return
}

// TestSystemProxyRoundTrips is the honesty check on the restore path: whatever
// the user had before must be exactly what they have after, including the
// difference between an absent value and an empty one.
func TestSystemProxyRoundTrips(t *testing.T) {
	requireSysProxyOptIn(t)

	beforeEnable, hadEnable, beforeServer, hadServer := readProxyValues(t)
	t.Logf("before: ProxyEnable=%d (present=%v) ProxyServer=%q (present=%v)",
		beforeEnable, hadEnable, beforeServer, hadServer)

	saved, err := setSystemProxy("127.0.0.1:18199")
	if err != nil {
		t.Fatalf("setSystemProxy: %v", err)
	}
	// Registered immediately: from here on the user's settings are ours, and
	// they must go back however this test exits.
	t.Cleanup(func() {
		if err := restoreSystemProxy(saved); err != nil {
			t.Errorf("EMERGENCY: could not restore WinINET proxy settings: %v", err)
		}
	})

	gotEnable, _, gotServer, _ := readProxyValues(t)
	if gotEnable != 1 {
		t.Errorf("ProxyEnable = %d, want 1", gotEnable)
	}
	if gotServer != "127.0.0.1:18199" {
		t.Errorf("ProxyServer = %q, want the proxy address", gotServer)
	}

	if err := restoreSystemProxy(saved); err != nil {
		t.Fatalf("restoreSystemProxy: %v", err)
	}
	afterEnable, afterHadEnable, afterServer, afterHadServer := readProxyValues(t)
	if afterHadEnable != hadEnable || (hadEnable && afterEnable != beforeEnable) {
		t.Errorf("ProxyEnable = %d (present=%v) after restore, want %d (present=%v)",
			afterEnable, afterHadEnable, beforeEnable, hadEnable)
	}
	if afterHadServer != hadServer || (hadServer && afterServer != beforeServer) {
		t.Errorf("ProxyServer = %q (present=%v) after restore, want %q (present=%v)",
			afterServer, afterHadServer, beforeServer, hadServer)
	}
	t.Log("WinINET settings restored exactly as found")
}

// TestRestoreSystemProxyOnNilIsANoOp covers the path taken when the policy
// never asked for system proxy settings.
func TestRestoreSystemProxyOnNilIsANoOp(t *testing.T) {
	if err := restoreSystemProxy(nil); err != nil {
		t.Errorf("restoring nil settings should do nothing: %v", err)
	}
}
