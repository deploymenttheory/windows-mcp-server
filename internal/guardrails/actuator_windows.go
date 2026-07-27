//go:build windows && (amd64 || arm64)

package guardrails

import (
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/diagnostics/toolhelp"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/shutdown"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/threading"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/ui/shell"
)

// winActuator is the Windows SystemActuator. All actions are best-effort; the
// elevation-gated ones (isolate/kill/shutdown) are only invoked by the kill
// executor when Elevated() is true.
type winActuator struct{ logger *slog.Logger }

// NewSystemActuator returns the Windows SystemActuator.
func NewSystemActuator(logger *slog.Logger) SystemActuator {
	if logger == nil {
		logger = slog.Default()
	}
	return winActuator{logger: logger}
}

// Elevated reports whether the process holds an elevated token.
func (winActuator) Elevated() bool { return DetectRunContext().Elevated }

// IsolateNetwork blocks all non-loopback traffic via the Windows Firewall and
// returns a restore func. Loopback is exempt from the firewall by default, so
// the loopback status endpoint survives isolation.
func (winActuator) IsolateNetwork() (func() error, error) { return firewallIsolate() }

// KillProcesses terminates every running process whose image name matches one
// of names (case-insensitive, e.g. "powershell.exe").
func (a winActuator) KillProcesses(names []string) []error {
	if len(names) == 0 {
		return nil
	}
	want := make(map[string]bool, len(names))
	for _, n := range names {
		want[strings.ToLower(n)] = true
	}
	snap, err := toolhelp.CreateToolhelp32Snapshot(toolhelp.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return []error{fmt.Errorf("snapshot: %w", err)}
	}
	defer foundation.CloseHandle(snap)

	var pe toolhelp.PROCESSENTRY32
	pe.DwSize = uint32(unsafe.Sizeof(pe))
	if err := toolhelp.Process32First(snap, &pe); err != nil {
		return []error{fmt.Errorf("process32first: %w", err)}
	}
	var errs []error
	for {
		if want[strings.ToLower(charsToString(pe.SzExeFile[:]))] {
			h, err := threading.OpenProcess(threading.PROCESS_TERMINATE, false, pe.Th32ProcessID)
			if err != nil {
				errs = append(errs, fmt.Errorf("open pid %d: %w", pe.Th32ProcessID, err))
			} else {
				if err := threading.TerminateProcess(h, 1); err != nil {
					errs = append(errs, fmt.Errorf("terminate pid %d: %w", pe.Th32ProcessID, err))
				}
				foundation.CloseHandle(h)
			}
		}
		if err := toolhelp.Process32Next(snap, &pe); err != nil {
			break // ERROR_NO_MORE_FILES
		}
	}
	return errs
}

// LockWorkstation locks the interactive session (no elevation required).
func (winActuator) LockWorkstation() error { return shutdown.LockWorkStation() }

// Shutdown initiates a forced shutdown after delay, enabling SeShutdownPrivilege
// first. Requires elevation.
func (winActuator) Shutdown(reason string, delay time.Duration) error {
	if err := enableShutdownPrivilege(); err != nil {
		return fmt.Errorf("enable shutdown privilege: %w", err)
	}
	secs := uint32(delay / time.Second)
	msg := "Windows MCP security kill switch: " + reason
	return shutdown.InitiateSystemShutdownEx("", msg, secs, true /*force*/, false, /*reboot*/
		shutdown.SHTDN_REASON_MAJOR_OTHER|shutdown.SHTDN_REASON_MINOR_OTHER|shutdown.SHTDN_REASON_FLAG_PLANNED)
}

// enableShutdownPrivilege grants SeShutdownPrivilege to the current process token.
func enableShutdownPrivilege() error {
	var tok foundation.HANDLE
	if err := threading.OpenProcessToken(threading.GetCurrentProcess(),
		security.TOKEN_ADJUST_PRIVILEGES|security.TOKEN_QUERY, &tok); err != nil {
		return err
	}
	defer foundation.CloseHandle(tok)

	var luid foundation.LUID
	if err := security.LookupPrivilegeValue("", security.SE_SHUTDOWN_NAME, &luid); err != nil {
		return err
	}
	tp := security.TOKEN_PRIVILEGES{PrivilegeCount: 1}
	tp.Privileges[0] = security.LUID_AND_ATTRIBUTES{Luid: luid, Attributes: security.SE_PRIVILEGE_ENABLED}
	return security.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil)
}

// charsToString converts a NUL-terminated Win32 CHAR array to a Go string.
func charsToString(b []foundation.CHAR) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		out = append(out, byte(c))
	}
	return string(out)
}

// CurrentUserIsAdmin reports local-Administrators membership (used by the
// not-admin pre-flight check via the systemProbe adapter).
func CurrentUserIsAdmin() bool { return shell.IsUserAnAdmin() }
