//go:build windows && (amd64 || arm64)

package signals

import (
	"unsafe"

	win32 "github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/remotedesktop"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/threading"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/windowsprogramming"
)

// DetectRunContext inspects the current process token and session to determine
// whether the server runs as SYSTEM vs an interactive user, its session, and
// whether it is elevated.
func DetectRunContext() RunContext {
	var rc RunContext

	var sess uint32
	if err := remotedesktop.ProcessIdToSessionId(threading.GetCurrentProcessId(), &sess); err == nil {
		rc.SessionID = sess
	}

	var token foundation.HANDLE
	if err := threading.OpenProcessToken(threading.GetCurrentProcess(), security.TOKEN_QUERY, &token); err == nil {
		defer func() { _ = foundation.CloseHandle(token) }()
		rc.IsSystem = tokenIsSystem(token)
		rc.Elevated = tokenIsElevated(token)
	} else {
		// Record that the fields below are unset rather than answered. Leaving
		// IsSystem false here used to read as "not SYSTEM", which passed the check.
		rc.TokenUnread = true
	}

	rc.User = currentUserName()
	return rc
}

// tokenInfo reads a token information class into a byte buffer (two-call
// pattern: probe length, then fill).
func tokenInfo(token foundation.HANDLE, class security.TOKEN_INFORMATION_CLASS) []byte {
	var n uint32
	_ = security.GetTokenInformation(token, class, nil, &n) // expected to fail, sets n
	if n == 0 {
		return nil
	}
	buf := make([]byte, n)
	if err := security.GetTokenInformation(token, class, buf, &n); err != nil {
		return nil
	}
	return buf
}

func tokenIsSystem(token foundation.HANDLE) bool {
	buf := tokenInfo(token, security.TokenUser)
	if buf == nil {
		return false
	}
	tu := (*security.TOKEN_USER)(unsafe.Pointer(&buf[0]))
	return security.IsWellKnownSid(tu.User.Sid, security.WinLocalSystemSid)
}

func tokenIsElevated(token foundation.HANDLE) bool {
	buf := tokenInfo(token, security.TokenElevation)
	if buf == nil {
		return false
	}
	te := (*security.TOKEN_ELEVATION)(unsafe.Pointer(&buf[0]))
	return te.TokenIsElevated != 0
}

func currentUserName() string {
	const capacity = 256 // UNLEN+1 is 257; GetUserName truncates beyond it
	buf := make([]uint16, capacity)
	n := uint32(capacity)
	if err := windowsprogramming.GetUserName(foundation.PWSTR(&buf[0]), &n); err != nil {
		return ""
	}
	return win32.UTF16ToString(&buf[0])
}
