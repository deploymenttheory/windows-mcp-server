//go:build windows && (amd64 || arm64)

package desktop

import (
	win32 "github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
)

// bstrToString converts a BSTR to a Go string and frees the BSTR. Pass a BSTR
// received from a COM out-param; do not use the BSTR afterwards.
func bstrToString(bstr foundation.BSTR) string {
	if bstr == nil {
		return ""
	}
	s := win32.UTF16ToString(bstr)
	foundation.SysFreeString(bstr)
	return s
}

// boolVal reports whether a Win32 BOOL is true (non-zero).
func boolVal(b foundation.BOOL) bool { return b != 0 }
