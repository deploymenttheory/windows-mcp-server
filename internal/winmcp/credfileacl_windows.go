//go:build windows && (amd64 || arm64)

package winmcp

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ErrCredentialsFileBroadlyReadable reports a credentials file whose DACL grants
// read access to a broad group rather than only to specific principals.
var ErrCredentialsFileBroadlyReadable = errors.New("credentials file is readable by a broad group")

// readAccessMask is the set of rights that would let a principal read the file's
// contents: the specific right, the generic read/all bits that subsume it, and
// STANDARD_RIGHTS_ALL as carried by a full-control ACE.
const readAccessMask = windows.FILE_READ_DATA |
	windows.GENERIC_READ |
	windows.GENERIC_ALL |
	windows.FILE_GENERIC_READ

// broadSIDs are the well-known groups that effectively mean "other users on this
// machine". A credentials file granting any of them read access is treated as
// disclosed.
//
// Checking the real DACL matters because the Unix permission bits Go reports on
// Windows are synthesized from the read-only attribute — every normal file reports
// 0666 — so a mode-based check is simultaneously useless and, if enforced,
// impossible to satisfy.
var broadSIDs = []struct {
	kind windows.WELL_KNOWN_SID_TYPE
	name string
}{
	{windows.WinWorldSid, "Everyone"},
	{windows.WinBuiltinUsersSid, "BUILTIN\\Users"},
	{windows.WinAuthenticatedUserSid, "NT AUTHORITY\\Authenticated Users"},
	{windows.WinInteractiveSid, "NT AUTHORITY\\INTERACTIVE"},
}

// checkCredentialsFileACL fails when the file's DACL grants read access to a broad
// group. It returns nil when the DACL is absent or NULL, which means the object has
// no discretionary protection to evaluate — reported by the caller as a warning
// rather than silently accepted.
func checkCredentialsFileACL(path string) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read credentials file security descriptor: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read credentials file DACL: %w", err)
	}
	if dacl == nil {
		// A NULL DACL grants everyone full control.
		return fmt.Errorf("%w: %q has a NULL DACL (everyone has full control)",
			ErrCredentialsFileBroadlyReadable, path)
	}

	offenders, err := broadReaders(dacl)
	if err != nil {
		return err
	}
	if len(offenders) > 0 {
		return fmt.Errorf("%w: %q grants read to %s; restrict it, e.g.\n"+
			"    icacls %q /inheritance:r /grant:r \"%%USERNAME%%:R\"",
			ErrCredentialsFileBroadlyReadable, path, strings.Join(offenders, ", "), path)
	}
	return nil
}

// broadReaders walks the DACL and returns the names of any broad groups granted
// read access by an allow ACE.
//
// x/sys/windows exposes no GetAce wrapper, so the ACE array is walked directly:
// ACEs follow the ACL header contiguously, each self-describing its size.
func broadReaders(dacl *windows.ACL) ([]string, error) {
	known := make([]*windows.SID, 0, len(broadSIDs))
	for _, b := range broadSIDs {
		sid, err := windows.CreateWellKnownSid(b.kind)
		if err != nil {
			return nil, fmt.Errorf("create well-known SID %s: %w", b.name, err)
		}
		known = append(known, sid)
	}

	var offenders []string
	seen := map[string]bool{}
	cursor := unsafe.Pointer(uintptr(unsafe.Pointer(dacl)) + unsafe.Sizeof(*dacl))

	for i := 0; i < int(dacl.AceCount); i++ {
		header := (*windows.ACE_HEADER)(cursor)
		if header.AceSize == 0 {
			break // malformed; refuse to spin
		}
		if header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE {
			ace := (*windows.ACCESS_ALLOWED_ACE)(cursor)
			if uint32(ace.Mask)&readAccessMask != 0 {
				sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
				for j, k := range known {
					if sid.Equals(k) && !seen[broadSIDs[j].name] {
						seen[broadSIDs[j].name] = true
						offenders = append(offenders, broadSIDs[j].name)
					}
				}
			}
		}
		cursor = unsafe.Pointer(uintptr(cursor) + uintptr(header.AceSize))
	}
	return offenders, nil
}
