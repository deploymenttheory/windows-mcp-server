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
// It is an allowlist because the denylist it replaced named four groups —
// Everyone, Users, Authenticated Users, INTERACTIVE — and silently accepted every
// other trustee: "Domain Users:R", Guests, NETWORK, BATCH, Backup Operators, or
// any custom or domain group. docs/credentials.md presented the four as if they
// were the whole risk. An allowlist fails the right way when something
// unanticipated appears in the DACL.
var trustedSIDKinds = []windows.WELL_KNOWN_SID_TYPE{
	windows.WinLocalSystemSid,
	windows.WinBuiltinAdministratorsSid,
}

// accessAllowedCallbackACEType is ACCESS_ALLOWED_CALLBACK_ACE_TYPE. x/sys/windows
// does not export it, and it shares the leading layout of ACCESS_ALLOWED_ACE, so
// it is read the same way rather than skipped — an unrecognised allow ACE passing
// unexamined is the failure an allowlist exists to prevent.
const accessAllowedCallbackACEType = 9

// trustedSIDs resolves the allowlist, including the account this process runs as,
// which is not a well-known SID and has to come from the token.
func trustedSIDs() ([]*windows.SID, error) {
	out := make([]*windows.SID, 0, len(trustedSIDKinds)+1)
	for _, kind := range trustedSIDKinds {
		sid, err := windows.CreateWellKnownSid(kind)
		if err != nil {
			return nil, fmt.Errorf("create well-known SID: %w", err)
		}
		out = append(out, sid)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("read the current user SID: %w", err)
	}
	return append(out, user.User.Sid), nil
}

// isTrusted reports whether sid is on the allowlist.
func isTrusted(sid *windows.SID, trusted []*windows.SID) bool {
	for _, t := range trusted {
		if sid.Equals(t) {
			return true
		}
	}
	return false
}

// checkCredentialsFileACL fails when the file's DACL grants read access to a broad
// group. It returns nil when the DACL is absent or NULL, which means the object has
// no discretionary protection to evaluate — reported by the caller as a warning
// rather than silently accepted.
func checkCredentialsFileACL(path string) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read credentials file security descriptor: %w", err)
	}
	// Only the DACL used to be requested. The owner holds WRITE_DAC implicitly and
	// can grant themselves read whenever they like, so a restrictive-looking DACL
	// proves nothing about a file owned by an untrusted account.
	if err := checkCredentialsFileOwner(sd, path); err != nil {
		return err
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

	offenders, err := untrustedReaders(dacl)
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

// checkCredentialsFileOwner fails when the file is owned by an untrusted account.
func checkCredentialsFileOwner(sd *windows.SECURITY_DESCRIPTOR, path string) error {
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("read credentials file owner: %w", err)
	}
	trusted, err := trustedSIDs()
	if err != nil {
		return err
	}
	if isTrusted(owner, trusted) {
		return nil
	}
	return fmt.Errorf("%w: %q is owned by %s, which can grant itself read access at any time; "+
		"take ownership, e.g.\n    icacls %q /setowner \"%%USERNAME%%\"",
		ErrCredentialsFileBroadlyReadable, path, owner.String(), path)
}

// untrustedReaders walks the DACL and returns every trustee granted read access
// that is not on the allowlist.
//
// x/sys/windows exposes no GetAce wrapper, so the ACE array is walked directly:
// ACEs follow the ACL header contiguously, each self-describing its size.
func untrustedReaders(dacl *windows.ACL) ([]string, error) {
	trusted, err := trustedSIDs()
	if err != nil {
		return nil, err
	}

	var offenders []string
	seen := map[string]bool{}
	cursor := unsafe.Pointer(uintptr(unsafe.Pointer(dacl)) + unsafe.Sizeof(*dacl))

	for i := 0; i < int(dacl.AceCount); i++ {
		header := (*windows.ACE_HEADER)(cursor)
		if header.AceSize == 0 {
			break // malformed; refuse to spin
		}
		if header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE ||
			header.AceType == accessAllowedCallbackACEType {
			ace := (*windows.ACCESS_ALLOWED_ACE)(cursor)
			if uint32(ace.Mask)&readAccessMask != 0 {
				sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
				if name := sid.String(); !isTrusted(sid, trusted) && !seen[name] {
					seen[name] = true
					offenders = append(offenders, describeSID(sid))
				}
			}
		}
		cursor = unsafe.Pointer(uintptr(cursor) + uintptr(header.AceSize))
	}
	return offenders, nil
}

// describeSID renders a SID for an operator: an account name where Windows can
// resolve one, and the SID string either way so the message is actionable even
// when the trustee is an orphaned or remote principal.
func describeSID(sid *windows.SID) string {
	account, domain, _, err := sid.LookupAccount("")
	if err != nil {
		return sid.String()
	}
	if domain != "" {
		return domain + "\\" + account + " (" + sid.String() + ")"
	}
	return account + " (" + sid.String() + ")"
}
