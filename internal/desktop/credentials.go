//go:build windows && (amd64 || arm64)

// Credential Manager integration.
//
// Credentials supplied to the server at init are installed into the Windows
// Credential Manager for the *calling user's* credential set, so anything running
// in that user context (browsers, RDP, mapped drives, Windows SSO, or a launched
// line-of-business app) can consume them the normal way.
//
// The plaintext secret is confined to this file. It is read back from the
// Credential Manager only inside InjectCredential, converted straight to
// keystrokes, and the intermediate buffers are zeroed. No function here returns a
// secret to a caller, so a secret can never reach a tool result, the audit log, or
// the model's context.
//
// wincred (CredRead/CredWrite/CredDelete) is a plain advapi32 API — not COM, and
// not thread-affine — so the store operations do not need the engine's STA thread.
// InjectCredential does run on it, because it synthesizes input.
package desktop

import (
	"errors"
	"fmt"
	"unicode/utf16"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security/credentials"
	km "github.com/deploymenttheory/go-bindings-win32/bindings/win32/ui/input/keyboardandmouse"
)

// credMaxBlobSize is CRED_MAX_CREDENTIAL_BLOB_SIZE (5 * 512). CredWrite rejects
// anything larger, so reject it here with a clear message instead.
const credMaxBlobSize = 5 * 512

// credMaxTargetNameLen is CRED_MAX_GENERIC_TARGET_NAME_LENGTH.
const credMaxTargetNameLen = 32767

var (
	// ErrCredentialNotFound reports a target absent from the Credential Manager.
	ErrCredentialNotFound = errors.New("credential not found")
	// ErrCredentialEmpty reports a stored credential with a zero-length secret.
	ErrCredentialEmpty = errors.New("credential has an empty secret")
	// ErrSecretTooLarge reports a secret over the Credential Manager blob limit.
	ErrSecretTooLarge = errors.New("secret exceeds the Credential Manager blob limit")
)

// CredentialType is the Credential Manager credential class.
type CredentialType string

const (
	// CredentialGeneric is CRED_TYPE_GENERIC: an application-defined credential,
	// the right class for app, web, and API secrets.
	CredentialGeneric CredentialType = "generic"
	// CredentialDomainPassword is CRED_TYPE_DOMAIN_PASSWORD, consumed by Windows
	// itself for network authentication (SSO, mapped drives, RDP). Windows will not
	// hand the blob back to a caller for this class — see InjectCredential.
	CredentialDomainPassword CredentialType = "domain_password"
)

// win32Type maps to the CRED_TYPE enum.
func (t CredentialType) win32Type() (credentials.CRED_TYPE, error) {
	switch t {
	case CredentialGeneric, "":
		return credentials.CRED_TYPE_GENERIC, nil
	case CredentialDomainPassword:
		return credentials.CRED_TYPE_DOMAIN_PASSWORD, nil
	default:
		return 0, fmt.Errorf("unknown credential type %q (want generic or domain_password)", t)
	}
}

// Readable reports whether Windows will return this class's secret to a caller.
// Only CRED_TYPE_GENERIC blobs are readable by the owning user; domain-password
// blobs are write-only by design, so they can be installed for Windows to use but
// never injected as keystrokes.
func (t CredentialType) Readable() bool {
	return t == CredentialGeneric || t == ""
}

// CredentialPersist controls how long Windows retains the credential.
type CredentialPersist string

const (
	// PersistSession drops the credential at logoff. The default.
	PersistSession CredentialPersist = "session"
	// PersistLocalMachine keeps it on this machine across logons.
	PersistLocalMachine CredentialPersist = "local_machine"
	// PersistEnterprise additionally roams with the profile.
	PersistEnterprise CredentialPersist = "enterprise"
)

func (p CredentialPersist) win32Persist() (credentials.CRED_PERSIST, error) {
	switch p {
	case PersistSession, "":
		return credentials.CRED_PERSIST_SESSION, nil
	case PersistLocalMachine:
		return credentials.CRED_PERSIST_LOCAL_MACHINE, nil
	case PersistEnterprise:
		return credentials.CRED_PERSIST_ENTERPRISE, nil
	default:
		return 0, fmt.Errorf("unknown persistence %q (want session, local_machine or enterprise)", p)
	}
}

// CredentialSpec is one credential to install.
//
// Secret is held as a byte slice rather than a string so the caller can zero it
// after installation; Go strings are immutable and cannot be wiped.
type CredentialSpec struct {
	// Name is the stable handle the agent uses to refer to this credential. It is
	// never the secret and is safe to log.
	Name string
	// Target is the Credential Manager target name (e.g. a host or URL).
	Target string
	// Username is stored alongside the secret; safe to log.
	Username string
	// Comment is an optional human-readable note stored on the credential.
	Comment string
	// Secret is the UTF-8 plaintext. Zeroed by the caller after WriteCredential.
	Secret  []byte
	Type    CredentialType
	Persist CredentialPersist
}

// CredentialInfo is the non-secret view of an installed credential — everything
// the Credentials tool is allowed to report.
type CredentialInfo struct {
	Name     string `json:"name"`
	Target   string `json:"target"`
	Username string `json:"username,omitempty"`
	Type     string `json:"type"`
	Persist  string `json:"persist"`
	Present  bool   `json:"present"`
	// Injectable is false for credential classes Windows will not read back.
	Injectable bool `json:"injectable"`
	// AllowUnmaskedTarget lets this credential be injected into a control that
	// does not report itself as masked. It defaults to false, so injection
	// normally requires a confirmed password field — see requireMaskedFocus. It is
	// an operator decision, declared per credential in the credentials document,
	// because it trades the never-read guarantee for reach into destinations that
	// cannot report IsPassword (a console window, some Electron and Java apps).
	AllowUnmaskedTarget bool `json:"allow_unmasked_target"`
}

// WriteCredential installs a credential into the calling user's credential set.
// The secret is copied into a UTF-16 blob, handed to CredWrite, and the blob is
// zeroed before returning.
func (d *Desktop) WriteCredential(spec CredentialSpec) error {
	if spec.Target == "" {
		return errors.New("credential target must not be empty")
	}
	if len(spec.Target) > credMaxTargetNameLen {
		return fmt.Errorf("credential target exceeds %d characters", credMaxTargetNameLen)
	}
	if len(spec.Secret) == 0 {
		return ErrCredentialEmpty
	}
	credType, err := spec.Type.win32Type()
	if err != nil {
		return err
	}
	persist, err := spec.Persist.win32Persist()
	if err != nil {
		return err
	}

	// The blob for these classes is the secret as UTF-16LE, without a terminator.
	blob := utf16Bytes(spec.Secret)
	defer zero(blob)
	if len(blob) > credMaxBlobSize {
		return fmt.Errorf("%w: %d bytes (limit %d)", ErrSecretTooLarge, len(blob), credMaxBlobSize)
	}

	cred := credentials.CREDENTIALW{
		Type:       credType,
		TargetName: foundation.PWSTR(win32.UTF16Ptr(spec.Target)),
		// Bounded by the credMaxBlobSize check above.
		CredentialBlobSize: uint32(len(blob)), //nolint:gosec // bounded above
		CredentialBlob:     &blob[0],
		Persist:            persist,
	}
	if spec.Username != "" {
		cred.UserName = foundation.PWSTR(win32.UTF16Ptr(spec.Username))
	}
	if spec.Comment != "" {
		cred.Comment = foundation.PWSTR(win32.UTF16Ptr(spec.Comment))
	}

	if err := credentials.CredWrite(&cred, 0); err != nil {
		return fmt.Errorf("CredWrite %q: %w", spec.Target, err)
	}
	return nil
}

// DeleteCredential removes a credential. A target that is already absent is not
// an error, so shutdown cleanup is idempotent.
func (d *Desktop) DeleteCredential(target string, t CredentialType) error {
	credType, err := t.win32Type()
	if err != nil {
		return err
	}
	if err := credentials.CredDelete(target, credType); err != nil {
		if present, perr := d.CredentialPresent(target, t); perr == nil && !present {
			return nil // already gone
		}
		return fmt.Errorf("CredDelete %q: %w", target, err)
	}
	return nil
}

// CredentialPresent reports whether a target exists in the credential set. The
// secret is read but never returned, and its buffer is released immediately.
func (d *Desktop) CredentialPresent(target string, t CredentialType) (bool, error) {
	credType, err := t.win32Type()
	if err != nil {
		return false, err
	}
	var cred *credentials.CREDENTIALW
	if err := credentials.CredRead(target, credType, &cred); err != nil {
		return false, nil //nolint:nilerr // absence is the common case, not a fault
	}
	credentials.CredFree(unsafe.Pointer(cred))
	return true, nil
}

// InjectCredential types a stored secret as keystrokes without ever returning it.
//
// If clickAt is non-nil the point is clicked first, so a caller can focus the
// password field in the same serialized operation — no window can steal focus
// between the click and the keystrokes.
//
// It returns the number of characters typed, which is safe to report: the length
// alone tells a caller the injection happened without disclosing the value.
func (d *Desktop) InjectCredential(target string, t CredentialType, clickAt *Point, allowUnmasked bool) (int, error) {
	if !t.Readable() {
		return 0, fmt.Errorf("credential type %q is write-only: Windows does not return its secret to callers, "+
			"so it can be installed for Windows to use but not injected as keystrokes", t)
	}
	credType, err := t.win32Type()
	if err != nil {
		return 0, err
	}

	if clickAt != nil && d.overlay != nil {
		d.overlay.flashClick(clickAt.X, clickAt.Y) // queued outside Do, as Click does
	}

	var typed int
	err = d.Do(func() error {
		if clickAt != nil {
			if err := leftClickAt(clickAt.X, clickAt.Y); err != nil {
				return err
			}
		}

		// The destination is checked here, on the STA thread, after the click and
		// immediately before the keystrokes — so what is verified is what receives
		// them. Doing it in the tool layer would leave a window in which focus moved.
		if !allowUnmasked {
			if err := requireMaskedFocus(d); err != nil {
				return err
			}
		}

		units, err := readSecretUnits(target, credType)
		if err != nil {
			return err
		}
		defer zeroUnits(units)

		for _, u := range units {
			if u == 0 {
				break // defensive: honour an embedded terminator
			}
			if err := sendInputs([]km.INPUT{unicodeKeyInput(u, false), unicodeKeyInput(u, true)}); err != nil {
				return err
			}
			typed++
		}
		return nil
	})
	return typed, err
}

// ErrInjectTargetNotMasked is returned when a credential injection cannot be
// confirmed to be landing in a control that masks its input. Callers match on it
// to distinguish a refused destination from an engine failure; the wrapped detail
// explains which of the checks could not be satisfied, and every message names
// the allow_unmasked_target remedy through injectRemedy.
var ErrInjectTargetNotMasked = errors.New("refusing to inject the credential")

// InjectRemedy names the documented escape hatch, for the tool layer to append to
// a refusal. It is not baked into each error so the sentinel's message stays
// short and the guidance appears exactly once.
func InjectRemedy() string { return injectRemedy }

const injectRemedy = ` Set "allow_unmasked_target": true on this credential if the destination ` +
	`genuinely cannot report a masked field (a console window, or some Electron and Java applications).`

// requireMaskedFocus fails unless the focused element masks its input.
// STA-thread only; call it inside the same Do job that types the secret.
//
// The guarantee this protects is that the agent may *use* a secret but never
// *read* one. Without it, the agent chose where the keystrokes landed: open
// Notepad, click into it, inject, then read the plaintext straight back out with
// Screenshot, GetText, or the clipboard. The credential engine never returns a
// secret, so the destination is the whole of the remaining exposure.
//
// It fails closed. "Cannot tell" is not "not a password": if UIA is unavailable,
// reports no focused element, or does not support the property, the secret is not
// typed. A caller with a legitimate destination that cannot report IsPassword —
// a console window, some Electron and Java apps, a field with "show password"
// toggled — declares allow_unmasked_target on that credential, which makes the
// exception explicit, per-credential, and visible in the credentials document.
func requireMaskedFocus(d *Desktop) error {
	if d.uia == nil || d.uia.automation == nil {
		return fmt.Errorf("%w: UI Automation is unavailable, so the destination cannot be confirmed "+
			"to be a password field", ErrInjectTargetNotMasked)
	}
	el, err := d.uia.automation.GetFocusedElement()
	if err != nil {
		return fmt.Errorf("%w: could not read the focused element, so the destination cannot be "+
			"confirmed to be a password field (%v)", ErrInjectTargetNotMasked, err)
	}
	if el == nil {
		return fmt.Errorf("%w: nothing is focused, so there is no confirmed password field to receive "+
			"the secret — click the field first, or pass a target", ErrInjectTargetNotMasked)
	}
	defer el.Release()

	masked, err := el.Get_CurrentIsPassword()
	if err != nil {
		return fmt.Errorf("%w: the focused element does not report whether it masks input (%w)",
			ErrInjectTargetNotMasked, err)
	}
	if !boolVal(masked) {
		return fmt.Errorf("%w: the focused element is not a password field, and typing a secret into "+
			"an unmasked control would put it on screen and in reach of Screenshot, GetText and the "+
			"clipboard", ErrInjectTargetNotMasked)
	}
	return nil
}

// Point is a screen coordinate in physical pixels.
type Point struct{ X, Y int }

// readSecretUnits reads a stored secret and returns it as UTF-16 code units the
// caller owns (and must zero). This is the exact payload InjectCredential converts
// to keystrokes, factored out so it can be tested against a real store round-trip
// without synthesizing input into whatever window happens to have focus.
//
// It never returns a string: a string could not be wiped, and would be one
// refactor away from reaching a caller.
func readSecretUnits(target string, credType credentials.CRED_TYPE) ([]uint16, error) {
	var cred *credentials.CREDENTIALW
	if err := credentials.CredRead(target, credType, &cred); err != nil {
		return nil, fmt.Errorf("%w: %q", ErrCredentialNotFound, target)
	}
	defer credentials.CredFree(unsafe.Pointer(cred))

	if cred.CredentialBlobSize == 0 || cred.CredentialBlob == nil {
		return nil, fmt.Errorf("%w: %q", ErrCredentialEmpty, target)
	}
	// Copy out of the Windows allocation, which CredFree releases on return.
	return utf16UnitsFromBlob(cred.CredentialBlob, cred.CredentialBlobSize), nil
}

// utf16Bytes re-encodes UTF-8 plaintext as a UTF-16LE byte blob.
func utf16Bytes(secret []byte) []byte {
	units := utf16.Encode([]rune(string(secret)))
	out := make([]byte, len(units)*2)
	for i, u := range units {
		// Truncation is the operation: low byte then high byte, little-endian.
		out[i*2] = byte(u)        //nolint:gosec // deliberate UTF-16LE split
		out[i*2+1] = byte(u >> 8) //nolint:gosec // deliberate UTF-16LE split
	}
	return out
}

// utf16UnitsFromBlob copies a CredentialBlob into a UTF-16 code-unit slice we own.
func utf16UnitsFromBlob(blob *byte, size uint32) []uint16 {
	raw := unsafe.Slice(blob, size)
	units := make([]uint16, size/2)
	for i := range units {
		units[i] = uint16(raw[i*2]) | uint16(raw[i*2+1])<<8
	}
	return units
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func zeroUnits(u []uint16) {
	for i := range u {
		u[i] = 0
	}
}
