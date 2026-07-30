//go:build windows && (amd64 || arm64)

package desktop

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf16"
)

// testTarget is namespaced so a stray failure cannot collide with a real
// credential in the developer's store.
const testTarget = "windows-mcp-server/test/credentials_test"

func TestCredentialTypeMapping(t *testing.T) {
	for _, tc := range []struct {
		in         CredentialType
		wantErr    bool
		injectable bool
	}{
		{CredentialGeneric, false, true},
		{"", false, true}, // empty defaults to generic
		{CredentialDomainPassword, false, false},
		{"nonsense", true, false},
	} {
		_, err := tc.in.win32Type()
		if (err != nil) != tc.wantErr {
			t.Errorf("%q: err = %v, wantErr %t", tc.in, err, tc.wantErr)
		}
		if got := tc.in.Readable(); got != tc.injectable {
			t.Errorf("%q: Readable() = %t, want %t", tc.in, got, tc.injectable)
		}
	}
}

func TestCredentialPersistMapping(t *testing.T) {
	for _, p := range []CredentialPersist{PersistSession, "", PersistLocalMachine, PersistEnterprise} {
		if _, err := p.win32Persist(); err != nil {
			t.Errorf("%q should map cleanly: %v", p, err)
		}
	}
	if _, err := CredentialPersist("forever").win32Persist(); err == nil {
		t.Error("unknown persistence should error")
	}
}

// TestUTF16BlobRoundTrip covers the encode/decode pair that carries the secret
// into and back out of the Credential Manager blob, including non-BMP runes
// (which occupy two UTF-16 code units) and characters outside ASCII.
func TestUTF16BlobRoundTrip(t *testing.T) {
	for _, secret := range []string{
		"hunter2",
		"pä$$wörd-with-ünïcode",
		"emoji-\U0001F510-key", // surrogate pair
		strings.Repeat("x", 200),
	} {
		blob := utf16Bytes([]byte(secret))
		units := utf16UnitsFromBlobBytes(blob)
		if got := string(utf16.Decode(units)); got != secret {
			t.Errorf("round trip: got %q, want %q", got, secret)
		}
	}
}

// utf16UnitsFromBlobBytes mirrors utf16UnitsFromBlob for a Go-owned slice, so the
// round trip can be tested without a Windows allocation.
func utf16UnitsFromBlobBytes(blob []byte) []uint16 {
	if len(blob) == 0 {
		return nil
	}
	return utf16UnitsFromBlob(&blob[0], uint32(len(blob)))
}

func TestZeroWipesBuffers(t *testing.T) {
	b := []byte("secret")
	zero(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d not zeroed: %d", i, v)
		}
	}
	u := []uint16{1, 2, 3}
	zeroUnits(u)
	for i, v := range u {
		if v != 0 {
			t.Fatalf("unit %d not zeroed: %d", i, v)
		}
	}
}

func TestWriteCredentialValidates(t *testing.T) {
	d := &Desktop{} // no engine needed: these paths reject before any syscall

	if err := d.WriteCredential(CredentialSpec{Secret: []byte("x")}); err == nil {
		t.Error("empty target must be rejected")
	}
	if err := d.WriteCredential(CredentialSpec{Target: "t"}); !errors.Is(err, ErrCredentialEmpty) {
		t.Errorf("empty secret should be ErrCredentialEmpty, got %v", err)
	}
	big := CredentialSpec{Target: "t", Secret: []byte(strings.Repeat("a", credMaxBlobSize))}
	if err := d.WriteCredential(big); !errors.Is(err, ErrSecretTooLarge) {
		t.Errorf("oversized secret should be ErrSecretTooLarge, got %v", err)
	}
	bad := CredentialSpec{Target: "t", Secret: []byte("x"), Type: "nope"}
	if err := d.WriteCredential(bad); err == nil {
		t.Error("unknown credential type must be rejected")
	}
}

// TestInjectRejectsWriteOnlyType guards the invariant that a domain-password
// credential is never attempted as keystrokes: Windows will not return its blob,
// so the caller gets a clear explanation rather than an opaque CredRead failure.
// It must reject before touching the engine, hence the zero-value Desktop.
func TestInjectRejectsWriteOnlyType(t *testing.T) {
	d := &Desktop{}
	n, err := d.InjectCredential("anything", CredentialDomainPassword, nil)
	if err == nil {
		t.Fatal("domain_password injection must be refused")
	}
	if n != 0 {
		t.Errorf("nothing should be typed, got %d", n)
	}
	if !strings.Contains(err.Error(), "write-only") {
		t.Errorf("error should explain why: %v", err)
	}
}

// TestCredentialRoundTrip exercises the real Windows Credential Manager in the
// current user's credential set: write, confirm presence, delete, confirm
// absence, and confirm delete is idempotent. Generic credentials need no
// elevation. It always cleans up after itself.
func TestCredentialRoundTrip(t *testing.T) {
	d := &Desktop{}

	present, err := d.CredentialPresent(testTarget, CredentialGeneric)
	if err != nil {
		t.Fatalf("presence check failed: %v", err)
	}
	if present {
		t.Skip("test target already exists in the credential store; refusing to clobber it")
	}

	spec := CredentialSpec{
		Name:     "roundtrip",
		Target:   testTarget,
		Username: "tester@example.invalid",
		Comment:  "windows-mcp-server unit test; safe to delete",
		Secret:   []byte("pä$$wörd"),
		Type:     CredentialGeneric,
		Persist:  PersistSession,
	}
	if err := d.WriteCredential(spec); err != nil {
		t.Fatalf("WriteCredential: %v", err)
	}
	t.Cleanup(func() { _ = d.DeleteCredential(testTarget, CredentialGeneric) })

	present, err = d.CredentialPresent(testTarget, CredentialGeneric)
	if err != nil {
		t.Fatalf("presence check after write: %v", err)
	}
	if !present {
		t.Fatal("credential should be present after WriteCredential")
	}

	if err := d.DeleteCredential(testTarget, CredentialGeneric); err != nil {
		t.Fatalf("DeleteCredential: %v", err)
	}
	present, err = d.CredentialPresent(testTarget, CredentialGeneric)
	if err != nil {
		t.Fatalf("presence check after delete: %v", err)
	}
	if present {
		t.Error("credential should be absent after DeleteCredential")
	}

	// Cleanup runs on every shutdown path, so deleting an absent target must be a
	// no-op rather than an error.
	if err := d.DeleteCredential(testTarget, CredentialGeneric); err != nil {
		t.Errorf("delete of absent credential should be idempotent, got %v", err)
	}
}

// TestInjectionPayloadMatchesStoredSecret is the deterministic check on what
// InjectCredential would actually type. It writes a secret to the real Credential
// Manager, reads it back through the same code path injection uses, and asserts the
// UTF-16 code-unit sequence is exactly what the keystroke loop will emit — one
// keystroke pair per unit.
//
// This deliberately stops short of calling SendInput: synthesizing keystrokes in a
// test would type into whichever window happens to have focus. The delivery step
// itself is the same unicodeKeyInput/sendInputs path the Type tool uses.
func TestInjectionPayloadMatchesStoredSecret(t *testing.T) {
	d := &Desktop{}
	target := testTarget + "/payload"

	for _, secret := range []string{
		"tok_abcdef123456",
		"pä$$wörd!",
		"emoji-\U0001F510-key", // surrogate pair: two units, two keystrokes
	} {
		if err := d.WriteCredential(CredentialSpec{
			Target: target, Secret: []byte(secret), Type: CredentialGeneric, Persist: PersistSession,
		}); err != nil {
			t.Fatalf("WriteCredential(%q): %v", secret, err)
		}

		units, err := readSecretUnits(target, 1 /* CRED_TYPE_GENERIC */)
		if err != nil {
			t.Fatalf("readSecretUnits(%q): %v", secret, err)
		}
		want := utf16.Encode([]rune(secret))
		if len(units) != len(want) {
			t.Errorf("%q: %d code units, want %d", secret, len(units), len(want))
		}
		for i := range want {
			if i < len(units) && units[i] != want[i] {
				t.Errorf("%q: unit %d = %#04x, want %#04x", secret, i, units[i], want[i])
			}
		}
		// The keystroke loop emits one press/release pair per non-zero unit, so the
		// reported "characters injected" count must equal the unit count.
		if got := string(utf16.Decode(units)); got != secret {
			t.Errorf("payload decodes to %q, want %q", got, secret)
		}
		if err := d.DeleteCredential(target, CredentialGeneric); err != nil {
			t.Fatalf("cleanup: %v", err)
		}
	}
}

// TestReadSecretUnitsMissingTarget covers the not-found path injection reports.
func TestReadSecretUnitsMissingTarget(t *testing.T) {
	_, err := readSecretUnits(testTarget+"/definitely-absent", 1)
	if !errors.Is(err, ErrCredentialNotFound) {
		t.Errorf("want ErrCredentialNotFound, got %v", err)
	}
}

// TestWriteCredentialZeroesSecretBlob confirms the caller's secret slice is not
// mutated by WriteCredential (it copies), so the caller controls its own wipe.
func TestWriteCredentialZeroesSecretBlob(t *testing.T) {
	d := &Desktop{}
	secret := []byte("keepme")
	original := string(secret)

	if err := d.WriteCredential(CredentialSpec{
		Target: testTarget + "/zero", Secret: secret, Type: CredentialGeneric, Persist: PersistSession,
	}); err != nil {
		t.Fatalf("WriteCredential: %v", err)
	}
	t.Cleanup(func() { _ = d.DeleteCredential(testTarget+"/zero", CredentialGeneric) })

	if string(secret) != original {
		t.Errorf("WriteCredential must not mutate the caller's secret: %q", secret)
	}
}
