//go:build windows && (amd64 || arm64)

package winmcp

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The DACL check had no test at all: nothing referenced checkCredentialsFileACL
// or the SID walk, so neither the four-SID denylist it used nor the allowlist
// that replaced it was ever exercised. These use icacls rather than building
// descriptors by hand, so what is asserted is the behaviour against a real DACL.

// writeCredsFile creates a file with inheritance removed and only the current
// user granted read — the shape the documentation tells operators to produce.
func writeCredsFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "creds.json")
	if err := os.WriteFile(path, []byte(`{"credentials":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	run(t, "icacls", path, "/inheritance:r", "/grant:r", os.Getenv("USERNAME")+":R")
	return path
}

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Skipf("%s failed in this environment (%v): %s", name, err, out)
	}
}

// TestCredentialsFileACLAcceptsAnOwnerOnlyFile is the baseline: the arrangement
// the docs prescribe must pass, or the check is unusable.
func TestCredentialsFileACLAcceptsAnOwnerOnlyFile(t *testing.T) {
	path := writeCredsFile(t)
	if err := checkCredentialsFileACL(path); err != nil {
		t.Errorf("a file readable only by its owner should be accepted, got %v", err)
	}
}

// TestCredentialsFileACLRejectsUnanticipatedTrustees is the reason the check is
// an allowlist. The denylist named Everyone, Users, Authenticated Users and
// INTERACTIVE, and accepted every other trustee silently — so granting read to
// any other group disclosed the secrets while startup reported the file safe.
func TestCredentialsFileACLRejectsUnanticipatedTrustees(t *testing.T) {
	// BUILTIN\Guests is not on the old denylist and is not a trusted reader.
	// Using a well-known group keeps the test independent of domain membership.
	path := writeCredsFile(t)
	run(t, "icacls", path, "/grant", "*S-1-5-32-546:R") // BUILTIN\Guests

	err := checkCredentialsFileACL(path)
	if err == nil {
		t.Fatal("a trustee outside the allowlist must be refused; the old denylist accepted it")
	}
	if !errors.Is(err, ErrCredentialsFileBroadlyReadable) {
		t.Errorf("want ErrCredentialsFileBroadlyReadable, got %v", err)
	}
}

// TestCredentialsFileACLRejectsEveryone keeps the case the denylist did catch.
func TestCredentialsFileACLRejectsEveryone(t *testing.T) {
	path := writeCredsFile(t)
	run(t, "icacls", path, "/grant", "*S-1-1-0:R") // Everyone

	if err := checkCredentialsFileACL(path); !errors.Is(err, ErrCredentialsFileBroadlyReadable) {
		t.Errorf("a world-readable credentials file must be refused, got %v", err)
	}
}
