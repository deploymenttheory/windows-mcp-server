//go:build windows && (amd64 || arm64)

package winmcp

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// auditKeyFile is the per-machine key file, kept beside the audit directory.
const auditKeyFile = ".audit-key"

// resolveAuditKey returns the key the audit chain is written under.
//
// WINDOWS_MCP_AUDIT_KEY wins when set: an operator who supplies a key out of band
// is the only arrangement that survives an attacker with write access to the box,
// because a key stored next to the log is readable by anyone who can rewrite the
// log. Absent that, a key is generated on first use and persisted with a
// restrictive DACL.
//
// The default used to be no key at all, which made the chain tamper-*evident*
// rather than unforgeable: anyone able to write the file could edit an entry and
// recompute every hash after it, and VerifyChain reported a clean chain. The
// generated key does not defeat an attacker who reads the key file, and is not
// meant to; it raises the bar from "recompute the chain" to "find and read the
// key", and it makes the keyed path -- including the manifest MACs -- the one
// everybody exercises rather than an opt-in nobody sets.
//
// A stderr destination gets no key: there is no file to protect, and nowhere
// beside it to keep one.
func resolveAuditKey(destination string, logger *slog.Logger) []byte {
	if k := os.Getenv("WINDOWS_MCP_AUDIT_KEY"); k != "" {
		return []byte(k)
	}
	dir := auditKeyDir(destination)
	if dir == "" {
		return nil
	}

	path := filepath.Join(dir, auditKeyFile)
	if raw, err := os.ReadFile(path); err == nil { //nolint:gosec // a path this server owns
		if key := strings.TrimSpace(string(raw)); key != "" {
			return []byte(key)
		}
	}

	key, err := newAuditKey()
	if err != nil {
		// Not fatal. An unkeyed chain is what shipped until now, and refusing to
		// start because a key could not be minted would turn a hardening step into
		// an outage. Say plainly what the chain does and does not prove.
		if logger != nil {
			logger.Warn("could not generate an audit key; the chain will be unkeyed and "+
				"therefore tamper-evident but not unforgeable. Set WINDOWS_MCP_AUDIT_KEY",
				"error", err)
		}
		return nil
	}
	if err := writeAuditKey(dir, path, key); err != nil {
		if logger != nil {
			logger.Warn("could not persist the audit key; this session's chain is keyed but "+
				"the next will use a different key, so cross-session verification will fail. "+
				"Set WINDOWS_MCP_AUDIT_KEY to fix this permanently",
				"path", path, "error", err)
		}
	}
	return key
}

// auditKeyDir returns the directory to keep the key in, or "" when there is no
// file destination to protect.
func auditKeyDir(destination string) string {
	if destination == "" || destination == "stderr" {
		return ""
	}
	if auditDestinationIsDir(destination) {
		return destination
	}
	return filepath.Dir(destination)
}

func newAuditKey() ([]byte, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("generate audit key: %w", err)
	}
	return []byte(hex.EncodeToString(raw)), nil
}

// writeAuditKey persists the key, refusing to clobber one written concurrently.
func writeAuditKey(dir, path string, key []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create audit key directory: %w", err)
	}
	// O_EXCL so two starts racing cannot leave one session's chain keyed under a
	// key the other overwrote.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil // another start won; its key is the one on disk
		}
		return fmt.Errorf("create audit key file: %w", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(key); err != nil {
		return fmt.Errorf("write audit key: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync audit key: %w", err)
	}
	return nil
}
