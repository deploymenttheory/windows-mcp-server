package audit

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ManifestName is the fixed filename of the per-directory audit manifest. One
// manifest lives alongside the session files it links.
const ManifestName = "audit-manifest.jsonl"

// ErrManifestBroken is returned by VerifyManifest when the manifest records do
// not form an unbroken hash chain. ErrSessionFile wraps failures to create a
// session's entry file.
var (
	ErrManifestBroken = errors.New("audit manifest broken")
	ErrSessionFile    = errors.New("audit session file")
)

// ManifestRecord is one line of the audit manifest. Directory-mode sinks write an
// open record when a session starts and a seal record when it ends, each linked
// to the previous record's hash. The chain of records is what carries continuity
// across restarts: a session that crashed without sealing still left an open
// record chained into the manifest, so its existence — and the gap where its seal
// should be — is detectable rather than lost.
type ManifestRecord struct {
	// SessionFile is the basename of the session's entry file, in this directory.
	SessionFile string `json:"session_file"`
	// OpenedAt is when the session destination was created (RFC3339Nano, UTC).
	OpenedAt string `json:"opened_at"`
	// SealedAt is when it was closed cleanly; empty on an open record.
	SealedAt string `json:"sealed_at,omitempty"`
	// HeadSeq is the number of entries in the session file at record time, and
	// HeadHash the hash of the last one — the head VerifyDir cross-checks the
	// session file against. Both are zero/empty on the open record.
	HeadSeq  uint64 `json:"head_seq"`
	HeadHash string `json:"head_hash"`
	// PrevManifestHash links to the prior record's EntryHash ("" for the first).
	PrevManifestHash string `json:"prev_manifest_hash"`
	// EntryHash commits to every field above plus PrevManifestHash.
	EntryHash string `json:"entry_hash"`
	// Mac is the HMAC of EntryHash under the audit key, present only on a keyed
	// log. Without it the manifest is only tamper-evident: the chain is plain
	// SHA-256, so anyone who can write the file can drop the last record and
	// recompute the rest. That matters because the seal record is what pins a
	// session's head, and dropping it is how a truncated session file passes
	// verification.
	Mac string `json:"mac,omitempty"`
}

// hashManifest computes a manifest record's hash over its fields plus the previous
// record's hash. EntryHash itself is excluded so verification can recompute it.
func hashManifest(r ManifestRecord) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%s\n%s\n%d\n%s\n", r.SessionFile, r.OpenedAt, r.SealedAt, r.HeadSeq, r.HeadHash)
	h.Write([]byte(r.PrevManifestHash))
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyManifest checks that records form an unbroken hash chain: each record's
// PrevManifestHash equals the prior record's EntryHash (the first is empty) and
// each EntryHash recomputes. It does not read the session files — VerifyDir does
// that and cross-checks each sealed head against its file.
// A non-empty key additionally requires every record to carry a valid MAC, which
// is what makes dropping the tail detectable rather than merely visible.
func VerifyManifest(records []ManifestRecord, key []byte) error {
	prev := ""
	for i, r := range records {
		if r.PrevManifestHash != prev {
			return fmt.Errorf(
				"%w: record %d (%s): prev_manifest_hash does not chain",
				ErrManifestBroken,
				i,
				r.SessionFile,
			)
		}
		if got := hashManifest(r); got != r.EntryHash {
			return fmt.Errorf("%w: record %d (%s): entry_hash mismatch (tampered)", ErrManifestBroken, i, r.SessionFile)
		}
		if len(key) > 0 && !hmac.Equal([]byte(r.Mac), []byte(macOf(key, r.EntryHash))) {
			return fmt.Errorf("%w: record %d (%s): mac does not verify under the audit key",
				ErrManifestBroken, i, r.SessionFile)
		}
		prev = r.EntryHash
	}
	return nil
}

// sessionDestination is the directory-mode Destination: one session-<id>.audit.jsonl for the
// entries plus the shared, hash-chained audit-manifest.jsonl. It writes an open
// manifest record on creation and a seal record on Close, and tracks the running
// head so the seal record can name it without a second pass over the file.
type sessionDestination struct {
	mu           sync.Mutex
	key          []byte
	entries      *os.File
	manifest     *os.File
	sessionFile  string
	openedAt     string
	prevManifest string
	count        uint64
	headHash     string
	sealed       bool
}

func newSessionDestination(dir, sessionID string, key []byte) (Destination, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("audit dir %q: %w", dir, err)
	}
	if sessionID == "" {
		sessionID = time.Now().UTC().Format("20060102-150405")
	}

	name, entries, err := createSessionFile(dir, sessionID)
	if err != nil {
		return nil, err
	}

	manifestPath := filepath.Join(dir, ManifestName)
	mf, err := os.OpenFile(manifestPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		_ = entries.Close()
		return nil, fmt.Errorf("audit manifest %q: %w", manifestPath, err)
	}
	prev, err := lastManifestHash(manifestPath)
	if err != nil {
		_ = entries.Close()
		_ = mf.Close()
		return nil, err
	}

	s := &sessionDestination{
		key:          key,
		entries:      entries,
		manifest:     mf,
		sessionFile:  name,
		openedAt:     time.Now().UTC().Format(time.RFC3339Nano),
		prevManifest: prev,
	}
	if err := s.writeManifest(false); err != nil {
		_ = entries.Close()
		_ = mf.Close()
		return nil, err
	}
	return s, nil
}

// createSessionFile opens the session's entry file with O_EXCL so two runs in the
// same clock second never append into one chain (which would corrupt both). On a
// name collision it disambiguates with a counter rather than clobbering.
func createSessionFile(dir, sessionID string) (string, *os.File, error) {
	for i := 0; i <= 1000; i++ {
		name := "session-" + sessionID + ".audit.jsonl"
		if i > 0 {
			name = fmt.Sprintf("session-%s-%d.audit.jsonl", sessionID, i)
		}
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			return name, f, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return "", nil, fmt.Errorf("%w: %w", ErrSessionFile, err)
		}
	}
	return "", nil, fmt.Errorf("%w: too many name collisions for session %q", ErrSessionFile, sessionID)
}

// lastManifestHash returns the EntryHash of the final record in an existing
// manifest, or "" when the manifest does not exist yet.
func lastManifestHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("audit manifest %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	var last string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		var r ManifestRecord
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return "", fmt.Errorf("audit manifest %q: %w", path, err)
		}
		last = r.EntryHash
	}
	if err := sc.Err(); err != nil {
		return "", fmt.Errorf("audit manifest %q: %w", path, err)
	}
	return last, nil
}

// writeManifest appends one record (open when seal is false, seal when true),
// fsyncs the manifest and advances the running manifest head. The caller holds
// s.mu when seal is true; at open time the destination is not yet shared.
func (s *sessionDestination) writeManifest(seal bool) error {
	r := ManifestRecord{
		SessionFile:      s.sessionFile,
		OpenedAt:         s.openedAt,
		HeadSeq:          s.count,
		HeadHash:         s.headHash,
		PrevManifestHash: s.prevManifest,
	}
	if seal {
		r.SealedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	r.EntryHash = hashManifest(r)
	if len(s.key) > 0 {
		r.Mac = macOf(s.key, r.EntryHash)
	}

	b, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("audit manifest: marshal record: %w", err)
	}
	if _, err := s.manifest.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("audit manifest: write: %w", err)
	}
	if err := s.manifest.Sync(); err != nil {
		return fmt.Errorf("audit manifest: sync: %w", err)
	}
	s.prevManifest = r.EntryHash
	return nil
}

func (s *sessionDestination) Write(e AuditEntry) error {
	b, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("audit entry: marshal: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.entries.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("audit entry: write: %w", err)
	}
	s.count = e.Seq + 1
	s.headHash = e.EntryHash
	return nil
}

func (s *sessionDestination) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.entries.Sync(); err != nil {
		return fmt.Errorf("audit entries: sync: %w", err)
	}
	return nil
}

// Close writes the seal manifest record, then closes both files. It is
// idempotent: a second Close (the kill path and the normal-exit defer can both
// fire) writes nothing more.
func (s *sessionDestination) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sealed {
		return nil
	}
	s.sealed = true

	_ = s.entries.Sync()
	sealErr := s.writeManifest(true)
	entErr := s.entries.Close()
	manErr := s.manifest.Close()

	return errors.Join(sealErr, entErr, manErr)
}
