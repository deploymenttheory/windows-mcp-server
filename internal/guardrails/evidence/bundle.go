package evidence

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
)

// SchemaVersion is the evidence-bundle manifest version.
const SchemaVersion = 1

// ErrReservedName reports a source that would collide with the manifest or its
// signature. ErrMemberNotFound reports a member missing from a bundle.
var (
	ErrReservedName   = errors.New("source uses a reserved bundle name")
	ErrMemberNotFound = errors.New("bundle member not found")
)

// Reserved archive members: the manifest and its detached signature. They are
// exported because a caller shipping a bundle off the device writes them out
// alongside it, so a reviewer can check provenance from an object listing without
// downloading the archive.
const (
	ManifestName  = "manifest.json"
	SignatureName = "manifest.sig"
)

// Unexported aliases, so the body of this package reads as it did before the two
// names above were exported for the evidence-export path.
const (
	manifestName = ManifestName
	sigName      = SignatureName
)

// Manifest is the index of a bundle: every member and its hash, so the archive
// verifies against itself, plus the metadata a reviewer needs.
type Manifest struct {
	Version   int    `json:"version"`
	Session   string `json:"session"`
	CreatedAt string `json:"created_at"`
	// AuditHead is the head hash of the session's audit chain, echoing the
	// tamper-evident tip into the signed manifest.
	AuditHead string     `json:"audit_head,omitempty"`
	Files     []FileHash `json:"files"`
	Signed    bool       `json:"signed"`
	// PublicKey is the signer's key, hex-encoded, for reference. Trust still comes
	// from a verifier supplying the key it expects, not from this field.
	PublicKey string `json:"public_key,omitempty"`
}

// FileHash records one member's archive path, size and SHA-256.
type FileHash struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Source is one member to place in a bundle: its path within the archive, and
// where its bytes come from — a file on disk, or inline content.
type Source struct {
	ArchivePath string
	FilePath    string
	Bytes       []byte
}

func (s Source) read() ([]byte, error) {
	if s.FilePath != "" {
		b, err := os.ReadFile(s.FilePath)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", s.ArchivePath, err)
		}
		return b, nil
	}
	return s.Bytes, nil
}

// SealOptions configures a Seal.
type SealOptions struct {
	OutPath   string
	Session   string
	CreatedAt string // caller-supplied; the package reads no clock
	AuditHead string
	Signer    *Signer // nil produces an unsigned bundle
}

// Seal writes the sources into a zip at opts.OutPath, appends a manifest hashing
// every member, and — when a signer is given — a detached signature over the
// manifest. It returns the manifest it wrote. Sealing never fails for lack of a
// key: an unsigned bundle is still a self-verifying one.
func Seal(sources []Source, opts SealOptions) (Manifest, error) {
	// Deterministic order, so the same inputs produce the same manifest.
	sorted := slices.Clone(sources)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ArchivePath < sorted[j].ArchivePath })

	f, err := os.Create(opts.OutPath)
	if err != nil {
		return Manifest{}, fmt.Errorf("create bundle: %w", err)
	}
	defer func() { _ = f.Close() }()

	zw := zip.NewWriter(f)

	man := Manifest{
		Version:   SchemaVersion,
		Session:   opts.Session,
		CreatedAt: opts.CreatedAt,
		AuditHead: opts.AuditHead,
	}
	for _, s := range sorted {
		if s.ArchivePath == manifestName || s.ArchivePath == sigName {
			return Manifest{}, fmt.Errorf("%w: %s", ErrReservedName, s.ArchivePath)
		}
		b, err := s.read()
		if err != nil {
			return Manifest{}, err
		}
		if err := writeZip(zw, s.ArchivePath, b); err != nil {
			return Manifest{}, err
		}
		sum := sha256.Sum256(b)
		man.Files = append(man.Files, FileHash{
			Path: s.ArchivePath, Size: int64(len(b)), SHA256: hex.EncodeToString(sum[:]),
		})
	}

	if opts.Signer != nil {
		man.Signed = true
		man.PublicKey = opts.Signer.PublicHex()
	}

	manifestBytes, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		return Manifest{}, fmt.Errorf("marshal manifest: %w", err)
	}
	if err := writeZip(zw, manifestName, manifestBytes); err != nil {
		return Manifest{}, err
	}
	if opts.Signer != nil {
		if err := writeZip(zw, sigName, opts.Signer.sign(manifestBytes)); err != nil {
			return Manifest{}, err
		}
	}

	if err := zw.Close(); err != nil {
		return Manifest{}, fmt.Errorf("finalize bundle: %w", err)
	}
	return man, nil
}

func writeZip(zw *zip.Writer, name string, content []byte) error {
	w, err := zw.Create(name)
	if err != nil {
		return fmt.Errorf("zip entry %s: %w", name, err)
	}
	if _, err := w.Write(content); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	return nil
}

// ReadBundleMember reads one member out of a sealed bundle by name.
//
// It exists for the export path, which writes manifest.json and manifest.sig out
// as loose objects beside the archive. Reading them back out of the bundle rather
// than keeping the bytes from Seal is deliberate: the sidecars are then provably
// the same bytes the manifest was hashed and signed over, not a second rendering
// of the same struct that could drift from it.
func ReadBundleMember(zipPath, name string) ([]byte, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, fmt.Errorf("open bundle: %w", err)
	}
	defer func() { _ = zr.Close() }()
	return readZipFile(&zr.Reader, name)
}

// readZipFile reads one member of an open zip reader.
func readZipFile(zr *zip.Reader, name string) ([]byte, error) {
	for _, f := range zr.File {
		if f.Name != name {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("open bundle member %q: %w", name, err)
		}
		defer func() { _ = rc.Close() }()
		b, err := io.ReadAll(rc)
		if err != nil {
			return nil, fmt.Errorf("read bundle member %q: %w", name, err)
		}
		return b, nil
	}
	return nil, fmt.Errorf("%w: %q", ErrMemberNotFound, name)
}
