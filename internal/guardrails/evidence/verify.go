package evidence

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// Report is the outcome of verifying a bundle.
type Report struct {
	Session string
	Files   int
	Signed  bool
	// SigChecked is true when a signature was present and a key was available to
	// check it against; SigValid is the result.
	SigChecked bool
	SigValid   bool
	Problems   []string
}

// OK reports whether the bundle verified — every member hashed as recorded, no
// stray members, and (if signed and checked) a valid signature.
func (r Report) OK() bool {
	return len(r.Problems) == 0 && (!r.SigChecked || r.SigValid)
}

// Verify checks a bundle against its own manifest: every member is present and
// hashes as recorded, no member is unaccounted for, and — when the bundle is
// signed — the signature is valid. If expectedPubKeyHex is given, the signature is
// checked against that key (the trusted, out-of-band one) and a mismatch with the
// manifest's own key is reported; otherwise the manifest's key is used, which
// proves internal consistency but not provenance.
func Verify(zipPath, expectedPubKeyHex string) (Report, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return Report{}, fmt.Errorf("open bundle: %w", err)
	}
	defer func() { _ = zr.Close() }()

	manifestBytes, err := readZipFile(&zr.Reader, manifestName)
	if err != nil {
		return Report{}, fmt.Errorf("read manifest: %w", err)
	}
	var man Manifest
	if err := json.Unmarshal(manifestBytes, &man); err != nil {
		return Report{}, fmt.Errorf("parse manifest: %w", err)
	}

	rep := Report{Session: man.Session, Files: len(man.Files), Signed: man.Signed}

	// Every member the manifest names must be present and hash as recorded.
	accounted := map[string]bool{manifestName: true, sigName: true}
	for _, fh := range man.Files {
		accounted[fh.Path] = true
		b, err := readZipFile(&zr.Reader, fh.Path)
		if err != nil {
			rep.Problems = append(rep.Problems, fmt.Sprintf("%s: missing from the bundle", fh.Path))
			continue
		}
		sum := sha256.Sum256(b)
		if got := hex.EncodeToString(sum[:]); got != fh.SHA256 {
			rep.Problems = append(rep.Problems, fmt.Sprintf("%s: content does not match its hash (edited)", fh.Path))
		}
	}
	// A member not named in the manifest is an addition after sealing.
	for _, f := range zr.File {
		if !accounted[f.Name] {
			rep.Problems = append(rep.Problems, fmt.Sprintf("%s: present but not in the manifest (added)", f.Name))
		}
	}

	if man.Signed {
		sig, err := readZipFile(&zr.Reader, sigName)
		if err != nil {
			rep.Problems = append(rep.Problems, "manifest is signed but the signature is missing")
		} else {
			key := man.PublicKey
			if expectedPubKeyHex != "" {
				key = expectedPubKeyHex
				if !strings.EqualFold(strings.TrimSpace(expectedPubKeyHex), strings.TrimSpace(man.PublicKey)) {
					rep.Problems = append(rep.Problems,
						"the signing key does not match the expected key: the bundle was signed by someone else")
				}
			}
			rep.SigChecked = true
			rep.SigValid = verifySig(key, manifestBytes, sig)
			if !rep.SigValid {
				rep.Problems = append(rep.Problems, "signature does not verify")
			}
		}
	}

	return rep, nil
}

// String renders a report for the CLI.
func (r Report) String() string {
	state := "signed"
	switch {
	case !r.Signed:
		state = "unsigned"
	case r.SigChecked && r.SigValid:
		state = "signed, signature valid"
	case r.SigChecked:
		state = "signed, SIGNATURE INVALID"
	}
	out := fmt.Sprintf("session %s — %d file(s), %s\n", r.Session, r.Files, state)
	if len(r.Problems) == 0 {
		return out + "verified: the bundle is intact\n"
	}
	out += fmt.Sprintf("%d problem(s):\n", len(r.Problems))
	for _, p := range r.Problems {
		out += "  - " + p + "\n"
	}
	return out
}
