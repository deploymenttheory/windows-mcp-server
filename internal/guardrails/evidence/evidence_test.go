package evidence

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func sealSample(t *testing.T, signer *Signer) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "b.evidence.zip")
	_, err := Seal([]Source{
		{ArchivePath: "audit/session-x.audit.jsonl", Bytes: []byte("line1\nline2\n")},
		{ArchivePath: "verdicts.json", Bytes: []byte(`[{"event":"policy.decided"}]`)},
	}, SealOptions{
		OutPath: out, Session: "20260803-120000",
		CreatedAt: "2026-08-03T12:00:00Z", AuditHead: "abc123", Signer: signer,
	})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return out
}

func TestSealVerifyRoundTripSigned(t *testing.T) {
	signer, _ := GenerateSigner()
	out := sealSample(t, signer)

	rep, err := Verify(out, signer.PublicHex())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !rep.OK() {
		t.Fatalf("a freshly sealed bundle should verify: %s", rep)
	}
	if !rep.Signed || !rep.SigChecked || !rep.SigValid {
		t.Errorf("expected a valid signature: %+v", rep)
	}
	if rep.Files != 2 {
		t.Errorf("files = %d, want 2", rep.Files)
	}
}

func TestSealVerifyUnsigned(t *testing.T) {
	out := sealSample(t, nil)
	rep, err := Verify(out, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !rep.OK() {
		t.Fatalf("an unsigned bundle should still verify: %s", rep)
	}
	if rep.Signed || rep.SigChecked {
		t.Errorf("unsigned bundle should report no signature: %+v", rep)
	}
}

func TestVerifyDetectsEditedMember(t *testing.T) {
	signer, _ := GenerateSigner()
	out := sealSample(t, signer)
	edited := filepath.Join(t.TempDir(), "edited.zip")
	rezip(t, out, edited, map[string][]byte{"verdicts.json": []byte(`[{"event":"forged"}]`)}, nil, nil)

	rep, _ := Verify(edited, signer.PublicHex())
	if rep.OK() {
		t.Error("an edited member must fail verification")
	}
}

func TestVerifyDetectsAddedMember(t *testing.T) {
	signer, _ := GenerateSigner()
	out := sealSample(t, signer)
	added := filepath.Join(t.TempDir(), "added.zip")
	rezip(t, out, added, nil, nil, map[string][]byte{"stowaway.txt": []byte("snuck in")})

	rep, _ := Verify(added, signer.PublicHex())
	if rep.OK() {
		t.Error("a member not in the manifest must fail verification")
	}
}

func TestVerifyDetectsWrongKey(t *testing.T) {
	signer, _ := GenerateSigner()
	other, _ := GenerateSigner()
	out := sealSample(t, signer)

	rep, _ := Verify(out, other.PublicHex())
	if rep.OK() || rep.SigValid {
		t.Errorf("verifying against the wrong key must fail: %+v", rep)
	}
}

func TestLoadSignerRoundTrip(t *testing.T) {
	signer, _ := GenerateSigner()
	keyPath := filepath.Join(t.TempDir(), "evidence.key")
	if err := os.WriteFile(keyPath, []byte(signer.SeedHex()), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadSigner(keyPath)
	if err != nil {
		t.Fatalf("LoadSigner: %v", err)
	}
	if loaded.PublicHex() != signer.PublicHex() {
		t.Error("a loaded key should reproduce the same public key")
	}
}

// rezip copies a bundle, applying edits (replace member content), drops (omit a
// member), and adds (new members) — for constructing tampered bundles.
func rezip(t *testing.T, src, dst string, edits map[string][]byte, drop map[string]bool, add map[string][]byte) {
	t.Helper()
	zr, err := zip.OpenReader(src)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = zr.Close() }()

	f, err := os.Create(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	zw := zip.NewWriter(f)

	for _, m := range zr.File {
		if drop[m.Name] {
			continue
		}
		content := edits[m.Name]
		if content == nil {
			rc, _ := m.Open()
			content, _ = io.ReadAll(rc)
			_ = rc.Close()
		}
		w, _ := zw.Create(m.Name)
		_, _ = w.Write(content)
	}
	for name, content := range add {
		w, _ := zw.Create(name)
		_, _ = w.Write(content)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}
