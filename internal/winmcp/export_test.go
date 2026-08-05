//go:build windows && (amd64 || arm64)

package winmcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/evidence"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/export"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/policy"
)

// fakeSink records what the seal handed it, and can be made to fail or panic.
type fakeSink struct {
	names   []string
	err     error
	panics  bool
	closed  bool
	describ string
}

func (f *fakeSink) Put(_ context.Context, o export.Object) (string, error) {
	if f.panics {
		panic("sink exploded")
	}
	f.names = append(f.names, o.Name)
	if f.err != nil {
		return "", f.err
	}
	return "test://" + o.Name, nil
}

func (f *fakeSink) Describe() string {
	if f.describ != "" {
		return f.describ
	}
	return "test://destination"
}
func (f *fakeSink) Close() error { f.closed = true; return nil }

var _ export.Sink = (*fakeSink)(nil)

// exportTP builds a transparency policy with a sealed-and-shipped destination
// over freshly made audit and evidence directories.
func exportTP(t *testing.T, session string) policy.TransparencyPolicy {
	t.Helper()
	auditDir, evDir := t.TempDir(), t.TempDir()
	writeSession(t, auditDir, session)
	return policy.TransparencyPolicy{
		AuditDestination: auditDir,
		EvidenceDir:      evDir,
		Export: policy.ExportPolicy{
			Provider: policy.ExportSignedURL,
			Timeout:  policy.Duration(policy.DefaultExportTimeout),
		},
	}
}

// evidenceKeyFile mints a signing key and returns its path, so the seal produces
// a signed bundle and therefore a manifest.sig to ship.
func evidenceKeyFile(t *testing.T) string {
	t.Helper()
	signer, err := evidence.GenerateSigner()
	if err != nil {
		t.Fatalf("generate signer: %v", err)
	}
	path := filepath.Join(t.TempDir(), "evidence.key")
	if err := os.WriteFile(path, []byte(signer.SeedHex()), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return path
}

func readReceipt(t *testing.T, evDir, session string) export.Receipt {
	t.Helper()
	path := filepath.Join(evDir, "session-"+session+".export.json")
	blob, err := os.ReadFile(path) //nolint:gosec // a path this test just produced
	if err != nil {
		t.Fatalf("a receipt must be written whatever happened: %v", err)
	}
	var r export.Receipt
	if err := json.Unmarshal(blob, &r); err != nil {
		t.Fatalf("parse receipt: %v", err)
	}
	return r
}

// TestAutoSealShipsTheBundleAndItsManifestSidecar covers the payload agreed for
// this feature: the archive, plus manifest.json beside it so a reviewer can check
// provenance from an object listing without downloading the bundle.
func TestAutoSealShipsTheBundleAndItsManifestSidecar(t *testing.T) {
	t.Setenv("WINDOWS_MCP_EVIDENCE_KEY_FILE", "") // unsigned, so no .manifest.sig
	const session = "20260805-120000"
	tp := exportTP(t, session)
	sink := &fakeSink{}

	autoSealEvidence(tp, session, nil, nil, sink, discardLogger())

	want := []string{"session-" + session + ".evidence.zip", "session-" + session + ".manifest.json"}
	if !slices.Equal(sink.names, want) {
		t.Errorf("shipped %v, want %v", sink.names, want)
	}
	// The bundle goes first: a destination that takes one object and then fails
	// still has the artifact that matters.
	if len(sink.names) > 0 && !strings.HasSuffix(sink.names[0], ".evidence.zip") {
		t.Error("the bundle must be shipped before its sidecars")
	}
	if !sink.closed {
		t.Error("the sink must be closed after the export")
	}

	r := readReceipt(t, tp.EvidenceDir, session)
	if !r.Shipped() {
		t.Errorf("receipt should report a clean export: %+v", r.Objects)
	}
	if r.AuditHead == "" {
		t.Error("the receipt must echo the bundle's audit head, so it can be tied to the artifact")
	}
	for _, o := range r.Objects {
		if o.SHA256 == "" || o.Bytes == 0 {
			t.Errorf("each object needs its size and digest in the receipt: %+v", o)
		}
	}
}

// TestSignedBundleAlsoShipsItsSignature: the detached signature is what proves
// provenance to a third party, so when there is one it must travel beside the
// manifest rather than only inside the archive.
func TestSignedBundleAlsoShipsItsSignature(t *testing.T) {
	const session = "20260805-130000"
	tp := exportTP(t, session)

	t.Setenv("WINDOWS_MCP_EVIDENCE_KEY_FILE", evidenceKeyFile(t))

	sink := &fakeSink{}
	autoSealEvidence(tp, session, nil, nil, sink, discardLogger())

	if !slices.Contains(sink.names, "session-"+session+".manifest.sig") {
		t.Errorf("a signed bundle must ship its signature sidecar; shipped %v", sink.names)
	}
}

// TestExportFailureIsRecordedAndNeverCrashesShutdown. This runs from the
// audit-close defer, so a panic or an error here would turn a clean exit into
// something the host reads as instability — and the receipt is the only record,
// because the audit chain is already sealed inside the artifact being shipped.
func TestExportFailureIsRecordedAndNeverCrashesShutdown(t *testing.T) {
	t.Run("upload error", func(t *testing.T) {
		const session = "20260805-140000"
		tp := exportTP(t, session)
		autoSealEvidence(tp, session, nil, nil,
			&fakeSink{err: errors.New("destination refused")}, discardLogger())

		r := readReceipt(t, tp.EvidenceDir, session)
		if r.Shipped() {
			t.Error("a refused upload must not report as shipped")
		}
		if len(r.Objects) == 0 || r.Objects[0].Error == "" {
			t.Errorf("the receipt must carry the reason: %+v", r.Objects)
		}
	})

	t.Run("sink panics", func(t *testing.T) {
		const session = "20260805-150000"
		tp := exportTP(t, session)
		// autoSealEvidence recovers; reaching the next line at all is the assertion.
		autoSealEvidence(tp, session, nil, nil, &fakeSink{panics: true}, discardLogger())

		bundle := filepath.Join(tp.EvidenceDir, "session-"+session+".evidence.zip")
		if _, err := os.Stat(bundle); err != nil {
			t.Errorf("the bundle must still be on disk after a failed export: %v", err)
		}
	})
}

// TestNoSinkSealsWithoutShipping: export off is the default, and it must leave the
// seal exactly as it was — no receipt, no attempt.
func TestNoSinkSealsWithoutShipping(t *testing.T) {
	const session = "20260805-160000"
	tp := exportTP(t, session)
	tp.Export = policy.ExportPolicy{}

	autoSealEvidence(tp, session, nil, nil, nil, discardLogger())

	if _, err := os.Stat(filepath.Join(tp.EvidenceDir, "session-"+session+".evidence.zip")); err != nil {
		t.Fatalf("the bundle must still be sealed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tp.EvidenceDir, "session-"+session+".export.json")); err == nil {
		t.Error("no receipt should be written when no destination is configured")
	}
}

// storingSink keeps the bytes it was given, and refuses a key it already holds —
// the create-only behaviour a real store enforces through If-None-Match. It is
// how the round trip below is checked end to end; the HTTP request shape that
// produces that behaviour is covered in the export package's own tests.
type storingSink struct {
	stored map[string][]byte
}

func newStoringSink() *storingSink { return &storingSink{stored: map[string][]byte{}} }

func (s *storingSink) Put(_ context.Context, o export.Object) (string, error) {
	if _, exists := s.stored[o.Name]; exists {
		return "", fmt.Errorf("%w: %s", export.ErrAlreadyExists, o.Name)
	}
	blob, err := os.ReadFile(o.Path) //nolint:gosec // a path the seal just wrote
	if err != nil {
		return "", fmt.Errorf("read %s: %w", o.Name, err)
	}
	s.stored[o.Name] = blob
	return "test://" + o.Name, nil
}

func (s *storingSink) Describe() string { return "test://destination" }
func (s *storingSink) Close() error     { return nil }

var _ export.Sink = (*storingSink)(nil)

// TestBundleSurvivesTheRoundTripAndIsNeverOverwritten is the end-to-end property
// the whole feature rests on: what arrives at the destination must still verify
// against its own manifest and signature, and a second session that would land on
// the same key must leave the stored copy exactly as it was.
//
// A bundle that does not verify after shipping is not evidence, and an overwrite
// would destroy the record it was shipped to preserve.
func TestBundleSurvivesTheRoundTripAndIsNeverOverwritten(t *testing.T) {
	const session = "20260805-170000"
	tp := exportTP(t, session)
	t.Setenv("WINDOWS_MCP_EVIDENCE_KEY_FILE", evidenceKeyFile(t))

	sink := newStoringSink()
	autoSealEvidence(tp, session, nil, nil, sink, discardLogger())

	bundleName := "session-" + session + ".evidence.zip"
	shipped, ok := sink.stored[bundleName]
	if !ok {
		t.Fatalf("the bundle never reached the destination; stored %v", sink.stored)
	}

	// The bytes that arrived, written back out and verified as an archive.
	roundTrip := filepath.Join(t.TempDir(), "roundtrip.zip")
	if err := os.WriteFile(roundTrip, shipped, 0o600); err != nil {
		t.Fatalf("write round trip: %v", err)
	}
	rep, err := evidence.Verify(roundTrip, "")
	if err != nil {
		t.Fatalf("verify round trip: %v", err)
	}
	if !rep.OK() || !rep.SigChecked || !rep.SigValid {
		t.Fatalf("a shipped bundle must still verify and its signature must hold: %s", rep)
	}

	// The manifest sidecar must be byte-identical to the archive member it was
	// lifted from — that is what makes it usable as provenance from a listing.
	inArchive, err := evidence.ReadBundleMember(roundTrip, evidence.ManifestName)
	if err != nil {
		t.Fatalf("read manifest from the shipped bundle: %v", err)
	}
	if !bytes.Equal(inArchive, sink.stored["session-"+session+".manifest.json"]) {
		t.Error("the manifest sidecar must be the same bytes the manifest was hashed and signed over")
	}

	// A second seal onto an occupied key is refused, and changes nothing.
	autoSealEvidence(tp, session, nil, nil, sink, discardLogger())
	if !bytes.Equal(sink.stored[bundleName], shipped) {
		t.Error("a refused overwrite must leave the stored evidence untouched")
	}
	r := readReceipt(t, tp.EvidenceDir, session)
	if r.Shipped() {
		t.Error("a refused overwrite must not report as shipped")
	}
	if len(r.Objects) == 0 || !strings.Contains(r.Objects[0].Error, "already exists") {
		t.Errorf("the receipt must say the object was already there: %+v", r.Objects)
	}
}

// TestExportSecretsAreScrubbedFromTheEnvironment. The credentials are read once at
// startup into the sink; leaving them in the environment would let any process
// started outside powerShellEnv inherit them — and a pre-signed URL is a
// write credential for the evidence bucket.
func TestExportSecretsAreScrubbedFromTheEnvironment(t *testing.T) {
	for _, name := range []string{
		export.EnvSignedURL, export.EnvSignedURLManifest, export.EnvSignedURLSignature,
	} {
		if !slices.Contains(secretEnvVars, name) {
			t.Errorf("%s is a credential and must be in secretEnvVars", name)
		}
		if !strings.HasPrefix(name, "WINDOWS_MCP_") {
			t.Errorf("%s must carry the WINDOWS_MCP_ prefix: that prefix is what "+
				"internal/desktop withholds from every child process", name)
		}
	}
}

// TestExportProviderConstantsMatchPolicy pins the two lists together. The export
// package deliberately does not import policy — the decision lives in the
// document, the transport does not — so nothing but this test stops them drifting
// into a provider that validates and cannot be constructed.
func TestExportProviderConstantsMatchPolicy(t *testing.T) {
	if export.ProviderSignedURL != policy.ExportSignedURL {
		t.Errorf("export.ProviderSignedURL = %q, policy.ExportSignedURL = %q",
			export.ProviderSignedURL, policy.ExportSignedURL)
	}
	for _, p := range policy.ExportProviders() {
		_, err := export.New(export.Config{Provider: p, Timeout: policy.DefaultExportTimeout},
			export.Credentials{SignedURLBundle: "https://bucket.example/o?sig=a"})
		if errors.Is(err, export.ErrUnknownProvider) {
			t.Errorf("policy admits provider %q but export.New has no backend for it", p)
		}
	}
}

// TestExportStatusReportsOnlyAWorkingDestination. A configured-but-unbuildable
// export must report nil, or a watcher polling the status endpoint would read
// intent as posture.
func TestExportStatusReportsOnlyAWorkingDestination(t *testing.T) {
	enabled := policy.ExportPolicy{Provider: policy.ExportSignedURL}

	if got := exportStatus(enabled, nil); got != nil {
		t.Errorf("a configured export with no sink must report nil, got %+v", got)
	}
	if got := exportStatus(policy.ExportPolicy{}, &fakeSink{}); got != nil {
		t.Errorf("export off must report nil, got %+v", got)
	}
	got := exportStatus(enabled, &fakeSink{describ: "https://bucket.example/b.zip"})
	if got == nil || got.Provider != policy.ExportSignedURL {
		t.Fatalf("a working destination must be reported, got %+v", got)
	}
	if strings.Contains(got.Destination, "?") {
		t.Errorf("the status destination must not carry a query string: %q", got.Destination)
	}
}

// TestProvisionExportIsOffWhenUnconfigured is the default path: no document, no
// sink, and no environment read.
func TestProvisionExportIsOffWhenUnconfigured(t *testing.T) {
	if sink := provisionExport(&policy.Policy{}, nil, discardLogger()); sink != nil {
		t.Errorf("an unconfigured export must produce no sink, got %T", sink)
	}
}
