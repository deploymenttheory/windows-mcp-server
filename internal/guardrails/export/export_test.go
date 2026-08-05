package export

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- helpers -----------------------------------------------------------------

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func sha256Of(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// recordingSink captures what Ship asked it to upload, so the orchestration can
// be asserted without a network.
type recordingSink struct {
	puts   []Object
	err    error
	closed bool
}

func (r *recordingSink) Put(_ context.Context, o Object) (string, error) {
	r.puts = append(r.puts, o)
	if r.err != nil {
		return "", r.err
	}
	return "test://" + o.Name, nil
}
func (r *recordingSink) Describe() string { return "test://destination" }
func (r *recordingSink) Close() error     { r.closed = true; return nil }

var _ Sink = (*recordingSink)(nil)

// --- construction ------------------------------------------------------------

// TestUnknownProviderIsRefused: a provider with no backend must fail at
// construction, where the operator is watching, rather than at session end inside
// a shutdown defer.
func TestUnknownProviderIsRefused(t *testing.T) {
	_, err := New(Config{Provider: "s3", Timeout: time.Minute}, Credentials{})
	if !errors.Is(err, ErrUnknownProvider) {
		t.Fatalf("want ErrUnknownProvider, got %v", err)
	}
}

// TestSignedURLNeedsItsBundleURL: the whole destination is the URL, so an unset
// variable is a configuration error and the message must name the variable.
func TestSignedURLNeedsItsBundleURL(t *testing.T) {
	_, err := New(Config{Provider: ProviderSignedURL, Timeout: time.Minute}, Credentials{})
	if !errors.Is(err, ErrMissingCredence) {
		t.Fatalf("want ErrMissingCredence, got %v", err)
	}
	if !strings.Contains(err.Error(), EnvSignedURL) {
		t.Errorf("the refusal must name %s so the operator knows what to set; got %q", EnvSignedURL, err)
	}
}

// TestZeroTimeoutIsRefused: a zero timeout would make the upload context expire
// before the first byte, which reads in the receipt as an unreachable destination
// rather than a missing setting.
func TestZeroTimeoutIsRefused(t *testing.T) {
	_, err := New(Config{Provider: ProviderSignedURL}, Credentials{SignedURLBundle: "https://x.example/o"})
	if !errors.Is(err, ErrMissingConfig) {
		t.Fatalf("want ErrMissingConfig, got %v", err)
	}
}

// --- the plaintext refusal ---------------------------------------------------

// TestSignedURLRefusesPlaintextHTTP is the property that has no exemption: the
// signature travels in the query string, so a plaintext pre-signed URL hands an
// on-path observer a replayable write token for the evidence bucket. Unlike the
// approvals webhook and the OTLP endpoint, not even loopback is excused — a local
// relay is still a relay.
func TestSignedURLRefusesPlaintextHTTP(t *testing.T) {
	for _, raw := range []string{
		"http://bucket.example/o?sig=abc",
		"HTTP://bucket.example/o?sig=abc", // url.Parse keeps the caller's case
		"http://127.0.0.1:9000/o?sig=abc", // no loopback exemption here
		"http://localhost/o?sig=abc",
	} {
		_, err := New(
			Config{Provider: ProviderSignedURL, Timeout: time.Minute},
			Credentials{SignedURLBundle: raw},
		)
		if !errors.Is(err, ErrInsecureURL) {
			t.Errorf("%q must be refused as insecure; got %v", raw, err)
		}
	}
}

// TestSignedURLAcceptsHTTPSInAnyCase pins the other half of the case-insensitive
// comparison: refusing a valid https URL because it was written in capitals would
// be a bug, not a control.
func TestSignedURLAcceptsHTTPSInAnyCase(t *testing.T) {
	for _, raw := range []string{"https://bucket.example/o?sig=a", "HTTPS://bucket.example/o?sig=a"} {
		if _, err := New(
			Config{Provider: ProviderSignedURL, Timeout: time.Minute},
			Credentials{SignedURLBundle: raw},
		); err != nil {
			t.Errorf("%q is https and must be accepted; got %v", raw, err)
		}
	}
}

// --- the SSRF vetting --------------------------------------------------------

// TestSignedURLRefusesForbiddenAddressLiterals covers the destinations that would
// mean the bundle never leaves this machine, or that reach the cloud metadata
// endpoint this package's no-ambient-credentials rule exists to keep out of reach.
//
// A literal is settled at construction; a *name* answering with one of these is
// caught at dial time by dialContext, which is the case
// TestDialContextRefusesAForbiddenAnswer covers.
func TestSignedURLRefusesForbiddenAddressLiterals(t *testing.T) {
	for _, host := range []string{
		"127.0.0.1",            // loopback: shipping evidence to the box it came from
		"10.1.2.3",             // RFC1918
		"192.168.0.9",          // RFC1918
		"169.254.169.254",      // cloud metadata
		"100.64.0.1",           // CGNAT
		"[::1]",                // loopback, v6
		"[64:ff9b::a9fe:a9fe]", // metadata through NAT64
		"[::7f00:1]",           // loopback through an IPv4-compatible address
	} {
		_, err := New(
			Config{Provider: ProviderSignedURL, Timeout: time.Minute},
			Credentials{SignedURLBundle: "https://" + host + "/o?sig=a"},
		)
		if !errors.Is(err, ErrForbiddenAddr) {
			t.Errorf("https://%s/ must be refused as a forbidden destination; got %v", host, err)
		}
	}
}

// TestDialContextRefusesAForbiddenAnswer proves the check runs on the *resolved*
// address, not just on a literal in the URL. localhost is a name, so it survives
// construction and has to be caught at dial time.
func TestDialContextRefusesAForbiddenAnswer(t *testing.T) {
	sink, err := New(
		Config{Provider: ProviderSignedURL, Timeout: 5 * time.Second},
		Credentials{SignedURLBundle: "https://localhost:9/o?sig=a"},
	)
	if err != nil {
		t.Fatalf("a name must survive construction; it is the dial that vets it: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	_, err = sink.Put(context.Background(), Object{
		Name: "session-x" + bundleSuffix, Path: writeTemp(t, "b.zip", "bytes"),
	})
	if err == nil {
		t.Fatal("a destination resolving to loopback must not be dialled")
	}
	// Asserted on ErrForbiddenAddr's own text rather than on the word "loopback":
	// where localhost resolves to ::1, hostmatch.ForbiddenAddr reaches it through
	// the ::/96 IPv4-compatible branch and reports "an IANA special-purpose address
	// reached through an IPv6 transition address". The refusal is right either way,
	// and pinning the exact wording here would pin that quirk.
	if !strings.Contains(err.Error(), "will not dial") {
		t.Errorf("the refusal should say the address was rejected; got %v", err)
	}
}

// --- credential hygiene ------------------------------------------------------

// TestDescribeAndErrorsNeverLeakTheSignature is the property that makes a signed
// URL safe to configure at all: the query string is the credential, so it must not
// reach a log line, an error, or the receipt.
func TestDescribeAndErrorsNeverLeakTheSignature(t *testing.T) {
	const secret = "SIGNATURE-THAT-MUST-NOT-APPEAR"
	target := "https://bucket.example/session-x.evidence.zip?X-Amz-Signature=" + secret

	sink, err := New(
		Config{Provider: ProviderSignedURL, Timeout: 2 * time.Second},
		Credentials{SignedURLBundle: target},
	)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	if strings.Contains(sink.Describe(), secret) {
		t.Errorf("Describe() leaked the signature: %q", sink.Describe())
	}

	// bucket.example does not resolve, so this fails in the transport — which is
	// exactly the path that wraps *url.Error and would otherwise carry the full URL.
	_, putErr := sink.Put(context.Background(), Object{
		Name: "session-x" + bundleSuffix, Path: writeTemp(t, "b.zip", "bytes"),
	})
	if putErr == nil {
		t.Fatal("expected the upload to fail")
	}
	if strings.Contains(putErr.Error(), secret) {
		t.Errorf("the upload error leaked the signature: %q", putErr)
	}
}

// --- the upload --------------------------------------------------------------

// TestSignedURLPutsTheBytes checks the request shape all three clouds require of
// a pre-signed PUT: the method, an explicit Content-Length (a chunked PUT is
// refused by S3 and Azure), the blob-type header Azure needs, and the body.
func TestSignedURLPutsTheBytes(t *testing.T) {
	const body = "evidence-bundle-bytes"
	var (
		gotMethod, gotType, gotBlobType, gotIfNoneMatch string
		gotLen                                          int64
		gotBody                                         string
	)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotLen = r.Method, r.ContentLength
		gotType = r.Header.Get("Content-Type")
		gotBlobType = r.Header.Get("x-ms-blob-type")
		gotIfNoneMatch = r.Header.Get("If-None-Match")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	sink := sinkAgainst(t, srv, srv.URL+"/session-x.evidence.zip?sig=a")
	uri, err := sink.Put(context.Background(), Object{
		Name:        "session-x" + bundleSuffix,
		Path:        writeTemp(t, "b.zip", body),
		ContentType: "application/zip",
	})
	if err != nil {
		t.Fatalf("put: %v", err)
	}

	if gotMethod != http.MethodPut {
		t.Errorf("method = %s, want PUT", gotMethod)
	}
	if gotLen != int64(len(body)) {
		t.Errorf("Content-Length = %d, want %d; a chunked PUT is refused by S3 and Azure", gotLen, len(body))
	}
	if gotType != "application/zip" {
		t.Errorf("Content-Type = %q, want application/zip", gotType)
	}
	if gotBlobType != "BlockBlob" {
		t.Errorf("x-ms-blob-type = %q, want BlockBlob; Azure needs it and the others ignore it", gotBlobType)
	}
	if gotIfNoneMatch != "*" {
		t.Errorf("If-None-Match = %q, want \"*\"; evidence must never overwrite an existing "+
			"object, and for a signed URL the store is the only place that can be enforced",
			gotIfNoneMatch)
	}
	if gotBody != body {
		t.Errorf("body = %q, want %q", gotBody, body)
	}
	if strings.Contains(uri, "sig=") {
		t.Errorf("the returned URI must be redacted; got %q", uri)
	}
}

// TestNonSuccessStatusIsAnError: a destination that answers 403 has not stored the
// evidence, and reporting success would put "shipped": true in the receipt for an
// object that does not exist.
func TestNonSuccessStatusIsAnError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	sink := sinkAgainst(t, srv, srv.URL+"/o?sig=a")
	_, err := sink.Put(context.Background(), Object{
		Name: "session-x" + bundleSuffix, Path: writeTemp(t, "b.zip", "x"),
	})
	if !errors.Is(err, ErrUpload) {
		t.Fatalf("want ErrUpload, got %v", err)
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("the error should carry the status; got %v", err)
	}
}

// TestExistingObjectIsNeverOverwritten. An object already at the key is somebody's
// record of a session; replacing it would destroy exactly the artifact this
// subsystem exists to preserve. Both statuses a store uses to refuse a
// create-only write must come back as ErrAlreadyExists, so the receipt says what
// happened rather than leaving an operator to interpret a bare 409.
func TestExistingObjectIsNeverOverwritten(t *testing.T) {
	for _, status := range []int{http.StatusPreconditionFailed, http.StatusConflict} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("If-None-Match") == "*" {
					w.WriteHeader(status)
					return
				}
				w.WriteHeader(http.StatusCreated)
			}))
			defer srv.Close()

			sink := sinkAgainst(t, srv, srv.URL+"/o?sig=a")
			_, err := sink.Put(context.Background(), Object{
				Name: "session-x" + bundleSuffix, Path: writeTemp(t, "b.zip", "x"),
			})
			if !errors.Is(err, ErrAlreadyExists) {
				t.Fatalf("want ErrAlreadyExists, got %v", err)
			}
			if errors.Is(err, ErrUpload) {
				t.Error("a refused overwrite is its own outcome, not a generic upload failure")
			}
		})
	}
}

// TestAnObjectWithNoURLIsReportedNotSilentlyDropped: with only the bundle URL set
// the sidecars cannot ship, and that must be a per-object failure in the receipt
// rather than a silent omission.
func TestAnObjectWithNoURLIsReportedNotSilentlyDropped(t *testing.T) {
	sink, err := New(
		Config{Provider: ProviderSignedURL, Timeout: time.Minute},
		Credentials{SignedURLBundle: "https://bucket.example/b.zip?sig=a"},
	)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	_, err = sink.Put(context.Background(), Object{
		Name: "session-x" + manifestSuffix, Path: writeTemp(t, "m.json", "{}"),
	})
	if !errors.Is(err, ErrMissingCredence) {
		t.Fatalf("want ErrMissingCredence, got %v", err)
	}
	if !strings.Contains(err.Error(), EnvSignedURLManifest) {
		t.Errorf("the error must name %s; got %v", EnvSignedURLManifest, err)
	}
}

// --- Ship orchestration ------------------------------------------------------

// TestShipHashesEveryObjectAndCarriesTheDigest: the digest travels with the object
// so a reviewer pulling it out of the bucket can tell it is the artifact this
// device sealed, without unpacking it.
func TestShipHashesEveryObjectAndCarriesTheDigest(t *testing.T) {
	const body = "bundle"
	sink := &recordingSink{}
	results := Ship(context.Background(), sink, []Object{
		{Name: "a" + bundleSuffix, Path: writeTemp(t, "a.zip", body)},
	})

	if len(results) != 1 || !results[0].Shipped {
		t.Fatalf("want one shipped result, got %+v", results)
	}
	if results[0].SHA256 != sha256Of(body) || results[0].Bytes != int64(len(body)) {
		t.Errorf("result = %+v, want the file's size and digest", results[0])
	}
	if got := sink.puts[0].Metadata["sha256"]; got != sha256Of(body) {
		t.Errorf("the digest must reach the object metadata; got %q", got)
	}
}

// TestShipRecordsAPartialFailureRatherThanStopping: a destination that takes the
// bundle and then fails must still produce a result per object, because the
// receipt is the only record of what happened — the audit chain is already sealed
// inside the artifact being shipped.
func TestShipRecordsAPartialFailureRatherThanStopping(t *testing.T) {
	sink := &recordingSink{err: errors.New("destination refused")}
	results := Ship(context.Background(), sink, []Object{
		{Name: "a" + bundleSuffix, Path: writeTemp(t, "a.zip", "x")},
		{Name: "a" + manifestSuffix, Path: writeTemp(t, "a.json", "{}")},
	})
	if len(results) != 2 {
		t.Fatalf("every object needs a result; got %d", len(results))
	}
	for _, r := range results {
		if r.Shipped || r.Error == "" {
			t.Errorf("a failed upload must be recorded with its reason; got %+v", r)
		}
	}
}

// TestShipReportsAMissingFileWithoutCallingTheSink: a bundle that is not on disk
// is a local failure, and spending an upload attempt on it would confuse the
// receipt's error with a destination problem.
func TestShipReportsAMissingFileWithoutCallingTheSink(t *testing.T) {
	sink := &recordingSink{}
	results := Ship(context.Background(), sink, []Object{
		{Name: "a" + bundleSuffix, Path: filepath.Join(t.TempDir(), "absent.zip")},
	})
	if len(results) != 1 || results[0].Shipped || results[0].Error == "" {
		t.Fatalf("want one failed result with a reason, got %+v", results)
	}
	if len(sink.puts) != 0 {
		t.Error("the sink must not be called for a file that could not be read")
	}
}

// --- the receipt -------------------------------------------------------------

// TestReceiptDistinguishesNeverTriedFromTriedAndFailed. Silence is the one answer
// an evidence trail must never give, so a receipt is written either way and
// Shipped() reports honestly on both.
func TestReceiptDistinguishesNeverTriedFromTriedAndFailed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		objects []Result
		want    bool
	}{
		{name: "never tried", objects: nil, want: false},
		{name: "tried and failed", objects: []Result{{Name: "a", Error: "refused"}}, want: false},
		{name: "partially shipped", objects: []Result{{Name: "a", Shipped: true}, {Name: "b"}}, want: false},
		{name: "all shipped", objects: []Result{{Name: "a", Shipped: true}}, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := (Receipt{Objects: tc.objects}).Shipped(); got != tc.want {
				t.Errorf("Shipped() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestWriteReceiptRoundTrips checks the file a fleet tool reads: 0600, versioned,
// and carrying each object's disposition.
func TestWriteReceiptRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session-x.export.json")
	err := WriteReceipt(path, Receipt{
		Session: "x", CreatedAt: "2026-08-05T00:00:00Z",
		Provider: ProviderSignedURL, Destination: "https://bucket.example/b.zip",
		AuditHead: "9f2c", Objects: []Result{{Name: "a", Shipped: true}, {Name: "b", Error: "timeout"}},
	})
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	blob, err := os.ReadFile(path) //nolint:gosec // a path this test just wrote
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var got Receipt
	if err := json.Unmarshal(blob, &got); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Version != ReceiptSchemaVersion {
		t.Errorf("version = %d, want %d", got.Version, ReceiptSchemaVersion)
	}
	if len(got.Objects) != 2 || got.Objects[1].Error != "timeout" {
		t.Errorf("objects did not round-trip: %+v", got.Objects)
	}
	if got.Shipped() {
		t.Error("a receipt with a failed object must not report as shipped")
	}
}

// TestReceiptCarriesNoCredentialFields guards the shape of the artifact that is
// written to disk and read by whoever collects it. A field added here that held a
// URL with its query string, or any credential, would publish it.
func TestReceiptCarriesNoCredentialFields(t *testing.T) {
	blob, err := json.Marshal(Receipt{Objects: []Result{{Name: "a"}}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(blob, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, banned := range []string{"credential", "secret", "token", "key", "password", "signature", "sas"} {
		for field := range generic {
			if strings.Contains(strings.ToLower(field), banned) {
				t.Errorf("receipt field %q looks like a credential; the receipt is written to disk "+
					"and collected off the device", field)
			}
		}
	}
}

// --- helper ------------------------------------------------------------------

// sinkAgainst builds a signed-URL sink pointed at an httptest TLS server.
//
// It assembles the struct rather than calling New, and that is not a shortcut: an
// httptest server listens on loopback with a self-signed certificate, so New
// refuses its URL outright — which is the behaviour
// TestSignedURLRefusesForbiddenAddressLiterals exists to pin. Swapping the client
// swaps the TLS trust and the dial vetting together; everything else about the
// request path below is the production one.
func sinkAgainst(t *testing.T, srv *httptest.Server, target string) Sink {
	t.Helper()
	client := srv.Client()
	client.Timeout = 10 * time.Second
	s := &signedURLSink{
		client:   client,
		byName:   map[string]string{bundleSuffix: target},
		describe: redactURL(target),
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
