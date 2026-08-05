package export

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
)

// signedURLSink ships to operator-minted URLs: an S3 pre-signed PUT, an Azure SAS
// blob URL, or a GCS V4 signed URL. All three are the same operation — PUT these
// bytes here — which is why one backend covers all three clouds with no SDK and
// no principal on the device.
//
// The trade-off is that a signature covers a single object name, so there is no
// prefix to write under and each artifact needs its own URL. The bundle's URL is
// required; the two sidecars are optional, and with neither set only the bundle
// ships. That is not a loss of evidence: manifest.json is inside the bundle, and
// the sidecars exist only so a reviewer can check provenance from a listing
// without downloading the archive.
type signedURLSink struct {
	client *http.Client
	// byName maps an object name to the URL that signs it. Built at construction so
	// an object with no URL fails with a message naming the variable to set.
	byName map[string]string
	// describe is the destination as it may be written down: host and path only.
	describe string
}

// Object names, fixed so the sink can map a URL to an artifact. They are the
// suffixes internal/winmcp builds its object names from.
const (
	bundleSuffix    = ".evidence.zip"
	manifestSuffix  = ".manifest.json"
	signatureSuffix = ".manifest.sig"
)

// The environment variables a signed_url destination reads. Named here so the
// refusal message can tell the operator exactly what to set.
const (
	EnvSignedURL          = "WINDOWS_MCP_EXPORT_SIGNED_URL"
	EnvSignedURLManifest  = "WINDOWS_MCP_EXPORT_SIGNED_URL_MANIFEST"
	EnvSignedURLSignature = "WINDOWS_MCP_EXPORT_SIGNED_URL_SIGNATURE"
)

func newSignedURLSink(cfg Config, creds Credentials) (Sink, error) {
	if strings.TrimSpace(creds.SignedURLBundle) == "" {
		return nil, fmt.Errorf("%w: provider %q needs %s",
			ErrMissingCredence, cfg.Provider, EnvSignedURL)
	}

	s := &signedURLSink{client: newHTTPClient(cfg.Timeout), byName: map[string]string{}}
	for suffix, raw := range map[string]string{
		bundleSuffix:    creds.SignedURLBundle,
		manifestSuffix:  creds.SignedURLManifest,
		signatureSuffix: creds.SignedURLSignature,
	} {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if err := vetSignedURL(raw); err != nil {
			return nil, fmt.Errorf("%s: %w", envForSuffix(suffix), err)
		}
		s.byName[suffix] = raw
	}
	s.describe = redactURL(creds.SignedURLBundle)
	return s, nil
}

// vetSignedURL refuses a URL that would leak its own credential or send the
// bundle back at this machine.
//
// https is required unconditionally here, independently of the document's
// enforce_https: the signature *is* the credential and it travels in the query
// string, so a plaintext pre-signed URL hands an on-path observer a replayable
// write token for the evidence bucket. There is no loopback exemption for the
// same reason — a local relay is still a relay.
func vetSignedURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("is not a URL: %w", err)
	}
	// Compare case-insensitively: url.Parse keeps the caller's case, and
	// "HTTPS://host" is a valid equivalent URL.
	if !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("%w: scheme is %q; the signature travels in the query string "+
			"and would be readable in transit", ErrInsecureURL, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("%w: has no host", ErrInsecureURL)
	}
	return vetHost(u.Hostname())
}

func envForSuffix(suffix string) string {
	switch suffix {
	case manifestSuffix:
		return EnvSignedURLManifest
	case signatureSuffix:
		return EnvSignedURLSignature
	default:
		return EnvSignedURL
	}
}

// Put streams one artifact to the URL that signs it.
func (s *signedURLSink) Put(ctx context.Context, o Object) (string, error) {
	target, ok := s.urlFor(o.Name)
	if !ok {
		return "", fmt.Errorf("%w: no signed URL for %s; set %s",
			ErrMissingCredence, o.Name, envForSuffix(suffixOf(o.Name)))
	}

	f, err := os.Open(o.Path) //nolint:gosec // an operator-configured evidence path
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path.Base(o.Path), err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("stat %s: %w", path.Base(o.Path), err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, target, f)
	if err != nil {
		return "", fmt.Errorf("build upload request: %w", err)
	}
	// ContentLength must be set explicitly: an *os.File is not one of the body
	// types net/http measures for itself, and S3 and Azure both refuse a
	// chunked PUT against a pre-signed URL.
	req.ContentLength = info.Size()
	if o.ContentType != "" {
		req.Header.Set("Content-Type", o.ContentType)
	}
	// Azure needs the blob type on every PUT; S3 and GCS ignore an unknown header,
	// so one request shape serves all three.
	req.Header.Set("x-ms-blob-type", "BlockBlob")
	// Create-only. Evidence is never overwritten — an object already at this key is
	// somebody's record of a session, and a signed URL is minted by hand, so a
	// reused one is exactly the mistake that would destroy it.
	//
	// This is a conditional the *store* enforces, which is the only place it can be
	// enforced for a signed URL: the object name is covered by the signature, so
	// this end cannot pick a different key. S3 and Azure both honour If-None-Match
	// on a create and answer 412 and 409 respectively. Google Cloud Storage's XML
	// API uses x-goog-if-generation-match instead, and that header would have to be
	// covered by the V4 signature to take effect — so a GCS signed URL carries no
	// server-side guarantee from here. See docs/evidence-export.md.
	//
	// Safe to send unconditionally: SigV4 enforces only the headers named in
	// SignedHeaders, and an Azure SAS signature covers the URL rather than the
	// request headers, so adding this to an existing signed URL does not invalidate it.
	req.Header.Set("If-None-Match", "*")

	resp, err := s.client.Do(req)
	if err != nil {
		// The error from net/http embeds the request URL, and for a signed URL that
		// is the credential. Replace it rather than let it reach a log or a receipt.
		return "", fmt.Errorf("%w: PUT %s: %s", ErrUpload, redactURL(target), redactErr(err, target))
	}
	defer func() { _ = resp.Body.Close() }()

	// The two answers a store gives when If-None-Match refused the write. Reported
	// distinctly so the receipt says "there was already something there" rather
	// than a bare status an operator has to go and interpret.
	if resp.StatusCode == http.StatusPreconditionFailed || resp.StatusCode == http.StatusConflict {
		return "", fmt.Errorf("%w: PUT %s returned %s", ErrAlreadyExists, redactURL(target), resp.Status)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("%w: PUT %s returned %s", ErrUpload, redactURL(target), resp.Status)
	}
	return redactURL(target), nil
}

func (s *signedURLSink) Describe() string { return s.describe }

// Close releases the idle connections the transport holds. There is nothing else
// to tear down: the sink owns no credential material beyond the URLs themselves.
func (s *signedURLSink) Close() error {
	s.client.CloseIdleConnections()
	return nil
}

func (s *signedURLSink) urlFor(name string) (string, bool) {
	target, ok := s.byName[suffixOf(name)]
	return target, ok
}

// suffixOf classifies an object name into one of the three artifacts. Matching on
// the suffix rather than the full name keeps the sink independent of the session
// stamp the caller builds names from.
func suffixOf(name string) string {
	for _, suffix := range []string{bundleSuffix, manifestSuffix, signatureSuffix} {
		if strings.HasSuffix(name, suffix) {
			return suffix
		}
	}
	return ""
}

// redactErr renders a transport error with any occurrence of the signed URL
// replaced by its redacted form. net/http wraps errors in *url.Error, which
// carries the full target, so returning one verbatim would write the signature
// into the log or the receipt.
func redactErr(err error, target string) string {
	return strings.ReplaceAll(err.Error(), target, redactURL(target))
}
