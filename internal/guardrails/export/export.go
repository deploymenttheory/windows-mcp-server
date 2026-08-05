// Package export ships a sealed evidence bundle off the device to cloud blob
// storage.
//
// It is the fourth transparency destination. The audit destination, the recording
// directory and the evidence directory all write to the same disk the session is
// running on; the anchor publishes the chain *head* somewhere the session cannot
// reach back into. This publishes the whole artifact, for the same reason — an
// on-box adversary, a reimaged VM or a deleted directory otherwise takes the
// evidence with it.
//
// Three properties are load-bearing:
//
//   - **One dialer.** Every backend is built on the client in dial.go, which
//     resolves, vets each answer with hostmatch.ForbiddenAddr and dials the vetted
//     address rather than the name. The destination is operator-supplied, so a name
//     answering with 127.0.0.1, 10.x or 169.254.169.254 is exactly the shape this
//     has to refuse — and shipping evidence *to* the box it came from is not an
//     export.
//   - **No ambient credential chain.** Credentials are service-principal values
//     read from fixed WINDOWS_MCP_EXPORT_* environment variables and passed in.
//     The SDKs' default chains (config.LoadDefaultConfig,
//     azidentity.DefaultAzureCredential, Google ADC) are deliberately not used:
//     they read the vendors' bare environment names, which the desktop engine does
//     *not* withhold from child processes, and they reach IMDS at
//     169.254.169.254, which the dialer above exists to refuse.
//   - **It never fails the session.** Construction failure disables export with a
//     warning, and an upload failure is recorded in the receipt. This runs from a
//     shutdown defer; a missing upload must not turn a clean exit into a crash.
//
// Nothing here imports the policy package or any MCP type, the same posture as
// package telemetry: the decision to export lives in the document, and the
// translation from document to Config lives in internal/winmcp.
package export

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"time"
)

// ProviderSignedURL is the unauthenticated destination: an operator-minted
// pre-signed PUT URL, Azure SAS URL or GCS V4 signed URL, supplied in the
// environment. It mirrors the policy document's
// transparency.export.provider value; TestExportProviderConstantsMatchPolicy in
// internal/winmcp pins the two together, since this package deliberately does not
// import policy.
//
// The credentialed s3/azblob/gcs providers land with their SDK backends.
const ProviderSignedURL = "signed_url"

// Errors reported by construction and upload. They are distinct values so a
// caller can explain which half of the configuration is wrong without matching on
// rendered text.
var (
	ErrUnknownProvider = errors.New("unknown export provider")
	ErrMissingConfig   = errors.New("incomplete export configuration")
	ErrMissingCredence = errors.New("export credentials are not set in the environment")
	ErrInsecureURL     = errors.New("signed URL must be https")
	ErrForbiddenAddr   = errors.New("destination resolves to an address this server will not dial")
	ErrUpload          = errors.New("upload failed")
	// ErrAlreadyExists reports a destination that already holds an object at this
	// key. Evidence is never overwritten: the existing object is somebody's record
	// of a session, and replacing it silently would destroy exactly the artifact
	// this whole subsystem exists to preserve. It is a failure, recorded in the
	// receipt, not a condition to retry past.
	ErrAlreadyExists = errors.New("an object already exists at the destination; nothing was overwritten")
)

// Config is the routing half of an export destination: everything the operator
// writes in the policy document, and nothing secret. Credentials are separate and
// come from the environment.
// A signed_url destination is addressed entirely by its URLs, so this carries no
// bucket, prefix or host: those arrive with the credentialed backends, which are
// the ones that choose an object key.
type Config struct {
	Provider string
	Timeout  time.Duration
}

// Credentials are the service-principal values, read from the environment before
// the process scrubs them. A zero Credentials is what a signed_url destination
// uses beyond its URLs.
//
// This struct must never be logged, marshalled or placed in an audit payload.
type Credentials struct {
	// SignedURL destinations. Bundle is required; the other two are optional, and
	// their absence means the sidecars are not shipped.
	SignedURLBundle    string
	SignedURLManifest  string
	SignedURLSignature string
}

// Object is one artifact to ship.
type Object struct {
	// Name is the key relative to the destination prefix, and also the file's base
	// name on disk. It is never a path: the prefix decides where the object lands.
	Name        string
	Path        string // the file to stream; never read fully into memory
	ContentType string
	Metadata    map[string]string
}

// Result is the outcome of one object's upload, and is what the receipt records.
type Result struct {
	Name    string `json:"name"`
	Bytes   int64  `json:"bytes,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
	URI     string `json:"uri,omitempty"`
	Shipped bool   `json:"shipped"`
	Error   string `json:"error,omitempty"`
}

// Sink ships evidence objects to an operator-declared destination.
//
// The four implementations differ only in how bytes are addressed and
// authenticated; every one of them is constructed over the client in dial.go, and
// none of them reads anything back. A write-only principal is the intended
// posture.
type Sink interface {
	// Put uploads one object and returns the URI it landed at. Implementations
	// stream from disk: an evidence bundle carries session video and can be large.
	Put(ctx context.Context, o Object) (uri string, err error)
	// Describe names the destination for the receipt and the log. It must never
	// contain a credential — in particular a signed_url sink describes its host and
	// path, never its query string, which is where the signature lives.
	Describe() string
	// Close releases whatever the backend holds. It is safe to call on a sink whose
	// uploads failed.
	Close() error
}

// New builds the sink for cfg. It performs no network I/O: a destination that is
// unreachable is discovered at upload time, not here, so a device that is offline
// at startup still starts. What it does check is that the credentials the chosen
// provider needs are actually present, so a missing environment variable is
// reported while the operator is watching rather than during shutdown.
func New(cfg Config, creds Credentials) (Sink, error) {
	if cfg.Timeout <= 0 {
		return nil, fmt.Errorf("%w: timeout must be positive", ErrMissingConfig)
	}
	switch cfg.Provider {
	case ProviderSignedURL:
		return newSignedURLSink(cfg, creds)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnknownProvider, cfg.Provider)
	}
}

// Ship uploads every object in order and returns one Result each, in the same
// order. It never returns an error: a partial failure is the interesting case and
// belongs in the receipt, where a fleet tool can find it, rather than collapsed
// into a single error the shutdown path would discard.
//
// Objects are uploaded sequentially. The bundle is first, so a destination that
// accepts one object and then fails still has the artifact that matters — the
// sidecars are a listing convenience and the manifest is inside the bundle
// regardless.
func Ship(ctx context.Context, s Sink, objs []Object) []Result {
	results := make([]Result, 0, len(objs))
	for _, o := range objs {
		results = append(results, shipOne(ctx, s, o))
	}
	return results
}

func shipOne(ctx context.Context, s Sink, o Object) Result {
	res := Result{Name: o.Name}

	size, sum, err := statAndHash(o.Path)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.Bytes, res.SHA256 = size, sum

	// The digest travels with the object so a reviewer pulling it out of the bucket
	// can tell it is the artifact this device sealed, without unpacking it.
	if o.Metadata == nil {
		o.Metadata = map[string]string{}
	}
	o.Metadata["sha256"] = sum

	uri, err := s.Put(ctx, o)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.URI, res.Shipped = uri, true
	return res
}

// statAndHash returns the size and SHA-256 of a file, streaming it rather than
// reading it in: an evidence bundle carrying session video can be hundreds of
// megabytes, and this runs during shutdown.
func statAndHash(filePath string) (int64, string, error) {
	f, err := os.Open(filePath) //nolint:gosec // an operator-configured evidence path
	if err != nil {
		return 0, "", fmt.Errorf("open %s: %w", path.Base(filePath), err)
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		return 0, "", fmt.Errorf("hash %s: %w", path.Base(filePath), err)
	}
	return size, hex.EncodeToString(h.Sum(nil)), nil
}

// redactURL renders a URL with its query string removed, for logs, the receipt
// and Describe. A pre-signed URL carries its credential in the query, so the
// query is exactly the part that must never be written down.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "(unparseable url)"
	}
	return u.Scheme + "://" + u.Host + u.EscapedPath()
}
