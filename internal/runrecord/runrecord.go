// Package runrecord builds the OpenTelemetry trace that records a journey run,
// and serialises it as OTLP/JSON.
//
// A run is a trace: a root span for the journey, a child per step, and a child of
// that per assertion or evidence capture. The requirement it serves is narrow and
// hard — after a run, someone who was not watching must be able to establish what
// was asserted, what was actually observed, and whether that matched. A rendered
// text log does not carry that: it says an assertion failed, not what was on
// screen instead.
//
// Three decisions are load-bearing, and each is written up in docs/journey-evidence.md:
//
//   - The spans are built directly as OTLP protocol buffers rather than through
//     the OTel SDK. The SDK has no file exporter, and routing evidence through a
//     TracerProvider would put it behind a sampler — a run record holding a
//     statistical subset of its own steps is not evidence.
//   - protojson output is deliberately unstable: it injects randomised whitespace
//     to discourage byte comparison. The artifact is SHA-256'd into a bundle
//     manifest and compared on verification, so it is canonicalised before it is
//     written (see MarshalOTLPJSON).
//   - Trace and span ids are random, so two runs of one document produce different
//     files. That is correct: the run differs. The stable identity is the journey
//     document's hash and the compiled plan id, both of which are span attributes.
//
// The package holds no Windows or MCP types, so the whole serialisation is
// testable on any platform.
package runrecord

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"time"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// ScopeName is the instrumentation scope every journey span is recorded under.
const ScopeName = "windows-mcp-server/journeys"

// SpanID identifies a span within the run. The zero value means "no parent",
// which is how the root span is written.
type SpanID [8]byte

// IsZero reports whether the id is unset.
func (s SpanID) IsZero() bool { return s == SpanID{} }

// Options configures a recorder's resource attributes.
//
// SessionID is the one that matters and the one that has never reached OTLP: it
// is the stamp that names the session's audit file and its recording, so without
// it a trace cannot be tied to the chain it belongs to.
type Options struct {
	ServiceName    string
	ServiceVersion string
	SessionID      string
	HostName       string
	// Rand supplies trace and span ids. Nil uses crypto/rand; a test supplies a
	// deterministic reader so a recorded document can be compared.
	Rand io.Reader
}

// Recorder accumulates the spans of one run.
type Recorder struct {
	traceID  [16]byte
	resource *resourcepb.Resource
	spans    []*tracepb.Span
	rnd      io.Reader
}

// New starts a recorder for one run.
func New(opts Options) *Recorder {
	rnd := opts.Rand
	if rnd == nil {
		rnd = rand.Reader
	}
	r := &Recorder{
		rnd: rnd,
		resource: &resourcepb.Resource{Attributes: attrs(
			String("service.name", orDefault(opts.ServiceName, "windows-mcp-server")),
			String("service.version", orDefault(opts.ServiceVersion, "dev")),
			String("session.id", opts.SessionID),
			String("host.name", opts.HostName),
		)},
	}
	_, _ = io.ReadFull(r.rnd, r.traceID[:])
	return r
}

// TraceID returns the run's trace id as hex, for a log line that ties a run to
// what a collector received.
func (r *Recorder) TraceID() string { return fmt.Sprintf("%x", r.traceID) }

// Span is one recorded operation.
type Span struct {
	Name   string
	Parent SpanID
	Start  time.Time
	End    time.Time
	Attrs  []Attr
	// Failed sets the span's status to Error. Status is set explicitly either way:
	// a span with no status is indistinguishable from one nobody decided about, and
	// the point of recording every assertion — not only the failures — is to be able
	// to answer "was this ever checked?".
	Failed bool
	// Message is the status description, which for an assertion carries the
	// comparison: expected "EXP-[0-9]{6}", observed "EXP-4471".
	Message string
}

// Add records a span and returns its id, for use as a parent.
func (r *Recorder) Add(s Span) SpanID {
	var id SpanID
	_, _ = io.ReadFull(r.rnd, id[:])

	status := &tracepb.Status{Code: tracepb.Status_STATUS_CODE_OK}
	if s.Failed {
		status = &tracepb.Status{Code: tracepb.Status_STATUS_CODE_ERROR, Message: s.Message}
	} else if s.Message != "" {
		status.Message = s.Message
	}

	span := &tracepb.Span{
		TraceId:           r.traceID[:],
		SpanId:            id[:],
		Name:              s.Name,
		Kind:              tracepb.Span_SPAN_KIND_INTERNAL,
		StartTimeUnixNano: uint64(s.Start.UnixNano()), //nolint:gosec // a wall-clock timestamp
		EndTimeUnixNano:   uint64(s.End.UnixNano()),   //nolint:gosec // a wall-clock timestamp
		Attributes:        attrs(s.Attrs...),
		Status:            status,
	}
	if !s.Parent.IsZero() {
		parent := s.Parent
		span.ParentSpanId = parent[:]
	}
	r.spans = append(r.spans, span)
	return id
}

// Open records a span whose end is not yet known — the run itself — returning its
// id, so children can be parented to it, and a function that closes it.
//
// The alternative, adding the root last, does not work: a child needs its
// parent's id before it can be recorded, and a run's outcome is not known until
// every child has been.
func (r *Recorder) Open(s Span) (SpanID, func(end time.Time, failed bool, message string, extra ...Attr)) {
	id := r.Add(s)
	idx := len(r.spans) - 1
	return id, func(end time.Time, failed bool, message string, extra ...Attr) {
		span := r.spans[idx]
		span.EndTimeUnixNano = uint64(end.UnixNano()) //nolint:gosec // a wall-clock timestamp
		span.Attributes = append(span.Attributes, attrs(extra...)...)
		if failed {
			span.Status = &tracepb.Status{Code: tracepb.Status_STATUS_CODE_ERROR, Message: message}
			return
		}
		span.Status = &tracepb.Status{Code: tracepb.Status_STATUS_CODE_OK, Message: message}
	}
}

// MarshalOTLPJSON renders the run as OTLP/JSON — the standard ResourceSpans
// encoding, so a collector, otel-cli, a Jaeger import or any OTLP-aware tool
// reads it with no bespoke parser.
//
// The output is canonicalised. protojson randomises its whitespace on purpose to
// discourage byte comparison of its output, and this artifact is hashed into an
// evidence manifest and compared on verification — so it is decoded into a
// generic value and re-encoded through encoding/json, which sorts object keys and
// emits stable separators. Without this a file hashes differently every time it
// is written and verification fails for no visible reason.
func (r *Recorder) MarshalOTLPJSON() ([]byte, error) {
	data := &tracepb.TracesData{ResourceSpans: []*tracepb.ResourceSpans{{
		Resource: r.resource,
		ScopeSpans: []*tracepb.ScopeSpans{{
			Scope: &commonpb.InstrumentationScope{Name: ScopeName},
			Spans: r.spans,
		}},
	}}}

	raw, err := protojson.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("marshal run record: %w", err)
	}
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil, fmt.Errorf("canonicalize run record: %w", err)
	}
	out, err := json.MarshalIndent(generic, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("canonicalize run record: %w", err)
	}
	return append(out, '\n'), nil
}

// Attr is one span or resource attribute.
type Attr struct {
	Key   string
	Value *commonpb.AnyValue
}

// String, Int, Bool and Float build attributes. An empty string value is dropped
// by attrs, so an absent property is absent rather than present-and-empty.
func String(k, v string) Attr {
	return Attr{k, &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v}}}
}

func Int(k string, v int64) Attr {
	return Attr{k, &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: v}}}
}

func Bool(k string, v bool) Attr {
	return Attr{k, &commonpb.AnyValue{Value: &commonpb.AnyValue_BoolValue{BoolValue: v}}}
}

func Float(k string, v float64) Attr {
	return Attr{k, &commonpb.AnyValue{Value: &commonpb.AnyValue_DoubleValue{DoubleValue: v}}}
}

// attrs converts to protocol buffers, dropping empty-string attributes.
func attrs(in ...Attr) []*commonpb.KeyValue {
	out := make([]*commonpb.KeyValue, 0, len(in))
	for _, a := range in {
		if a.Key == "" || a.Value == nil {
			continue
		}
		if sv, ok := a.Value.Value.(*commonpb.AnyValue_StringValue); ok && sv.StringValue == "" {
			continue
		}
		out = append(out, &commonpb.KeyValue{Key: a.Key, Value: a.Value})
	}
	return out
}

func orDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
