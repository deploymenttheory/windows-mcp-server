package runrecord

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// fixedRand gives deterministic ids so a test can compare whole documents.
type fixedRand struct{ n byte }

func (f *fixedRand) Read(p []byte) (int, error) {
	for i := range p {
		f.n++
		p[i] = f.n
	}
	return len(p), nil
}

func newTestRecorder() *Recorder {
	return New(Options{
		ServiceName: "windows-mcp-server", ServiceVersion: "test",
		SessionID: "20260805-141233", HostName: "lab-vm",
		Rand: &fixedRand{},
	})
}

func TestMarshalProducesOTLPJSON(t *testing.T) {
	r := newTestRecorder()
	start := time.Unix(1786055553, 0)
	run := r.Add(Span{Name: "journey expenses-submit", Start: start, End: start.Add(4 * time.Second)})
	r.Add(Span{
		Name: "assert result.text matches", Parent: run,
		Start: start, End: start.Add(11 * time.Millisecond),
		Attrs: []Attr{
			String("journey.assertion.subject", "result.text"),
			String("journey.assertion.observed", "EXP-4471"),
			Bool("journey.assertion.passed", false),
			Int("journey.assertion.polls", 1),
		},
		Failed:  true,
		Message: `expected "EXP-[0-9]{6}", observed "EXP-4471"`,
	})

	blob, err := r.MarshalOTLPJSON()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(blob, &doc); err != nil {
		t.Fatalf("the artifact must be valid JSON: %v\n%s", err, blob)
	}
	rs, ok := doc["resourceSpans"].([]any)
	if !ok || len(rs) != 1 {
		t.Fatalf("want one resourceSpans entry, got %v", doc["resourceSpans"])
	}

	// The session stamp is what ties a trace to the audit chain and the recording,
	// and is the resource attribute that has never reached OTLP before.
	if !strings.Contains(string(blob), "20260805-141233") {
		t.Error("session.id should be on the resource")
	}
	// The observed value is the reason the artifact exists.
	if !strings.Contains(string(blob), "EXP-4471") {
		t.Error("the observed value should be recorded")
	}
	if !strings.Contains(string(blob), ScopeName) {
		t.Error("spans should carry the journeys instrumentation scope")
	}
}

// TestMarshalIsByteStable is the canonicalisation guard. protojson deliberately
// randomises its whitespace to discourage byte comparison of its output — and this
// artifact is SHA-256'd into an evidence manifest and compared on verification, so
// an unstable encoding means a bundle that fails to verify for no visible reason.
func TestMarshalIsByteStable(t *testing.T) {
	build := func() []byte {
		r := newTestRecorder()
		start := time.Unix(1786055553, 0)
		run := r.Add(Span{Name: "journey x", Start: start, End: start.Add(time.Second)})
		r.Add(Span{
			Name: "click \"Submit\"", Parent: run, Start: start, End: start.Add(time.Millisecond),
			Attrs: []Attr{
				String("journey.step.verb", "click"),
				Int("journey.step.index", 3),
				Bool("journey.selector.durable", true),
				Float("journey.assertion.timeout", 15),
			},
		})
		blob, err := r.MarshalOTLPJSON()
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return blob
	}

	first := build()
	for i := range 8 {
		if got := build(); !bytes.Equal(first, got) {
			t.Fatalf("run %d differs from the first; the encoding is not canonical:\n%s\n---\n%s",
				i, first, got)
		}
	}

	// And the same recorder marshalled twice must agree, which is the property
	// protojson does not give on its own.
	r := newTestRecorder()
	r.Add(Span{Name: "journey x", Start: time.Unix(1, 0), End: time.Unix(2, 0)})
	a, _ := r.MarshalOTLPJSON()
	b, _ := r.MarshalOTLPJSON()
	if !bytes.Equal(a, b) {
		t.Errorf("marshalling the same recorder twice must agree:\n%s\n---\n%s", a, b)
	}
}

// TestStatusIsAlwaysSet: a span with no status is indistinguishable from one
// nobody decided about, and recording passes as well as failures is what lets the
// record answer "was this ever checked?".
func TestStatusIsAlwaysSet(t *testing.T) {
	r := newTestRecorder()
	r.Add(Span{Name: "passed", Start: time.Unix(1, 0), End: time.Unix(2, 0)})
	r.Add(Span{Name: "failed", Start: time.Unix(1, 0), End: time.Unix(2, 0), Failed: true, Message: "nope"})

	blob, err := r.MarshalOTLPJSON()
	if err != nil {
		t.Fatal(err)
	}
	// OTLP/JSON renders the enum by name; OK is 1 and ERROR is 2.
	if !strings.Contains(string(blob), "STATUS_CODE_OK") {
		t.Error("a passing span should carry an explicit Ok status")
	}
	if !strings.Contains(string(blob), "STATUS_CODE_ERROR") {
		t.Error("a failing span should carry an Error status")
	}
	if !strings.Contains(string(blob), "nope") {
		t.Error("the status message should carry the comparison")
	}
}

func TestParentIsRecorded(t *testing.T) {
	r := newTestRecorder()
	run := r.Add(Span{Name: "journey x", Start: time.Unix(1, 0), End: time.Unix(9, 0)})
	r.Add(Span{Name: "step", Parent: run, Start: time.Unix(2, 0), End: time.Unix(3, 0)})

	blob, _ := r.MarshalOTLPJSON()
	var doc struct {
		ResourceSpans []struct {
			ScopeSpans []struct {
				Spans []struct {
					Name         string `json:"name"`
					SpanID       string `json:"spanId"`
					ParentSpanID string `json:"parentSpanId"`
				} `json:"spans"`
			} `json:"scopeSpans"`
		} `json:"resourceSpans"`
	}
	if err := json.Unmarshal(blob, &doc); err != nil {
		t.Fatal(err)
	}
	spans := doc.ResourceSpans[0].ScopeSpans[0].Spans
	if len(spans) != 2 {
		t.Fatalf("want two spans, got %d", len(spans))
	}
	if spans[0].ParentSpanID != "" {
		t.Error("the root span should have no parent")
	}
	if spans[1].ParentSpanID != spans[0].SpanID {
		t.Errorf("the step should be a child of the run: %q vs %q", spans[1].ParentSpanID, spans[0].SpanID)
	}
}

// TestEmptyAttributesAreDropped: an absent property should be absent, not
// present-and-empty, or a query for "steps with no automation id" cannot
// distinguish them.
func TestEmptyAttributesAreDropped(t *testing.T) {
	r := newTestRecorder()
	r.Add(Span{
		Name: "x", Start: time.Unix(1, 0), End: time.Unix(2, 0),
		Attrs: []Attr{String("journey.selector.name", ""), String("journey.step.verb", "click")},
	})
	blob, _ := r.MarshalOTLPJSON()
	if strings.Contains(string(blob), "journey.selector.name") {
		t.Errorf("an empty attribute should not be written:\n%s", blob)
	}
	if !strings.Contains(string(blob), "journey.step.verb") {
		t.Error("a set attribute should survive")
	}
}
