package policy

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// FuzzParse drives the policy-document parser — the largest file in the repo, with
// several hand-written JSON codecs (Severity, Duration, StringSet) — on arbitrary
// input. An operator may source a document from elsewhere, so the parser must
// never panic, and a document that parses must survive a marshal/parse round-trip
// unchanged: an asymmetry in a custom codec would silently rewrite a policy, which
// on a security document is a correctness bug of the first order.
func FuzzParse(f *testing.F) {
	// Seed with the built-in default and every shipped example, so the corpus
	// starts from real documents that exercise the codecs, then mutates outward.
	if def := Default(); def != nil {
		if b, err := json.Marshal(def); err == nil {
			f.Add(b)
		}
	}
	for _, path := range shippedExamples() {
		if b, err := os.ReadFile(path); err == nil {
			f.Add(b)
		}
	}
	// A few inline documents that lean on the custom codecs specifically.
	for _, s := range []string{
		`{"version":1,"mode":"enforce","rules":[{"name":"r","match":{"toolset":"*"},"require":["run-context"],"on_fail":"kill"}]}`,
		`{"version":1,"signals":{"x":{"ttl":"0s"}},"transparency":{"heartbeat":"5m","anchor":{"destination":"eventlog","cadence":"90s"}}}`,
		`{"version":1,"credentials":{"acknowledge_toolset_exposure":"shell"}}`,
		`{"version":1,"egress":{"enabled":true,"allow":["*.example.com","10.0.0.1"],"allow_ports":[443,80]}}`,
	} {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		p, err := Parse(raw)
		if err != nil {
			return // an invalid document is a valid outcome; it just must not panic
		}

		// The canonical form of a parsed policy must be stable: marshaling it and
		// parsing that back must marshal identically. That is what "round-trips
		// unchanged" means for a config document — a codec that rewrote a value
		// (a Duration, a Severity, a scalar-or-array StringSet) would show up as a
		// difference here. (Struct-level equality is deliberately not used: a nil
		// and an empty slice mean the same thing and serialize the same way.)
		b1, err := json.Marshal(p)
		if err != nil {
			t.Fatalf("a parsed policy failed to marshal: %v", err)
		}
		p2, err := Parse(b1)
		if err != nil {
			t.Fatalf("re-parsing a marshaled policy failed: %v\ndocument: %s", err, b1)
		}
		b2, err := json.Marshal(p2)
		if err != nil {
			t.Fatalf("re-marshaling failed: %v", err)
		}
		if !bytes.Equal(b1, b2) {
			t.Fatalf("marshal/parse is not idempotent:\nfirst:  %s\nsecond: %s", b1, b2)
		}
	})
}

// shippedExamples returns the paths of the committed example policies, or nil if
// the directory cannot be located (the seeds are a convenience, not required).
func shippedExamples() []string {
	matches, err := filepath.Glob(filepath.Join("..", "..", "..", "policy", "examples", "*.json"))
	if err != nil {
		return nil
	}
	return matches
}
