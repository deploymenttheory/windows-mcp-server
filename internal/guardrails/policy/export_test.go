package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// exportDoc splices a transparency block into an otherwise minimal valid policy,
// so each case below reads as the one thing it is testing. It mirrors egressDoc
// in egress_test.go.
func exportDoc(t *testing.T, transparency string) *Policy {
	t.Helper()
	raw := fmt.Sprintf(`{
	  "version": 1,
	  "mode": "audit",
	  "signals": {},
	  "rules": [],
	  "transparency": %s
	}`, transparency)
	p, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return p
}

// TestExportIsOffByDefault. A server that began shipping a session's evidence
// off-box on upgrade, with no operator action, is the same class of regression as
// one that began refusing tool calls — so the embedded default must name no
// destination, and a document that omits the block must parse to the zero value.
func TestExportIsOffByDefault(t *testing.T) {
	if e := Default().Transparency.Export; e.Enabled() {
		t.Errorf("the embedded default policy must not export evidence; got provider %q", e.Provider)
	}
	p := exportDoc(t, `{"audit_destination":"stderr"}`)
	if p.Transparency.Export.Enabled() {
		t.Error("a document with no export block must leave export disabled")
	}
	if p.Transparency.Export.Timeout != 0 {
		t.Error("a disabled export block must stay the zero value, so validation can tell " +
			"\"written but not in force\" from \"not written at all\"")
	}
}

// TestExportValidation covers each way a destination can be written wrong. Every
// one of them fails at load: the upload runs from a shutdown defer, where a
// refusal would land in a log nobody is watching.
func TestExportValidation(t *testing.T) {
	for _, tc := range []struct {
		name         string
		transparency string
		want         string
	}{
		{
			name:         "unknown provider",
			transparency: `{"audit_destination":"C:\\audit\\","evidence_dir":"C:\\ev","export":{"provider":"ftp"}}`,
			want:         "is not a provider this build implements",
		},
		{
			name: "a provider with no backend yet is refused, not deferred",
			transparency: `{"audit_destination":"C:\\audit\\","evidence_dir":"C:\\ev",` +
				`"export":{"provider":"s3"}}`,
			want: "is not a provider this build implements",
		},
		{
			name:         "configured but no provider",
			transparency: `{"audit_destination":"stderr","export":{"timeout":"30s"}}`,
			want:         "names no provider",
		},
		{
			name:         "no evidence_dir to seal a bundle into",
			transparency: `{"audit_destination":"C:\\audit\\","export":{"provider":"signed_url"}}`,
			want:         "transparency.evidence_dir is empty",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := exportDoc(t, tc.transparency).Validate(nil)
			if err == nil {
				t.Fatalf("want a validation error mentioning %q", tc.want)
			}
			if !errors.Is(err, ErrInvalidPolicy) {
				t.Errorf("want ErrInvalidPolicy, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error should mention %q; got %v", tc.want, err)
			}
		})
	}
}

// TestValidExportDocumentLoads is the positive case, and pins the default the
// operator does not have to write.
func TestValidExportDocumentLoads(t *testing.T) {
	p := exportDoc(t,
		`{"audit_destination":"C:\\audit\\","evidence_dir":"C:\\ev","export":{"provider":"signed_url"}}`)
	if err := p.Validate(nil); err != nil {
		t.Fatalf("a complete export block must validate: %v", err)
	}
	if got := p.Transparency.Export.Timeout.Std(); got != DefaultExportTimeout {
		t.Errorf("timeout = %s, want the %s default applied at parse", got, DefaultExportTimeout)
	}
}

// TestExportProviderMustHaveABackend guards the invariant behind the "refused, not
// deferred" case above: ExportProviders is the list validation admits, so a name
// added to it without a backend produces a document that loads and a server that
// cannot do what it says.
func TestExportProviderMustHaveABackend(t *testing.T) {
	for _, p := range ExportProviders() {
		if p != ExportSignedURL {
			t.Errorf("ExportProviders lists %q, which this build has no backend for; "+
				"add the provider constant in the same change as its sink", p)
		}
	}
}

// TestExportPolicyCarriesNoSecretFields. The policy document is registered as an
// agent-readable protected path, and the shell and filesystem toolsets bypass that
// check entirely — so a credential field added here would be readable by the model.
// Credentials come from fixed WINDOWS_MCP_EXPORT_* variables instead.
//
// Asserted on the serialized keys rather than on substrings of the whole document,
// so a legitimate value that happens to contain "key" cannot fail it.
func TestExportPolicyCarriesNoSecretFields(t *testing.T) {
	blob, err := json.Marshal(ExportPolicy{Provider: ExportSignedURL, Timeout: Duration(1)})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(blob, &fields); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for field := range fields {
		lower := strings.ToLower(field)
		for _, banned := range []string{
			"secret", "password", "token", "credential", "signature", "sas", "url", "key",
		} {
			if strings.Contains(lower, banned) {
				t.Errorf("transparency.export.%s looks like it carries a credential; "+
					"the document is reviewable and agent-readable, so secrets belong in "+
					"WINDOWS_MCP_EXPORT_* environment variables", field)
			}
		}
	}
}

// TestExportRoundTripsThroughTheDocument: the block must survive marshal/parse, or
// `policy explain` and the fuzz round-trip would disagree with what was loaded.
func TestExportRoundTripsThroughTheDocument(t *testing.T) {
	original := exportDoc(t,
		`{"audit_destination":"C:\\audit\\","evidence_dir":"C:\\ev",`+
			`"export":{"provider":"signed_url","timeout":"90s"}}`)

	blob, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	reparsed, err := Parse(blob)
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	if reparsed.Transparency.Export != original.Transparency.Export {
		t.Errorf("export block did not round-trip: %+v vs %+v",
			reparsed.Transparency.Export, original.Transparency.Export)
	}
}
