package policy

import "testing"

// TestAuditSinkAliasStillLoads pins backward compatibility for the rename: a
// policy written with the old audit_sink key still loads, folded into
// audit_destination, so nothing that worked before the rename breaks.
func TestAuditSinkAliasStillLoads(t *testing.T) {
	p, err := Parse([]byte(`{"version":1,"transparency":{"audit_sink":"C:\\logs\\audit\\"}}`))
	if err != nil {
		t.Fatalf("a policy using the deprecated audit_sink should still parse: %v", err)
	}
	if p.Transparency.AuditDestination != `C:\logs\audit\` {
		t.Errorf("audit_sink should fold into AuditDestination, got %q", p.Transparency.AuditDestination)
	}
	if p.Transparency.AuditSink != "" {
		t.Error("the alias field should be cleared after folding, so the canonical form is audit_destination")
	}

	// The new key loads directly.
	p2, err := Parse([]byte(`{"version":1,"transparency":{"audit_destination":"stderr"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if p2.Transparency.AuditDestination != "stderr" {
		t.Errorf("audit_destination should load directly, got %q", p2.Transparency.AuditDestination)
	}

	// When both are present, the new key wins and the alias is dropped.
	p3, _ := Parse([]byte(`{"version":1,"transparency":{"audit_destination":"stderr","audit_sink":"C:\\old\\"}}`))
	if p3.Transparency.AuditDestination != "stderr" {
		t.Errorf("audit_destination should take precedence over the alias, got %q", p3.Transparency.AuditDestination)
	}
}
