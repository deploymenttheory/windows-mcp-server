package policy

import (
	"strings"
	"testing"
)

func TestTelemetryValidation(t *testing.T) {
	mustParse := func(s string) *Policy {
		p, err := Parse([]byte(s))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		return p
	}

	if err := mustParse(`{"version":1,"telemetry":{"endpoint":"localhost:4318","protocol":"grpc"}}`).Validate(nil); err == nil ||
		!strings.Contains(err.Error(), "not supported") {
		t.Errorf("an unsupported protocol should be rejected, got %v", err)
	}
	if err := mustParse(`{"version":1,"telemetry":{"endpoint":"x","sample_ratio":2}}`).Validate(nil); err == nil ||
		!strings.Contains(err.Error(), "out of range") {
		t.Errorf("a sample_ratio above 1 should be rejected, got %v", err)
	}
	if err := mustParse(`{"version":1,"telemetry":{"endpoint":"localhost:4318","sample_ratio":0.5}}`).Validate(nil); err != nil {
		t.Errorf("a valid telemetry block should pass, got %v", err)
	}
	// With no endpoint telemetry is off, so its other fields are not validated.
	if err := mustParse(`{"version":1,"telemetry":{"protocol":"grpc","sample_ratio":9}}`).Validate(nil); err != nil {
		t.Errorf("telemetry with no endpoint is off and should not be validated, got %v", err)
	}
}

func TestDefaultPolicyHasNoTelemetry(t *testing.T) {
	if Default().Telemetry.Endpoint != "" {
		t.Error("the built-in default must not enable telemetry: nothing is exported unless an operator asks")
	}
}
