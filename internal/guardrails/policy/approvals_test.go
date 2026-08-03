package policy

import (
	"strings"
	"testing"
)

// approveRule is a minimal valid document whose one rule disposes to approve,
// parameterised by the approvals block appended to it.
func holdDoc(approvals string) string {
	return `{
		"version": 1,
		"mode": "enforce",
		"signals": {"device-encryption": {"ttl": "0s"}},
		"rules": [{
			"name": "gate-destructive",
			"match": {"annotation": "destructive"},
			"require": ["device-encryption"],
			"on_fail": "hold"
		}]` + approvals + `
	}`
}

func TestApprovalsValidation(t *testing.T) {
	known := []string{"device-encryption"}

	t.Run("hold rule needs a webhook", func(t *testing.T) {
		p, err := Parse([]byte(holdDoc("")))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		err = p.Validate(known)
		if err == nil || !strings.Contains(err.Error(), "needs an authoriser") {
			t.Fatalf("an hold rule without a webhook must be refused, got %v", err)
		}
	})

	t.Run("hold rule with a webhook passes and defaults timings", func(t *testing.T) {
		p, err := Parse([]byte(holdDoc(`, "approvals": {"webhook_url": "https://approver.example/hook"}`)))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if err := p.Validate(known); err != nil {
			t.Fatalf("valid approvals document rejected: %v", err)
		}
		if p.Approvals.Timeout.Std() != DefaultApprovalTimeout {
			t.Errorf("timeout default = %s, want %s", p.Approvals.Timeout, DefaultApprovalTimeout)
		}
		if p.Approvals.PollInterval.Std() != DefaultApprovalPoll {
			t.Errorf("poll default = %s, want %s", p.Approvals.PollInterval, DefaultApprovalPoll)
		}
	})

	t.Run("webhook must be http or https", func(t *testing.T) {
		p, _ := Parse([]byte(holdDoc(`, "approvals": {"webhook_url": "ftp://approver.example/hook"}`)))
		if err := p.Validate(known); err == nil || !strings.Contains(err.Error(), "http or https") {
			t.Fatalf("a non-http webhook must be refused, got %v", err)
		}
	})

	t.Run("poll interval may not exceed the timeout", func(t *testing.T) {
		p, _ := Parse([]byte(holdDoc(
			`, "approvals": {"webhook_url": "https://x/y", "timeout": "5s", "poll_interval": "30s"}`)))
		if err := p.Validate(known); err == nil || !strings.Contains(err.Error(), "exceeds the timeout") {
			t.Fatalf("poll > timeout must be refused, got %v", err)
		}
	})

	t.Run("approve is rejected on a startup rule", func(t *testing.T) {
		doc := `{
			"version": 1, "mode": "enforce",
			"signals": {"device-encryption": {"ttl": "0s"}},
			"rules": [{"name": "s", "match": {"scope": "startup"}, "require": ["device-encryption"], "on_fail": "hold"}],
			"approvals": {"webhook_url": "https://x/y"}
		}`
		p, err := Parse([]byte(doc))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if err := p.Validate(known); err == nil || !strings.Contains(err.Error(), "startup") {
			t.Fatalf("approve on a startup rule must be refused, got %v", err)
		}
	})

	t.Run("approve is rejected on a rate limit", func(t *testing.T) {
		doc := `{
			"version": 1, "mode": "enforce",
			"signals": {"device-encryption": {"ttl": "0s"}},
			"rules": [{"name": "r", "match": {"toolset": "*"}, "require": ["device-encryption"], "on_fail": "warn"}],
			"rate_limits": [{"name": "rl", "match": {"toolset": "*"}, "window": "1m", "max": 5, "on_exceed": "hold"}]
		}`
		p, err := Parse([]byte(doc))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if err := p.Validate(known); err == nil || !strings.Contains(err.Error(), "rate limit cannot suspend") {
			t.Fatalf("approve on a rate limit must be refused, got %v", err)
		}
	})
}

func TestHoldClampsToWarnInAuditMode(t *testing.T) {
	// Audit mode caps everything at warn, so an hold rule never suspends a call
	// on a device whose operator has not switched enforcement on.
	if got := ModeAuditOnly.clamp(SeverityHold); got != SeverityWarn {
		t.Fatalf("approve should clamp to warn in audit mode, got %v", got)
	}
	if got := ModeEnforcing.clamp(SeverityHold); got != SeverityHold {
		t.Fatalf("approve should survive enforcing mode, got %v", got)
	}
}

func TestDefaultPolicyHasNoApprovals(t *testing.T) {
	if Default().Approvals.WebhookURL != "" {
		t.Error("the built-in default must not configure approvals")
	}
	if Default().usesHold() {
		t.Error("the built-in default must not use the approve disposition")
	}
}

func TestApprovalTimingsDefaultOnlyWithWebhook(t *testing.T) {
	// With no webhook, the timings stay zero: absent config is dual control off, not
	// dual control with defaults.
	p, err := Parse([]byte(`{"version": 1}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Approvals.Timeout != 0 || p.Approvals.PollInterval != 0 {
		t.Errorf("timings should stay zero without a webhook, got %s/%s",
			p.Approvals.Timeout, p.Approvals.PollInterval)
	}
}
