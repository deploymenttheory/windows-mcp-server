package status

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/contain"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/signals"
)

// TestKillToolRoutesToSuppliedStop pins the indirection that lets the server layer
// decide what "Kill" means: the tool never reaches for the kill switch itself, so
// an unarmed operator gets a graceful stop instead of the containment ladder.
func TestKillToolRoutesToSuppliedStop(t *testing.T) {
	var got string
	tool, handler := KillTool(func(reason string) { got = reason })

	if tool.Name != "Kill" {
		t.Errorf("tool name = %q, want Kill", tool.Name)
	}
	if tool.Annotations == nil || tool.Annotations.DestructiveHint == nil || !*tool.Annotations.DestructiveHint {
		t.Error("Kill must carry a destructive hint")
	}

	req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{
		Name:      "Kill",
		Arguments: json.RawMessage(`{"reason":"journey complete"}`),
	}}
	res, err := handler(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || len(res.Content) == 0 {
		t.Fatal("Kill must return a result")
	}
	if !strings.Contains(got, "journey complete") {
		t.Errorf("stop reason = %q, want the caller's reason", got)
	}
}

// TestKillToolWithoutReasonStillStops covers the no-arguments call.
func TestKillToolWithoutReasonStillStops(t *testing.T) {
	var called bool
	_, handler := KillTool(func(string) { called = true })

	req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "Kill"}}
	if _, err := handler(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Error("Kill with no reason must still stop the session")
	}
}

// TestGuardrailStatusOmitsDurableDeviceIdentifiers pins what the agent-facing
// tool does not return.
//
// GuardrailStatus serialised the whole decision, including the hardware serial,
// the Entra device ID and the tenant ID. Those identify the machine and the
// organisation, are durable, and tell an agent nothing about what it may do --
// they are worth something only to an attacker correlating this session with a
// fleet, and a prompt-injected agent can put whatever it reads into an outbound
// request. The authenticated loopback endpoint still returns everything.
func TestGuardrailStatusOmitsDurableDeviceIdentifiers(t *testing.T) {
	decision := signals.Decision{
		Admit: true,
		Device: signals.DeviceIdentity{
			Hostname:      "WORKSTATION-01",
			Serial:        "SERIAL-SECRET-123",
			EntraDeviceID: "11111111-2222-3333-4444-555555555555",
			TenantID:      "66666666-7777-8888-9999-000000000000",
		},
	}
	_, handler := StatusTool(
		func() signals.Decision { return decision },
		func() ServerStatus { return ServerStatus{} },
		contain.NewKillSwitch(nil),
	)
	res, err := handler(context.Background(), &mcp.CallToolRequest{})
	if err != nil {
		t.Fatal(err)
	}
	body := res.Content[0].(*mcp.TextContent).Text

	for _, secret := range []string{"SERIAL-SECRET-123", "11111111-2222", "66666666-7777"} {
		if strings.Contains(body, secret) {
			t.Errorf("GuardrailStatus leaked a durable device identifier containing %q", secret)
		}
	}
	if !strings.Contains(body, "WORKSTATION-01") {
		t.Error("hostname should still be reported: it is how a report names the machine, " +
			"and it is visible from a dozen other places on the desktop")
	}
}

// TestStatusServerRefusesToBindWithoutAToken asserts the requirement at the
// listener, not only at policy load.
//
// auth() was a no-op when Token was empty, so an empty token meant no
// authentication at all rather than a closed door -- and /revoke trips the kill
// switch. StatusServer is an exported struct with exported fields, so any
// construction path that does not go through policy.Load got an unauthenticated
// kill endpoint that any local process could reach.
func TestStatusServerRefusesToBindWithoutAToken(t *testing.T) {
	ss := &StatusServer{
		Addr:    "127.0.0.1:0",
		Current: func() signals.Decision { return signals.Decision{} },
		Kill:    contain.NewKillSwitch(nil),
	}
	err := ss.Start(context.Background())
	if err == nil {
		t.Fatal("binding without a token must fail: /revoke would be unauthenticated")
	}
	if !errors.Is(err, ErrStatusTokenRequired) {
		t.Errorf("want ErrStatusTokenRequired, got %v", err)
	}
}
