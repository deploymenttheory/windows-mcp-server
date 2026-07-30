package guardrails

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// memSink captures entries in memory for verification.
type memSink struct {
	mu      sync.Mutex
	entries []AuditEntry
	flushes int
}

func (m *memSink) Write(e AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, e)
	return nil
}
func (m *memSink) Flush() error { m.mu.Lock(); defer m.mu.Unlock(); m.flushes++; return nil }
func (m *memSink) Close() error { return nil }

func TestAuditChainVerifies(t *testing.T) {
	sink := &memSink{}
	log := NewAuditLog(sink)
	for i := 0; i < 5; i++ {
		if _, err := log.Append("test.event", map[string]any{"i": i}); err != nil {
			t.Fatal(err)
		}
	}
	if err := VerifyChain(sink.entries); err != nil {
		t.Fatalf("valid chain should verify: %v", err)
	}
	if seq, head := log.Head(); seq != 5 || head == "" {
		t.Errorf("Head() = %d,%q; want seq 5 and non-empty head", seq, head)
	}
}

func TestAuditDetectsTamper(t *testing.T) {
	sink := &memSink{}
	log := NewAuditLog(sink)
	for i := 0; i < 4; i++ {
		log.Append("e", map[string]any{"i": i})
	}

	// Edit a payload without recomputing hashes → chain must break.
	tampered := append([]AuditEntry(nil), sink.entries...)
	tampered[1].Payload = json.RawMessage(`{"i":999}`)
	if err := VerifyChain(tampered); err == nil {
		t.Error("edited payload should break the chain")
	}

	// Delete an entry (gap) → break.
	gap := []AuditEntry{sink.entries[0], sink.entries[2], sink.entries[3]}
	if err := VerifyChain(gap); err == nil {
		t.Error("deleted entry should break the chain")
	}

	// Reorder → break.
	reordered := []AuditEntry{sink.entries[1], sink.entries[0], sink.entries[2], sink.entries[3]}
	if err := VerifyChain(reordered); err == nil {
		t.Error("reordered entries should break the chain")
	}
}

func TestAuditMiddlewareLogsDigestNotArgs(t *testing.T) {
	sink := &memSink{}
	log := NewAuditLog(sink)
	mw := log.Middleware()
	secret := `{"command":"super-secret-password"}`
	req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "PowerShell", Arguments: json.RawMessage(secret)}}

	var reached bool
	next := func(context.Context, string, mcp.Request) (mcp.Result, error) {
		reached = true
		return &mcp.CallToolResult{}, nil
	}
	if _, err := mw(next)(context.Background(), "tools/call", req); err != nil {
		t.Fatal(err)
	}
	if !reached {
		t.Error("audit middleware must always call next (never blocks)")
	}
	if len(sink.entries) != 1 {
		t.Fatalf("want 1 audit entry, got %d", len(sink.entries))
	}
	payload := string(sink.entries[0].Payload)
	if containsSubstr(payload, "super-secret-password") {
		t.Errorf("raw args leaked into audit payload: %s", payload)
	}
	if !containsSubstr(payload, "args_sha256") || !containsSubstr(payload, "PowerShell") {
		t.Errorf("audit payload missing tool/digest: %s", payload)
	}
}

func containsSubstr(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

// TestAuditCoversResourceAndPromptReads is the guard on the data-egress paths
// added alongside prompts and resources. A resource read returns desktop or
// system state to the caller; leaving it out of the hash chain would be a hole in
// the audit trail.
func TestAuditCoversResourceAndPromptReads(t *testing.T) {
	sink := &memSink{}
	log := NewAuditLog(sink)
	mw := log.Middleware()
	next := func(context.Context, string, mcp.Request) (mcp.Result, error) {
		return &mcp.CallToolResult{}, nil
	}

	readReq := &mcp.ReadResourceRequest{Params: &mcp.ReadResourceParams{URI: "windows://desktop/snapshot"}}
	if _, err := mw(next)(context.Background(), "resources/read", readReq); err != nil {
		t.Fatal(err)
	}
	promptReq := &mcp.GetPromptRequest{Params: &mcp.GetPromptParams{
		Name:      "rpa-journey",
		Arguments: map[string]string{"goal": "sign in"},
	}}
	if _, err := mw(next)(context.Background(), "prompts/get", promptReq); err != nil {
		t.Fatal(err)
	}

	if len(sink.entries) != 2 {
		t.Fatalf("want 2 audit entries, got %d", len(sink.entries))
	}
	if sink.entries[0].Event != "resource.read" {
		t.Errorf("entry 0 event = %q, want resource.read", sink.entries[0].Event)
	}
	if !containsSubstr(string(sink.entries[0].Payload), "windows://desktop/snapshot") {
		t.Errorf("resource audit should record the URI: %s", sink.entries[0].Payload)
	}
	if sink.entries[1].Event != "prompt.get" {
		t.Errorf("entry 1 event = %q, want prompt.get", sink.entries[1].Event)
	}
	// Prompt arguments are digested, never recorded raw.
	if containsSubstr(string(sink.entries[1].Payload), "sign in") {
		t.Errorf("prompt arguments leaked into the audit payload: %s", sink.entries[1].Payload)
	}
	if !containsSubstr(string(sink.entries[1].Payload), "args_sha256") {
		t.Errorf("prompt audit should carry an argument digest: %s", sink.entries[1].Payload)
	}
	if err := VerifyChain(sink.entries); err != nil {
		t.Errorf("chain must remain verifiable: %v", err)
	}
}

// TestPromptArgsDigestIsDeterministic ensures map iteration order cannot change
// the digest, which would make the audit trail non-reproducible.
func TestPromptArgsDigestIsDeterministic(t *testing.T) {
	a := promptArgsBytes(map[string]string{"z": "1", "a": "2", "m": "3"})
	b := promptArgsBytes(map[string]string{"m": "3", "z": "1", "a": "2"})
	if string(a) != string(b) {
		t.Errorf("digest input depends on map order:\n%q\n%q", a, b)
	}
}
