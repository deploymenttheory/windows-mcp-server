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
