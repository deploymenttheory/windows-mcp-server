package watch

import (
	"sync"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/audit"
)

// memSink captures audit entries in memory for verification.
type memSink struct {
	mu      sync.Mutex
	entries []audit.AuditEntry
	flushes int
}

func (m *memSink) Write(e audit.AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, e)
	return nil
}
func (m *memSink) Flush() error { m.mu.Lock(); defer m.mu.Unlock(); m.flushes++; return nil }
func (m *memSink) Close() error { return nil }
