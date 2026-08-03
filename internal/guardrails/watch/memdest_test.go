package watch

import (
	"sync"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/audit"
)

// memDest captures audit entries in memory for verification.
type memDest struct {
	mu      sync.Mutex
	entries []audit.AuditEntry
	flushes int
}

func (m *memDest) Write(e audit.AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, e)
	return nil
}
func (m *memDest) Flush() error { m.mu.Lock(); defer m.mu.Unlock(); m.flushes++; return nil }
func (m *memDest) Close() error { return nil }
