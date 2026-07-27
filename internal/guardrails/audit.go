package guardrails

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// AuditEntry is one record in the tamper-evident, hash-chained audit log. Each
// entry commits to the previous entry's hash, so any insertion, deletion,
// reordering, or edit breaks the chain and is detectable by VerifyChain.
type AuditEntry struct {
	Seq       uint64          `json:"seq"`
	Timestamp string          `json:"timestamp"`
	Event     string          `json:"event"`
	Payload   json.RawMessage `json:"payload,omitempty"`
	PrevHash  string          `json:"prev_hash"`
	EntryHash string          `json:"entry_hash"`
}

// Sink persists audit entries. Flush must durably commit (fsync) so the chain
// survives an abrupt shutdown triggered by the kill switch.
type Sink interface {
	Write(AuditEntry) error
	Flush() error
	Close() error
}

// NewSink resolves a --with-logging target to a Sink: "" or "stderr" writes JSON
// lines to stderr (stdout is reserved for the MCP stdio transport); any other
// value is treated as a file path, appended to as JSONL and fsync-ed on Flush.
func NewSink(target string) (Sink, error) {
	switch target {
	case "", "stderr":
		return &stderrSink{}, nil
	default:
		f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, fmt.Errorf("audit sink %q: %w", target, err)
		}
		return &jsonlSink{f: f}, nil
	}
}

type stderrSink struct{ mu sync.Mutex }

func (s *stderrSink) Write(e AuditEntry) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = fmt.Fprintln(os.Stderr, "AUDIT "+string(b))
	return err
}
func (s *stderrSink) Flush() error { return nil }
func (s *stderrSink) Close() error { return nil }

type jsonlSink struct {
	mu sync.Mutex
	f  *os.File
}

func (s *jsonlSink) Write(e AuditEntry) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.f.Write(append(b, '\n'))
	return err
}
func (s *jsonlSink) Flush() error { s.mu.Lock(); defer s.mu.Unlock(); return s.f.Sync() }
func (s *jsonlSink) Close() error { s.mu.Lock(); defer s.mu.Unlock(); return s.f.Close() }

// AuditLog is an append-only, hash-chained log. It is safe for concurrent use
// and is one of the always-on transparency services the agent cannot disable.
type AuditLog struct {
	mu       sync.Mutex
	sink     Sink
	seq      uint64
	prevHash string
	clock    func() time.Time
}

// NewAuditLog builds a log over the given sink.
func NewAuditLog(sink Sink) *AuditLog {
	return &AuditLog{sink: sink, clock: time.Now}
}

// Append writes one entry linking to the prior entry's hash. payload is
// JSON-marshaled (falling back to its %v form if it cannot be marshaled). The
// chain advances only after the sink accepts the entry, so a write failure does
// not leave a gap.
func (a *AuditLog) Append(event string, payload any) (AuditEntry, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	var raw json.RawMessage
	if payload != nil {
		if b, err := json.Marshal(payload); err == nil {
			raw = b
		} else {
			raw, _ = json.Marshal(fmt.Sprintf("%v", payload))
		}
	}
	e := AuditEntry{
		Seq:       a.seq,
		Timestamp: a.clock().UTC().Format(time.RFC3339Nano),
		Event:     event,
		Payload:   raw,
		PrevHash:  a.prevHash,
	}
	e.EntryHash = hashEntry(e)
	if a.sink != nil {
		if err := a.sink.Write(e); err != nil {
			return e, err
		}
	}
	a.seq++
	a.prevHash = e.EntryHash
	return e, nil
}

// Flush durably commits the sink.
func (a *AuditLog) Flush() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sink == nil {
		return nil
	}
	return a.sink.Flush()
}

// Close flushes and closes the sink.
func (a *AuditLog) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sink == nil {
		return nil
	}
	_ = a.sink.Flush()
	return a.sink.Close()
}

// Head returns the current sequence length and the hash of the last entry (the
// chain head) — surfaced in the status snapshot so a poller can detect stalls
// or divergence.
func (a *AuditLog) Head() (seq uint64, headHash string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.seq, a.prevHash
}

// hashEntry computes the entry hash over its canonical fields plus the previous
// hash. EntryHash itself is excluded so verification can recompute it.
func hashEntry(e AuditEntry) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d\n%s\n%s\n", e.Seq, e.Timestamp, e.Event)
	h.Write(e.Payload)
	h.Write([]byte{'\n'})
	h.Write([]byte(e.PrevHash))
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyChain checks that entries form an unbroken hash chain: contiguous
// sequence from 0, each PrevHash equal to the prior EntryHash, and each
// EntryHash matching a recomputation. Any tamper (edit/insert/delete/reorder)
// returns an error naming the first broken entry.
func VerifyChain(entries []AuditEntry) error {
	prev := ""
	for i, e := range entries {
		if e.Seq != uint64(i) {
			return fmt.Errorf("entry %d: sequence gap (seq=%d)", i, e.Seq)
		}
		if e.PrevHash != prev {
			return fmt.Errorf("entry %d: prev_hash does not chain to prior entry", i)
		}
		if got := hashEntry(e); got != e.EntryHash {
			return fmt.Errorf("entry %d: entry_hash mismatch (content tampered)", i)
		}
		prev = e.EntryHash
	}
	return nil
}

// Middleware records every tools/call in the audit chain. It logs the tool name
// and a SHA-256 digest of the raw arguments — never the raw arguments
// themselves, which may carry secrets. It always calls next (audit never
// blocks; blocking is the circuit breaker's job).
func (a *AuditLog) Middleware() mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method == "tools/call" {
				if p, ok := req.GetParams().(*mcp.CallToolParamsRaw); ok {
					_, _ = a.Append("tool.call", map[string]any{
						"tool":        p.Name,
						"args_sha256": digestBytes(p.Arguments),
						"args_len":    len(p.Arguments),
					})
				}
			}
			return next(ctx, method, req)
		}
	}
}

func digestBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
