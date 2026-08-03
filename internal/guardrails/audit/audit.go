// Package audit is the tamper-evident record of what a session did.
//
// Every entry commits to the previous entry's hash, so any edit, insertion,
// deletion or reorder breaks the chain and VerifyChain says where. It is a leaf
// of the guardrails stack: the policy engine, the watchers and the containment
// ladder all write to it, and it depends on none of them.
//
// That direction is deliberate. Recording must never be contingent on the thing
// being recorded — a containment action that failed to run still has to leave a
// trace that it was attempted.
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
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
	// Mac is an HMAC-SHA256 over EntryHash under a key the session holds but does
	// not write down. It is present only when the log was keyed
	// (WINDOWS_MCP_AUDIT_KEY set); an unkeyed chain omits it. Because EntryHash
	// already commits to every other field, MACing it binds the whole entry.
	Mac string `json:"mac,omitempty"`
}

// Destination persists audit entries. Flush must durably commit (fsync) so the chain
// survives an abrupt shutdown triggered by the kill switch.
type Destination interface {
	Write(AuditEntry) error
	Flush() error
	Close() error
}

// NewDestination resolves an audit_sink target to a Destination without a session id. Prefer
// OpenDestination from a server that has a session id to name a per-session file after;
// this exists for callers that only ever use stderr or a single-file destination.
func NewDestination(target string) (Destination, error) { return OpenDestination(target, "") }

// OpenDestination resolves an audit_sink target plus a session id into a Destination. The id is
// a timestamp stamp such as "20260803-120000", shared with the recorder so the
// audit file and the recording correlate by name.
//
// Three modes:
//   - "" or "stderr": JSON lines to stderr (stdout is reserved for the MCP stdio
//     transport). The id is ignored.
//   - a directory (an existing directory, or any path ending in a separator): one
//     session-<id>.audit.jsonl per run plus a shared, hash-chained
//     audit-manifest.jsonl that links session heads. Because each run writes its
//     own file, restarting no longer restarts the sequence inside a shared file;
//     the manifest is what carries continuity across runs, and an unsealed session
//     still leaves a chained trace, so a restart cannot silently drop history.
//   - any other value: a single append-only JSONL file, fsync-ed on Flush — the
//     legacy behaviour, preserved so existing configurations keep working.
func OpenDestination(target, sessionID string) (Destination, error) {
	switch {
	case target == "" || target == "stderr":
		return &stderrDestination{}, nil
	case isDirTarget(target):
		return newSessionDestination(target, sessionID)
	default:
		f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, fmt.Errorf("audit destination %q: %w", target, err)
		}
		return &jsonlDestination{f: f}, nil
	}
}

// isDirTarget reports whether an audit_sink value names a directory: an explicit
// trailing separator (so a not-yet-created directory still resolves to directory
// mode) or an existing directory on disk.
func isDirTarget(target string) bool {
	if strings.HasSuffix(target, "/") || strings.HasSuffix(target, `\`) {
		return true
	}
	info, err := os.Stat(target)
	return err == nil && info.IsDir()
}

type stderrDestination struct{ mu sync.Mutex }

func (s *stderrDestination) Write(e AuditEntry) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = fmt.Fprintln(os.Stderr, "AUDIT "+string(b))
	return err
}
func (s *stderrDestination) Flush() error { return nil }
func (s *stderrDestination) Close() error { return nil }

type jsonlDestination struct {
	mu sync.Mutex
	f  *os.File
}

func (s *jsonlDestination) Write(e AuditEntry) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.f.Write(append(b, '\n'))
	return err
}
func (s *jsonlDestination) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.f.Sync(); err != nil {
		return fmt.Errorf("audit destination: sync: %w", err)
	}
	return nil
}

func (s *jsonlDestination) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.f.Close(); err != nil {
		return fmt.Errorf("audit destination: close: %w", err)
	}
	return nil
}

// AuditLog is an append-only, hash-chained log. It is safe for concurrent use
// and is one of the always-on transparency services the agent cannot disable.
type AuditLog struct {
	mu       sync.Mutex
	dest     Destination
	seq      uint64
	prevHash string
	clock    func() time.Time
	key      []byte
}

// Option configures an AuditLog at construction.
type Option func(*AuditLog)

// WithHMACKey keys the log: every entry gets an HMAC over its EntryHash under key.
// An empty key is ignored, so an absent WINDOWS_MCP_AUDIT_KEY leaves the log
// unkeyed — the default — rather than keyed with nothing.
func WithHMACKey(key []byte) Option {
	return func(a *AuditLog) {
		if len(key) > 0 {
			a.key = key
		}
	}
}

// NewAuditLog builds a log over the given destination. With no options it is unkeyed,
// which is the default posture; pass WithHMACKey to bind each entry with an HMAC.
func NewAuditLog(dest Destination, opts ...Option) *AuditLog {
	a := &AuditLog{dest: dest, clock: time.Now}
	for _, o := range opts {
		o(a)
	}
	return a
}

// Append writes one entry linking to the prior entry's hash. payload is
// JSON-marshaled (falling back to its %v form if it cannot be marshaled). The
// chain advances only after the destination accepts the entry, so a write failure does
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
	if a.key != nil {
		e.Mac = macOf(a.key, e.EntryHash)
	}
	if a.dest != nil {
		if err := a.dest.Write(e); err != nil {
			return e, err
		}
	}
	a.seq++
	a.prevHash = e.EntryHash
	return e, nil
}

// Flush durably commits the destination.
func (a *AuditLog) Flush() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.dest == nil {
		return nil
	}
	if err := a.dest.Flush(); err != nil {
		return fmt.Errorf("audit flush: %w", err)
	}
	return nil
}

// Close flushes and closes the destination.
func (a *AuditLog) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.dest == nil {
		return nil
	}
	_ = a.dest.Flush()
	if err := a.dest.Close(); err != nil {
		return fmt.Errorf("audit close: %w", err)
	}
	return nil
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

// ErrChainBroken is returned by VerifyChain and VerifyChainSegment when entries
// do not form an unbroken hash chain; the wrapped message names the first break.
var ErrChainBroken = errors.New("audit chain broken")

// VerifyChain checks that entries form an unbroken hash chain rooted at seq 0:
// contiguous sequence from 0, each PrevHash equal to the prior EntryHash, and
// each EntryHash matching a recomputation. Any tamper (edit/insert/delete/reorder)
// returns an error naming the first broken entry. It is VerifyChainSegment with a
// zero start and an empty preceding hash.
func VerifyChain(entries []AuditEntry) error {
	return VerifyChainSegment(entries, 0, "")
}

// VerifyChainSegment checks that entries form an unbroken hash chain beginning at
// startSeq with prevHash as the hash preceding the first entry. It is what lets a
// slice of a chain be verified on its own — a session file that does not begin at
// 0, or a range lifted into an evidence bundle — without the whole chain in hand.
// A full chain rooted at 0 is the (0, "") case that VerifyChain calls.
func VerifyChainSegment(entries []AuditEntry, startSeq uint64, prevHash string) error {
	prev := prevHash
	for i, e := range entries {
		if want := startSeq + uint64(i); e.Seq != want {
			return fmt.Errorf("%w: entry %d: sequence gap (seq=%d, want %d)", ErrChainBroken, i, e.Seq, want)
		}
		if e.PrevHash != prev {
			return fmt.Errorf("%w: entry %d: prev_hash does not chain to prior entry", ErrChainBroken, i)
		}
		if got := hashEntry(e); got != e.EntryHash {
			return fmt.Errorf("%w: entry %d: entry_hash mismatch (content tampered)", ErrChainBroken, i)
		}
		prev = e.EntryHash
	}
	return nil
}

// Middleware records every invocation that can move data in the audit chain:
// tools/call, resources/read, prompts/get, subscriptions/listen and
// server/discover.
//
// Resources and prompts are audited for the same reason tools are — a resource
// read returns desktop or system state to the caller, so it is a data-egress path
// and an unaudited one would be a hole in the chain. Arguments are recorded as a
// SHA-256 digest, never raw, since they may carry secrets.
//
// The last two exist because protocol 2026-07-28 restructured the connection
// (SEP-2575). server/discover replaced the initialize handshake, so without it the
// chain would carry no record that a client ever connected or under which
// revision; subscriptions/listen replaced the HTTP GET stream and
// resources/subscribe with a long-lived server-to-client stream, which is a
// standing data-egress path and the longest-lived one the server has.
//
// It always calls next: audit never blocks, blocking is the circuit breaker's job.
func (a *AuditLog) Middleware() mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			switch method {
			case "tools/call":
				if p, ok := req.GetParams().(*mcp.CallToolParamsRaw); ok {
					_, _ = a.Append("tool.call", map[string]any{
						"tool":        p.Name,
						"args_sha256": digestBytes(p.Arguments),
						"args_len":    len(p.Arguments),
					})
				}
			case "resources/read":
				if p, ok := req.GetParams().(*mcp.ReadResourceParams); ok {
					_, _ = a.Append("resource.read", map[string]any{"uri": p.URI})
				}
			case "prompts/get":
				if p, ok := req.GetParams().(*mcp.GetPromptParams); ok {
					_, _ = a.Append("prompt.get", map[string]any{
						"prompt":      p.Name,
						"args_sha256": digestBytes(promptArgsBytes(p.Arguments)),
					})
				}
			case "server/discover":
				if p, ok := req.GetParams().(*mcp.DiscoverParams); ok {
					_, _ = a.Append("server.discover", clientIdentity(p.Meta))
				}
			case "subscriptions/listen":
				if p, ok := req.GetParams().(*mcp.SubscriptionsListenParams); ok {
					_, _ = a.Append("subscriptions.listen", subscriptionFields(p.Notifications))
				}
			}
			return next(ctx, method, req)
		}
	}
}

// clientIdentity extracts who is connecting and under which protocol revision
// from the per-request _meta triple that 2026-07-28 uses in place of the
// initialize handshake. Fields absent from _meta are simply omitted: a
// pre-2026-07-28 client reaching server/discover as a compatibility probe carries
// none of them, and that is not an error.
func clientIdentity(meta mcp.Meta) map[string]any {
	fields := map[string]any{}
	if v, ok := meta[mcp.MetaKeyProtocolVersion].(string); ok {
		fields["protocol_version"] = v
	}
	// clientInfo arrives as decoded JSON, so it is a map rather than an
	// mcp.Implementation. Only name and version are recorded — the audit chain
	// wants an identifier, not an arbitrary client-supplied blob.
	if info, ok := meta[mcp.MetaKeyClientInfo].(map[string]any); ok {
		if name, ok := info["name"].(string); ok {
			fields["client_name"] = name
		}
		if version, ok := info["version"].(string); ok {
			fields["client_version"] = version
		}
	}
	return fields
}

// subscriptionFields records what a client asked the server to stream to it.
// The opted-in notification types and the subscribed resource URIs are
// identifiers, recorded in full for the same reason resource.read records its
// URI; nothing here carries a payload.
func subscriptionFields(n *mcp.NotificationSubscriptions) map[string]any {
	if n == nil {
		return map[string]any{}
	}
	return map[string]any{
		"tools_list_changed":     n.ToolsListChanged,
		"prompts_list_changed":   n.PromptsListChanged,
		"resources_list_changed": n.ResourcesListChanged,
		"resource_subscriptions": n.ResourceSubscriptions,
	}
}

// promptArgsBytes renders prompt arguments deterministically for digesting. Keys
// are sorted so the same arguments always produce the same digest.
func promptArgsBytes(args map[string]string) []byte {
	if len(args) == 0 {
		return nil
	}
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b bytes.Buffer
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(args[k])
		b.WriteByte('\n')
	}
	return b.Bytes()
}

func digestBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
