package guardrails

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// HashTools computes a canonical SHA-256 fingerprint of a tool manifest: each
// tool's name, description, input/output schemas, and annotations, hashed in
// name order so the result is independent of registration/list order.
func HashTools(tools []*mcp.Tool) string {
	sorted := make([]*mcp.Tool, len(tools))
	copy(sorted, tools)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	h := sha256.New()
	enc := json.NewEncoder(h)
	for _, t := range sorted {
		if t == nil {
			continue
		}
		_ = enc.Encode(struct {
			Name         string               `json:"name"`
			Description  string               `json:"description"`
			InputSchema  any                  `json:"input_schema"`
			OutputSchema any                  `json:"output_schema"`
			Annotations  *mcp.ToolAnnotations `json:"annotations"`
		}{t.Name, t.Description, t.InputSchema, t.OutputSchema, t.Annotations})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// RugPull detects "rug pulls": a server mutating its advertised tool set after
// deployment (added/removed/renamed tools, or silently changed descriptions or
// schemas) to smuggle unauthorized behavior past the initial approval. It pins
// a baseline fingerprint at startup and trips the kill switch on any drift,
// detected both inline (the tools/list response the client actually receives)
// and out-of-band (the periodic monitor recheck).
type RugPull struct {
	onTrip func(reason string)
	audit  *AuditLog

	mu       sync.Mutex
	baseline string
	tripped  bool
}

// NewRugPull builds a detector; onTrip fires the kill switch, audit records the
// event (both may be nil in tests).
func NewRugPull(onTrip func(reason string), audit *AuditLog) *RugPull {
	return &RugPull{onTrip: onTrip, audit: audit}
}

// SetBaseline pins the fingerprint of the manifest as registered at startup
// (call after every AddTool, before serving). Returns the baseline hash.
func (r *RugPull) SetBaseline(tools []*mcp.Tool) string {
	h := HashTools(tools)
	r.mu.Lock()
	r.baseline = h
	r.mu.Unlock()
	return h
}

// Baseline returns the pinned fingerprint (for the status snapshot).
func (r *RugPull) Baseline() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.baseline
}

// compare trips once if hash diverges from the baseline. Returns an error on
// drift (used by the monitor recheck).
func (r *RugPull) compare(hash, source string) error {
	r.mu.Lock()
	if r.baseline == "" || hash == r.baseline || r.tripped {
		r.mu.Unlock()
		return nil
	}
	r.tripped = true
	base := r.baseline
	r.mu.Unlock()

	reason := fmt.Sprintf("tool manifest changed after startup (%s): %s != baseline %s", source, short(hash), short(base))
	if r.audit != nil {
		_, _ = r.audit.Append("rugpull.detected", map[string]any{"source": source, "hash": hash, "baseline": base})
	}
	if r.onTrip != nil {
		r.onTrip(reason)
	}
	return fmt.Errorf("%s", reason)
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// Middleware re-fingerprints the tools/list response the client receives and
// trips on drift. It only compares complete single-page responses (no incoming
// cursor and no NextCursor) so pagination cannot cause a false positive; with
// the default page size (1000) the full manifest is always one page.
func (r *RugPull) Middleware() mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			res, err := next(ctx, method, req)
			if err != nil || method != "listTools" && method != "tools/list" {
				return res, err
			}
			lt, ok := res.(*mcp.ListToolsResult)
			if !ok || lt.NextCursor != "" {
				return res, err
			}
			if p, ok := req.GetParams().(*mcp.ListToolsParams); ok && p.Cursor != "" {
				return res, err // a later page; skip
			}
			_ = r.compare(HashTools(lt.Tools), "tools/list")
			return res, err
		}
	}
}

// Recheck re-fingerprints the current manifest out-of-band (registered by the
// in-flight monitor). The caller supplies the live tool set.
func (r *RugPull) Recheck(tools []*mcp.Tool) error {
	return r.compare(HashTools(tools), "monitor")
}
