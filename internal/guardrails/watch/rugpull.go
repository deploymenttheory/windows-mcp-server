package watch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/audit"
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

// HashPrompts fingerprints a prompt manifest: each prompt's name, description,
// title and argument list, hashed in name order.
func HashPrompts(prompts []*mcp.Prompt) string {
	sorted := make([]*mcp.Prompt, len(prompts))
	copy(sorted, prompts)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	h := sha256.New()
	enc := json.NewEncoder(h)
	for _, p := range sorted {
		if p == nil {
			continue
		}
		_ = enc.Encode(struct {
			Name        string                `json:"name"`
			Title       string                `json:"title"`
			Description string                `json:"description"`
			Arguments   []*mcp.PromptArgument `json:"arguments"`
		}{p.Name, p.Title, p.Description, p.Arguments})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// HashResources fingerprints a fixed-URI resource manifest: each resource's URI,
// name, title, description and MIME type, hashed in URI order.
func HashResources(resources []*mcp.Resource) string {
	sorted := make([]*mcp.Resource, len(resources))
	copy(sorted, resources)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].URI < sorted[j].URI })

	h := sha256.New()
	enc := json.NewEncoder(h)
	for _, res := range sorted {
		if res == nil {
			continue
		}
		_ = enc.Encode(struct {
			URI         string `json:"uri"`
			Name        string `json:"name"`
			Title       string `json:"title"`
			Description string `json:"description"`
			MIMEType    string `json:"mime_type"`
		}{res.URI, res.Name, res.Title, res.Description, res.MIMEType})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// HashDiscover fingerprints the server's *advertisement*: the capabilities it
// declares and the instructions it hands the model. Both reach the client through
// server/discover (protocol 2026-07-28, SEP-2575) and, for older clients, through
// initialize.
//
// SupportedVersions is deliberately excluded. It is derived by the SDK from the
// transport rather than declared by us, so it legitimately differs between the
// stdio server and an HTTP one — fingerprinting it would report a transport
// difference as an attack.
func HashDiscover(caps *mcp.ServerCapabilities, instructions string) string {
	h := sha256.New()
	// Capabilities carry Go maps (Experimental, Extensions); encoding/json sorts
	// map keys, so the encoding is canonical without sorting them here.
	_ = json.NewEncoder(h).Encode(struct {
		Capabilities *mcp.ServerCapabilities `json:"capabilities"`
		Instructions string                  `json:"instructions"`
	}{caps, instructions})
	return hex.EncodeToString(h.Sum(nil))
}

// RugPull detects "rug pulls": a server mutating its advertised tool set after
// deployment (added/removed/renamed tools, or silently changed descriptions or
// schemas) to smuggle unauthorized behavior past the initial approval. It pins
// a baseline fingerprint at startup and trips the kill switch on any drift,
// detected both inline (the tools/list response the client actually receives)
// and out-of-band (the periodic monitor recheck).
// Detection now spans four surfaces, because prompts and resources steer the
// model just as tools do — a mutated prompt changes the instructions the model
// follows, and a mutated resource URI changes what it reads — and because
// 2026-07-28 makes server/discover the canonical advertisement of capabilities
// and instructions, a channel that would otherwise drift unwatched.
type RugPull struct {
	onTrip func(reason string)
	audit  *audit.AuditLog

	mu sync.Mutex
	// baselines maps a surface ("tools", "prompts", "resources") to its pinned
	// fingerprint. A surface with no baseline is not checked, so a server that
	// serves no prompts cannot trip on them.
	baselines map[string]string
	tripped   bool
}

// Surfaces a rug pull can be detected on.
const (
	surfaceTools     = "tools"
	surfacePrompts   = "prompts"
	surfaceResources = "resources"
	surfaceDiscover  = "discover"
)

// NewRugPull builds a detector; onTrip fires the kill switch, audit records the
// event (both may be nil in tests).
func NewRugPull(onTrip func(reason string), audit *audit.AuditLog) *RugPull {
	return &RugPull{onTrip: onTrip, audit: audit, baselines: map[string]string{}}
}

// SetBaseline pins the fingerprint of the tool manifest as registered at startup
// (call after every AddTool, before serving). Returns the baseline hash.
func (r *RugPull) SetBaseline(tools []*mcp.Tool) string {
	return r.setBaseline(surfaceTools, HashTools(tools))
}

// SetPromptBaseline pins the fingerprint of the prompt manifest.
func (r *RugPull) SetPromptBaseline(prompts []*mcp.Prompt) string {
	return r.setBaseline(surfacePrompts, HashPrompts(prompts))
}

// SetResourceBaseline pins the fingerprint of the fixed-URI resource manifest.
func (r *RugPull) SetResourceBaseline(resources []*mcp.Resource) string {
	return r.setBaseline(surfaceResources, HashResources(resources))
}

// SetDiscoverBaseline pins the fingerprint of the capabilities and instructions
// handed to the server at construction — the values server/discover and
// initialize advertise. Pinning from what we pass in, rather than from the first
// response observed, means drift is caught on the very first client call.
func (r *RugPull) SetDiscoverBaseline(caps *mcp.ServerCapabilities, instructions string) string {
	return r.setBaseline(surfaceDiscover, HashDiscover(caps, instructions))
}

func (r *RugPull) setBaseline(surface, hash string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.baselines == nil {
		r.baselines = map[string]string{}
	}
	r.baselines[surface] = hash
	return hash
}

// Baseline returns the pinned tool fingerprint (for the status snapshot).
func (r *RugPull) Baseline() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.baselines[surfaceTools]
}

// compare trips once if the tool manifest diverges. Returns an error on drift
// (used by the monitor recheck).
func (r *RugPull) compare(hash, source string) error {
	return r.compareSurface(surfaceTools, hash, source)
}

func (r *RugPull) comparePrompts(hash, source string) error {
	return r.compareSurface(surfacePrompts, hash, source)
}

func (r *RugPull) compareResources(hash, source string) error {
	return r.compareSurface(surfaceResources, hash, source)
}

func (r *RugPull) compareDiscover(hash, source string) error {
	return r.compareSurface(surfaceDiscover, hash, source)
}

// compareSurface trips once if hash diverges from that surface's baseline. A
// surface with no pinned baseline is skipped rather than treated as drift.
func (r *RugPull) compareSurface(surface, hash, source string) error {
	r.mu.Lock()
	base := r.baselines[surface]
	if base == "" || hash == base || r.tripped {
		r.mu.Unlock()
		return nil
	}
	r.tripped = true
	r.mu.Unlock()

	reason := fmt.Sprintf("%s manifest changed after startup (%s): %s != baseline %s",
		surface, source, short(hash), short(base))
	if r.audit != nil {
		_, _ = r.audit.Append("rugpull.detected", map[string]any{
			"surface": surface, "source": source, "hash": hash, "baseline": base,
		})
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

// PromptMiddleware detects drift in the served prompt manifest, the same way
// Middleware does for tools. Prompts carry instructions that steer the model, so
// a silently mutated prompt is as much a rug pull as a mutated tool.
func (r *RugPull) PromptMiddleware() mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			res, err := next(ctx, method, req)
			if err != nil || method != "prompts/list" {
				return res, err
			}
			lp, ok := res.(*mcp.ListPromptsResult)
			if !ok || lp.NextCursor != "" {
				return res, err
			}
			if p, ok := req.GetParams().(*mcp.ListPromptsParams); ok && p.Cursor != "" {
				return res, err
			}
			_ = r.comparePrompts(HashPrompts(lp.Prompts), "prompts/list")
			return res, err
		}
	}
}

// ResourceMiddleware detects drift in the served resource manifest. A mutated
// resource URI or description can redirect what the model reads.
func (r *RugPull) ResourceMiddleware() mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			res, err := next(ctx, method, req)
			if err != nil || method != "resources/list" {
				return res, err
			}
			lr, ok := res.(*mcp.ListResourcesResult)
			if !ok || lr.NextCursor != "" {
				return res, err
			}
			if p, ok := req.GetParams().(*mcp.ListResourcesParams); ok && p.Cursor != "" {
				return res, err
			}
			_ = r.compareResources(HashResources(lr.Resources), "resources/list")
			return res, err
		}
	}
}

// DiscoverMiddleware detects drift in what the server advertises about itself.
//
// Protocol 2026-07-28 removed the initialize handshake and made server/discover
// the mandatory, canonical statement of a server's capabilities and instructions
// (SEP-2575). That makes it a rug-pull vector in its own right: a server can
// widen its declared capabilities, or rewrite the instructions steering the
// model, without touching tools/list at all. Both methods are covered, because
// the same advertisement reaches pre-2026-07-28 clients through initialize.
func (r *RugPull) DiscoverMiddleware() mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			res, err := next(ctx, method, req)
			if err != nil {
				return res, err
			}
			switch method {
			case "server/discover":
				if d, ok := res.(*mcp.DiscoverResult); ok {
					_ = r.compareDiscover(HashDiscover(d.Capabilities, d.Instructions), method)
				}
			case "initialize":
				if i, ok := res.(*mcp.InitializeResult); ok {
					_ = r.compareDiscover(HashDiscover(i.Capabilities, i.Instructions), method)
				}
			}
			return res, err
		}
	}
}

// Recheck re-fingerprints the current manifest out-of-band (registered by the
// in-flight monitor). The caller supplies the live tool set.
func (r *RugPull) Recheck(tools []*mcp.Tool) error {
	return r.compare(HashTools(tools), "monitor")
}
