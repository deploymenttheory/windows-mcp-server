package guardrails

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func tool(name, desc string) *mcp.Tool { return &mcp.Tool{Name: name, Description: desc} }

func TestHashToolsOrderIndependent(t *testing.T) {
	a := []*mcp.Tool{tool("Snapshot", "x"), tool("Click", "y"), tool("Kill", "z")}
	b := []*mcp.Tool{tool("Kill", "z"), tool("Snapshot", "x"), tool("Click", "y")}
	if HashTools(a) != HashTools(b) {
		t.Error("hash must be independent of tool order")
	}
}

func TestHashToolsChangesOnMutation(t *testing.T) {
	base := []*mcp.Tool{tool("A", "desc"), tool("B", "desc")}
	h := HashTools(base)
	if HashTools([]*mcp.Tool{tool("A", "desc-EDITED"), tool("B", "desc")}) == h {
		t.Error("edited description must change the hash")
	}
	if HashTools([]*mcp.Tool{tool("A", "desc"), tool("B", "desc"), tool("C", "new")}) == h {
		t.Error("added tool must change the hash")
	}
	if HashTools([]*mcp.Tool{tool("A", "desc")}) == h {
		t.Error("removed tool must change the hash")
	}
}

func TestRugPullRecheckTripsOnDrift(t *testing.T) {
	var trips int32
	rp := NewRugPull(func(string) { atomic.AddInt32(&trips, 1) }, NewAuditLog(&memSink{}))
	base := []*mcp.Tool{tool("A", "d"), tool("B", "d")}
	rp.SetBaseline(base)

	if err := rp.Recheck(base); err != nil {
		t.Errorf("unchanged manifest should not trip: %v", err)
	}
	if atomic.LoadInt32(&trips) != 0 {
		t.Fatal("no trip expected yet")
	}
	drift := append(base, tool("Evil", "exfiltrate"))
	if err := rp.Recheck(drift); err == nil {
		t.Error("added tool should trip + error")
	}
	if atomic.LoadInt32(&trips) != 1 {
		t.Errorf("want exactly 1 trip, got %d", trips)
	}
	// Idempotent: further drift does not double-trip.
	rp.Recheck(append(drift, tool("Evil2", "more")))
	if atomic.LoadInt32(&trips) != 1 {
		t.Errorf("trip must be idempotent, got %d", trips)
	}
}

func TestRugPullMiddlewareTripsOnServedDrift(t *testing.T) {
	var trips int32
	rp := NewRugPull(func(string) { atomic.AddInt32(&trips, 1) }, NewAuditLog(&memSink{}))
	base := []*mcp.Tool{tool("A", "d")}
	rp.SetBaseline(base)

	// next() returns a mutated served manifest.
	served := &mcp.ListToolsResult{Tools: []*mcp.Tool{tool("A", "d"), tool("Injected", "rug")}}
	next := func(context.Context, string, mcp.Request) (mcp.Result, error) { return served, nil }
	mw := rp.Middleware()(next)

	req := &mcp.ServerRequest[*mcp.ListToolsParams]{Params: &mcp.ListToolsParams{}}
	if _, err := mw(context.Background(), "tools/list", req); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&trips) != 1 {
		t.Errorf("served manifest drift must trip, got %d", trips)
	}
}

// TestHashToolsIgnoresResultEnvelope is the guard that matters across SDK
// upgrades. Protocol revision 2026-07-28 added required envelope fields to
// ListToolsResult (resultType, cacheScope, ttlMs), and the SDK populates them on
// every revision. The fingerprint must depend only on the tool definitions, or an
// envelope change would look like a rug pull.
//
// Note the baseline hash is NOT stable across SDK versions — go-sdk v1.7.0
// dropped omitempty from ToolAnnotations.ReadOnlyHint/IdempotentHint, so
// "readOnlyHint":false now serializes explicitly and every hash changed. That is
// harmless because the baseline and the comparison are always computed by the
// same SDK inside one process, but it means the hash is not a durable external
// identifier.
func TestHashToolsIgnoresResultEnvelope(t *testing.T) {
	tools := []*mcp.Tool{
		{Name: "A", Description: "a", InputSchema: map[string]any{"type": "object"}},
		{Name: "B", Description: "b", InputSchema: map[string]any{"type": "object"}},
	}
	want := HashTools(tools)

	// Wrap the same tools in a result carrying the 2026-07-28 envelope fields and
	// round-trip through JSON, exactly as the middleware sees them.
	raw, err := json.Marshal(map[string]any{
		"tools":      tools,
		"resultType": "complete",
		"cacheScope": "public",
		"ttlMs":      0,
	})
	if err != nil {
		t.Fatal(err)
	}
	var decoded mcp.ListToolsResult
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if got := HashTools(decoded.Tools); got != want {
		t.Errorf("envelope fields perturbed the fingerprint:\n got %s\nwant %s", got, want)
	}
}

// TestHashToolsStableAcrossPagination guards the other envelope field.
func TestHashToolsStableAcrossPagination(t *testing.T) {
	tools := []*mcp.Tool{{Name: "A", InputSchema: map[string]any{"type": "object"}}}
	a := mcp.ListToolsResult{Tools: tools}
	b := mcp.ListToolsResult{Tools: tools, NextCursor: "page2"}
	if HashTools(a.Tools) != HashTools(b.Tools) {
		t.Error("NextCursor must not affect the fingerprint")
	}
}

// TestPromptAndResourceBaselinesAreIndependent guards the multi-surface pinning:
// prompts and resources steer the model as much as tools do, so each surface must
// be fingerprinted, and a surface with no baseline must not trip.
func TestPromptAndResourceBaselinesAreIndependent(t *testing.T) {
	prompts := []*mcp.Prompt{{Name: "p1", Description: "does a thing"}}
	resources := []*mcp.Resource{{URI: "windows://a", Name: "a"}}

	t.Run("prompt drift trips", func(t *testing.T) {
		var tripped atomic.Int32
		rp := NewRugPull(func(string) { tripped.Add(1) }, nil)
		rp.SetPromptBaseline(prompts)
		if err := rp.comparePrompts(HashPrompts(prompts), "test"); err != nil {
			t.Errorf("identical prompts must not trip: %v", err)
		}
		mutated := []*mcp.Prompt{{Name: "p1", Description: "does something ELSE"}}
		if err := rp.comparePrompts(HashPrompts(mutated), "test"); err == nil {
			t.Error("a changed prompt description must trip")
		}
		if tripped.Load() != 1 {
			t.Errorf("want exactly one trip, got %d", tripped.Load())
		}
	})

	t.Run("resource drift trips", func(t *testing.T) {
		var tripped atomic.Int32
		rp := NewRugPull(func(string) { tripped.Add(1) }, nil)
		rp.SetResourceBaseline(resources)
		mutated := []*mcp.Resource{{URI: "windows://EVIL", Name: "a"}}
		if err := rp.compareResources(HashResources(mutated), "test"); err == nil {
			t.Error("a changed resource URI must trip")
		}
		if tripped.Load() != 1 {
			t.Errorf("want exactly one trip, got %d", tripped.Load())
		}
	})

	t.Run("unpinned surface never trips", func(t *testing.T) {
		var tripped atomic.Int32
		rp := NewRugPull(func(string) { tripped.Add(1) }, nil)
		rp.SetBaseline([]*mcp.Tool{tool("T", "d")}) // only tools pinned
		if err := rp.comparePrompts(HashPrompts(prompts), "test"); err != nil {
			t.Errorf("a server with no prompts must not trip on them: %v", err)
		}
		if err := rp.compareResources(HashResources(resources), "test"); err != nil {
			t.Errorf("a server with no resources must not trip on them: %v", err)
		}
		if tripped.Load() != 0 {
			t.Errorf("no trips expected, got %d", tripped.Load())
		}
	})

	t.Run("hashes are order independent", func(t *testing.T) {
		p2 := []*mcp.Prompt{{Name: "b"}, {Name: "a"}}
		p1 := []*mcp.Prompt{{Name: "a"}, {Name: "b"}}
		if HashPrompts(p1) != HashPrompts(p2) {
			t.Error("prompt hash must not depend on order")
		}
		r1 := []*mcp.Resource{{URI: "windows://a"}, {URI: "windows://b"}}
		r2 := []*mcp.Resource{{URI: "windows://b"}, {URI: "windows://a"}}
		if HashResources(r1) != HashResources(r2) {
			t.Error("resource hash must not depend on order")
		}
	})
}
