package guardrails

import (
	"context"
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
