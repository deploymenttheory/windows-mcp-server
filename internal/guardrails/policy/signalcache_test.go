package policy

import (
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/signals"

	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// countingRegistry builds a registry whose signals record how often they were
// evaluated, so the tests can assert the cache actually saves work rather than
// merely returning the right answer.
type countingRegistry struct {
	reg    *signals.Registry
	counts map[string]*atomic.Int32
	status map[string]signals.Status
	mu     sync.Mutex
}

func newCountingRegistry(ids ...string) *countingRegistry {
	c := &countingRegistry{
		reg:    signals.NewRegistry(),
		counts: map[string]*atomic.Int32{},
		status: map[string]signals.Status{},
	}
	for _, id := range ids {
		c.counts[id] = &atomic.Int32{}
		c.status[id] = signals.Pass
		c.reg.Register(signals.Guardrail{ID: id, Check: c.check(id)})
	}
	return c
}

func (c *countingRegistry) check(id string) signals.CheckFunc {
	return func(context.Context, *signals.Env) signals.Result {
		c.counts[id].Add(1)
		c.mu.Lock()
		defer c.mu.Unlock()
		return signals.Result{ID: id, Status: c.status[id]}
	}
}

func (c *countingRegistry) set(id string, s signals.Status) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status[id] = s
}

func (c *countingRegistry) calls(id string) int { return int(c.counts[id].Load()) }

// testCache wires a cache with a controllable clock.
func testCache(t *testing.T, policyJSON string, ids ...string) (*signalCache, *countingRegistry, *time.Time) {
	t.Helper()
	cr := newCountingRegistry(ids...)
	p, err := Parse([]byte(policyJSON))
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := newSignalCache(cr.reg, p, func() *signals.Env { return &signals.Env{Sys: nil} })
	c.now = func() time.Time { return clock }
	return c, cr, &clock
}

// TestCacheReusesAReadingInsideItsTTL is the reason the cache exists: without it
// every tool call pays for dsregcmd, WMI and tpmtool.
func TestCacheReusesAReadingInsideItsTTL(t *testing.T) {
	c, cr, clock := testCache(t, `{
	  "version": 1, "mode": "enforce",
	  "signals": { "bitlocker": { "ttl": "60s" } },
	  "rules": []
	}`, "bitlocker")
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		if got := c.Read(ctx, "bitlocker", nil); got.Status != signals.Pass {
			t.Fatalf("read %d: status = %v", i, got.Status)
		}
	}
	if got := cr.calls("bitlocker"); got != 1 {
		t.Errorf("evaluated %d times across 10 reads inside the TTL, want 1", got)
	}

	*clock = clock.Add(61 * time.Second)
	c.Read(ctx, "bitlocker", nil)
	if got := cr.calls("bitlocker"); got != 2 {
		t.Errorf("evaluated %d times after the TTL expired, want 2", got)
	}
}

// TestZeroTTLEvaluatesEveryTime pins the escape hatch for signals where a stale
// reading is unacceptable.
func TestZeroTTLEvaluatesEveryTime(t *testing.T) {
	c, cr, _ := testCache(t, `{
	  "version": 1, "mode": "enforce",
	  "signals": { "run-context": { "ttl": "0s" } },
	  "rules": []
	}`, "run-context")
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		c.Read(ctx, "run-context", nil)
	}
	if got := cr.calls("run-context"); got != 5 {
		t.Errorf("evaluated %d times, want 5: ttl 0 means live on every call", got)
	}
}

// TestCacheStartsUnreadNotPassing guards the dangerous default. If the cache
// began life holding a pass, the first calls of a session would be admitted
// without the device having been looked at.
func TestCacheStartsUnreadNotPassing(t *testing.T) {
	c, cr, _ := testCache(t, `{
	  "version": 1, "mode": "enforce",
	  "signals": { "bitlocker": { "ttl": "60s" } },
	  "rules": []
	}`, "bitlocker")

	for _, r := range c.Snapshot() {
		if r.Status == signals.Pass {
			t.Errorf("signal %q reports signals.Pass before it was ever evaluated", r.ID)
		}
	}
	if cr.calls("bitlocker") != 0 {
		t.Error("constructing the cache must not evaluate anything")
	}
	// The first read must actually evaluate.
	c.Read(context.Background(), "bitlocker", nil)
	if cr.calls("bitlocker") != 1 {
		t.Error("the first read must evaluate the signal")
	}
}

// TestCachePicksUpDrift covers the case the whole design is for: a signal that
// was passing starts failing, and the next read after the TTL sees it.
func TestCachePicksUpDrift(t *testing.T) {
	c, cr, clock := testCache(t, `{
	  "version": 1, "mode": "enforce",
	  "signals": { "bitlocker": { "ttl": "30s" } },
	  "rules": []
	}`, "bitlocker")
	ctx := context.Background()

	if got := c.Read(ctx, "bitlocker", nil); got.Status != signals.Pass {
		t.Fatalf("initial status = %v", got.Status)
	}
	cr.set("bitlocker", signals.Fail)

	// Inside the TTL the stale pass is still returned — the accepted trade.
	*clock = clock.Add(10 * time.Second)
	if got := c.Read(ctx, "bitlocker", nil); got.Status != signals.Pass {
		t.Errorf("inside the TTL the cached reading should stand, got %v", got.Status)
	}
	*clock = clock.Add(30 * time.Second)
	if got := c.Read(ctx, "bitlocker", nil); got.Status != signals.Fail {
		t.Errorf("after the TTL the drift must be visible, got %v", got.Status)
	}
}

// TestRefreshWarmsExpiredSignalsOnly checks the background path: the monitor
// tick should re-read what has gone stale and leave live-only signals alone.
func TestRefreshWarmsExpiredSignalsOnly(t *testing.T) {
	c, cr, clock := testCache(t, `{
	  "version": 1, "mode": "enforce",
	  "signals": { "bitlocker": { "ttl": "30s" }, "run-context": { "ttl": "0s" } },
	  "rules": []
	}`, "bitlocker", "run-context")
	ctx := context.Background()

	if err := c.Refresh(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if got := cr.calls("bitlocker"); got != 1 {
		t.Errorf("refresh should read an unread TTL signal once, got %d", got)
	}
	if got := cr.calls("run-context"); got != 0 {
		t.Errorf("refresh must not read a live-only signal (ttl 0), got %d reads", got)
	}

	// Not yet expired: refresh is a no-op.
	*clock = clock.Add(10 * time.Second)
	_ = c.Refresh(ctx, nil)
	if got := cr.calls("bitlocker"); got != 1 {
		t.Errorf("refresh re-read a signal inside its TTL, got %d", got)
	}

	*clock = clock.Add(30 * time.Second)
	_ = c.Refresh(ctx, nil)
	if got := cr.calls("bitlocker"); got != 2 {
		t.Errorf("refresh should re-read an expired signal, got %d", got)
	}
}

// TestRefreshNeverReportsAFailingSignalAsAnError pins a subtle wiring hazard.
// Refresh is registered as a monitor VerifyFunc, and a VerifyFunc returning an
// error fires that check's kill trigger. If a failing signal came back as an
// error, every signal failure would escalate to containment regardless of the
// severity its policy assigned.
func TestRefreshNeverReportsAFailingSignalAsAnError(t *testing.T) {
	c, cr, _ := testCache(t, `{
	  "version": 1, "mode": "enforce",
	  "signals": { "bitlocker": { "ttl": "30s" } },
	  "rules": []
	}`, "bitlocker")
	cr.set("bitlocker", signals.Fail)

	if err := c.Refresh(context.Background(), nil); err != nil {
		t.Errorf("a failing signal must not surface as a monitor error: %v", err)
	}
}

// TestReadOfAnUndeclaredSignalSkips: validation prevents a rule requiring one,
// but the cache must not invent a pass if it is ever asked.
func TestReadOfAnUndeclaredSignalSkips(t *testing.T) {
	c, _, _ := testCache(t, `{
	  "version": 1, "mode": "enforce",
	  "signals": { "bitlocker": { "ttl": "30s" } },
	  "rules": []
	}`, "bitlocker")

	got := c.Read(context.Background(), "secure-boot", nil)
	if got.Status != signals.Skip {
		t.Errorf("undeclared signal status = %v, want %v", got.Status, signals.Skip)
	}
}

// TestCacheIsConcurrencySafe: the engine is on the request path and the monitor
// refreshes in the background, so reads and refreshes overlap by construction.
func TestCacheIsConcurrencySafe(t *testing.T) {
	c, _, _ := testCache(t, `{
	  "version": 1, "mode": "enforce",
	  "signals": { "bitlocker": { "ttl": "1ms" }, "run-context": { "ttl": "0s" } },
	  "rules": []
	}`, "bitlocker", "run-context")
	c.now = time.Now // real clock, so entries genuinely expire during the run
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				c.Read(ctx, "bitlocker", nil)
				c.Read(ctx, "run-context", nil)
				_ = c.Snapshot()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 50; j++ {
			_ = c.Refresh(ctx, nil)
		}
	}()
	wg.Wait()
}
