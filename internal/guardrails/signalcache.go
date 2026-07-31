package guardrails

import (
	"context"
	"sort"
	"sync"
	"time"
)

// signalCache holds the last reading of each declared signal so the enforcement
// point can reach a verdict without paying for the device probes on every call.
//
// The signals behind this cache are not cheap: dsregcmd, WMI and tpmtool cost
// hundreds of milliseconds each, and a desktop-automation session makes many
// small tool calls. Evaluating them all per request would dominate the session.
// The trade is explicit and bounded: a reading may be up to its TTL out of date,
// so a policy declares `"ttl": "0s"` for any signal where that window is
// unacceptable, and the in-flight monitor refreshes expired entries in the
// background so the window is bounded in practice too.
type signalCache struct {
	reg *Registry
	// env builds a fresh evaluation environment. It is a function rather than a
	// value because the Windows probe caches WMI facts per instance, so reusing
	// one would defeat the point of re-reading.
	env func() *Env
	// now is injectable so tests can advance time without sleeping.
	now func() time.Time

	mu      sync.Mutex
	entries map[string]cachedSignal
}

// cachedSignal is one reading and when it was taken.
type cachedSignal struct {
	result Result
	readAt time.Time
	// ttl is copied from the policy at construction so a reading carries the
	// freshness rule it was taken under.
	ttl time.Duration
}

// expired reports whether the reading must be taken again. A zero TTL means the
// signal is always evaluated live.
func (c cachedSignal) expired(now time.Time) bool {
	if c.ttl <= 0 {
		return true
	}
	return now.Sub(c.readAt) >= c.ttl
}

// newSignalCache builds a cache for the signals a policy declares. Signals the
// registry does not know are dropped here rather than failing: Policy.Validate
// has already rejected that case at load, and this constructor runs after it.
func newSignalCache(reg *Registry, policy *Policy, env func() *Env) *signalCache {
	c := &signalCache{
		reg:     reg,
		env:     env,
		now:     time.Now,
		entries: map[string]cachedSignal{},
	}
	for id, cfg := range policy.Signals {
		if _, ok := reg.Get(id); !ok {
			continue
		}
		// readAt is left zero, so every signal is treated as expired until first
		// read. A cache that started "fresh and passing" would admit the first
		// calls of a session without having looked at the device at all.
		c.entries[id] = cachedSignal{ttl: cfg.TTL.Std(), result: Result{ID: id, Status: Skip}}
	}
	return c
}

// argFor returns the configured argument for a signal.
func argsFrom(policy *Policy) map[string]string {
	out := map[string]string{}
	for id, cfg := range policy.Signals {
		if cfg.Arg != "" {
			out[id] = cfg.Arg
		}
	}
	return out
}

// Read returns the current reading for a signal, evaluating it if the cached one
// has expired. An id the cache does not hold comes back as Skip: the policy did
// not declare it, so it cannot be required (validation guarantees that), and
// reporting Skip is more honest than inventing a pass.
func (c *signalCache) Read(ctx context.Context, id string, args map[string]string) Result {
	c.mu.Lock()
	entry, held := c.entries[id]
	now := c.now()
	if !held {
		c.mu.Unlock()
		return skip(id, "signal is not declared by the active policy")
	}
	if !entry.expired(now) {
		c.mu.Unlock()
		return entry.result
	}
	c.mu.Unlock()

	// Evaluated outside the lock: a check can take hundreds of milliseconds and
	// holding the mutex across it would serialize every concurrent tool call
	// behind one device probe. A duplicate concurrent evaluation is cheaper than
	// that, and the results are equivalent.
	res := c.evaluate(ctx, id, args[id])

	c.mu.Lock()
	defer c.mu.Unlock()
	// Re-read the entry: a concurrent Refresh may have replaced the TTL.
	entry = c.entries[id]
	entry.result, entry.readAt = res, c.now()
	c.entries[id] = entry
	return res
}

// evaluate runs one signal's check against a fresh environment.
func (c *signalCache) evaluate(ctx context.Context, id, arg string) Result {
	g, ok := c.reg.Get(id)
	if !ok {
		return skip(id, "signal is not registered in this build")
	}
	env := c.env()
	if env == nil {
		return errf(id, "no evaluation environment available")
	}
	e := *env
	e.Arg = arg
	return g.Check(ctx, &e)
}

// Refresh re-evaluates every expired signal. It is registered as an in-flight
// monitor VerifyFunc, so the background loop keeps readings warm and bounds how
// stale a cached value can be regardless of when calls happen to arrive.
//
// It returns nil always: a failing signal is a policy outcome for the
// enforcement point to weigh, not a monitor error. Reporting it as an error here
// would trip whichever kill trigger the VerifyFunc is wired to, bypassing the
// severity the policy assigned to that signal.
func (c *signalCache) Refresh(ctx context.Context, args map[string]string) error {
	for _, id := range c.ids() {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		c.mu.Lock()
		entry, held := c.entries[id]
		expired := held && entry.expired(c.now())
		c.mu.Unlock()
		if !expired {
			continue
		}
		// A zero-TTL signal is deliberately not refreshed here: it is declared
		// live-only, so the reading that matters is the one taken on the call.
		if entry.ttl <= 0 {
			continue
		}
		_ = c.Read(ctx, id, args)
	}
	return nil
}

// Snapshot returns the current readings, for the status surface and the decision
// document. Entries never read are included with Skip status so the reader can
// tell "not yet evaluated" from "evaluated and passing".
func (c *signalCache) Snapshot() []Result {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Result, 0, len(c.entries))
	for _, id := range c.idsLocked() {
		out = append(out, c.entries[id].result)
	}
	return out
}

func (c *signalCache) ids() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.idsLocked()
}

func (c *signalCache) idsLocked() []string {
	out := make([]string, 0, len(c.entries))
	for id := range c.entries {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
