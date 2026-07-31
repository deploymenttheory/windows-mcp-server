package egress

import (
	"sort"
	"sync"
	"sync/atomic"
)

// maxTrackedDeniedHosts bounds the distinct-host table.
//
// Every refusal is interesting to an operator, but the audit log is a hash
// chain that fsyncs, so a client rotating through hostnames must not be able to
// drive its length. Past the cap the counters still rise; only the names stop
// being recorded.
const maxTrackedDeniedHosts = 50

// Counters are the running totals for one session.
type Counters struct {
	Allowed       uint64 `json:"allowed"`
	DeniedHost    uint64 `json:"denied_host"`
	DeniedPort    uint64 `json:"denied_port"`
	DeniedAddress uint64 `json:"denied_address"`
	DeniedAuth    uint64 `json:"denied_auth"`
	Failed        uint64 `json:"failed"`
}

// Total is every request the proxy refused, for the status snapshot.
func (c Counters) Denied() uint64 {
	return c.DeniedHost + c.DeniedPort + c.DeniedAddress + c.DeniedAuth
}

type counters struct {
	allowed       atomic.Uint64
	deniedHost    atomic.Uint64
	deniedPort    atomic.Uint64
	deniedAddress atomic.Uint64
	deniedAuth    atomic.Uint64
	failed        atomic.Uint64

	mu     sync.Mutex
	denied map[string]uint64
}

func newCounters() *counters { return &counters{denied: map[string]uint64{}} }

func (c *counters) snapshot() Counters {
	return Counters{
		Allowed:       c.allowed.Load(),
		DeniedHost:    c.deniedHost.Load(),
		DeniedPort:    c.deniedPort.Load(),
		DeniedAddress: c.deniedAddress.Load(),
		DeniedAuth:    c.deniedAuth.Load(),
		Failed:        c.failed.Load(),
	}
}

// noteDenied records a refused host and reports whether this is the first time
// it has been seen, which is what the caller audits.
func (c *counters) noteDenied(host string) (first bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, seen := c.denied[host]; seen {
		c.denied[host]++
		return false
	}
	if len(c.denied) >= maxTrackedDeniedHosts {
		return false
	}
	c.denied[host] = 1
	return true
}

func (c *counters) deniedHosts() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.denied))
	for host := range c.denied {
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}
