//go:build windows && (amd64 || arm64)

package winmcp

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// recordingTransport wraps an mcp.Transport and records every JSON-RPC frame that
// crosses it, so conformance scoring can validate what a client actually receives
// rather than a re-marshalling of our Go types.
//
// This exists because the SDK's client-side accessors normalize results: on
// protocol 2026-07-28 the handshake is server/discover, but ClientSession only
// exposes InitializeResult() — a synthesized legacy view that omits the fields
// DiscoverResult requires. Validating that view reported the server as
// non-conformant when it was not.
//
// Preferred over the SDK's LoggingTransport for two reasons: it yields typed
// jsonrpc.Message values instead of a text log format that would have to be
// re-parsed, and LoggingTransport does not forward the optional interfaces the SDK
// probes for (notably ProtocolVersionSupporter, consulted by
// filterSupportedVersions), which can change the advertised version list and so
// perturb the very thing being measured.
type recordingTransport struct {
	inner  mcp.Transport
	frames *frameLog
}

// frameLog collects frames from both directions. Safe for concurrent use: the
// SDK reads and writes from different goroutines.
type frameLog struct {
	mu sync.Mutex
	// responses maps a JSON-RPC request id to the raw result bytes of its reply.
	responses map[string]json.RawMessage
	// methodByID records the method each outbound request used, so a response can
	// be attributed to a method (JSON-RPC replies carry only the id).
	methodByID map[string]string
}

func newFrameLog() *frameLog {
	return &frameLog{
		responses:  map[string]json.RawMessage{},
		methodByID: map[string]string{},
	}
}

// ResultFor returns the raw result bytes of the reply to the given method, and
// whether one was seen.
func (f *frameLog) ResultFor(method string) (json.RawMessage, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, m := range f.methodByID {
		if m != method {
			continue
		}
		if res, ok := f.responses[id]; ok {
			return res, true
		}
	}
	return nil, false
}

// Methods returns every request method observed on the wire.
func (f *frameLog) Methods() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	seen := map[string]bool{}
	out := make([]string, 0, len(f.methodByID))
	for _, m := range f.methodByID {
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	return out
}

func (f *frameLog) record(msg jsonrpc.Message) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch m := msg.(type) {
	case *jsonrpc.Request:
		if m.ID.IsValid() { // a call, not a notification
			f.methodByID[idKey(m.ID)] = m.Method
		}
	case *jsonrpc.Response:
		if m.ID.IsValid() && m.Result != nil {
			f.responses[idKey(m.ID)] = append(json.RawMessage(nil), m.Result...)
		}
	}
}

func idKey(id jsonrpc.ID) string {
	b, err := json.Marshal(id.Raw())
	if err != nil {
		return ""
	}
	return string(b)
}

// Connect implements mcp.Transport.
func (t *recordingTransport) Connect(ctx context.Context) (mcp.Connection, error) {
	conn, err := t.inner.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &recordingConn{inner: conn, frames: t.frames}, nil
}

type recordingConn struct {
	inner  mcp.Connection
	frames *frameLog
}

func (c *recordingConn) Read(ctx context.Context) (jsonrpc.Message, error) {
	msg, err := c.inner.Read(ctx)
	if err == nil {
		c.frames.record(msg)
	}
	return msg, err
}

func (c *recordingConn) Write(ctx context.Context, msg jsonrpc.Message) error {
	// Record before delegating: a frame we sent is part of the exchange even if
	// the write subsequently fails.
	c.frames.record(msg)
	return c.inner.Write(ctx, msg)
}

func (c *recordingConn) Close() error      { return c.inner.Close() }
func (c *recordingConn) SessionID() string { return c.inner.SessionID() }
