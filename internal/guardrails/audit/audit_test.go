package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// memDest captures entries in memory for verification.
type memDest struct {
	mu      sync.Mutex
	entries []AuditEntry
	flushes int
}

func (m *memDest) Write(e AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, e)
	return nil
}
func (m *memDest) Flush() error { m.mu.Lock(); defer m.mu.Unlock(); m.flushes++; return nil }
func (m *memDest) Close() error { return nil }

func TestAuditChainVerifies(t *testing.T) {
	dest := &memDest{}
	log := NewAuditLog(dest)
	for i := 0; i < 5; i++ {
		if _, err := log.Append("test.event", map[string]any{"i": i}); err != nil {
			t.Fatal(err)
		}
	}
	if err := VerifyChain(dest.entries); err != nil {
		t.Fatalf("valid chain should verify: %v", err)
	}
	if seq, head := log.Head(); seq != 5 || head == "" {
		t.Errorf("Head() = %d,%q; want seq 5 and non-empty head", seq, head)
	}
}

func TestAuditDetectsTamper(t *testing.T) {
	dest := &memDest{}
	log := NewAuditLog(dest)
	for i := 0; i < 4; i++ {
		log.Append("e", map[string]any{"i": i})
	}

	// Edit a payload without recomputing hashes → chain must break.
	tampered := append([]AuditEntry(nil), dest.entries...)
	tampered[1].Payload = json.RawMessage(`{"i":999}`)
	if err := VerifyChain(tampered); err == nil {
		t.Error("edited payload should break the chain")
	}

	// Delete an entry (gap) → break.
	gap := []AuditEntry{dest.entries[0], dest.entries[2], dest.entries[3]}
	if err := VerifyChain(gap); err == nil {
		t.Error("deleted entry should break the chain")
	}

	// Reorder → break.
	reordered := []AuditEntry{dest.entries[1], dest.entries[0], dest.entries[2], dest.entries[3]}
	if err := VerifyChain(reordered); err == nil {
		t.Error("reordered entries should break the chain")
	}
}

func TestAuditMiddlewareLogsDigestNotArgs(t *testing.T) {
	dest := &memDest{}
	log := NewAuditLog(dest)
	mw := log.Middleware()
	secret := `{"command":"super-secret-password"}`
	req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "PowerShell", Arguments: json.RawMessage(secret)}}

	var reached bool
	next := func(context.Context, string, mcp.Request) (mcp.Result, error) {
		reached = true
		return &mcp.CallToolResult{}, nil
	}
	if _, err := mw(next)(context.Background(), "tools/call", req); err != nil {
		t.Fatal(err)
	}
	if !reached {
		t.Error("audit middleware must always call next (never blocks)")
	}
	if len(dest.entries) != 1 {
		t.Fatalf("want 1 audit entry, got %d", len(dest.entries))
	}
	payload := string(dest.entries[0].Payload)
	if containsSubstr(payload, "super-secret-password") {
		t.Errorf("raw args leaked into audit payload: %s", payload)
	}
	if !containsSubstr(payload, "args_sha256") || !containsSubstr(payload, "PowerShell") {
		t.Errorf("audit payload missing tool/digest: %s", payload)
	}
}

func containsSubstr(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

// TestAuditCoversResourceAndPromptReads is the guard on the data-egress paths
// added alongside prompts and resources. A resource read returns desktop or
// system state to the caller; leaving it out of the hash chain would be a hole in
// the audit trail.
func TestAuditCoversResourceAndPromptReads(t *testing.T) {
	dest := &memDest{}
	log := NewAuditLog(dest)
	mw := log.Middleware()
	next := func(context.Context, string, mcp.Request) (mcp.Result, error) {
		return &mcp.CallToolResult{}, nil
	}

	readReq := &mcp.ReadResourceRequest{Params: &mcp.ReadResourceParams{URI: "windows://desktop/snapshot"}}
	if _, err := mw(next)(context.Background(), "resources/read", readReq); err != nil {
		t.Fatal(err)
	}
	promptReq := &mcp.GetPromptRequest{Params: &mcp.GetPromptParams{
		Name:      "rpa-journey",
		Arguments: map[string]string{"goal": "sign in"},
	}}
	if _, err := mw(next)(context.Background(), "prompts/get", promptReq); err != nil {
		t.Fatal(err)
	}

	if len(dest.entries) != 2 {
		t.Fatalf("want 2 audit entries, got %d", len(dest.entries))
	}
	if dest.entries[0].Event != "resource.read" {
		t.Errorf("entry 0 event = %q, want resource.read", dest.entries[0].Event)
	}
	if !containsSubstr(string(dest.entries[0].Payload), "windows://desktop/snapshot") {
		t.Errorf("resource audit should record the URI: %s", dest.entries[0].Payload)
	}
	if dest.entries[1].Event != "prompt.get" {
		t.Errorf("entry 1 event = %q, want prompt.get", dest.entries[1].Event)
	}
	// Prompt arguments are digested, never recorded raw.
	if containsSubstr(string(dest.entries[1].Payload), "sign in") {
		t.Errorf("prompt arguments leaked into the audit payload: %s", dest.entries[1].Payload)
	}
	if !containsSubstr(string(dest.entries[1].Payload), "args_sha256") {
		t.Errorf("prompt audit should carry an argument digest: %s", dest.entries[1].Payload)
	}
	if err := VerifyChain(dest.entries); err != nil {
		t.Errorf("chain must remain verifiable: %v", err)
	}
}

// TestAuditCoversTheStatelessConnection covers the two methods protocol
// 2026-07-28 introduced in place of the handshake and the GET stream (SEP-2575).
// Without them the chain would hold no record that a client ever connected, and
// none that a long-lived egress stream was opened.
func TestAuditCoversTheStatelessConnection(t *testing.T) {
	dest := &memDest{}
	mw := NewAuditLog(dest).Middleware()
	next := func(context.Context, string, mcp.Request) (mcp.Result, error) {
		return &mcp.CallToolResult{}, nil
	}

	discover := &mcp.ServerRequest[mcp.Params]{Params: &mcp.DiscoverParams{
		Meta: mcp.Meta{
			mcp.MetaKeyProtocolVersion: "2026-07-28",
			mcp.MetaKeyClientInfo:      map[string]any{"name": "conformance", "version": "0.2.0"},
		},
	}}
	if _, err := mw(next)(context.Background(), "server/discover", discover); err != nil {
		t.Fatal(err)
	}
	listen := &mcp.ServerRequest[mcp.Params]{Params: &mcp.SubscriptionsListenParams{
		Notifications: &mcp.NotificationSubscriptions{
			ToolsListChanged:      true,
			ResourceSubscriptions: []string{"windows://desktop/snapshot"},
		},
	}}
	if _, err := mw(next)(context.Background(), "subscriptions/listen", listen); err != nil {
		t.Fatal(err)
	}

	if len(dest.entries) != 2 {
		t.Fatalf("want 2 audit entries, got %d", len(dest.entries))
	}
	if dest.entries[0].Event != "server.discover" {
		t.Errorf("entry 0 event = %q, want server.discover", dest.entries[0].Event)
	}
	discovered := string(dest.entries[0].Payload)
	if !containsSubstr(discovered, "2026-07-28") || !containsSubstr(discovered, "conformance") {
		t.Errorf("discover audit should record who connected and under which revision: %s", discovered)
	}
	if dest.entries[1].Event != "subscriptions.listen" {
		t.Errorf("entry 1 event = %q, want subscriptions.listen", dest.entries[1].Event)
	}
	if !containsSubstr(string(dest.entries[1].Payload), "windows://desktop/snapshot") {
		t.Errorf("listen audit should record the subscribed URIs: %s", dest.entries[1].Payload)
	}
	if err := VerifyChain(dest.entries); err != nil {
		t.Errorf("chain must remain verifiable: %v", err)
	}
}

// TestCompletionIsAuditedWithoutTheTypedPrefix pins both halves of the
// completion/complete record.
//
// It has to exist at all because the handler answers with server-held names --
// including the names of installed credentials -- straight into the model's
// context, and it used to leave no record that it had been called. And it has to
// digest the value, because that is caller-chosen text on a method carrying no
// rate limit, and the chain is hashed, fsynced and never rotated.
func TestCompletionIsAuditedWithoutTheTypedPrefix(t *testing.T) {
	dest := &memDest{}
	mw := NewAuditLog(dest).Middleware()
	next := func(context.Context, string, mcp.Request) (mcp.Result, error) {
		return &mcp.CompleteResult{}, nil
	}

	const typed = "prod-service-account-p"
	complete := &mcp.ServerRequest[mcp.Params]{Params: &mcp.CompleteParams{
		Ref:      &mcp.CompleteReference{Type: "ref/prompt", Name: "rpa-journey"},
		Argument: mcp.CompleteParamsArgument{Name: "credential", Value: typed},
	}}
	if _, err := mw(next)(context.Background(), "completion/complete", complete); err != nil {
		t.Fatal(err)
	}

	if len(dest.entries) != 1 {
		t.Fatalf("want 1 audit entry, got %d", len(dest.entries))
	}
	if dest.entries[0].Event != "completion.complete" {
		t.Errorf("event = %q, want completion.complete", dest.entries[0].Event)
	}
	payload := string(dest.entries[0].Payload)
	if !containsSubstr(payload, "rpa-journey") || !containsSubstr(payload, "credential") {
		t.Errorf("the record should say which completion was asked for: %s", payload)
	}
	if containsSubstr(payload, typed) {
		t.Errorf("the typed prefix must be digested, not recorded: %s", payload)
	}
	if err := VerifyChain(dest.entries); err != nil {
		t.Errorf("chain must remain verifiable: %v", err)
	}
}

// TestDiscoverAuditToleratesAMissingMetaTriple guards the backward-compatibility
// probe: a pre-2026-07-28 client calling server/discover over stdio carries none
// of the _meta fields, and that must still produce an audit entry rather than a
// panic or a dropped record.
func TestDiscoverAuditToleratesAMissingMetaTriple(t *testing.T) {
	dest := &memDest{}
	mw := NewAuditLog(dest).Middleware()
	next := func(context.Context, string, mcp.Request) (mcp.Result, error) {
		return &mcp.CallToolResult{}, nil
	}
	req := &mcp.ServerRequest[mcp.Params]{Params: &mcp.DiscoverParams{}}
	if _, err := mw(next)(context.Background(), "server/discover", req); err != nil {
		t.Fatal(err)
	}
	if len(dest.entries) != 1 || dest.entries[0].Event != "server.discover" {
		t.Fatalf("a bare discover must still be audited, got %+v", dest.entries)
	}
}

// TestPromptArgsDigestIsDeterministic ensures map iteration order cannot change
// the digest, which would make the audit trail non-reproducible.
func TestPromptArgsDigestIsDeterministic(t *testing.T) {
	a := promptArgsBytes(map[string]string{"z": "1", "a": "2", "m": "3"})
	b := promptArgsBytes(map[string]string{"m": "3", "z": "1", "a": "2"})
	if string(a) != string(b) {
		t.Errorf("digest input depends on map order:\n%q\n%q", a, b)
	}
}

// TestClientSuppliedFieldsAreBounded is a regression test for unbounded audit
// growth. clientInfo.name and the resource-subscription list are the only places
// a client decides how many bytes an entry costs, and both were recorded in full.
// server/discover is deliberately outside the rate limits and is not decidable by
// the policy engine, so a client could loop it with a huge name and fill the audit
// volume -- taking the session recording with it, since they usually share a disk.
func TestClientSuppliedFieldsAreBounded(t *testing.T) {
	huge := strings.Repeat("A", 10<<20) // 10 MiB
	fields := clientIdentity(mcp.Meta{
		mcp.MetaKeyClientInfo: map[string]any{"name": huge, "version": huge},
	})
	for _, k := range []string{"client_name", "client_version"} {
		got, _ := fields[k].(string)
		if len(got) > maxRecordedString+32 {
			t.Errorf("%s recorded %d bytes; a client must not choose the entry size", k, len(got))
		}
	}

	many := make([]string, maxRecordedSubscriptions*3)
	for i := range many {
		many[i] = "windows://resource/" + strconv.Itoa(i)
	}
	subs := subscriptionFields(&mcp.NotificationSubscriptions{ResourceSubscriptions: many})
	recorded, _ := subs["resource_subscriptions"].([]string)
	if len(recorded) > maxRecordedSubscriptions {
		t.Errorf("recorded %d subscriptions, limit is %d", len(recorded), maxRecordedSubscriptions)
	}
	if subs["resource_subscriptions_dropped"] == nil {
		t.Error("a truncated list must say so; a silent truncation reads as a complete record")
	}
}

// TestArgumentDigestsAreNotGuessable pins that the digest is not a bare hash of
// the arguments.
//
// The "never raw, always digested" discipline is applied everywhere, but the
// digest was sha256.Sum256(rawJSON). Tool arguments here are short and highly
// structured -- {"text":"P@ssw0rd1"} from Type, {"command":"..."} from Shell --
// so anyone holding the audit file could confirm a guess instantly or run a
// dictionary over it, and the chain is meant to be handed to auditors and shipped
// in evidence bundles.
func TestArgumentDigestsAreNotGuessable(t *testing.T) {
	args := []byte(`{"text":"P@ssw0rd1"}`)

	bare := sha256.Sum256(args)
	if digestBytes(args) == hex.EncodeToString(bare[:]) {
		t.Error("the digest is a plain SHA-256 of the arguments, so a guessed value " +
			"can be confirmed offline by anyone holding the chain")
	}

	// Still deterministic within the process: correlating a plan step with the
	// call that ran it depends on it.
	if digestBytes(args) != digestBytes(args) {
		t.Error("the same arguments must digest the same way within a session")
	}
	if digestBytes(args) == digestBytes([]byte(`{"text":"different"}`)) {
		t.Error("different arguments must digest differently")
	}
}
