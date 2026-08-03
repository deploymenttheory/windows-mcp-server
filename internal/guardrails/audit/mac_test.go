package audit

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestKeyedChainCarriesValidMACs(t *testing.T) {
	key := []byte("a-shared-audit-key")
	dest := &memDest{}
	log := NewAuditLog(dest, WithHMACKey(key))
	for i := 0; i < 4; i++ {
		log.Append("e", map[string]any{"i": i})
	}

	if err := VerifyChain(dest.entries); err != nil {
		t.Fatalf("keyed chain should still verify as a chain: %v", err)
	}
	if err := VerifyMAC(dest.entries, key); err != nil {
		t.Errorf("valid MACs should verify under the right key: %v", err)
	}
	for i, e := range dest.entries {
		if e.Mac == "" {
			t.Errorf("keyed entry %d carries no MAC", i)
		}
	}
	// The wrong key must not verify.
	if err := VerifyMAC(dest.entries, []byte("the-wrong-key")); err == nil {
		t.Error("MAC verification should fail under the wrong key")
	}
	// A tampered payload that is re-hashed but not re-MACed (no key) is still
	// caught: the MAC binds the entry hash, and only a key holder can recompute it.
	tampered := append([]AuditEntry(nil), dest.entries...)
	tampered[1].Payload = json.RawMessage(`{"i":999}`)
	tampered[1].EntryHash = hashEntry(tampered[1])
	if err := VerifyMAC(tampered, key); err == nil {
		t.Error("an entry re-hashed without the key should fail MAC verification")
	}
}

func TestUnkeyedChainOmitsMAC(t *testing.T) {
	dest := &memDest{}
	log := NewAuditLog(dest)
	log.Append("e", map[string]any{"x": 1})

	if dest.entries[0].Mac != "" {
		t.Error("an unkeyed entry must have no MAC")
	}
	b, _ := json.Marshal(dest.entries[0])
	if strings.Contains(string(b), `"mac"`) {
		t.Errorf("unkeyed entry serialized a mac field: %s", b)
	}
	// Asking for MAC verification on an unkeyed chain fails: a missing MAC where
	// one is expected is exactly the "field stripped" case.
	if err := VerifyMAC(dest.entries, []byte("k")); err == nil {
		t.Error("unkeyed entries should fail MAC verification")
	}
}

func TestEmptyKeyLeavesLogUnkeyed(t *testing.T) {
	dest := &memDest{}
	// An absent WINDOWS_MCP_AUDIT_KEY reaches here as an empty slice; it must not
	// key the log with nothing.
	log := NewAuditLog(dest, WithHMACKey([]byte("")))
	log.Append("e", nil)
	if dest.entries[0].Mac != "" {
		t.Error("an empty key must leave the log unkeyed")
	}
}
