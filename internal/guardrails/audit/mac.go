package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// ErrMACInvalid is returned when a keyed verification finds an entry whose MAC is
// missing or does not match. It means the log was not produced (or was altered)
// by a holder of the key.
var ErrMACInvalid = errors.New("audit MAC invalid")

// macOf is the HMAC-SHA256 of an entry hash under key, hex-encoded. Because the
// entry hash already commits to every field of the entry and to the previous
// hash, MACing the hash binds the whole entry and its position in the chain.
func macOf(key []byte, entryHash string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(entryHash))
	return hex.EncodeToString(m.Sum(nil))
}

// VerifyMAC checks that every entry carries a MAC valid under key. It is used on
// top of VerifyChain when a key is supplied: the chain proves internal
// consistency, the MAC proves the chain was written by a key holder. An entry
// with no MAC is a failure here — a keyed session writes one on every entry, so a
// missing MAC means the entry was inserted or the field was stripped.
func VerifyMAC(entries []AuditEntry, key []byte) error {
	if len(key) == 0 {
		return fmt.Errorf("%w: no key supplied", ErrMACInvalid)
	}
	for i, e := range entries {
		if e.Mac == "" {
			return fmt.Errorf("%w: entry %d (seq=%d): missing MAC", ErrMACInvalid, i, e.Seq)
		}
		if !hmac.Equal([]byte(e.Mac), []byte(macOf(key, e.EntryHash))) {
			return fmt.Errorf("%w: entry %d (seq=%d): does not match", ErrMACInvalid, i, e.Seq)
		}
	}
	return nil
}
