package export

import (
	"encoding/json"
	"fmt"
	"os"
)

// ReceiptSchemaVersion is the export-receipt schema version.
const ReceiptSchemaVersion = 1

// Receipt records what left the device, and what did not.
//
// It is a file rather than an audit entry because of where the export happens:
// the bundle contains the session's audit chain, so the chain must be closed
// before the bundle can be sealed, and the upload runs after that. Resealing to
// fold the outcome in would invalidate the manifest the bundle was signed over.
//
// So the record is split. The chain carries the *intent* — an export.configured
// entry written at startup, naming the provider and destination — and this file
// carries the *outcome*. A receipt with any object where shipped is false is what
// a fleet tool looks for.
//
// It is written even when nothing shipped, so "the device never tried" and "the
// device tried and could not reach the destination" are distinguishable. That
// distinction is the whole point: silence is the one answer an evidence trail
// must never give.
type Receipt struct {
	Version   int    `json:"version"`
	Session   string `json:"session"`
	CreatedAt string `json:"created_at"` // caller-supplied; the package reads no clock
	Provider  string `json:"provider"`
	// Destination is the sink's Describe(). It never contains a credential.
	Destination string `json:"destination"`
	// AuditHead echoes the bundle manifest's chain head, so a receipt can be tied
	// to the artifact it describes without opening the archive.
	AuditHead string   `json:"audit_head,omitempty"`
	Objects   []Result `json:"objects"`
}

// Shipped reports whether every object landed. A receipt with no objects at all
// counts as not shipped: it means the upload never got as far as trying.
func (r Receipt) Shipped() bool {
	if len(r.Objects) == 0 {
		return false
	}
	for _, o := range r.Objects {
		if !o.Shipped {
			return false
		}
	}
	return true
}

// WriteReceipt writes the receipt to path with 0600 permissions.
//
// It records object names, sizes and digests — never a credential, and never the
// query string of a signed URL, which the sink has already redacted out of both
// Destination and each Result.URI.
func WriteReceipt(path string, r Receipt) error {
	r.Version = ReceiptSchemaVersion
	blob, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal export receipt: %w", err)
	}
	if err := os.WriteFile(path, append(blob, '\n'), 0o600); err != nil {
		return fmt.Errorf("write export receipt: %w", err)
	}
	return nil
}
