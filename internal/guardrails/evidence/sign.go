// Package evidence packages a session's record — its audit chain, extracted
// verdicts, and any recording — into one self-verifying, optionally signed
// archive. It is the artifact handed to an auditor or an incident review: here is
// what the session did, and here is the proof it has not been edited since.
//
// The signature is ed25519, not the audit chain's HMAC, on purpose: the consumer
// of a bundle is a third party who must be able to verify it without holding a
// secret. The public key travels in the manifest for reference, but real trust
// comes from a verifier supplying the key it expects out of band.
//
// The package is a leaf: standard library only, no clock (timestamps are passed
// in), so it is testable and deterministic on any platform.
package evidence

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// ErrBadKey reports a key file that is not a hex-encoded ed25519 seed or key.
var ErrBadKey = errors.New("evidence key must be a hex-encoded 32-byte seed or 64-byte private key")

// Signer holds an ed25519 private key used to sign a bundle's manifest.
type Signer struct {
	priv ed25519.PrivateKey
}

// GenerateSigner mints a fresh keypair, for tests and the keygen command.
func GenerateSigner() (*Signer, error) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("generate evidence key: %w", err)
	}
	return &Signer{priv: priv}, nil
}

// LoadSigner reads a hex-encoded ed25519 seed (32 bytes) or full private key (64
// bytes) from a file. The seed form is what `evidence keygen` writes.
func LoadSigner(path string) (*Signer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read evidence key: %w", err)
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadKey, err)
	}
	switch len(b) {
	case ed25519.SeedSize:
		return &Signer{priv: ed25519.NewKeyFromSeed(b)}, nil
	case ed25519.PrivateKeySize:
		return &Signer{priv: ed25519.PrivateKey(b)}, nil
	default:
		return nil, ErrBadKey
	}
}

// SeedHex returns the private seed, hex-encoded, for writing a key file.
func (s *Signer) SeedHex() string { return hex.EncodeToString(s.priv.Seed()) }

// PublicHex returns the public key, hex-encoded, for publishing and for the
// manifest.
func (s *Signer) PublicHex() string {
	return hex.EncodeToString(s.priv.Public().(ed25519.PublicKey))
}

func (s *Signer) sign(msg []byte) []byte { return ed25519.Sign(s.priv, msg) }

// verifySig checks a signature over msg under a hex-encoded public key.
func verifySig(pubHex string, msg, sig []byte) bool {
	pub, err := hex.DecodeString(strings.TrimSpace(pubHex))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}
