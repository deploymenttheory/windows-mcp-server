//go:build windows && (amd64 || arm64)

package winmcp

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	cng "github.com/deploymenttheory/go-bindings-win32/bindings/win32/security/cryptography"
)

// platformAIKName is the persisted machine-scoped Attestation Identity Key the
// server reuses across evaluations. It is created once (elevated) and reused.
const platformAIKName = "windows-mcp-server-platform-aik"

// tpmPlatformClaim produces a nonce-bound TPM platform attestation via the
// Platform Crypto Provider: NCryptCreateClaim(NCRYPT_CLAIM_PLATFORM) runs a
// TPM2_Quote over the PCRs with the caller's nonce as qualifying data, signed by
// a machine-scoped AIK, then NCryptVerifyClaim self-validates it. The parameter
// list shape (nonce buffer type 81 + a 3-byte PCR-selection mask buffer type 80)
// and the AIK provisioning (identity-key usage policy) were established
// empirically against real TPM 2.0 hardware.
//
// Platform quotes are a machine/SYSTEM operation: the machine-scoped AIK cannot
// be provisioned without elevation (NCryptCreatePersistedKey returns
// 0x80090010 Access denied), so callers gate this on an elevated/SYSTEM context.
func tpmPlatformClaim(nonce []byte) (quoteSize int, err error) {
	if len(nonce) == 0 {
		return 0, fmt.Errorf("empty nonce")
	}
	var prov cng.NCRYPT_PROV_HANDLE
	if err = cng.NCryptOpenStorageProvider(&prov, "Microsoft Platform Crypto Provider", 0); err != nil {
		return 0, fmt.Errorf("open Platform Crypto Provider: %w", err)
	}
	defer func() { _ = cng.NCryptFreeObject(cng.NCRYPT_HANDLE(prov)) }() // best-effort cleanup

	aik, err := openOrCreateAIK(prov)
	if err != nil {
		return 0, err
	}
	defer func() { _ = cng.NCryptFreeObject(cng.NCRYPT_HANDLE(aik)) }() // best-effort cleanup

	// Parameter list: the nonce (TPM2_Quote qualifying data) and a 3-byte PCR
	// selection mask covering PCRs 0-23.
	pcrMask := []byte{0xFF, 0xFF, 0xFF}
	bufs := []cng.BCryptBuffer{
		{CbBuffer: uint32(len(nonce)), BufferType: cng.NCRYPTBUFFER_TPM_PLATFORM_CLAIM_NONCE, PvBuffer: unsafe.Pointer(&nonce[0])},
		{CbBuffer: uint32(len(pcrMask)), BufferType: cng.NCRYPTBUFFER_TPM_PLATFORM_CLAIM_PCR_MASK, PvBuffer: unsafe.Pointer(&pcrMask[0])},
	}
	desc := cng.BCryptBufferDesc{UlVersion: cng.BCRYPTBUFFER_VERSION, CBuffers: uint32(len(bufs)), PBuffers: &bufs[0]}

	// Size, then produce the signed claim blob.
	var cb uint32
	if err = cng.NCryptCreateClaim(aik, 0, cng.NCRYPT_CLAIM_PLATFORM, &desc, nil, &cb, 0); err != nil {
		return 0, fmt.Errorf("NCryptCreateClaim (size): %w", err)
	}
	blob := make([]byte, cb)
	var written uint32
	if err = cng.NCryptCreateClaim(aik, 0, cng.NCRYPT_CLAIM_PLATFORM, &desc, blob, &written, 0); err != nil {
		return 0, fmt.Errorf("NCryptCreateClaim: %w", err)
	}

	// Self-verify the signature and that the nonce is bound into the quote.
	var out cng.BCryptBufferDesc
	if err = cng.NCryptVerifyClaim(aik, 0, cng.NCRYPT_CLAIM_PLATFORM, &desc, blob[:written], &out, 0); err != nil {
		return int(written), fmt.Errorf("NCryptVerifyClaim: %w", err)
	}
	return int(written), nil
}

// openOrCreateAIK reuses the persisted machine AIK, or provisions it (RSA key in
// the TPM with the identity-key usage policy). Machine scope requires elevation.
func openOrCreateAIK(prov cng.NCRYPT_PROV_HANDLE) (cng.NCRYPT_KEY_HANDLE, error) {
	var aik cng.NCRYPT_KEY_HANDLE
	if err := cng.NCryptOpenKey(prov, &aik, platformAIKName, 0, cng.NCRYPT_MACHINE_KEY_FLAG); err == nil {
		return aik, nil
	}
	if err := cng.NCryptCreatePersistedKey(prov, &aik, "RSA", platformAIKName, 0,
		cng.NCRYPT_MACHINE_KEY_FLAG|cng.NCRYPT_OVERWRITE_KEY_FLAG); err != nil {
		return 0, fmt.Errorf("provision machine AIK (requires elevation): %w", err)
	}
	usage := make([]byte, 4)
	binary.LittleEndian.PutUint32(usage, cng.NCRYPT_PCP_IDENTITY_KEY)
	if err := cng.NCryptSetProperty(cng.NCRYPT_HANDLE(aik), cng.NCRYPT_PCP_KEY_USAGE_POLICY_PROPERTY, usage, 0); err != nil {
		_ = cng.NCryptDeleteKey(aik, 0) // roll back the half-created key
		return 0, fmt.Errorf("set AIK usage policy: %w", err)
	}
	if err := cng.NCryptFinalizeKey(aik, 0); err != nil {
		_ = cng.NCryptDeleteKey(aik, 0) // roll back the half-created key
		return 0, fmt.Errorf("finalize AIK: %w", err)
	}
	return aik, nil
}
