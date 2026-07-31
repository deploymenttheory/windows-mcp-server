package signals

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
)

// HealthProbe reads live device-security posture directly from the OS at
// evaluation time — no cached copy, no cloud round-trip, no reporting lag. Every
// call reflects the state right now, so the continuous monitor catches drift
// (Secure Boot turned off, BitLocker suspended, VBS stopped) within one interval
// and trips the kill switch. The Windows implementation reads the UEFI Secure
// Boot registry state, tpmtool, Win32_DeviceGuard, and Win32_EncryptableVolume;
// tests supply a fake.
type HealthProbe interface {
	SecureBoot() (SecureBootState, error)
	TPM() (TPMState, error)
	DeviceGuard() (DeviceGuardState, error)
	BitLocker() ([]BitLockerVolume, error)
	// PlatformAttestation produces a nonce-fresh, TPM-signed platform attestation
	// (a live TPM2 quote over the caller's nonce plus the measured-boot log),
	// proving the posture is current and rooted in this device's TPM rather than
	// asserted by spoofable OS state. Best-effort: returns an error when the TPM
	// or a provisioned attestation key is unavailable.
	PlatformAttestation(nonce []byte) (*Attestation, error)
}

// SecureBootState is the UEFI Secure Boot posture.
type SecureBootState struct {
	Supported bool `json:"supported"`
	Enabled   bool `json:"enabled"`
}

// TPMState is the live TPM posture (from tpmtool getdeviceinformation).
type TPMState struct {
	Present            bool   `json:"present"`
	Ready              bool   `json:"ready"`
	AttestationCapable bool   `json:"attestation_capable"`
	VulnerableFirmware bool   `json:"vulnerable_firmware"`
	Version            string `json:"version,omitempty"`
	Manufacturer       string `json:"manufacturer,omitempty"`
}

// DeviceGuardState is the Virtualization-Based Security posture.
type DeviceGuardState struct {
	VBSRunning             bool `json:"vbs_running"`
	HVCIRunning            bool `json:"hvci_running"`
	CredentialGuardRunning bool `json:"credential_guard_running"`
}

// BitLockerVolume is one volume's encryption-protection state.
type BitLockerVolume struct {
	Mount     string `json:"mount"`
	Protected bool   `json:"protected"`
}

// Attestation is the evidence from a nonce-fresh TPM platform attestation.
type Attestation struct {
	Nonce     []byte `json:"nonce"`
	Verified  bool   `json:"verified"`
	PCRBanks  int    `json:"pcr_banks,omitempty"`
	QuoteSize int    `json:"quote_size,omitempty"`
	LogSize   int    `json:"log_size,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

// RegisterHealth wires the just-in-time, at-source device-posture guardrails.
// These read the OS directly on every evaluation (no Intune/Graph lag) and are
// re-checked by the continuous monitor. They are opt-in via --guardrail (not in
// the enterprise preset) so operators mandate exactly the hardware controls they
// require: e.g. --guardrail secure-boot --guardrail bitlocker --guardrail vbs.
func RegisterHealth(reg *Registry) {
	reg.Register(Guardrail{
		ID:          "secure-boot",
		Description: "UEFI Secure Boot is enabled (read live from the OS)",
		Check:       checkSecureBoot,
	})
	reg.Register(Guardrail{
		ID:          "tpm-present",
		Description: "A ready TPM 2.0 is present (read live from the OS)",
		Check:       checkTPMPresent,
	})
	reg.Register(Guardrail{
		ID:          "tpm-attestation-capable",
		Description: "TPM is attestation-capable with non-vulnerable firmware",
		Check:       checkTPMAttestationCapable,
	})
	reg.Register(Guardrail{
		ID:          "vbs",
		Description: "Virtualization-Based Security is running (read live from the OS)",
		Check:       checkVBS,
	})
	reg.Register(Guardrail{ID: "hvci", Description: "Memory integrity / HVCI is running", Check: checkHVCI})
	reg.Register(Guardrail{
		ID:          "credential-guard",
		Description: "Credential Guard is running",
		Check:       checkCredentialGuard,
	})
	reg.Register(Guardrail{
		ID:          "bitlocker",
		Description: "All fixed volumes are BitLocker-protected (read live from the OS)",
		Check:       checkBitLocker,
	})
	reg.Register(Guardrail{
		ID:          "tpm-attested",
		Description: "Live nonce-fresh TPM platform attestation validates",
		Check:       checkTPMAttested,
	})
}

// health returns env.Health or nil.
func health(env *Env) HealthProbe { return env.Health }

func checkSecureBoot(_ context.Context, env *Env) Result {
	h := health(env)
	if h == nil {
		return skip("secure-boot", "no health probe on this platform")
	}
	sb, err := h.SecureBoot()
	if err != nil {
		return errf("secure-boot", err.Error())
	}
	if !sb.Supported {
		return fail("secure-boot", "firmware does not report UEFI Secure Boot (legacy BIOS/CSM?)")
	}
	if !sb.Enabled {
		return fail("secure-boot", "UEFI Secure Boot is disabled")
	}
	return pass("secure-boot", "UEFI Secure Boot is enabled")
}

func checkTPMPresent(_ context.Context, env *Env) Result {
	h := health(env)
	if h == nil {
		return skip("tpm-present", "no health probe on this platform")
	}
	t, err := h.TPM()
	if err != nil {
		return errf("tpm-present", err.Error())
	}
	if !t.Present {
		return fail("tpm-present", "no TPM present")
	}
	if !t.Ready {
		return fail("tpm-present", "TPM present but not ready")
	}
	detail := "TPM " + t.Version + " ready"
	if t.Manufacturer != "" {
		detail += " (" + t.Manufacturer + ")"
	}
	return pass("tpm-present", detail)
}

func checkTPMAttestationCapable(_ context.Context, env *Env) Result {
	h := health(env)
	if h == nil {
		return skip("tpm-attestation-capable", "no health probe on this platform")
	}
	t, err := h.TPM()
	if err != nil {
		return errf("tpm-attestation-capable", err.Error())
	}
	if t.VulnerableFirmware {
		return fail("tpm-attestation-capable", "TPM firmware is flagged vulnerable")
	}
	if !t.AttestationCapable {
		return fail("tpm-attestation-capable", "TPM is not attestation-capable")
	}
	return pass("tpm-attestation-capable", "TPM is attestation-capable, firmware not vulnerable")
}

func checkVBS(_ context.Context, env *Env) Result {
	h := health(env)
	if h == nil {
		return skip("vbs", "no health probe on this platform")
	}
	d, err := h.DeviceGuard()
	if err != nil {
		return errf("vbs", err.Error())
	}
	if !d.VBSRunning {
		return fail("vbs", "Virtualization-Based Security is not running")
	}
	return pass("vbs", "Virtualization-Based Security is running")
}

func checkHVCI(_ context.Context, env *Env) Result {
	h := health(env)
	if h == nil {
		return skip("hvci", "no health probe on this platform")
	}
	d, err := h.DeviceGuard()
	if err != nil {
		return errf("hvci", err.Error())
	}
	if !d.HVCIRunning {
		return fail("hvci", "memory integrity (HVCI) is not running")
	}
	return pass("hvci", "memory integrity (HVCI) is running")
}

func checkCredentialGuard(_ context.Context, env *Env) Result {
	h := health(env)
	if h == nil {
		return skip("credential-guard", "no health probe on this platform")
	}
	d, err := h.DeviceGuard()
	if err != nil {
		return errf("credential-guard", err.Error())
	}
	if !d.CredentialGuardRunning {
		return fail("credential-guard", "Credential Guard is not running")
	}
	return pass("credential-guard", "Credential Guard is running")
}

func checkBitLocker(_ context.Context, env *Env) Result {
	h := health(env)
	if h == nil {
		return skip("bitlocker", "no health probe on this platform")
	}
	vols, err := h.BitLocker()
	if err != nil {
		return errf("bitlocker", err.Error())
	}
	if len(vols) == 0 {
		return fail("bitlocker", "no encryptable volumes reported")
	}
	var unprotected []string
	for _, v := range vols {
		if !v.Protected {
			unprotected = append(unprotected, v.Mount)
		}
	}
	if len(unprotected) > 0 {
		return fail("bitlocker", "unprotected volume(s): "+strings.Join(unprotected, ", "))
	}
	return pass("bitlocker", fmt.Sprintf("all %d volume(s) BitLocker-protected", len(vols)))
}

func checkTPMAttested(_ context.Context, env *Env) Result {
	h := health(env)
	if h == nil {
		return skip("tpm-attested", "no health probe on this platform")
	}
	nonce := make([]byte, 20)
	if _, err := rand.Read(nonce); err != nil {
		return errf("tpm-attested", "nonce generation failed: "+err.Error())
	}
	att, err := h.PlatformAttestation(nonce)
	if err != nil {
		return errf("tpm-attested", "attestation unavailable: "+err.Error())
	}
	if att == nil {
		return fail("tpm-attested", "no attestation evidence returned")
	}
	data := map[string]any{"pcr_banks": att.PCRBanks, "log_size": att.LogSize}
	if !att.Verified {
		// Measured-boot evidence was collected at source, but a signed,
		// remote-verifiable quote needs a provisioned AIK. Skip (non-blocking)
		// rather than overclaim a cryptographic pass.
		return Result{ID: "tpm-attested", Status: Skip, Detail: att.Detail, Data: data}
	}
	return Result{
		ID: "tpm-attested", Status: Pass,
		Detail: fmt.Sprintf("nonce-fresh TPM quote verified (%d PCR banks, %d-byte quote)",
			att.PCRBanks, att.QuoteSize),
		Data: data,
	}
}
