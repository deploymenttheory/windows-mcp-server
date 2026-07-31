package signals

import (
	"context"
	"errors"
	"testing"
)

// fakeHealth is a HealthProbe for tests.
type fakeHealth struct {
	sb     SecureBootState
	tpm    TPMState
	dg     DeviceGuardState
	bl     []BitLockerVolume
	att    *Attestation
	blErr  error
	attErr error
}

func (f fakeHealth) SecureBoot() (SecureBootState, error)   { return f.sb, nil }
func (f fakeHealth) TPM() (TPMState, error)                 { return f.tpm, nil }
func (f fakeHealth) DeviceGuard() (DeviceGuardState, error) { return f.dg, nil }
func (f fakeHealth) BitLocker() ([]BitLockerVolume, error)  { return f.bl, f.blErr }
func (f fakeHealth) PlatformAttestation(nonce []byte) (*Attestation, error) {
	return f.att, f.attErr
}

func run(check CheckFunc, h HealthProbe) Result {
	return check(context.Background(), &Env{Health: h})
}

func TestSecureBootStates(t *testing.T) {
	if got := run(
		checkSecureBoot,
		fakeHealth{sb: SecureBootState{Supported: true, Enabled: true}},
	); got.Status != Pass {
		t.Errorf("enabled: got %s", got.Status)
	}
	if got := run(
		checkSecureBoot,
		fakeHealth{sb: SecureBootState{Supported: true, Enabled: false}},
	); got.Status != Fail {
		t.Errorf("disabled: got %s", got.Status)
	}
	if got := run(checkSecureBoot, fakeHealth{sb: SecureBootState{Supported: false}}); got.Status != Fail {
		t.Errorf("unsupported: got %s", got.Status)
	}
}

func TestSecureBootSkipsWithoutProbe(t *testing.T) {
	if got := checkSecureBoot(context.Background(), &Env{}); got.Status != Skip {
		t.Errorf("no health probe should Skip, got %s", got.Status)
	}
}

func TestTPMChecks(t *testing.T) {
	ready := fakeHealth{tpm: TPMState{Present: true, Ready: true, AttestationCapable: true, Version: "2.0"}}
	if got := run(checkTPMPresent, ready); got.Status != Pass {
		t.Errorf("present+ready: got %s", got.Status)
	}
	if got := run(checkTPMPresent, fakeHealth{tpm: TPMState{Present: false}}); got.Status != Fail {
		t.Errorf("absent: got %s", got.Status)
	}
	if got := run(checkTPMAttestationCapable, ready); got.Status != Pass {
		t.Errorf("attestation-capable: got %s", got.Status)
	}
	if got := run(
		checkTPMAttestationCapable,
		fakeHealth{tpm: TPMState{Present: true, VulnerableFirmware: true}},
	); got.Status != Fail {
		t.Errorf("vulnerable firmware should Fail, got %s", got.Status)
	}
}

func TestDeviceGuardChecks(t *testing.T) {
	all := fakeHealth{dg: DeviceGuardState{VBSRunning: true, HVCIRunning: true, CredentialGuardRunning: true}}
	for name, c := range map[string]CheckFunc{"vbs": checkVBS, "hvci": checkHVCI, "credential-guard": checkCredentialGuard} {
		if got := run(c, all); got.Status != Pass {
			t.Errorf("%s all-on: got %s", name, got.Status)
		}
	}
	off := fakeHealth{dg: DeviceGuardState{}}
	if got := run(checkVBS, off); got.Status != Fail {
		t.Errorf("vbs off should Fail, got %s", got.Status)
	}
}

func TestBitLockerChecks(t *testing.T) {
	if got := run(
		checkBitLocker,
		fakeHealth{bl: []BitLockerVolume{{Mount: "C:", Protected: true}}},
	); got.Status != Pass {
		t.Errorf("protected: got %s", got.Status)
	}
	if got := run(
		checkBitLocker,
		fakeHealth{bl: []BitLockerVolume{{Mount: "C:", Protected: true}, {Mount: "D:", Protected: false}}},
	); got.Status != Fail {
		t.Errorf("one unprotected should Fail, got %s", got.Status)
	}
	if got := run(checkBitLocker, fakeHealth{blErr: errors.New("requires elevation")}); got.Status != Error {
		t.Errorf("probe error should be Error, got %s", got.Status)
	}
}

func TestTPMAttestedSemantics(t *testing.T) {
	// No signed quote (typical, no provisioned AIK) → Skip, non-blocking.
	skip := fakeHealth{att: &Attestation{Verified: false, LogSize: 4096, PCRBanks: 1, Detail: "measured-boot only"}}
	if got := run(checkTPMAttested, skip); got.Status != Skip {
		t.Errorf("unsigned attestation should Skip, got %s (%s)", got.Status, got.Detail)
	}
	// A verified signed quote → Pass.
	pass := fakeHealth{att: &Attestation{Verified: true, QuoteSize: 256, PCRBanks: 2}}
	if got := run(checkTPMAttested, pass); got.Status != Pass {
		t.Errorf("verified quote should Pass, got %s", got.Status)
	}
	// Probe error → Error.
	if got := run(checkTPMAttested, fakeHealth{attErr: errors.New("no TPM")}); got.Status != Error {
		t.Errorf("attestation error should be Error, got %s", got.Status)
	}
}

func TestHealthChecksRegistered(t *testing.T) {
	reg := NewRegistry()
	RegisterHealth(reg)
	for _, id := range []string{"secure-boot", "tpm-present", "tpm-attestation-capable", "vbs", "hvci", "credential-guard", "bitlocker", "tpm-attested"} {
		if _, ok := reg.Get(id); !ok {
			t.Errorf("health guardrail %q not registered", id)
		}
	}
}
