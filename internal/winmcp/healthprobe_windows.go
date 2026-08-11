//go:build windows && (amd64 || arm64)

package winmcp

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"unsafe"

	"github.com/deploymenttheory/agentweave-harness/guardrails/signals"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/registry"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/tpmbaseservices"
	wmirt "github.com/deploymenttheory/go-bindings-wmi/runtime/wmi"
)

// The systemProbe also implements signals.HealthProbe. Every method reads
// live OS/hardware state at call time via the win32 and WMI SDKs (no cache, no
// cloud), so the continuous monitor sees just-in-time posture and catches drift.

const secureBootStateKey = `SYSTEM\CurrentControlSet\Control\SecureBoot\State`

// SecureBoot reads the firmware-backed UEFI Secure Boot state from the registry
// (win32 RegGetValue; no elevation required). An absent key means the firmware
// is legacy BIOS / does not support Secure Boot.
func (p *systemProbe) SecureBoot() (signals.SecureBootState, error) {
	v, ok, err := regDWORD(secureBootStateKey, "UEFISecureBootEnabled")
	if err != nil {
		return signals.SecureBootState{}, err
	}
	if !ok {
		return signals.SecureBootState{Supported: false}, nil
	}
	return signals.SecureBootState{Supported: true, Enabled: v == 1}, nil
}

// regDWORD reads an HKLM DWORD value via the win32 registry binding. ok is false
// when the key/value is absent.
func regDWORD(subKey, value string) (uint32, bool, error) {
	var data uint32
	cb := uint32(unsafe.Sizeof(data))
	typ := registry.REG_VALUE_TYPE(0)
	rc := registry.RegGetValue(registry.HKEY_LOCAL_MACHINE, subKey, value,
		registry.RRF_RT_REG_DWORD, &typ, unsafe.Pointer(&data), &cb)
	switch rc {
	case 0: // ERROR_SUCCESS
		return data, true, nil
	case 2: // ERROR_FILE_NOT_FOUND
		return 0, false, nil
	default:
		return 0, false, fmt.Errorf("RegGetValue %s\\%s: win32 error %d", subKey, value, rc)
	}
}

// TPM reads live TPM posture from TPM Base Services (Tbsi_GetDeviceInfo — no
// elevation, unlike Win32_Tpm). Attestation capability is inferred from a
// present, ready TPM 2.0 plus a retrievable measured-boot log.
func (p *systemProbe) TPM() (signals.TPMState, error) {
	info := make([]byte, 16) // TPM_DEVICE_INFO: 4 x uint32
	rc := tpmbaseservices.Tbsi_GetDeviceInfo(info)
	if rc != 0 {
		// No TPM, or TBS unavailable.
		return signals.TPMState{Present: false}, nil
	}
	version := binary.LittleEndian.Uint32(info[4:8]) // TpmVersion: 1=1.2, 2=2.0
	verName := map[uint32]string{1: "1.2", 2: "2.0"}[version]
	if verName == "" {
		verName = fmt.Sprintf("v%d", version)
	}
	_, logErr := tbsTCGLog()
	return signals.TPMState{
		Present:            true,
		Ready:              true,
		AttestationCapable: version >= 2 && logErr == nil,
		Version:            verName,
	}, nil
}

// tbsTCGLog retrieves the current SRTM measured-boot (TCG) log directly from the
// TPM via TBS — at source, unprivileged, current.
func tbsTCGLog() ([]byte, error) {
	var cb uint32
	// First call sizes the buffer.
	_ = tpmbaseservices.Tbsi_Get_TCG_Log_Ex(0 /*TBS_TCGLOG_SRTM_CURRENT*/, nil, &cb)
	if cb == 0 {
		return nil, fmt.Errorf("no measured-boot log available")
	}
	buf := make([]byte, cb)
	rc := tpmbaseservices.Tbsi_Get_TCG_Log_Ex(0, &buf[0], &cb)
	if rc != 0 {
		return nil, fmt.Errorf("Tbsi_Get_TCG_Log_Ex: 0x%08x", rc)
	}
	return buf[:cb], nil
}

// DeviceGuard reads live VBS/HVCI/Credential Guard state from Win32_DeviceGuard
// via the WMI runtime (unprivileged).
func (p *systemProbe) DeviceGuard() (signals.DeviceGuardState, error) {
	rows, err := p.dsk.QueryWMI(`root\Microsoft\Windows\DeviceGuard`,
		"SELECT VirtualizationBasedSecurityStatus, SecurityServicesRunning FROM Win32_DeviceGuard")
	if err != nil {
		return signals.DeviceGuardState{}, fmt.Errorf("Win32_DeviceGuard: %w", err)
	}
	if len(rows) == 0 {
		return signals.DeviceGuardState{}, nil
	}
	row := rows[0]
	st := signals.DeviceGuardState{VBSRunning: wmirt.AsUint32(row["VirtualizationBasedSecurityStatus"]) == 2}
	for _, code := range wmirt.AsUint32Slice(row["SecurityServicesRunning"]) {
		switch code {
		case 1: // Credential Guard
			st.CredentialGuardRunning = true
		case 2: // Hypervisor-Enforced Code Integrity (memory integrity)
			st.HVCIRunning = true
		}
	}
	return st, nil
}

// BitLocker reads live per-volume protection from Win32_EncryptableVolume via
// the WMI runtime. That class requires elevation; when denied the error names
// the cause so the guardrail reports it rather than silently passing.
func (p *systemProbe) BitLocker() ([]signals.BitLockerVolume, error) {
	rows, err := p.dsk.QueryWMI(`root\CIMV2\Security\MicrosoftVolumeEncryption`,
		"SELECT DriveLetter, ProtectionStatus FROM Win32_EncryptableVolume")
	if err != nil {
		return nil, fmt.Errorf("cannot read BitLocker state (Win32_EncryptableVolume requires elevation): %w", err)
	}
	vols := make([]signals.BitLockerVolume, 0, len(rows))
	for _, row := range rows {
		mount := wmirt.AsString(row["DriveLetter"])
		if mount == "" {
			mount = "(system)"
		}
		vols = append(vols, signals.BitLockerVolume{
			Mount:     mount,
			Protected: wmirt.AsUint32(row["ProtectionStatus"]) == 1,
		})
	}
	return vols, nil
}

// PlatformAttestation produces a nonce-fresh TPM platform attestation. When the
// process is elevated/SYSTEM it provisions a machine-scoped AIK and runs a live
// TPM2_Quote over the PCRs bound to the nonce (Verified true). Otherwise — a
// machine-scoped AIK cannot be created without elevation — it degrades to the
// at-source measured-boot evidence (the TCG log via TBS) with Verified false so
// the caller reports honestly rather than overclaiming.
func (p *systemProbe) PlatformAttestation(nonce []byte) (*signals.Attestation, error) {
	log, err := tbsTCGLog()
	if err != nil {
		return nil, err
	}
	banks := 0
	if v, ok, _ := regDWORD(`SYSTEM\CurrentControlSet\Control\IntegrityServices`, "TPMActivePCRBanks"); ok {
		banks = bits.OnesCount32(v)
	}
	att := &signals.Attestation{Nonce: nonce, PCRBanks: banks, LogSize: len(log)}

	if signals.DetectRunContext().Elevated {
		if qsize, cerr := tpmPlatformClaim(nonce); cerr == nil {
			att.Verified = true
			att.QuoteSize = qsize
			att.Detail = fmt.Sprintf(
				"nonce-bound TPM platform quote created and verified (%d-byte claim, %d PCR banks)",
				qsize,
				banks,
			)
			return att, nil
		} else {
			att.Detail = fmt.Sprintf(
				"measured-boot log at source (%d bytes, %d PCR banks); signed quote attempt failed: %v",
				len(log),
				banks,
				cerr,
			)
			return att, nil
		}
	}
	att.Detail = fmt.Sprintf("measured-boot log retrieved at source (%d bytes, %d active PCR banks); "+
		"a signed, nonce-bound quote requires an elevated/SYSTEM context (machine-scoped AIK)", len(log), banks)
	return att, nil
}
