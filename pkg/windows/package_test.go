//go:build windows && (amd64 || arm64)

package windows

import "testing"

// TestPackageRefusesRemoteInstallers is a regression test for an ungated network
// fetch. The only validation was a ".msi" suffix, and msiexec /i accepts a URL or
// a UNC path -- so an http:// installer was downloaded and executed as the user,
// in clear, outside the egress proxy and the allowlist, and never seen by
// enforceHTTPSScheme. The schema says "local .msi by path".
func TestPackageRefusesRemoteInstallers(t *testing.T) {
	rejected := []string{
		"http://attacker.example/p.msi",
		"https://attacker.example/p.msi",
		`\attacker\share\p.msi`,
		"//attacker/share/p.msi",
		"relative/path.msi",
		`C:\installers\thing.exe`,
	}
	for _, msi := range rejected {
		if err := requireLocalMSI(msi); err == nil {
			t.Errorf("%s must be refused", msi)
		}
	}
	if err := requireLocalMSI(`C:\installers\thing.msi`); err != nil {
		t.Errorf("a local absolute .msi should be accepted, got %v", err)
	}
}
