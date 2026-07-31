//go:build windows && (amd64 || arm64)

package egress

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf16"
	"unsafe"

	win32 "github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/wininet"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/registry"
)

// internetSettingsKey is where WinINET keeps this user's proxy configuration.
// Chromium, the Settings UI, .NET Framework and anything else on WinINET read
// it; per-user, so writing it needs no elevation.
const internetSettingsKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

// savedProxySettings is the prior configuration, recorded so exiting puts back
// exactly what was there — including "there was no value at all", which is a
// different state from "the value was empty" and restores differently.
type savedProxySettings struct {
	Enable      uint32 `json:"enable"`
	HadEnable   bool   `json:"had_enable"`
	Server      string `json:"server"`
	HadServer   bool   `json:"had_server"`
	Override    string `json:"override"`
	HadOverride bool   `json:"had_override"`
}

var errRegistry = errors.New("registry")

// regErr turns a WIN32_ERROR into a Go error, or nil on success.
func regErr(op string, code foundation.WIN32_ERROR) error {
	if code == foundation.ERROR_SUCCESS {
		return nil
	}
	return fmt.Errorf("%w: %s failed with %d", errRegistry, op, uint32(code))
}

// openInternetSettings opens this user's WinINET key. The caller closes it.
func openInternetSettings(access registry.REG_SAM_FLAGS) (registry.HKEY, func(), error) {
	var key registry.HKEY
	code := registry.RegOpenKeyEx(registry.HKEY_CURRENT_USER, internetSettingsKey, 0, access, &key)
	if err := regErr("open "+internetSettingsKey, code); err != nil {
		return 0, nil, err
	}
	return key, func() { _ = registry.RegCloseKey(key) }, nil
}

// queryString reads a REG_SZ, reporting whether it was present at all.
func queryString(key registry.HKEY, name string) (string, bool) {
	var valueType registry.REG_VALUE_TYPE
	var size uint32
	if code := registry.RegQueryValueEx(key, name, &valueType, nil, &size); code != foundation.ERROR_SUCCESS {
		return "", false
	}
	if size == 0 {
		return "", true
	}
	buf := make([]byte, size)
	if code := registry.RegQueryValueEx(key, name, &valueType, &buf[0], &size); code != foundation.ERROR_SUCCESS {
		return "", false
	}
	// The value comes back as UTF-16 including its terminator.
	return win32.UTF16ToString((*uint16)(unsafe.Pointer(&buf[0]))), true
}

// queryDWord reads a REG_DWORD, reporting whether it was present at all.
func queryDWord(key registry.HKEY, name string) (uint32, bool) {
	var valueType registry.REG_VALUE_TYPE
	size := uint32(4)
	buf := make([]byte, 4)
	if code := registry.RegQueryValueEx(key, name, &valueType, &buf[0], &size); code != foundation.ERROR_SUCCESS {
		return 0, false
	}
	return binary.LittleEndian.Uint32(buf), true
}

// setString writes a REG_SZ as null-terminated little-endian UTF-16, which is
// the form the registry stores and WinINET expects to read back.
func setString(key registry.HKEY, name, value string) error {
	units := append(utf16.Encode([]rune(value)), 0)
	buf := make([]byte, len(units)*2)
	for i, u := range units {
		binary.LittleEndian.PutUint16(buf[i*2:], u)
	}
	return regErr("set "+name, registry.RegSetValueEx(key, name, registry.REG_SZ, buf))
}

func setDWord(key registry.HKEY, name string, value uint32) error {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, value)
	return regErr("set "+name, registry.RegSetValueEx(key, name, registry.REG_DWORD, buf))
}

// deleteValue removes a value, treating "it was not there" as success — this
// runs on restore paths where the value's absence is the desired end state.
func deleteValue(key registry.HKEY, name string) error {
	code := registry.RegDeleteValue(key, name)
	if code == foundation.ERROR_SUCCESS || code == foundation.ERROR_FILE_NOT_FOUND {
		return nil
	}
	return regErr("delete "+name, code)
}

// setSystemProxy points this user's WinINET settings at the proxy and returns
// what was replaced.
//
// This is a convenience, never enforcement: an application is free to ignore
// these settings, which is exactly why the firewall tiers exist. It is offered
// because otherwise every WinINET client would have to be pointed at the proxy
// by hand.
func setSystemProxy(addr string) (*savedProxySettings, error) {
	key, closeKey, err := openInternetSettings(registry.KEY_QUERY_VALUE | registry.KEY_SET_VALUE)
	if err != nil {
		return nil, err
	}
	defer closeKey()

	saved := &savedProxySettings{}
	saved.Enable, saved.HadEnable = queryDWord(key, "ProxyEnable")
	saved.Server, saved.HadServer = queryString(key, "ProxyServer")
	saved.Override, saved.HadOverride = queryString(key, "ProxyOverride")

	if err := setDWord(key, "ProxyEnable", 1); err != nil {
		return nil, err
	}
	if err := setString(key, "ProxyServer", addr); err != nil {
		_ = restoreSystemProxy(saved)
		return nil, err
	}
	// Local addresses bypass the proxy. Without this, every loopback and
	// intranet request would be sent to a proxy that refuses private targets by
	// default, which reads as a broken machine rather than as policy.
	if err := setString(key, "ProxyOverride", "<local>"); err != nil {
		_ = restoreSystemProxy(saved)
		return nil, err
	}

	notifyProxyChanged()
	return saved, nil
}

// restoreSystemProxy puts back what was there, deleting values that did not
// exist before rather than leaving an empty one behind.
func restoreSystemProxy(saved *savedProxySettings) error {
	if saved == nil {
		return nil
	}
	key, closeKey, err := openInternetSettings(registry.KEY_QUERY_VALUE | registry.KEY_SET_VALUE)
	if err != nil {
		return err
	}
	defer closeKey()

	// Every value is attempted even when one fails: stopping halfway would
	// leave the user pointed at a proxy that is no longer running.
	var firstErr error
	note := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if saved.HadEnable {
		note(setDWord(key, "ProxyEnable", saved.Enable))
	} else {
		note(deleteValue(key, "ProxyEnable"))
	}
	if saved.HadServer {
		note(setString(key, "ProxyServer", saved.Server))
	} else {
		note(deleteValue(key, "ProxyServer"))
	}
	if saved.HadOverride {
		note(setString(key, "ProxyOverride", saved.Override))
	} else {
		note(deleteValue(key, "ProxyOverride"))
	}

	notifyProxyChanged()
	if firstErr != nil {
		return fmt.Errorf("restore WinINET settings: %w", firstErr)
	}
	return nil
}

// notifyProxyChanged tells running processes to re-read the settings. A
// registry write alone changes nothing for a process that has already read
// them, so this is not optional — but it is best-effort, because a client that
// ignores the notification is not a failure this server can do anything about.
func notifyProxyChanged() {
	_ = wininet.InternetSetOption(nil, wininet.INTERNET_OPTION_SETTINGS_CHANGED, nil, 0)
	_ = wininet.InternetSetOption(nil, wininet.INTERNET_OPTION_REFRESH, nil, 0)
}
