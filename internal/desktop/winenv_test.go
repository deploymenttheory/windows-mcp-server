//go:build windows && (amd64 || arm64)

package desktop

import "testing"

func TestMergePath(t *testing.T) {
	got := mergePath(`C:\Windows;C:\Windows\System32`, `C:\Windows\System32;C:\Users\me\bin`)
	want := `C:\Windows;C:\Windows\System32;C:\Users\me\bin` // deduped, order preserved
	if got != want {
		t.Errorf("mergePath = %q, want %q", got, want)
	}
	// Case-insensitive dedup.
	got = mergePath(`C:\Windows`, `c:\windows`)
	if got != `C:\Windows` {
		t.Errorf("case-insensitive dedup: got %q", got)
	}
}

func TestEnvMapExpand(t *testing.T) {
	e := newEnvMap()
	e.set("SystemRoot", `C:\Windows`)
	e.set("Path", `%SystemRoot%\System32;%SystemRoot%\System32\Wbem`)
	e.set("Unknown", `%NOPE%\x`)
	e.expandAll()

	if v, _ := e.get("Path"); v != `C:\Windows\System32;C:\Windows\System32\Wbem` {
		t.Errorf("expanded Path = %q", v)
	}
	// Unknown variables are left intact.
	if v, _ := e.get("Unknown"); v != `%NOPE%\x` {
		t.Errorf("unknown var expansion = %q, want unchanged", v)
	}
}

func TestEnvMapCaseInsensitive(t *testing.T) {
	e := newEnvMap()
	e.set("Path", "a")
	e.set("PATH", "b") // same var, different case
	if v, _ := e.get("path"); v != "b" {
		t.Errorf("case-insensitive get = %q, want b", v)
	}
	// Only one entry should be emitted.
	count := 0
	for _, kv := range e.slice() {
		if len(kv) >= 4 && (kv[:4] == "Path" || kv[:4] == "PATH") {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected single PATH entry, got %d", count)
	}
}
