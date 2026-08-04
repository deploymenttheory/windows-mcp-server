//go:build windows && (amd64 || arm64)

package desktop

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/windows/registry"
)

// MCP hosts (e.g. Claude Desktop) frequently launch child servers with a
// stripped environment, so a naive PowerShell child would not see the user's
// PATH or common variables. powerShellEnv rebuilds a full environment block from
// the registry (system + user environment keys, with PATH merged and %VAR%
// references expanded), matching the Python implementation. The result is cached
// for the process lifetime.

var (
	psEnvOnce    sync.Once
	psEnvList    []string
	psPathValue  string
	psSystemRoot string
)

func ensureWindowsEnv() {
	psEnvOnce.Do(func() { psEnvList, psPathValue, psSystemRoot = buildWindowsEnv() })
}

// powerShellEnv returns the reconstructed environment block for child processes.
func powerShellEnv() []string {
	ensureWindowsEnv()
	return psEnvList
}

// resolvePwsh returns the absolute path to PowerShell 7 (pwsh) if available,
// otherwise Windows PowerShell 5.1. It searches the reconstructed PATH (not the
// possibly-stripped process PATH) and falls back to the deterministic System32
// location.
func resolvePwsh() string {
	ensureWindowsEnv()
	if p, ok := lookPathIn("pwsh", psPathValue); ok {
		return p
	}
	if p, ok := lookPathIn("powershell", psPathValue); ok {
		return p
	}
	return windowsPowerShellPath()
}

// resolveWindowsPowerShellExe returns the absolute path to Windows PowerShell
// 5.1 (powershell.exe), needed for WinRT APIs.
func resolveWindowsPowerShellExe() string {
	ensureWindowsEnv()
	if p, ok := lookPathIn("powershell", psPathValue); ok {
		return p
	}
	return windowsPowerShellPath()
}

func windowsPowerShellPath() string {
	root := psSystemRoot
	if root == "" {
		root = firstNonEmpty(os.Getenv("SystemRoot"), `C:\Windows`)
	}
	return filepath.Join(root, `System32`, `WindowsPowerShell`, `v1.0`, `powershell.exe`)
}

// lookPathIn searches a PATH string for an executable, returning its absolute
// path. It resolves the executable against the given PATH rather than the
// process environment.
func lookPathIn(exe, pathVal string) (string, bool) {
	exts := []string{".exe", ".cmd", ".bat", ""}
	for dir := range strings.SplitSeq(pathVal, ";") {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}
		for _, ext := range exts {
			cand := filepath.Join(dir, exe+ext)
			if fi, err := os.Stat(cand); err == nil && !fi.IsDir() {
				return cand, true
			}
		}
	}
	return "", false
}

// buildWindowsEnv reconstructs the environment and returns the env block, the
// merged PATH value, and SystemRoot.
func buildWindowsEnv() ([]string, string, string) {
	env := newEnvMap()

	// System environment (registry).
	sysVars := readEnvKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`)
	for k, v := range sysVars {
		env.set(k, v)
	}
	sysPath, _ := env.get("Path")

	// User environment overlays system (PATH is merged, not overwritten).
	userVars := readEnvKey(registry.CURRENT_USER, `Environment`)
	var userPath string
	for k, v := range userVars {
		if strings.EqualFold(k, "Path") {
			userPath = v
			continue
		}
		env.set(k, v)
	}
	if merged := mergePath(sysPath, userPath); merged != "" {
		env.set("Path", merged)
	}

	// Expand %VAR% references against the registry-derived map (single pass).
	env.expandAll()

	// Apply per-session dynamic variables LAST so they win over the registry's
	// system-account values (e.g. USERNAME in HKLM is "SYSTEM"). Each prefers the
	// current process value, falling back to a derived default so a fully
	// stripped host still yields a usable value.
	systemDrive := firstNonEmpty(os.Getenv("SystemDrive"), `C:`)
	systemRoot := firstNonEmpty(os.Getenv("SystemRoot"), os.Getenv("windir"), systemDrive+`\Windows`)
	userProfile := os.Getenv("USERPROFILE")
	if userProfile == "" {
		if home, err := os.UserHomeDir(); err == nil {
			userProfile = home
		}
	}
	seed := func(k, fallback string) {
		if v := firstNonEmpty(os.Getenv(k), fallback); v != "" {
			env.set(k, v)
		}
	}
	seed("SystemDrive", systemDrive)
	seed("SystemRoot", systemRoot)
	seed("windir", systemRoot)
	seed("USERPROFILE", userProfile)
	seed("USERNAME", "")
	seed("USERDOMAIN", "")
	seed("COMPUTERNAME", "")
	seed("PROCESSOR_ARCHITECTURE", "")
	seed("ProgramFiles", systemDrive+`\Program Files`)
	seed("ProgramFiles(x86)", systemDrive+`\Program Files (x86)`)
	seed("ProgramW6432", systemDrive+`\Program Files`)
	seed("ProgramData", systemDrive+`\ProgramData`)
	seed("ALLUSERSPROFILE", systemDrive+`\ProgramData`)
	seed("PUBLIC", systemDrive+`\Users\Public`)
	seed("HOMEDRIVE", systemDrive)
	if userProfile != "" {
		seed("APPDATA", userProfile+`\AppData\Roaming`)
		seed("LOCALAPPDATA", userProfile+`\AppData\Local`)
		seed("TEMP", userProfile+`\AppData\Local\Temp`)
		seed("TMP", userProfile+`\AppData\Local\Temp`)
	}

	// Preserve any host-provided variables not already set, so a good env is
	// never diminished — except this server's own, which are withheld. See
	// isServerOwnVar.
	for _, kv := range os.Environ() {
		if i := strings.IndexByte(kv, '='); i > 0 {
			if isServerOwnVar(kv[:i]) {
				continue
			}
			if _, ok := env.get(kv[:i]); !ok {
				env.set(kv[:i], kv[i+1:])
			}
		}
	}

	pathVal, _ := env.get("Path")
	return env.slice(), pathVal, systemRoot
}

// serverVarPrefix is the prefix of this server's own configuration and secret
// environment variables.
const serverVarPrefix = "WINDOWS_MCP_"

// isServerOwnVar reports whether name belongs to this server rather than to the
// user's desktop session, and so must never be handed to a child process.
//
// Several of these are secrets — the audit-chain HMAC key, the approvals key, the
// Graph client secret, the remote-policy token, the OTLP auth headers. They are
// read from the environment precisely so they stay out of argv, which is
// world-readable; inheriting them into a shell the model can drive would hand
// them straight back, and one "Get-ChildItem Env:" would disclose the key whose
// whole purpose is that the audited party cannot forge the chain.
//
// The non-secret WINDOWS_MCP_* variables are withheld too. A child process has no
// business reading this server's configuration, and a prefix rule cannot be got
// wrong the way a list of individual names can as new variables are added.
// Comparison is case-insensitive because Windows environment names are.
func isServerOwnVar(name string) bool {
	return len(name) >= len(serverVarPrefix) &&
		strings.EqualFold(name[:len(serverVarPrefix)], serverVarPrefix)
}

// envMap is a case-insensitive environment variable map (Windows env vars are
// case-insensitive) that preserves the original key casing.
type envMap struct {
	keys map[string]string // lower -> original key
	vals map[string]string // lower -> value
}

func newEnvMap() *envMap {
	return &envMap{keys: map[string]string{}, vals: map[string]string{}}
}

func (e *envMap) set(k, v string) {
	l := strings.ToLower(k)
	if _, ok := e.keys[l]; !ok {
		e.keys[l] = k
	}
	e.vals[l] = v
}

func (e *envMap) get(k string) (string, bool) {
	v, ok := e.vals[strings.ToLower(k)]
	return v, ok
}

func (e *envMap) expandAll() {
	for l, v := range e.vals {
		e.vals[l] = e.expand(v)
	}
}

// expand replaces %NAME% references using the map, in a single pass (no
// recursion, so it cannot loop on self-referential values).
func (e *envMap) expand(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	for {
		i := strings.IndexByte(s, '%')
		if i < 0 {
			b.WriteString(s)
			break
		}
		j := strings.IndexByte(s[i+1:], '%')
		if j < 0 {
			b.WriteString(s)
			break
		}
		name := s[i+1 : i+1+j]
		b.WriteString(s[:i])
		if val, ok := e.vals[strings.ToLower(name)]; ok {
			b.WriteString(val)
		} else {
			b.WriteString("%" + name + "%")
		}
		s = s[i+1+j+1:]
	}
	return b.String()
}

func (e *envMap) slice() []string {
	out := make([]string, 0, len(e.vals))
	for l, orig := range e.keys {
		out = append(out, orig+"="+e.vals[l])
	}
	return out
}

func readEnvKey(root registry.Key, path string) map[string]string {
	out := map[string]string{}
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return out
	}
	defer k.Close()
	names, err := k.ReadValueNames(0)
	if err != nil {
		return out
	}
	for _, name := range names {
		if val, _, err := k.GetStringValue(name); err == nil {
			out[name] = val
		}
	}
	return out
}

// mergePath concatenates two PATH values, de-duplicating entries
// case-insensitively while preserving order (system entries first).
func mergePath(sysPath, userPath string) string {
	seen := map[string]bool{}
	var parts []string
	add := func(p string) {
		for seg := range strings.SplitSeq(p, ";") {
			seg = strings.TrimSpace(seg)
			if seg == "" {
				continue
			}
			key := strings.ToLower(seg)
			if !seen[key] {
				seen[key] = true
				parts = append(parts, seg)
			}
		}
	}
	add(sysPath)
	add(userPath)
	return strings.Join(parts, ";")
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
