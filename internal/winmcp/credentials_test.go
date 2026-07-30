//go:build windows && (amd64 || arm64)

package winmcp

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/windows-mcp-server/internal/desktop"
)

// writeCredFile writes a credentials document into a per-test directory. t.TempDir
// inherits the user profile's ACL, so the DACL check passes without extra setup —
// which is also the shape a real operator should use.
func writeCredFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "creds.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadCredentialsFileValid(t *testing.T) {
	path := writeCredFile(t, `{
	  "credentials": [
	    {"name":"corp-sso","target":"login.contoso.com","username":"svc@contoso.com","secret":"s3cr3t"},
	    {"name":"api","target":"api.internal","secret":"tok","type":"generic","persist":"session"}
	  ]
	}`)

	entries, err := loadCredentialsFile(path)
	if err != nil {
		t.Fatalf("loadCredentialsFile: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("want 2 entries, got %d", len(entries))
	}
	if entries[0].Name != "corp-sso" || entries[0].Target != "login.contoso.com" {
		t.Errorf("unexpected first entry: %+v", entries[0])
	}
	if string(entries[0].Secret) != "s3cr3t" {
		t.Errorf("secret not decoded: %q", entries[0].Secret)
	}
	if entries[0].Username != "svc@contoso.com" {
		t.Errorf("username not decoded: %q", entries[0].Username)
	}
}

func TestLoadCredentialsFileRejects(t *testing.T) {
	for name, tc := range map[string]struct {
		body    string
		wantSub string
	}{
		"no entries":       {`{"credentials":[]}`, "no entries"},
		"missing name":     {`{"credentials":[{"target":"t","secret":"s"}]}`, "name is required"},
		"missing target":   {`{"credentials":[{"name":"n","secret":"s"}]}`, "target is required"},
		"missing secret":   {`{"credentials":[{"name":"n","target":"t"}]}`, "secret is required"},
		"duplicate name":   {`{"credentials":[{"name":"n","target":"a","secret":"s"},{"name":"n","target":"b","secret":"s"}]}`, "duplicate name"},
		"duplicate target": {`{"credentials":[{"name":"a","target":"t","secret":"s"},{"name":"b","target":"t","secret":"s"}]}`, "duplicate target"},
		"durable persist":  {`{"credentials":[{"name":"n","target":"t","secret":"s","persist":"local_machine"}]}`, "not supported"},
		"malformed json":   {`{"credentials":`, "parse credentials file"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := loadCredentialsFile(writeCredFile(t, tc.body))
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q should mention %q", err, tc.wantSub)
			}
		})
	}
}

func TestLoadCredentialsFileMissingPath(t *testing.T) {
	if _, err := loadCredentialsFile(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Error("a missing file must be an error")
	}
}

func TestLoadCredentialsFileRejectsDirectory(t *testing.T) {
	if _, err := loadCredentialsFile(t.TempDir()); err == nil {
		t.Error("a directory must be rejected")
	}
}

func TestLoadCredentialsFileRejectsOversized(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.json")
	if err := os.WriteFile(path, make([]byte, credentialFileMaxSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCredentialsFile(path); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Errorf("oversized file should be rejected with a limit message, got %v", err)
	}
}

// TestSecretBytesDecoding covers both decode paths: the unescaped fast path that
// avoids ever materializing a Go string, and the escaped fallback.
func TestSecretBytesDecoding(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`"plain"`, "plain"},
		{`"with spaces and $ymbols"`, "with spaces and $ymbols"},
		{`"esc\"aped"`, `esc"aped`},
		{`"tab\there"`, "tab\there"},
		{`"unicode é"`, "unicode é"},
		{`"back\\slash"`, `back\slash`},
	} {
		var s secretBytes
		if err := json.Unmarshal([]byte(tc.in), &s); err != nil {
			t.Errorf("%s: %v", tc.in, err)
			continue
		}
		if string(s) != tc.want {
			t.Errorf("%s decoded to %q, want %q", tc.in, s, tc.want)
		}
	}
}

// TestSecretBytesFastPathDoesNotAliasInput proves the unescaped path copies rather
// than aliasing the JSON buffer, which the loader wipes after parsing.
func TestSecretBytesFastPathDoesNotAliasInput(t *testing.T) {
	raw := []byte(`"topsecret"`)
	var s secretBytes
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	wipe(raw)
	if string(s) != "topsecret" {
		t.Errorf("secret aliased the wiped input buffer: %q", s)
	}
}

// TestLoadCredentialsFileWipesFileBuffer confirms the secret survives the loader's
// wipe of the raw file bytes — i.e. entries hold their own copies.
func TestLoadCredentialsFileWipesFileBuffer(t *testing.T) {
	path := writeCredFile(t, `{"credentials":[{"name":"n","target":"t","secret":"survives"}]}`)
	entries, err := loadCredentialsFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(entries[0].Secret) != "survives" {
		t.Errorf("secret did not survive the file-buffer wipe: %q", entries[0].Secret)
	}
}

func TestCredentialInfosOmitSecretsAndDefault(t *testing.T) {
	infos := credentialInfos([]installedCredential{
		{Name: "a", Target: "t1", Username: "u", Type: desktop.CredentialGeneric, Persist: desktop.PersistSession},
		{Name: "b", Target: "t2", Type: desktop.CredentialDomainPassword, Persist: desktop.PersistSession},
	})
	if len(infos) != 2 {
		t.Fatalf("want 2, got %d", len(infos))
	}
	if !infos[0].Injectable {
		t.Error("generic credentials should be injectable")
	}
	if infos[1].Injectable {
		t.Error("domain_password credentials must not be marked injectable")
	}
	// Assert on the serialized *keys* rather than substrings: "domain_password" is a
	// credential class name, not a secret, so a substring scan gives a false
	// positive. An allowlist of keys is what actually pins the guarantee — a new
	// field carrying a secret would have to be added to this list deliberately.
	b, err := json.Marshal(infos)
	if err != nil {
		t.Fatal(err)
	}
	var decoded []map[string]json.RawMessage
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{
		"name": true, "target": true, "username": true,
		"type": true, "persist": true, "present": true, "injectable": true,
	}
	for _, obj := range decoded {
		for k := range obj {
			if !allowed[k] {
				t.Errorf("credential info exposes unexpected field %q: a secret must never be "+
					"serializable to a tool result", k)
			}
		}
	}
}

func TestDefaultTypeAndPersist(t *testing.T) {
	if got := defaultType(""); got != desktop.CredentialGeneric {
		t.Errorf("defaultType(\"\") = %q", got)
	}
	if got := defaultPersist(""); got != desktop.PersistSession {
		t.Errorf("defaultPersist(\"\") = %q", got)
	}
	if got := defaultType(desktop.CredentialDomainPassword); got != desktop.CredentialDomainPassword {
		t.Errorf("explicit type should be preserved, got %q", got)
	}
}

// TestAuditViewHasNoSecret guards the audit path: identifiers only.
func TestAuditViewHasNoSecret(t *testing.T) {
	view := auditView([]installedCredential{
		{Name: "n", Target: "t", Username: "u", Type: desktop.CredentialGeneric, Persist: desktop.PersistSession},
	})
	b, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(b)), "secret") {
		t.Errorf("audit view must not carry secrets: %s", b)
	}
	for _, want := range []string{"name", "target", "username"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("audit view missing %q: %s", want, b)
		}
	}
}

// TestWithToolsetKeepsDefaults is the regression guard for auto-enabling the
// credentials toolset: a nil selection means "the defaults", so it must become
// default+credentials rather than credentials alone, which would silently drop
// every default toolset.
func TestWithToolsetKeepsDefaults(t *testing.T) {
	got := withToolset(nil, "credentials")
	if len(got) != 2 || got[0] != "default" || got[1] != "credentials" {
		t.Errorf("nil selection = %v, want [default credentials]", got)
	}
	if got := withToolset([]string{"all"}, "credentials"); len(got) != 1 || got[0] != "all" {
		t.Errorf("'all' should be left alone, got %v", got)
	}
	if got := withToolset([]string{"credentials"}, "credentials"); len(got) != 1 {
		t.Errorf("already-present toolset should not be duplicated, got %v", got)
	}
	got = withToolset([]string{"screen", "apps"}, "credentials")
	if len(got) != 3 || got[2] != "credentials" {
		t.Errorf("explicit selection = %v, want screen,apps,credentials", got)
	}
}

func TestErrNoCredentialsIsMatchable(t *testing.T) {
	_, err := loadCredentialsFile(writeCredFile(t, `{"credentials":[]}`))
	if !errors.Is(err, ErrNoCredentials) {
		t.Errorf("want ErrNoCredentials, got %v", err)
	}
}
