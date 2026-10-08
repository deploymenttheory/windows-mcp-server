//go:build windows && (amd64 || arm64)

package winmcp

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// TestGuardrailEnvCarriesEnforceHTTPS proves the setting actually reaches the
// guardrail checks, which is what lets remote-policy refuse a plaintext
// endpoint. It is on Config rather than read from the policy at each call
// site because it has to reach the tool dependencies and the guardrail Env,
// neither of which carries a policy.
func TestGuardrailEnvCarriesEnforceHTTPS(t *testing.T) {
	if env := guardrailEnv(Config{EnforceHTTPS: true}, nil, nil); !env.EnforceHTTPS {
		t.Error("guardrailEnv must propagate EnforceHTTPS")
	}
	if env := guardrailEnv(Config{}, nil, nil); env.EnforceHTTPS {
		t.Error("guardrailEnv must not set EnforceHTTPS when off")
	}
}

// TestShippedPolicyExamplesValidate pins that every example in policy/examples
// loads against this build's signal set, so a harness bump that renames a
// signal fails here rather than at an operator's first start.
func TestShippedPolicyExamplesValidate(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("..", "..", "policy", "examples"))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		n++
		path := filepath.Join("..", "..", "policy", "examples", e.Name())
		if _, err := ValidatePolicy(Config{PolicyConfig: path}); err != nil {
			t.Errorf("%s: %v", e.Name(), err)
		}
	}
	if n == 0 {
		t.Fatal("no policy examples found")
	}
}
