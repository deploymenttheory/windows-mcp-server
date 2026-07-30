package guardrails

import (
	"context"
	"testing"
)

func TestNotAdmin(t *testing.T) {
	if got := checkNotAdmin(context.Background(), &Env{Sys: fakeProbe{admin: false}}); got.Status != Pass {
		t.Errorf("non-admin should pass, got %s", got.Status)
	}
	if got := checkNotAdmin(context.Background(), &Env{Sys: fakeProbe{admin: true}}); got.Status != Fail {
		t.Errorf("admin should fail not-admin, got %s", got.Status)
	}
}

func TestLoggedOnAccount(t *testing.T) {
	env := func(user, pattern string) *Env {
		return &Env{Sys: fakeProbe{rc: RunContext{User: user}}, Arg: pattern}
	}
	if got := checkLoggedOnAccount(
		context.Background(),
		env("CONTOSO\\svc-rpa01", `^CONTOSO\\svc-rpa\d+$`),
	); got.Status != Pass {
		t.Errorf("matching user should pass, got %s (%s)", got.Status, got.Detail)
	}
	if got := checkLoggedOnAccount(context.Background(), env("Dafydd", `^svc-`)); got.Status != Fail {
		t.Errorf("non-matching user should fail, got %s", got.Status)
	}
	if got := checkLoggedOnAccount(context.Background(), env("x", "")); got.Status != Error {
		t.Errorf("empty pattern should error, got %s", got.Status)
	}
	if got := checkLoggedOnAccount(context.Background(), env("x", `(unclosed`)); got.Status != Error {
		t.Errorf("invalid regex should error, got %s", got.Status)
	}
}

func TestPreflightProvidersRegistered(t *testing.T) {
	reg := NewRegistry()
	RegisterBuiltins(reg)
	for _, id := range []string{"not-admin", "logged-on-account", "mdm-enrolled", "run-context"} {
		if _, ok := reg.Get(id); !ok {
			t.Errorf("preflight guardrail %q not registered", id)
		}
	}
}
