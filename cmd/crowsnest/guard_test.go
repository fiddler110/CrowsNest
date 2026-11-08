package main

import (
	"strings"
	"testing"
)

func TestGuardRefusesToStartWithoutValidScopes(t *testing.T) {
	for _, env := range []string{"", "not json", "[]", `[{"name": "game"}]`} {
		t.Setenv("GUARD_SCOPES", env)
		err := runGuard([]string{"--listen", "127.0.0.1:0", "--socket", "/nonexistent.sock"})
		if err == nil || !strings.Contains(err.Error(), "refusing to start") {
			t.Errorf("GUARD_SCOPES=%q: err = %v", env, err)
		}
	}
	t.Setenv("GUARD_SCOPES", `[{"name": "game", "images": ["a/b"]}]`)
	t.Setenv("GUARD_MAX_RESPONSE", "-1")
	if err := runGuard([]string{"--listen", "127.0.0.1:0"}); err == nil || !strings.Contains(err.Error(), "refusing to start") {
		t.Errorf("bad GUARD_MAX_RESPONSE: %v", err)
	}
}
