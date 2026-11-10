package auth

import "testing"

func TestEffectiveRoleDefaults(t *testing.T) {
	cases := []struct {
		name string
		rec  UserRecord
		want Role
	}{
		{"password account, no role", UserRecord{Hash: "h"}, RoleAdmin},
		{"google-only, no entry", UserRecord{}, RolePlayer},
		{"explicit admin without hash", UserRecord{Role: RoleAdmin}, RoleAdmin},
		{"explicit player with hash", UserRecord{Hash: "h", Role: RolePlayer}, RolePlayer},
	}
	for _, c := range cases {
		if got := c.rec.EffectiveRole(); got != c.want {
			t.Errorf("%s: EffectiveRole() = %q, want %q", c.name, got, c.want)
		}
	}
}
