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

func TestCanAccess(t *testing.T) {
	cases := []struct {
		name string
		rec  UserRecord
		id   string
		want bool
	}{
		{"no list means all", UserRecord{Role: RolePlayer}, "palworld", true},
		{"listed", UserRecord{Role: RolePlayer, Games: []string{"palworld"}}, "palworld", true},
		{"not listed", UserRecord{Role: RolePlayer, Games: []string{"palworld"}}, "valheim", false},
		{"admin ignores list", UserRecord{Role: RoleAdmin, Games: []string{"palworld"}}, "valheim", true},
	}
	for _, c := range cases {
		if got := c.rec.CanAccess(c.id); got != c.want {
			t.Errorf("%s: CanAccess(%q) = %v, want %v", c.name, c.id, got, c.want)
		}
	}
}

func TestGamesRoundTrip(t *testing.T) {
	path := t.TempDir() + "/users"
	if err := CreateUser(path, "sam", "h", "", RolePlayer); err != nil {
		t.Fatal(err)
	}
	if err := SetGames(path, "sam", []string{"Valheim", "palworld", "valheim"}); err != nil {
		t.Fatal(err)
	}
	u, err := LoadUsers(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := u["sam"].Games; len(got) != 2 || got[0] != "palworld" || got[1] != "valheim" {
		t.Fatalf("Games = %v", got)
	}
	if err := SetGames(path, "sam", nil); err != nil {
		t.Fatal(err)
	}
	u, _ = LoadUsers(path)
	if len(u["sam"].Games) != 0 {
		t.Fatalf("cleared Games = %v", u["sam"].Games)
	}
	if err := SetGames(path, "sam", []string{"bad id"}); err == nil {
		t.Fatal("want error for an invalid id")
	}
}

func TestAdoptUsers(t *testing.T) {
	path := t.TempDir() + "/users"
	if added, err := AdoptUsers(path, []string{"pal"}); err != nil || len(added) != 0 {
		t.Fatalf("empty file adopted %v, %v; want nothing", added, err)
	}
	if err := CreateUser(path, "admin", "h", "", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	added, err := AdoptUsers(path, []string{"Pal", "admin", "pal"})
	if err != nil || len(added) != 1 || added[0] != "pal" {
		t.Fatalf("adopted %v, %v", added, err)
	}
	u, _ := LoadUsers(path)
	if r := u["pal"]; r.Role != RolePlayer || r.Hash != "" || r.GoogleEmail != "" {
		t.Fatalf("pal = %+v", r)
	}
	if err := SetGames(path, "pal", []string{"palworld"}); err != nil {
		t.Fatalf("SetGames on adopted user: %v", err)
	}
	if added, _ := AdoptUsers(path, []string{"pal"}); len(added) != 0 {
		t.Fatalf("second adopt added %v", added)
	}
}

func TestReachability(t *testing.T) {
	users := Users{
		"root":   {Hash: "h", Role: RoleAdmin},
		"gina":   {Role: RolePlayer, GoogleEmail: "g@x.org"},
		"both":   {Hash: "h", Role: RoleAdmin, GoogleEmail: "b@x.org"},
		"pwonly": {Hash: "h", Role: RolePlayer},
	}
	r := Reachability(users, GoogleUsers{"e@x.org": "envuser"}, SignInMethods{true, true, false}, SignInMethods{false, true, false})
	if len(r.Locked) != 2 || r.Locked[0] != "pwonly" || r.Locked[1] != "root" {
		t.Errorf("locked = %v", r.Locked)
	}
	if r.AdminsLeft != 1 {
		t.Errorf("admins left = %d, want 1 (both)", r.AdminsLeft)
	}
	// Google off as well as passwords: nobody.
	if r := Reachability(users, nil, SignInMethods{true, true, false}, SignInMethods{}); r.AdminsLeft != 0 || len(r.Locked) != 4 {
		t.Errorf("everything off: %+v", r)
	}
	// Turning passwords on locks nobody.
	if r := Reachability(users, nil, SignInMethods{false, true, false}, SignInMethods{true, true, false}); len(r.Locked) != 0 {
		t.Errorf("widening locked %v", r.Locked)
	}
}
