package settings

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func defaults() Values {
	return Values{IdleEnabled: true, IdleMinutes: 15, NightStartHour: 23, NightEndHour: 5, MaxActiveGames: 1}
}

func TestPersistAndReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	s, err := New(defaults(), path)
	if err != nil {
		t.Fatal(err)
	}
	v := s.Get()
	v.IdleMinutes = 20
	v.AutoUpdate = true
	if err := s.Update(v); err != nil {
		t.Fatal(err)
	}
	s2, err := New(defaults(), path)
	if err != nil {
		t.Fatal(err)
	}
	if got := s2.Get(); got.IdleMinutes != 20 || !got.AutoUpdate {
		t.Fatalf("reloaded %+v", got)
	}
}

func TestUpdateRejectsInvalidAndKeepsOld(t *testing.T) {
	s, _ := New(defaults(), "")
	bad := defaults()
	bad.IdleMinutes = 0
	if err := s.Update(bad); err == nil {
		t.Fatal("expected error")
	}
	if s.Get().IdleMinutes != 15 {
		t.Fatal("value changed despite error")
	}
	bad = defaults()
	bad.NightEnabled, bad.NightStartHour, bad.NightEndHour = true, 3, 3
	if err := s.Update(bad); err == nil {
		t.Fatal("expected equal-hours error")
	}
}

func TestInvalidFileIsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	os.WriteFile(path, []byte(`{"idle_minutes": 99999}`), 0o600)
	if _, err := New(defaults(), path); err == nil {
		t.Fatal("expected error")
	}
}

func TestPartialFileKeepsDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	os.WriteFile(path, []byte(`{"idle_minutes": 30}`), 0o600)
	s, err := New(defaults(), path)
	if err != nil {
		t.Fatal(err)
	}
	if v := s.Get(); v.IdleMinutes != 30 || v.MaxActiveGames != 1 || !v.IdleEnabled {
		t.Fatalf("%+v", v)
	}
}

func TestModify_AtomicAndValidated(t *testing.T) {
	s, _ := New(Values{IdleMinutes: 10, MaxActiveGames: 1, NightStartHour: 23, NightEndHour: 5}, "")
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); s.Modify(func(v *Values) error { v.IdleMinutes++; return nil }) }()
		go func() { defer wg.Done(); s.Modify(func(v *Values) error { v.MaxActiveGames++; return nil }) }()
	}
	wg.Wait()
	if v := s.Get(); v.IdleMinutes != 30 || v.MaxActiveGames != 21 {
		t.Fatalf("concurrent partial updates lost writes: %+v", v)
	}
	if _, err := s.Modify(func(v *Values) error { v.IdleMinutes = 0; return nil }); err == nil {
		t.Fatal("Modify accepted an invalid value")
	}
	if s.Get().IdleMinutes != 30 {
		t.Fatal("a rejected Modify changed the values")
	}
}

func intp(n int) *int { return &n }

func TestPerGame_ReplaceRemoveAndValidate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	s, _ := New(defaults(), path)
	night := false
	if _, err := s.Modify(func(v *Values) error {
		v.PerGame = map[string]GameValues{"valheim": {IdleMinutes: intp(5), NightShutdown: &night}, "palworld": {RestartCooldownSeconds: intp(0)}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	v := s.Get()
	if on, set := v.NightOverride("valheim"); !set || on {
		t.Fatalf("night override = %v %v", on, set)
	}
	if secs, set := v.CooldownOverride("palworld"); !set || secs != 0 {
		t.Fatalf("cooldown override = %v %v", secs, set)
	}
	if _, set := v.CooldownOverride("valheim"); set {
		t.Fatal("valheim has no cooldown override")
	}
	// Editing a snapshot must not reach the store.
	v.PerGame["valheim"] = GameValues{}
	if s.Get().PerGame["valheim"].IdleMinutes == nil {
		t.Fatal("Get shares its map with the store")
	}
	// An all-empty entry is dropped; a rejected change leaves the map alone.
	if _, err := s.Modify(func(v *Values) error { v.PerGame["valheim"] = GameValues{}; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Get().PerGame["valheim"]; ok {
		t.Fatal("empty entry kept")
	}
	if _, err := s.Modify(func(v *Values) error { v.PerGame["palworld"] = GameValues{IdleMinutes: intp(0)}; return nil }); err == nil {
		t.Fatal("accepted idle_minutes 0")
	}
	if _, err := s.Modify(func(v *Values) error {
		v.PerGame["palworld"] = GameValues{RestartCooldownSeconds: intp(MaxCooldownSeconds + 1)}
		return nil
	}); err == nil {
		t.Fatal("accepted an oversized cooldown")
	}
	if secs, _ := s.Get().CooldownOverride("palworld"); secs != 0 {
		t.Fatal("a rejected Modify changed the live map")
	}
	s2, err := New(defaults(), path)
	if err != nil {
		t.Fatal(err)
	}
	if _, set := s2.Get().CooldownOverride("palworld"); !set {
		t.Fatal("override not persisted")
	}
}
