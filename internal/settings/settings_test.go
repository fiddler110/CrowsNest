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
