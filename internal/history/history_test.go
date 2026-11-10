package history

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newStore(t *testing.T, retention time.Duration) (*Store, *time.Time, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sub", "events.jsonl")
	clock := time.Date(2026, 11, 1, 20, 0, 0, 0, time.UTC)
	s, err := Open(path, retention)
	if err != nil {
		t.Fatal(err)
	}
	s.Now = func() time.Time { return clock }
	return s, &clock, path
}

func TestRecordPersistsAndReloads(t *testing.T) {
	s, clock, path := newStore(t, 0)
	s.Record(KindStart, "palworld", "scott", "")
	*clock = clock.Add(time.Minute)
	s.Record(KindStop, "palworld", "scott", "")

	re, err := Open(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := re.Recent(10, "")
	if len(got) != 2 || got[0].Kind != KindStop || got[1].Kind != KindStart {
		t.Fatalf("Recent after reload = %+v, want stop then start (newest first)", got)
	}
	if len(re.Recent(10, "valheim")) != 0 || len(re.Recent(1, "")) != 1 {
		t.Fatal("game filter / limit not applied")
	}
}

func TestOpenSkipsGarbageLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "e.jsonl")
	os.WriteFile(path, []byte("not json\n{\"t\":\"2026-11-01T10:00:00Z\",\"kind\":\"start\",\"game\":\"g\"}\n\n"), 0o600)
	s, err := Open(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(s.Recent(10, "")); n != 1 {
		t.Fatalf("loaded %d events, want the 1 valid one", n)
	}
}

func TestPruneDropsOldEventsOnDisk(t *testing.T) {
	s, clock, path := newStore(t, 24*time.Hour)
	s.Record(KindStart, "g", "old", "")
	*clock = clock.Add(48 * time.Hour)
	s.Record(KindStart, "g", "new", "")
	if err := s.Prune(); err != nil {
		t.Fatal(err)
	}
	if got := s.Recent(10, ""); len(got) != 1 || got[0].Actor != "new" {
		t.Fatalf("after prune = %+v", got)
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "old") {
		t.Fatal("pruned event still on disk")
	}
}

func TestPlaytime(t *testing.T) {
	s, clock, _ := newStore(t, 0)
	at := func(m int) { *clock = time.Date(2026, 11, 1, 20, m, 0, 0, time.UTC) }
	at(0)
	s.Record(KindLeave, "g", "ghost", "") // no join: ignored
	s.Record(KindJoin, "g", "ann", "")
	s.Record(KindJoin, "g", "bob", "")
	at(30)
	s.Record(KindLeave, "g", "ann", "") // ann: 30m
	at(50)
	s.Record(KindStop, "g", "scott", "") // closes bob: 50m
	at(55)
	s.Record(KindJoin, "g", "cat", "")
	at(60) // cat still aboard: 5m to now

	got := s.Playtime()
	want := map[string]int64{"bob": 50 * 60, "ann": 30 * 60, "cat": 5 * 60}
	if len(got) != 3 {
		t.Fatalf("Playtime = %+v", got)
	}
	for _, p := range got {
		if want[p.Player] != p.Seconds {
			t.Errorf("%s = %ds, want %ds", p.Player, p.Seconds, want[p.Player])
		}
	}
	if got[0].Player != "bob" {
		t.Errorf("not sorted longest first: %+v", got)
	}
}

func TestNilStoreIsSafe(t *testing.T) {
	var s *Store
	s.Record(KindStart, "g", "a", "")
}

func TestRecentExcludingStillFillsLimit(t *testing.T) {
	s, _, _ := newStore(t, 0)
	s.Record(KindJoin, "g", "ann", "")
	s.Record(KindSettings, "", "root", "x")
	s.Record(KindConsole, "g", "root", "y")
	s.Record(KindLeave, "g", "ann", "")
	s.Record(KindUsers, "", "root", "z")
	got := s.RecentExcluding(2, "", KindSettings, KindConsole, KindUsers)
	if len(got) != 2 || got[0].Kind != KindLeave || got[1].Kind != KindJoin {
		t.Fatalf("RecentExcluding = %+v", got)
	}
}

func TestPlaytimeCacheInvalidates(t *testing.T) {
	s, clock, _ := newStore(t, 0)
	s.Record(KindJoin, "g", "ann", "")
	*clock = clock.Add(10 * time.Minute)
	if got := s.Playtime(); len(got) != 1 || got[0].Seconds != 600 {
		t.Fatalf("open visit = %+v", got)
	}
	*clock = clock.Add(5 * time.Minute) // cached: open visit keeps accruing
	if got := s.Playtime(); got[0].Seconds != 900 {
		t.Fatalf("cached open visit = %+v", got)
	}
	s.Record(KindLeave, "g", "ann", "") // Record must invalidate
	*clock = clock.Add(time.Hour)
	if got := s.Playtime(); got[0].Seconds != 900 {
		t.Fatalf("after leave = %+v", got)
	}
}
