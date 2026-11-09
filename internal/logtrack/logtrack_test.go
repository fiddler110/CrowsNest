package logtrack

import (
	"context"
	"regexp"
	"strings"
	"testing"
)

func valheimSpec() Spec {
	return Spec{
		Name:  "valheim",
		Ready: regexp.MustCompile(`Loading: Done\.|Opened Steam server`),
		Join:  regexp.MustCompile(`Got handshake from client (\S+)`),
		Leave: regexp.MustCompile(`Closing socket (\S+)`),
		World: regexp.MustCompile(`Load world:\s*(.+?)\s*$`),
	}
}

func count(t *testing.T, tr *Tracker) (int, []string, bool) {
	t.Helper()
	return tr.PlayerCount(context.Background())
}

func TestPlayerCount_UnattachedIsUndeterminable(t *testing.T) {
	if _, _, ok := count(t, New(nil, "v", valheimSpec())); ok {
		t.Fatal("ok = true before any log stream attached")
	}
}

func TestScan_TracksJoinsAndLeaves(t *testing.T) {
	tr := New(nil, "v", valheimSpec())
	tr.attached = true
	tr.scan(strings.NewReader(strings.Join([]string{
		"02/06/2026 15:26:38: Got handshake from client 111",
		"Got handshake from client V_222",
		"Got character ZDOID from Alice : 123",
		"Closing socket 111",
	}, "\n")))
	n, names, ok := count(t, tr)
	if !ok || n != 1 || names[0] != "V_222" {
		t.Fatalf("got %d %v %v, want [V_222]", n, names, ok)
	}
	tr.scan(strings.NewReader("Closing socket V_222\n"))
	if n, _, _ := count(t, tr); n != 0 {
		t.Fatalf("count after leave = %d", n)
	}
}

func TestScan_ReadyLatchesAndResetClears(t *testing.T) {
	tr := New(nil, "v", valheimSpec())
	tr.scan(strings.NewReader("Game server connected\n"))
	if tr.ready {
		t.Fatal("ready too early")
	}
	tr.scan(strings.NewReader("09:47:12: Loading: Done. Total seconds sinze ZNet start: 27.97\n"))
	if !tr.ready {
		t.Fatal("not ready after marker")
	}
	tr.reset()
	if tr.ready || tr.attached {
		t.Fatal("state survived reset")
	}
}

func TestScan_WorldAndReset(t *testing.T) {
	tr := New(nil, "v", valheimSpec())
	tr.scan(strings.NewReader("02/06/2026 15:00:00: Load world: Midgard\n"))
	if tr.world != "Midgard" {
		t.Fatalf("world = %q", tr.world)
	}
	tr.reset()
	if tr.world != "" {
		t.Fatal("world survived reset")
	}
}

func TestStatusOnlyTrackerIgnoresPlayers(t *testing.T) {
	tr := New(nil, "w", Spec{Name: "w", Ready: regexp.MustCompile(`ready`)})
	tr.attached = true
	tr.scan(strings.NewReader("Got handshake from client 1\nserver ready\n"))
	if n, _, _ := count(t, tr); n != 0 || !tr.ready {
		t.Fatalf("players=%d ready=%v", n, tr.ready)
	}
}

func TestInfo_UnattachedIsUnavailable(t *testing.T) {
	info, ok := New(nil, "v", valheimSpec()).Info(context.Background())
	if !ok || info["available"] != false {
		t.Fatalf("Info = %v %v", info, ok)
	}
}
