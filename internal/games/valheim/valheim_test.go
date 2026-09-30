package valheim

import (
	"context"
	"strings"
	"testing"
)

func TestPlayerCount_UnattachedIsUndeterminable(t *testing.T) {
	tr := NewTracker(nil, "valheim")
	_, _, ok := tr.PlayerCount(context.Background())
	if ok {
		t.Fatal("PlayerCount() ok = true before any log stream attached, want false")
	}
}

func TestScan_TracksConnectAndDisconnect(t *testing.T) {
	tr := NewTracker(nil, "valheim")
	tr.attached = true

	log := strings.Join([]string{
		"02/06/2026 15:26:38: Got handshake from client 76561197987220805",
		"02/06/2026 15:26:40: Network version check",
		"02/06/2026 15:27:00: Got character ZDOID from Alice : 123",
	}, "\n")
	tr.scan(strings.NewReader(log))

	count, names, ok := tr.PlayerCount(context.Background())
	if !ok {
		t.Fatal("PlayerCount() ok = false, want true (attached)")
	}
	if count != 1 || names[0] != "76561197987220805" {
		t.Fatalf("PlayerCount() = %d, %v, want [76561197987220805]", count, names)
	}

	tr.scan(strings.NewReader("02/06/2026 15:40:00: Closing socket 76561197987220805\n"))
	count, _, _ = tr.PlayerCount(context.Background())
	if count != 0 {
		t.Fatalf("count after disconnect = %d, want 0", count)
	}
}

func TestScan_TracksMultiplePlayersIndependently(t *testing.T) {
	tr := NewTracker(nil, "valheim")
	tr.attached = true

	tr.scan(strings.NewReader(strings.Join([]string{
		"Got handshake from client 111",
		"Got handshake from client 222",
		"Closing socket 111",
	}, "\n")))

	count, names, _ := tr.PlayerCount(context.Background())
	if count != 1 || names[0] != "222" {
		t.Fatalf("PlayerCount() = %d, %v, want [222]", count, names)
	}
}

func TestScan_NewerPlatformPrefixedIDsRoundTrip(t *testing.T) {
	tr := NewTracker(nil, "valheim")
	tr.attached = true

	tr.scan(strings.NewReader("Got handshake from client V_76561198012345678\n"))
	count, names, _ := tr.PlayerCount(context.Background())
	if count != 1 || names[0] != "V_76561198012345678" {
		t.Fatalf("PlayerCount() = %d, %v, want [V_76561198012345678]", count, names)
	}

	tr.scan(strings.NewReader("Closing socket V_76561198012345678\n"))
	count, _, _ = tr.PlayerCount(context.Background())
	if count != 0 {
		t.Fatalf("count after disconnect = %d, want 0", count)
	}
}

func TestReset_ClearsStateAndAttachment(t *testing.T) {
	tr := NewTracker(nil, "valheim")
	tr.attached = true
	tr.connected["111"] = struct{}{}

	tr.reset()

	_, _, ok := tr.PlayerCount(context.Background())
	if ok {
		t.Fatal("PlayerCount() ok = true after reset, want false")
	}
}

// Lines copied from a real lloesche/valheim-server run (Valheim l-1.0.16).
func TestScan_ReadyMarkerFromRealLog(t *testing.T) {
	tr := NewTracker(nil, "valheim")
	tr.scan(strings.NewReader(strings.Join([]string{
		"Sep 30 09:46:44 supervisord: valheim-server 09/30/2026 09:46:44: Load world: TestWorld (TestWorld)",
		"Sep 30 09:46:49 supervisord: valheim-server 09/30/2026 09:46:49: Game server connected",
	}, "\n")))
	if tr.ready {
		t.Fatal("ready before world finished loading")
	}
	tr.scan(strings.NewReader("Sep 30 09:47:12 supervisord: valheim-server 09/30/2026 09:47:12: Loading: Done. Total seconds sinze ZNet start: 27.97\n"))
	if !tr.ready {
		t.Fatal("not ready after 'Loading: Done.'")
	}
	tr.reset()
	if tr.ready {
		t.Fatal("ready survived reset")
	}
}

func TestStartup_RealLogLines(t *testing.T) {
	pct := func(line string) int {
		if p, _, ok := Startup.Parse(line); ok {
			return p
		}
		for _, m := range Startup.Milestones {
			if m.Pattern.MatchString(line) {
				return m.Pct
			}
		}
		return -1
	}
	cases := []struct {
		line string
		want int
	}{
		{"supervisord: valheim-updater INFO - Downloading/updating/validating Valheim server from Steam", 5},
		{"supervisord: valheim-updater  Update state (0x61) downloading, progress: 50.00 (1093324632 / 2186649264)", 40},
		{"supervisord: valheim-server 09/30/2026 09:46:41: Zonesystem Awake 5366", 72},
		{"supervisord: valheim-server 09/30/2026 09:46:44: Load world: TestWorld (TestWorld)", 80},
		{"supervisord: valheim-server 09/30/2026 09:46:49: Loading: Generating locations", 88},
		{"supervisord: valheim-server 09/30/2026 09:47:12: Loading: Done. Total seconds sinze ZNet start: 27.97", 100},
		{"supervisord: valheim-server The referenced script on this Behaviour is missing!", -1},
	}
	for _, c := range cases {
		if got := pct(c.line); got != c.want {
			t.Errorf("pct(%q) = %d, want %d", c.line, got, c.want)
		}
	}
}
