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
