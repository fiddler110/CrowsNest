package valheim

import (
	"regexp"
	"testing"
)

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

// The tracker built for Valheim must match real log lines end to end.
func TestTrackerRegexes_RealLogLines(t *testing.T) {
	for line, re := range map[string]*regexp.Regexp{
		"Sep 30 09:47:12 supervisord: valheim-server 09/30/2026 09:47:12: Loading: Done. Total seconds sinze ZNet start: 27.97": readyRe,
		"02/06/2026 15:26:38: Got handshake from client 76561197987220805":                                                      connectRe,
		"02/06/2026 15:40:00: Closing socket V_76561198012345678":                                                               disconnectRe,
		"Sep 30 09:46:44 supervisord: valheim-server 09/30/2026 09:46:44: Load world: TestWorld (TestWorld)":                    worldRe,
	} {
		if !re.MatchString(line) {
			t.Errorf("%v did not match %q", re, line)
		}
	}
}
