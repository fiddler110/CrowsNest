package windrose

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/fiddler110/crowsnest/internal/games"
)

func TestConsole_ActionsSendWpCommands(t *testing.T) {
	f := newFakeWplusServer(t, "pw")
	var mu sync.Mutex
	var cmds []string
	f.rconFunc = func(cmd string) (string, bool) {
		mu.Lock()
		defer mu.Unlock()
		cmds = append(cmds, cmd)
		return "ok: " + cmd, true
	}
	c := newTestClient(f.URL, "pw", nil)
	ctx := context.Background()

	for _, tc := range []struct {
		action string
		args   map[string]string
		want   string
	}{
		{"players", nil, "wp.players"},
		{"status", nil, "wp.status"},
		{"listbans", nil, "wp.listbans"},
		{"kick", map[string]string{"player": "Ann", "reason": "afk too long"}, "wp.kick Ann afk too long"},
		{"kick", map[string]string{"player": "Ann"}, "wp.kick Ann"},
		{"ban", map[string]string{"player": "Bob", "reason": "x"}, "wp.ban Bob x"},
		{"unban", map[string]string{"player": "Bob"}, "wp.unban Bob"},
	} {
		out, err := c.Run(ctx, tc.action, tc.args)
		if err != nil || out != "ok: "+tc.want {
			t.Errorf("%s %v = %q, %v; want reply for %q", tc.action, tc.args, out, err, tc.want)
		}
		if got := cmds[len(cmds)-1]; got != tc.want {
			t.Errorf("%s %v sent %q, want %q", tc.action, tc.args, got, tc.want)
		}
	}
}

func TestConsole_RejectsBadInputWithoutSending(t *testing.T) {
	f := newFakeWplusServer(t, "pw")
	c := newTestClient(f.URL, "pw", nil)
	for name, tc := range map[string]struct {
		action string
		args   map[string]string
	}{
		"kick without player":      {"kick", nil},
		"player with space":        {"kick", map[string]string{"player": "Ann Lee"}},
		"player with newline":      {"ban", map[string]string{"player": "Ann\nwp.ban"}},
		"long player":              {"unban", map[string]string{"player": strings.Repeat("x", 65)}},
		"reason with control char": {"kick", map[string]string{"player": "Ann", "reason": "a\x00b"}},
		"long reason":              {"kick", map[string]string{"player": "Ann", "reason": strings.Repeat("x", 201)}},
		"unknown action":           {"shutdown", nil},
	} {
		if _, err := c.Run(context.Background(), tc.action, tc.args); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	if n := f.rconCalls.Load(); n != 0 {
		t.Errorf("rejected input reached Windrose+ (%d rcon calls)", n)
	}
}

func TestConsole_UnreachableIsAnError(t *testing.T) {
	c := newTestClient("http://127.0.0.1:1", "pw", nil)
	if _, err := c.Run(context.Background(), "players", nil); err == nil {
		t.Fatal("want error when Windrose+ is unreachable")
	}
	if _, err := c.Raw(context.Background(), "wp.version"); err == nil {
		t.Fatal("raw: want error when Windrose+ is unreachable")
	}
}

func TestRaw(t *testing.T) {
	f := newFakeWplusServer(t, "pw")
	f.rconFunc = func(cmd string) (string, bool) { return "v1.3.28 for " + cmd, true }
	c := newTestClient(f.URL, "pw", nil)
	out, err := c.Raw(context.Background(), "  wp.version ")
	if err != nil || out != "v1.3.28 for wp.version" {
		t.Fatalf("Raw = %q, %v", out, err)
	}
	for _, bad := range []string{"", "a\nb", strings.Repeat("x", 1001)} {
		if _, err := c.Raw(context.Background(), bad); !errors.Is(err, games.ErrBadInput) {
			t.Errorf("Raw(%q): %v, want ErrBadInput", bad, err)
		}
	}
}
