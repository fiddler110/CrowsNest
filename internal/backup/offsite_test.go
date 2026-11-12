package backup

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fiddler110/crowsnest/internal/games"
)

func writeOffsite(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "offsite.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReadOffsite(t *testing.T) {
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	at := func(ago time.Duration) string { return now.Add(-ago).Format(time.RFC3339) }
	good := func(ago time.Duration) string {
		return `{"ok":true,"at":"` + at(ago) + `","last_ok":"` + at(ago) + `","interval_seconds":3600,"remote":"offsite:x","error":""}`
	}
	if st := ReadOffsite("", now); st.Configured || !st.Healthy() {
		t.Errorf("unset = %+v", st)
	}
	if st := ReadOffsite(filepath.Join(t.TempDir(), "nope"), now); st.State != OffsiteMissing || st.Healthy() {
		t.Errorf("missing = %+v", st)
	}
	if st := ReadOffsite(writeOffsite(t, good(30*time.Minute)), now); st.State != OffsiteOK || !st.Healthy() || st.Remote != "offsite:x" {
		t.Errorf("fresh ok = %+v", st)
	}
	// Two intervals and ten minutes late is stale, even though its last words were "ok".
	if st := ReadOffsite(writeOffsite(t, good(3*time.Hour)), now); st.State != OffsiteStale {
		t.Errorf("stale = %+v", st)
	}
	failed := `{"ok":false,"at":"` + at(time.Minute) + `","last_ok":"` + at(5*time.Hour) + `","interval_seconds":3600,"remote":"r","error":"the last copy failed"}`
	if st := ReadOffsite(writeOffsite(t, failed), now); st.State != OffsiteFailed || st.Message != "the last copy failed" {
		t.Errorf("failed = %+v", st)
	}
	if st := ReadOffsite(writeOffsite(t, "{not json"), now); st.State != OffsiteMissing || !strings.Contains(st.Message, "unreadable") {
		t.Errorf("garbage = %+v", st)
	}
	if st := ReadOffsite(writeOffsite(t, `{"ok":true,"error":"`+strings.Repeat("x", 20000)+`"}`), now); st.Healthy() {
		t.Errorf("an oversized file was trusted: %+v", st)
	}
}

type captureNotifier struct {
	mu   sync.Mutex
	msgs []string
}

func (c *captureNotifier) Notify(_ context.Context, m string) {
	c.mu.Lock()
	c.msgs = append(c.msgs, m)
	c.mu.Unlock()
}

func TestOffsiteAlertsOnChangeOnly(t *testing.T) {
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "o.json")
	put := func(ok bool, msg string) {
		body := `{"ok":` + map[bool]string{true: "true", false: "false"}[ok] + `,"at":"` + now.Format(time.RFC3339) + `","last_ok":"` + now.Format(time.RFC3339) + `","interval_seconds":3600,"remote":"r","error":"` + msg + `"}`
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	n := &captureNotifier{}
	m := &Manager{Root: &Root{Mount: t.TempDir()}, OffsiteFile: path, Notifier: n}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	put(true, "")
	done := make(chan struct{})
	go func() { m.RunMonitor(ctx, 20*time.Millisecond, func() []games.GameDef { return nil }); close(done) }()
	time.Sleep(100 * time.Millisecond)
	put(false, "boom")
	time.Sleep(150 * time.Millisecond) // many checks, one alert
	put(true, "")
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done
	n.mu.Lock()
	defer n.mu.Unlock()
	var bad, good int
	for _, s := range n.msgs {
		switch {
		case strings.Contains(s, "offsite backup copy has a problem") && strings.Contains(s, "boom"):
			bad++
		case strings.Contains(s, "offsite backup copy is working again"):
			good++
		}
	}
	if bad != 1 || good != 1 {
		t.Errorf("alerts bad=%d good=%d: %q", bad, good, n.msgs)
	}
}
