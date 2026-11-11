package web

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/hoststats"
	"github.com/fiddler110/crowsnest/internal/statehub"
)

// CrashStats supplies per-game crash counts; satisfied by *crashwatch.Watcher.
type CrashStats interface {
	Total(id string) uint64
	Looping(id string) bool
}

type gameObs struct {
	def  games.GameDef
	obs  statehub.Observation
	seen bool
}

// handleMetrics serves Prometheus text exposition, for a scraper that sends
// `Authorization: Bearer <metrics token>`. The route exists only when a token
// is configured, and it is not behind the login session.
func (a *App) handleMetrics(w http.ResponseWriter, r *http.Request) {
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(a.MetricsToken)) != 1 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="crowsnest"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var b strings.Builder
	metric := func(name, help, typ string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
	}
	defs := a.Registry.All()
	var obs []gameObs
	for _, d := range defs {
		o := gameObs{def: d}
		if a.Hub != nil {
			o.obs, o.seen = a.Hub.Get(d.ID)
		}
		obs = append(obs, o)
	}

	metric("crowsnest_game_up", "1 when the game is online, 0 otherwise.", "gauge")
	for _, o := range obs {
		up := 0
		if o.seen && o.obs.Status == games.StatusOnline {
			up = 1
		}
		fmt.Fprintf(&b, "crowsnest_game_up{game=%q} %d\n", o.def.ID, up)
	}
	metric("crowsnest_game_players", "Players connected, when the count could be read.", "gauge")
	for _, o := range obs {
		if o.seen && o.obs.Status == games.StatusOnline && o.obs.PlayersOK {
			fmt.Fprintf(&b, "crowsnest_game_players{game=%q} %d\n", o.def.ID, o.obs.Count)
		}
	}
	if a.Crashes != nil {
		metric("crowsnest_game_crashes_total", "Crashes seen since CrowsNest started.", "counter")
		for _, o := range obs {
			fmt.Fprintf(&b, "crowsnest_game_crashes_total{game=%q} %d\n", o.def.ID, a.Crashes.Total(o.def.ID))
		}
		metric("crowsnest_game_crash_looping", "1 while the game is over the crash-loop threshold.", "gauge")
		for _, o := range obs {
			v := 0
			if a.Crashes.Looping(o.def.ID) {
				v = 1
			}
			fmt.Fprintf(&b, "crowsnest_game_crash_looping{game=%q} %d\n", o.def.ID, v)
		}
	}

	if a.Backups != nil && a.Backups.Root != nil {
		h := a.Backups.Health()
		metric("crowsnest_backups_ok", "1 while the shared backups folder passes its checks.", "gauge")
		ok := 0
		if a.Backups.Healthy() {
			ok = 1
		}
		fmt.Fprintf(&b, "crowsnest_backups_ok %d\n", ok)
		metric("crowsnest_backups_free_bytes", "Free space in the shared backups folder.", "gauge")
		fmt.Fprintf(&b, "crowsnest_backups_free_bytes %d\n", h.Free)
	}

	snap, _ := a.hostMemo.Do(r.Context(), "host", 5*time.Second, func(context.Context) hoststats.Snapshot {
		return hoststats.Read(a.HostPaths)
	})
	metric("crowsnest_host_memory_total_bytes", "Host memory.", "gauge")
	fmt.Fprintf(&b, "crowsnest_host_memory_total_bytes %d\n", snap.MemTotal)
	metric("crowsnest_host_memory_available_bytes", "Host memory available to start new work.", "gauge")
	fmt.Fprintf(&b, "crowsnest_host_memory_available_bytes %d\n", snap.MemAvailable)
	metric("crowsnest_host_load1", "Host 1-minute load average.", "gauge")
	fmt.Fprintf(&b, "crowsnest_host_load1 %g\n", snap.Load1)
	metric("crowsnest_host_disk_total_bytes", "Size of a watched filesystem.", "gauge")
	for _, d := range snap.Disks {
		fmt.Fprintf(&b, "crowsnest_host_disk_total_bytes{path=%q} %d\n", d.Path, d.Total)
	}
	metric("crowsnest_host_disk_free_bytes", "Free space on a watched filesystem.", "gauge")
	for _, d := range snap.Disks {
		fmt.Fprintf(&b, "crowsnest_host_disk_free_bytes{path=%q} %d\n", d.Path, d.Free)
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}
