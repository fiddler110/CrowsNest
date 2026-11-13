package web

import (
	"context"
	"github.com/fiddler110/crowsnest/internal/notify"
	"log"
	"net/http"
	"time"

	"github.com/fiddler110/crowsnest/internal/hoststats"
)

// handleHost reports host memory, load and disk space.
func (a *App) handleHost(w http.ResponseWriter, r *http.Request) {
	snap, err := a.hostMemo.Do(r.Context(), "host", 5*time.Second, func(context.Context) hoststats.Snapshot {
		return hoststats.Read(a.HostPaths)
	})
	if err != nil {
		http.Error(w, "host stats unavailable", http.StatusGatewayTimeout)
		return
	}
	if snap.Disks == nil {
		snap.Disks = []hoststats.Disk{}
	}
	writeJSON(w, http.StatusOK, snap)
}

// handleHealth reports whether CrowsNest can reach Docker. It's separate from
// /healthz, the container liveness probe: a restart wouldn't fix a stopped
// daemon, so liveness stays green while this goes red and the dashboard warns.
// The reason is logged, not returned.
func (a *App) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.health(r.Context()))
}

// health is the /api/health body; /api/events sends the same.
func (a *App) health(ctx context.Context) map[string]bool {
	ok, err := a.healthMemo.Do(ctx, "docker", a.statusTTL(), func(ctx context.Context) bool {
		if err := a.Docker.Ping(ctx); err != nil {
			log.Printf("web: docker unreachable: %v", err)
			return false
		}
		return true
	})
	h := map[string]bool{"docker": err == nil && ok}
	if a.Backups != nil && a.Backups.Root != nil {
		h["backups"] = a.Backups.Healthy()
		if a.Backups.Offsite().Configured {
			h["offsite"] = a.Backups.OffsiteHealthy()
		}
	}
	if a.NotifyConfigured && a.Notify != nil {
		h["notify"] = a.Notify.Healthy()
	}
	return h
}

// handleNotifyStatus lists the notification channels whose last message failed (admin only).
func (a *App) handleNotifyStatus(w http.ResponseWriter, r *http.Request) {
	failing := a.Notify.Failing()
	if failing == nil {
		failing = []notify.ChannelStatus{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"configured": a.NotifyConfigured, "failing": failing})
}
