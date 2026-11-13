package web

import (
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fiddler110/crowsnest/internal/auth"
	"github.com/fiddler110/crowsnest/internal/history"
)

const (
	defaultActivityLimit = 40
	maxActivityLimit     = 500
)

// shortDetail keeps the tail of raw error text (where the cause usually is)
// on one line, for admins.
func shortDetail(msg string) string {
	msg = strings.Join(strings.Fields(msg), " ")
	if r := []rune(msg); len(r) > 400 {
		msg = "…" + string(r[len(r)-400:])
	}
	return msg
}

// handleActivity returns the newest activity events (optionally for one
// game) and the playtime totals derived from join/leave events.
func (a *App) handleActivity(w http.ResponseWriter, r *http.Request) {
	if a.History == nil {
		writeJSON(w, http.StatusOK, map[string]any{"events": []history.Event{}, "playtime": []history.Playtime{}})
		return
	}
	limit := defaultActivityLimit
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 {
		limit = min(n, maxActivityLimit)
	}
	var hide []string
	if a.Auth.Sessions.RoleFor(actor(r)) != auth.RoleAdmin {
		hide = []string{history.KindUsers, history.KindConsole, history.KindFiles, history.KindSettings, history.KindGames}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"events":   a.History.RecentAllowed(limit, r.URL.Query().Get("game"), func(id string) bool { return a.canSee(r, id) }, hide...),
		"playtime": a.visiblePlaytime(r),
	})
}

// visiblePlaytime is the playtime totals for the games r's user may see.
func (a *App) visiblePlaytime(r *http.Request) []history.Playtime {
	all := a.History.Playtime()
	out := make([]history.Playtime, 0, len(all))
	for _, p := range all {
		if a.canSee(r, p.Game) {
			out = append(out, p)
		}
	}
	return out
}

// handleAuditExport downloads the tamper-evident audit file (admin only). `crowsnest audit verify <file>` checks it.
func (a *App) handleAuditExport(w http.ResponseWriter, r *http.Request) {
	if a.AuditFile == "" {
		http.Error(w, "no audit file is configured", http.StatusNotFound)
		return
	}
	f, err := os.Open(a.AuditFile) // #nosec G304 -- operator-configured path
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "nothing has been recorded yet", http.StatusNotFound)
			return
		}
		http.Error(w, "could not read the audit file", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", `attachment; filename="crowsnest-audit.jsonl"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.Copy(w, f)
}

// handleAudit is the admin audit view's feed: every kind of event, filtered
// by game, kind(s), actor, free text and time range, one page at a time.
// Query: game, kind (comma list), actor, q, since, until (RFC 3339 or
// YYYY-MM-DD), offset, limit.
func (a *App) handleAudit(w http.ResponseWriter, r *http.Request) {
	if a.History == nil {
		writeJSON(w, http.StatusOK, map[string]any{"events": []history.Event{}, "more": false})
		return
	}
	q := r.URL.Query()
	f := history.Filter{Game: q.Get("game"), Actor: q.Get("actor"), Text: q.Get("q")}
	if k := q.Get("kind"); k != "" {
		f.Kinds = strings.Split(k, ",")
	}
	parse := func(name string) (time.Time, bool) {
		v := q.Get(name)
		if v == "" {
			return time.Time{}, true
		}
		for _, layout := range []string{time.RFC3339, "2006-01-02"} {
			if t, err := time.Parse(layout, v); err == nil {
				return t, true
			}
		}
		http.Error(w, name+": want an RFC 3339 time or YYYY-MM-DD", http.StatusBadRequest)
		return time.Time{}, false
	}
	var ok bool
	if f.Since, ok = parse("since"); !ok {
		return
	}
	if f.Until, ok = parse("until"); !ok {
		return
	}
	limit := defaultActivityLimit
	if n, err := strconv.Atoi(q.Get("limit")); err == nil && n > 0 {
		limit = min(n, maxActivityLimit)
	}
	offset, _ := strconv.Atoi(q.Get("offset"))
	events, more := a.History.Query(f, max(offset, 0), limit)
	writeJSON(w, http.StatusOK, map[string]any{"events": events, "more": more})
}
