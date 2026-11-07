package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/history"
)

const (
	maxConsoleBody    = 8 << 10
	consoleTimeout    = 15 * time.Second
	maxConsoleOutput  = 16 << 10
	maxLoggedCommand  = 200
	consoleDeniedText = "the raw console is switched off — an admin can enable it in Settings"
)

// rawConsoleEnabled reports whether admins switched the raw console on.
func (a *App) rawConsoleEnabled() bool {
	return a.Settings != nil && a.Settings.Get().RawConsole
}

// handleConsole describes a game's console: its fixed actions and whether
// the raw box is currently usable. Admin only.
func (a *App) handleConsole(w http.ResponseWriter, r *http.Request) {
	d, ok := a.gameOr404(w, r)
	if !ok {
		return
	}
	if d.Console == nil {
		http.Error(w, "this game has no console", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"actions":       d.Console.Actions(),
		"raw_available": d.RawConsole != nil,
		"raw_enabled":   d.RawConsole != nil && a.rawConsoleEnabled(),
	})
}

type consoleRequest struct {
	Action  string            `json:"action"`
	Args    map[string]string `json:"args"`
	Command string            `json:"command"`
}

func readConsoleRequest(w http.ResponseWriter, r *http.Request) (consoleRequest, bool) {
	var req consoleRequest
	r.Body = http.MaxBytesReader(w, r.Body, maxConsoleBody)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return req, false
	}
	return req, true
}

func (a *App) handleConsoleAction(w http.ResponseWriter, r *http.Request) {
	d, ok := a.gameOr404(w, r)
	if !ok {
		return
	}
	if d.Console == nil {
		http.Error(w, "this game has no console", http.StatusNotFound)
		return
	}
	req, ok := readConsoleRequest(w, r)
	if !ok {
		return
	}
	known := false
	for _, act := range d.Console.Actions() {
		if act.ID == req.Action {
			known = true
		}
	}
	if !known {
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), consoleTimeout)
	defer cancel()
	out, err := d.Console.Run(ctx, req.Action, req.Args)
	a.finishConsole(w, r, d, "action: "+req.Action+describeArgs(req.Args), out, err)
}

func (a *App) handleConsoleRaw(w http.ResponseWriter, r *http.Request) {
	d, ok := a.gameOr404(w, r)
	if !ok {
		return
	}
	if d.RawConsole == nil {
		http.Error(w, "this game has no raw console", http.StatusNotFound)
		return
	}
	if !a.rawConsoleEnabled() {
		log.Printf("audit: %s tried the raw console on %s while it is off", actor(r), d.ID)
		if a.History != nil {
			a.History.Record(history.KindConsole, d.ID, actor(r), "raw: refused, console is off")
		}
		http.Error(w, consoleDeniedText, http.StatusForbidden)
		return
	}
	req, ok := readConsoleRequest(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), consoleTimeout)
	defer cancel()
	out, err := d.RawConsole.Raw(ctx, req.Command)
	a.finishConsole(w, r, d, "raw: "+truncate(req.Command, maxLoggedCommand), out, err)
}

// describeArgs renders action arguments for the audit trail, e.g.
// " userid=abc message=hi".
func describeArgs(args map[string]string) string {
	var b strings.Builder
	for _, k := range []string{"userid", "message"} {
		if v := strings.TrimSpace(args[k]); v != "" {
			fmt.Fprintf(&b, " %s=%q", k, truncate(v, 60))
		}
	}
	return b.String()
}

func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n]) + "…"
}

// finishConsole audits the command and writes the reply. Every command is
// recorded whether or not it succeeded.
func (a *App) finishConsole(w http.ResponseWriter, r *http.Request, d games.GameDef, what, out string, err error) {
	detail := what
	if err != nil {
		detail += " (failed)"
	}
	log.Printf("audit: %s console %s: %s", actor(r), d.ID, detail)
	if a.History != nil {
		a.History.Record(history.KindConsole, d.ID, actor(r), detail)
	}
	if err != nil {
		code, msg := http.StatusBadGateway, publicError(err)
		if errors.Is(err, games.ErrBadInput) {
			code, msg = http.StatusBadRequest, strings.TrimPrefix(err.Error(), games.ErrBadInput.Error()+": ")
		}
		http.Error(w, msg, code)
		return
	}
	if len(out) > maxConsoleOutput {
		out = out[:maxConsoleOutput] + "\n… (output truncated)"
	}
	writeJSON(w, http.StatusOK, map[string]string{"output": out})
}
