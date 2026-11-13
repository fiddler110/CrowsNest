package web

import (
	"net/http"

	"github.com/fiddler110/crowsnest/internal/auth"
	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/statehub"
)

// loginPage is the login template's data. Error is one of a fixed set of
// messages chosen by code, never text taken from the request.
type loginPage struct {
	PasswordLogin  bool
	GoogleStartURL string
	OIDC           []oidcButton
	Error          string
}

var loginErrors = map[string]string{
	auth.LoginErrorDenied:     "Sign-in was cancelled.",
	auth.LoginErrorExpired:    "That sign-in attempt expired. Please try again.",
	auth.LoginErrorNotAllowed: "That account isn't on this ship's crew list.",
	auth.LoginErrorFailed:     "Sign-in failed. Please try again.",
	auth.LoginErrorRateLimit:  "Too many sign-in attempts. Try again in a few minutes.",
}

func (a *App) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if a.setupNeeded() {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	page := loginPage{PasswordLogin: !a.Auth.PasswordLoginDisabled(), Error: loginErrors[r.URL.Query().Get("error")]}
	page.OIDC = a.oidcButtons()
	if a.Google.Active() {
		page.GoogleStartURL = a.Google.StartURL()
	}
	render(w, a.Templates.Login, page, "login page")
}

type dashboardGame struct {
	ID          string
	DisplayName string
	Initial     string // first letter, for the card's emblem
	Status      string

	// ConnectAddress/ConnectNote are the optional display-only connection
	// details; the template renders nothing when both are empty.
	ConnectAddress string
	ConnectNote    string
	ConnectSecrets []games.ConnectSecret

	// HasBackup is true when a backup is configured and the viewer is an
	// admin, which is the only role that sees the Backups panel.
	HasBackup bool

	// HasConsole is true for admins on games that offer console actions.
	HasConsole bool
	// HasFiles is true for admins on games whose module declares editable files.
	HasFiles bool

	// HasInfo is true when the game has an info provider; otherwise the card
	// has no Info tab.
	HasInfo bool

	// Accent is the card's "#rrggbb" accent from the game's module, or empty.
	Accent string
}

// dashboardData is the data of every signed-in page. Page names the page
// ("dashboard", "games", "settings") so the shared top bar can mark it.
type dashboardData struct {
	Page     string
	Username string
	// DisplayName is what the user chose to be called, "" to show Username.
	DisplayName string
	IsAdmin     bool
	CSRFToken   string
	Games       []dashboardGame
	// NeedsPassword: an admin with no stored password sees a banner, because
	// widening the guard asks for one.
	NeedsPassword bool
}

func (a *App) handleDashboard(w http.ResponseWriter, r *http.Request) {
	session, _ := auth.FromContext(r.Context())
	defs := a.visibleGames(r)
	data := dashboardData{
		Page:          "dashboard",
		Username:      session.Username,
		DisplayName:   a.Profiles.DisplayName(session.Username),
		IsAdmin:       a.Auth.Sessions.RoleFor(session.Username) == auth.RoleAdmin,
		NeedsPassword: a.Auth.Sessions.RoleFor(session.Username) == auth.RoleAdmin && !a.Auth.HasPassword(session.Username),
		CSRFToken:     session.CSRFToken,
	}
	// First paint must not wait on game probes (a booting game's API can
	// take seconds to time out): use the hub's latest observation if any,
	// else "unknown"; the page's JS refreshes statuses immediately on load.
	for _, d := range defs {
		snap := statehub.Observation{Status: games.StatusUnknown}
		if a.Hub != nil {
			if o, ok := a.Hub.Get(d.ID); ok {
				snap = o
			}
		}
		data.Games = append(data.Games, dashboardGame{
			ID:          d.ID,
			DisplayName: d.DisplayName,
			Initial:     initialOf(d.DisplayName),
			Status:      a.gameStatus(d, snap.Status).String(),

			ConnectAddress: d.ConnectAddress,
			ConnectNote:    d.ConnectNote,
			ConnectSecrets: d.ConnectSecrets,
			HasBackup:      data.IsAdmin && d.Backup != nil && a.Backups != nil,
			HasConsole:     data.IsAdmin && d.Console != nil,
			HasFiles:       data.IsAdmin && len(d.Files) > 0 && a.Files != nil,
			HasInfo:        d.Info != nil,
			Accent:         d.Accent,
		})
	}
	render(w, a.Templates.Dashboard, data, "dashboard")
}
