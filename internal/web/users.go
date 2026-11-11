package web

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"slices"
	"sort"
	"strings"

	"github.com/fiddler110/crowsnest/internal/auth"
	"github.com/fiddler110/crowsnest/internal/history"
)

const (
	maxUserBodyBytes = 4096
	minPasswordLen   = 8
	maxPasswordLen   = 72 // bcrypt ignores everything past 72 bytes
)

// userView is one row of the Users panel. Hashes never leave the server.
type userView struct {
	Username    string    `json:"username"`
	Role        auth.Role `json:"role"`
	HasPassword bool      `json:"has_password"`
	Google      bool      `json:"google"`
	GoogleEmail string    `json:"google_email,omitempty"`
	// OIDCEmail is the email an OIDC provider may sign them in as (first time).
	OIDCEmail string `json:"oidc_email,omitempty"`
	// Games is the player's allowlist; empty means every game.
	Games []string `json:"games"`
	// MFA is whether the user has an authenticator app set up.
	MFA  bool `json:"mfa"`
	Self bool `json:"self"`
	// Managed users live in the users file and can be edited here; users
	// that exist only in the Google env allowlist cannot.
	Managed bool `json:"managed"`
}

type userBody struct {
	Username string  `json:"username"`
	Password *string `json:"password"`
	Role     *string `json:"role"`
	// GoogleEmail links a Google account to the user; "" on update removes it.
	GoogleEmail *string `json:"google_email"`
	// OIDCEmail links an OIDC sign-in email to the user; "" on update removes it.
	OIDCEmail *string `json:"oidc_email"`
	Revoke    bool    `json:"revoke_sessions"`
	// ResetMFA removes the user's authenticator app (a lost phone) and signs them out.
	ResetMFA bool `json:"reset_mfa"`
	// Games limits a player to these game ids; an empty list means all games.
	Games *[]string `json:"games"`
}

// checkGames validates an allowlist against the games the registry knows.
func (a *App) checkGames(ids []string) ([]string, error) {
	list, err := auth.ParseGameList(strings.Join(ids, ","))
	if err != nil {
		return nil, err
	}
	for _, id := range list {
		if _, ok := a.Registry.Get(id); !ok {
			return nil, errors.New("unknown game " + id)
		}
	}
	return list, nil
}

func (a *App) userList(self string) []userView {
	snap := a.Auth.Store.Snapshot()
	byName := map[string]*userView{}
	for name, rec := range snap {
		byName[name] = &userView{Username: name, Role: rec.EffectiveRole(), HasPassword: rec.Hash != "",
			Google: rec.GoogleEmail != "", GoogleEmail: rec.GoogleEmail, OIDCEmail: rec.OIDCEmail, Games: rec.Games, Managed: true}
	}
	if a.Google.Active() {
		for _, name := range a.Google.Users {
			v := byName[name]
			if v == nil {
				v = &userView{Username: name, Role: auth.UserRecord{}.EffectiveRole()}
				byName[name] = v
			}
			v.Google = true
		}
	}
	out := make([]userView, 0, len(byName))
	for _, v := range byName {
		v.Self = v.Username == self
		if v.Games == nil {
			v.Games = []string{}
		}
		v.MFA = a.MFA != nil && a.MFA.Enabled(v.Username)
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}

func (a *App) usersEnabled(w http.ResponseWriter, r *http.Request) bool {
	if a.Auth == nil || a.Auth.Store == nil {
		http.NotFound(w, r)
		return false
	}
	return true
}

// adoptGoogleUsers writes a users-file entry for every Google allowlist user
// that has none, so each can be edited in the panel.
func (a *App) adoptGoogleUsers() {
	if !a.Google.Active() {
		return
	}
	names := make([]string, 0, len(a.Google.Users))
	for _, n := range a.Google.Users {
		names = append(names, n)
	}
	added, err := auth.AdoptUsers(a.Auth.Store.Path(), names)
	if err != nil {
		log.Printf("auth: add Google users to %s: %v", a.Auth.Store.Path(), err)
		return
	}
	if len(added) > 0 {
		log.Printf("auth: added Google allowlist users to %s: %s", a.Auth.Store.Path(), strings.Join(added, ", "))
		if _, err := a.Auth.Store.Reload(); err != nil {
			log.Printf("auth: reload users: %v", err)
		}
	}
}

func (a *App) handleListUsers(w http.ResponseWriter, r *http.Request) {
	if !a.usersEnabled(w, r) {
		return
	}
	a.adoptGoogleUsers()
	type gameRef struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	refs := []gameRef{}
	for _, d := range a.Registry.All() {
		refs = append(refs, gameRef{d.ID, d.DisplayName})
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": a.userList(actor(r)), "google_enabled": a.Google.Active(), "games": refs})
}

func readUserBody(w http.ResponseWriter, r *http.Request) (userBody, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUserBodyBytes)
	raw, err := io.ReadAll(r.Body)
	var b userBody
	if err == nil {
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.DisallowUnknownFields()
		err = dec.Decode(&b)
	}
	if err != nil {
		http.Error(w, "invalid request: "+err.Error(), http.StatusBadRequest)
		return b, false
	}
	return b, true
}

func checkPassword(p string) error {
	if len(p) < minPasswordLen {
		return errors.New("password must be at least 8 characters")
	}
	if len(p) > maxPasswordLen {
		return errors.New("password must be at most 72 bytes")
	}
	return nil
}

// adminsAfter counts file-backed admins that would remain if name's role
// became newRole ("" with remove=true deletes the entry).
func (a *App) adminsAfter(name string, newRole auth.Role, remove bool) int {
	n := 0
	for u, rec := range a.Auth.Store.Snapshot() {
		role := rec.EffectiveRole()
		if u == name {
			if remove {
				continue
			}
			role = newRole
		}
		if role == auth.RoleAdmin && (rec.Hash != "" || rec.GoogleEmail != "") {
			n++
		}
	}
	return n
}

// checkGoogleEmail validates email and that no other account already uses
// it. forUser is the user being edited ("" when creating).
func (a *App) checkGoogleEmail(email, forUser string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if !a.Google.Active() {
		return "", errors.New("Google sign-in isn't enabled on this server")
	}
	if err := auth.ValidateEmail(email); err != nil {
		return "", err
	}
	if owner, taken := a.Google.Lookup(email); taken && owner != forUser {
		return "", errors.New("that Google account is already linked to " + owner)
	}
	return email, nil
}

func (a *App) userChanged(r *http.Request, detail string) {
	if _, err := a.Auth.Store.Reload(); err != nil {
		log.Printf("auth: reload users after change: %v", err)
	}
	if a.History != nil {
		a.History.Record(history.KindUsers, "", actor(r), detail)
	}
	log.Printf("audit: %s %q", actor(r), detail)
}

func (a *App) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if !a.usersEnabled(w, r) {
		return
	}
	b, ok := readUserBody(w, r)
	if !ok {
		return
	}
	name := strings.ToLower(strings.TrimSpace(b.Username))
	role := auth.RolePlayer
	if b.Role != nil {
		pr, err := auth.ParseRole(*b.Role)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		role = pr
	}
	email := ""
	if b.GoogleEmail != nil && strings.TrimSpace(*b.GoogleEmail) != "" {
		e, err := a.checkGoogleEmail(*b.GoogleEmail, "")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		email = e
	}
	hash := ""
	if b.Password != nil && *b.Password != "" {
		if err := checkPassword(*b.Password); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		h, err := auth.HashPassword(*b.Password)
		if err != nil {
			http.Error(w, "could not save user", http.StatusInternalServerError)
			return
		}
		hash = h
	}
	if hash == "" && email == "" {
		http.Error(w, "give the user a password, a Google account, or both", http.StatusBadRequest)
		return
	}
	if err := auth.ValidateUsername(name); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if _, exists := a.Auth.Store.Lookup(name); exists {
		http.Error(w, "that user already exists", http.StatusConflict)
		return
	}
	var allowed []string
	if b.Games != nil {
		l, err := a.checkGames(*b.Games)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		allowed = l
	}
	if err := auth.CreateUser(a.Auth.Store.Path(), name, hash, email, role); err != nil {
		log.Printf("audit: %s create user %q failed: %v", actor(r), name, err)
		http.Error(w, "could not save user", http.StatusInternalServerError)
		return
	}
	how := ""
	if len(allowed) > 0 {
		if err := auth.SetGames(a.Auth.Store.Path(), name, allowed); err != nil {
			http.Error(w, "user added but their games could not be saved", http.StatusInternalServerError)
			return
		}
		how += ", games " + strings.Join(allowed, "/")
	}
	if email != "" {
		how += ", Google " + email
	}
	a.userChanged(r, "created user "+name+" ("+string(role)+how+")")
	writeJSON(w, http.StatusCreated, map[string]any{"users": a.userList(actor(r))})
}

func (a *App) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	if !a.usersEnabled(w, r) {
		return
	}
	name := strings.ToLower(r.PathValue("name"))
	self := actor(r)
	rec, exists := a.Auth.Store.Lookup(name)
	if !exists {
		http.Error(w, "no such user", http.StatusNotFound)
		return
	}
	b, ok := readUserBody(w, r)
	if !ok {
		return
	}
	path := a.Auth.Store.Path()
	var changes []string
	revoke := b.Revoke

	if b.Role != nil {
		role, err := auth.ParseRole(*b.Role)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if role != rec.EffectiveRole() {
			if name == self {
				http.Error(w, "you can't change your own role", http.StatusBadRequest)
				return
			}
			if a.adminsAfter(name, role, false) < 1 {
				http.Error(w, "there must be at least one admin", http.StatusBadRequest)
				return
			}
			if err := auth.SetRole(path, name, role, false); err != nil {
				http.Error(w, "could not save user", http.StatusInternalServerError)
				return
			}
			changes = append(changes, "role "+string(role))
		}
	}
	if b.Games != nil {
		list, err := a.checkGames(*b.Games)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !slices.Equal(list, rec.Games) {
			if err := auth.SetGames(path, name, list); err != nil {
				http.Error(w, "could not save user", http.StatusInternalServerError)
				return
			}
			if len(list) == 0 {
				changes = append(changes, "games: all")
			} else {
				changes = append(changes, "games "+strings.Join(list, "/"))
			}
		}
	}
	if b.GoogleEmail != nil {
		email := strings.TrimSpace(*b.GoogleEmail)
		if email == "" {
			if rec.GoogleEmail != "" {
				if rec.Hash == "" {
					http.Error(w, "set a password first, or the user would have no way to sign in", http.StatusBadRequest)
					return
				}
				if err := auth.SetGoogleEmail(path, name, ""); err != nil {
					http.Error(w, "could not save user", http.StatusInternalServerError)
					return
				}
				changes = append(changes, "Google account removed")
			}
		} else {
			e, err := a.checkGoogleEmail(email, name)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if e != rec.GoogleEmail {
				if err := auth.SetGoogleEmail(path, name, e); err != nil {
					http.Error(w, "could not save user", http.StatusInternalServerError)
					return
				}
				changes = append(changes, "Google account "+e)
			}
		}
	}
	if b.OIDCEmail != nil {
		email := strings.ToLower(strings.TrimSpace(*b.OIDCEmail))
		if email != "" {
			if err := auth.ValidateEmail(email); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			for other, orec := range a.Auth.Store.Snapshot() {
				if orec.OIDCEmail == email && other != name {
					http.Error(w, "that email is already linked to "+other, http.StatusBadRequest)
					return
				}
			}
		}
		if email != rec.OIDCEmail {
			if email == "" && rec.Hash == "" && rec.GoogleEmail == "" {
				http.Error(w, "set a password first, or the user would have no way to sign in", http.StatusBadRequest)
				return
			}
			if err := auth.SetOIDCEmail(path, name, email); err != nil {
				http.Error(w, "could not save user", http.StatusInternalServerError)
				return
			}
			if a.OIDC != nil {
				_ = a.OIDC.Store.Unlink(name) // a new email must prove itself again
			}
			if email == "" {
				changes = append(changes, "SSO email removed")
			} else {
				changes = append(changes, "SSO email "+email)
			}
		}
	}
	if b.Password != nil && *b.Password != "" {
		if err := checkPassword(*b.Password); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		hash, err := auth.HashPassword(*b.Password)
		if err != nil {
			http.Error(w, "could not save user", http.StatusInternalServerError)
			return
		}
		if err := auth.SetUserHash(path, name, hash); err != nil {
			http.Error(w, "could not save user", http.StatusInternalServerError)
			return
		}
		changes = append(changes, "password reset")
		if name != self {
			revoke = true // a reset should end sessions held under the old password
		}
	}
	if b.ResetMFA {
		if err := a.resetMFA(name); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		changes = append(changes, "authenticator app removed")
		if name != self {
			revoke = true
		}
	}
	if revoke {
		if name == self {
			http.Error(w, "use Log out to end your own session", http.StatusBadRequest)
			return
		}
		if err := auth.RevokeSessions(path, name, false); err != nil {
			http.Error(w, "could not save user", http.StatusInternalServerError)
			return
		}
		changes = append(changes, "sessions revoked")
	}
	if len(changes) == 0 {
		http.Error(w, "nothing to change", http.StatusBadRequest)
		return
	}
	a.userChanged(r, "updated user "+name+": "+strings.Join(changes, ", "))
	writeJSON(w, http.StatusOK, map[string]any{"users": a.userList(self)})
}

func (a *App) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if !a.usersEnabled(w, r) {
		return
	}
	name := strings.ToLower(r.PathValue("name"))
	if name == actor(r) {
		http.Error(w, "you can't delete your own account", http.StatusBadRequest)
		return
	}
	if _, ok := a.Auth.Store.Lookup(name); !ok {
		http.Error(w, "no such user", http.StatusNotFound)
		return
	}
	if a.adminsAfter(name, "", true) < 1 {
		http.Error(w, "there must be at least one admin", http.StatusBadRequest)
		return
	}
	if a.MFA != nil {
		_ = a.MFA.Remove(name)
	}
	if a.OIDC != nil {
		_ = a.OIDC.Store.Unlink(name)
	}
	if err := auth.DeleteUser(a.Auth.Store.Path(), name); err != nil {
		http.Error(w, "could not delete user", http.StatusInternalServerError)
		return
	}
	a.userChanged(r, "deleted user "+name)
	writeJSON(w, http.StatusOK, map[string]any{"users": a.userList(actor(r))})
}
