package auth

import (
	"fmt"
	"net/http"
	"strings"
)

// Role is what a signed-in user may do. Admins can do everything; players can
// start, stop and switch games but cannot change global settings (or, later,
// manage users or backups).
type Role string

const (
	RoleAdmin  Role = "admin"
	RolePlayer Role = "player"
)

// ParseRole accepts "admin" or "player" (any case).
func ParseRole(s string) (Role, error) {
	switch r := Role(strings.ToLower(strings.TrimSpace(s))); r {
	case RoleAdmin, RolePlayer:
		return r, nil
	}
	return "", fmt.Errorf("auth: unknown role %q (want admin or player)", s)
}

// EffectiveRole is the record's role. With none set, a password account is an
// admin (every account that predates roles keeps working) and anything else
// is a player: a Google allowlist name with no users-file entry, or with only
// a revocation marker, must be promoted on purpose with
// `crowsnest set-role <user> admin`.
func (u UserRecord) EffectiveRole() Role {
	if u.Role != "" {
		return u.Role
	}
	if u.Hash != "" {
		return RoleAdmin
	}
	return RolePlayer
}

// RoleFor returns username's current role. It is looked up on every request
// rather than stored in the session cookie, so a demotion applies at once.
// A name with no users-file entry (a Google-only user) is a player.
func (m *SessionManager) RoleFor(username string) Role {
	rec, _ := m.lookupUser(username)
	return rec.EffectiveRole()
}

// RequireAdmin rejects non-admin users with 403. Must run behind
// RequireSession.
func RequireAdmin(sessions *SessionManager, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, ok := FromContext(r.Context())
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if sessions.RoleFor(session.Username) != RoleAdmin {
			http.Error(w, "this action needs an admin account", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// CanAccess reports whether the user may see and control the game with this
// id: admins always, and anyone with no games list.
func (u UserRecord) CanAccess(gameID string) bool {
	if u.EffectiveRole() == RoleAdmin || len(u.Games) == 0 {
		return true
	}
	for _, g := range u.Games {
		if g == gameID {
			return true
		}
	}
	return false
}

// CanAccessGame is CanAccess for username's current record, looked up on
// every call so a change applies at once.
func (m *SessionManager) CanAccessGame(username, gameID string) bool {
	rec, _ := m.lookupUser(username)
	return rec.CanAccess(gameID)
}
