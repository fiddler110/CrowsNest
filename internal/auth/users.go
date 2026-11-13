// Package auth implements CrowsNest's login system: a flat users file of
// bcrypt password hashes, stateless HMAC-signed session cookies, CSRF token
// verification, and per-IP login rate limiting. It has no server-side
// session store — everything needed to verify a request is in the request
// itself.
package auth

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/fiddler110/crowsnest/internal/atomicfile"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// usersMu serialises read-modify-write cycles on the users file, so two web
// requests (or a request and the CLI in the same process) can't lose updates.
var usersMu sync.Mutex

// ValidateUsername checks name is usable as a users-file key: lowercase
// letters, digits, '_' and '-', 1-32 characters, starting alphanumeric.
func ValidateUsername(name string) error {
	if !usernamePattern.MatchString(name) {
		return fmt.Errorf("username must be 1-32 lowercase letters, digits, '_' or '-', starting with a letter or digit")
	}
	return nil
}

// ValidateEmail checks email looks like a plain address (ASCII only).
func ValidateEmail(email string) error {
	if !emailPattern.MatchString(email) {
		return fmt.Errorf("that doesn't look like an email address")
	}
	return nil
}

// CreateUser adds a new user with a role and a password hash, a Google
// email, or both (hash and googleEmail may each be empty, not both). It fails
// if the name already has an entry.
func CreateUser(path, username, hash, googleEmail string, role Role) error {
	username = strings.ToLower(username)
	if err := ValidateUsername(username); err != nil {
		return err
	}
	if _, err := ParseRole(string(role)); err != nil {
		return err
	}
	googleEmail = strings.ToLower(googleEmail)
	if hash == "" && googleEmail == "" {
		return fmt.Errorf("auth: a user needs a password or a Google email")
	}
	usersMu.Lock()
	defer usersMu.Unlock()
	existing, err := LoadUsers(path)
	if err != nil {
		return err
	}
	if _, ok := existing[username]; ok {
		return fmt.Errorf("auth: user %q already exists", username)
	}
	existing[username] = UserRecord{Hash: hash, Role: role, GoogleEmail: googleEmail}
	return writeUsers(path, existing)
}

// DeleteUser removes username's entry (password, role and revocation marker).
func DeleteUser(path, username string) error {
	usersMu.Lock()
	defer usersMu.Unlock()
	existing, err := LoadUsers(path)
	if err != nil {
		return err
	}
	key := strings.ToLower(username)
	if _, ok := existing[key]; !ok {
		return fmt.Errorf("auth: no such user %q in %s", username, path)
	}
	delete(existing, key)
	return writeUsers(path, existing)
}

const (
	passwordHashSuffix = "_PASSWORD_HASH"
	validAfterSuffix   = "_VALID_AFTER"
	roleSuffix         = "_ROLE"
	googleEmailSuffix  = "_GOOGLE_EMAIL"
	gamesSuffix        = "_GAMES"
	oidcEmailSuffix    = "_OIDC_EMAIL"
)

// UserRecord is one user's stored credential plus revocation state.
type UserRecord struct {
	Hash string

	// ValidAfter is the earliest session IssuedAt time SessionManager.Decode
	// will accept for this user. Zero means no restriction. RevokeSessions
	// sets it to "now" to force every outstanding session for this user to
	// re-authenticate.
	ValidAfter time.Time

	// Role is "admin" or "player"; empty means admin for a password account and player otherwise (see EffectiveRole).
	Role Role

	// GoogleEmail, when set, lets that Google account sign in as this user
	// (in addition to any CROWSNEST_GOOGLE_USERS entry). Such a user may have
	// no password at all.
	GoogleEmail string

	// OIDCEmail, when set, is the (verified) email an OIDC provider may sign
	// in as this user with, the first time; after that the provider's own
	// subject id is what identifies them.
	OIDCEmail string

	// Games, when non-empty, limits a player to these game ids: they see and
	// control only those. Empty means every game. Admins ignore it (see
	// CanAccess).
	Games []string
}

// Users maps username (lowercased) to their stored record.
type Users map[string]UserRecord

// LoadUsers reads a users file: one <NAME>_PASSWORD_HASH=<bcrypt hash> line
// per user, plus an optional <NAME>_VALID_AFTER=<unix seconds> line (written
// by RevokeSessions). Blank lines and lines starting with '#' are ignored. A
// missing file is not an error — it means no users have been created yet
// (run `crowsnest set-password <username>`).
func LoadUsers(path string) (Users, error) {
	f, err := os.Open(path) // #nosec G304 -- users_file path comes from the operator's config.yaml
	if err != nil {
		if os.IsNotExist(err) {
			return Users{}, nil
		}
		return nil, fmt.Errorf("auth: read users file %s: %w", path, err)
	}
	defer f.Close()

	users := Users{}
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("auth: %s:%d: expected KEY=value", path, lineNo)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		switch {
		case strings.HasSuffix(key, passwordHashSuffix):
			username := strings.ToLower(strings.TrimSuffix(key, passwordHashSuffix))
			rec := users[username]
			rec.Hash = value
			users[username] = rec
		case strings.HasSuffix(key, validAfterSuffix):
			username := strings.ToLower(strings.TrimSuffix(key, validAfterSuffix))
			ts, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("auth: %s:%d: invalid %s value %q: %w", path, lineNo, validAfterSuffix, value, err)
			}
			rec := users[username]
			rec.ValidAfter = time.Unix(ts, 0).UTC()
			users[username] = rec
		case strings.HasSuffix(key, roleSuffix):
			username := strings.ToLower(strings.TrimSuffix(key, roleSuffix))
			role, err := ParseRole(value)
			if err != nil {
				return nil, fmt.Errorf("auth: %s:%d: %w", path, lineNo, err)
			}
			rec := users[username]
			rec.Role = role
			users[username] = rec
		case strings.HasSuffix(key, googleEmailSuffix):
			username := strings.ToLower(strings.TrimSuffix(key, googleEmailSuffix))
			rec := users[username]
			rec.GoogleEmail = strings.ToLower(value)
			users[username] = rec
		case strings.HasSuffix(key, oidcEmailSuffix):
			username := strings.ToLower(strings.TrimSuffix(key, oidcEmailSuffix))
			rec := users[username]
			rec.OIDCEmail = strings.ToLower(value)
			users[username] = rec
		case strings.HasSuffix(key, gamesSuffix):
			username := strings.ToLower(strings.TrimSuffix(key, gamesSuffix))
			games, err := ParseGameList(value)
			if err != nil {
				return nil, fmt.Errorf("auth: %s:%d: %w", path, lineNo, err)
			}
			rec := users[username]
			rec.Games = games
			users[username] = rec
		default:
			return nil, fmt.Errorf("auth: %s:%d: key %q must end with %s, %s, %s, %s, %s or %s", path, lineNo, key, passwordHashSuffix, validAfterSuffix, roleSuffix, googleEmailSuffix, oidcEmailSuffix, gamesSuffix)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("auth: read users file %s: %w", path, err)
	}
	return users, nil
}

// SetUserHash upserts username's password hash in the users file at path,
// creating the file if it doesn't exist. Other entries (including an
// existing ValidAfter marker) are preserved.
func SetUserHash(path, username, hash string) error {
	usersMu.Lock()
	defer usersMu.Unlock()
	existing, err := LoadUsers(path)
	if err != nil {
		return err
	}
	key := strings.ToLower(username)
	rec := existing[key]
	rec.Hash = hash
	existing[key] = rec
	return writeUsers(path, existing)
}

// RevokeSessions sets username's ValidAfter marker to now, persisted to the
// users file at path — every session issued for them before this call will
// fail SessionManager.Decode from that point on. A running server watches
// the file (see UserStore), so this applies within a few seconds.
//
// A name with no entry in the file is an error unless allowNew is set: the
// caller passes true for a Google sign-in user (who has no password, so no
// entry yet), and the marker is then written on its own.
func RevokeSessions(path, username string, allowNew bool) error {
	usersMu.Lock()
	defer usersMu.Unlock()
	existing, err := LoadUsers(path)
	if err != nil {
		return err
	}
	key := strings.ToLower(username)
	rec, ok := existing[key]
	if !ok && !allowNew {
		return fmt.Errorf("auth: no such user %q in %s", username, path)
	}
	rec.ValidAfter = time.Now().UTC()
	existing[key] = rec
	return writeUsers(path, existing)
}

// SetRole sets username's role in the users file at path. Like
// RevokeSessions, a name with no entry is an error unless allowNew is set
// (a Google-only user, who has no password entry).
func SetRole(path, username string, role Role, allowNew bool) error {
	usersMu.Lock()
	defer usersMu.Unlock()
	if _, err := ParseRole(string(role)); err != nil {
		return err
	}
	existing, err := LoadUsers(path)
	if err != nil {
		return err
	}
	key := strings.ToLower(username)
	rec, ok := existing[key]
	if !ok && !allowNew {
		return fmt.Errorf("auth: no such user %q in %s", username, path)
	}
	rec.Role = role
	existing[key] = rec
	return writeUsers(path, existing)
}

// AdoptUsers gives each name that has no users-file entry a plain player
// entry, so a user who signs in only through the Google allowlist can be
// managed (games, sessions) like any other. The entry holds no password and
// no email: sign-in still comes from the allowlist, so dropping a name from
// it still ends their access. An empty or missing file is left alone, since
// any entry there would end first-run setup. It returns the names added.
func AdoptUsers(path string, names []string) ([]string, error) {
	usersMu.Lock()
	defer usersMu.Unlock()
	existing, err := LoadUsers(path)
	if err != nil {
		return nil, err
	}
	if len(existing) == 0 {
		return nil, nil
	}
	var added []string
	for _, name := range names {
		name = strings.ToLower(name)
		if _, ok := existing[name]; ok || ValidateUsername(name) != nil {
			continue
		}
		existing[name] = UserRecord{Role: RolePlayer}
		added = append(added, name)
	}
	if len(added) == 0 {
		return nil, nil
	}
	sort.Strings(added)
	return added, writeUsers(path, existing)
}

// ImportGoogleEmails records each email in emails (email -> username) on that
// user's users-file entry, creating a player entry for a name that has none.
// A user who already has a different Google email keeps it and the extra one
// is returned in skipped. An empty or missing file is left alone, since any
// entry there would end first-run setup.
func ImportGoogleEmails(path string, emails GoogleUsers) (imported, skipped []string, err error) {
	usersMu.Lock()
	defer usersMu.Unlock()
	existing, err := LoadUsers(path)
	if err != nil {
		return nil, nil, err
	}
	if len(existing) == 0 {
		return nil, nil, nil
	}
	keys := make([]string, 0, len(emails))
	for e := range emails {
		keys = append(keys, e)
	}
	sort.Strings(keys)
	for _, email := range keys {
		name := strings.ToLower(emails[email])
		if ValidateUsername(name) != nil {
			continue
		}
		rec, ok := existing[name]
		if !ok {
			rec = UserRecord{Role: RolePlayer}
		}
		switch {
		case rec.GoogleEmail == "" || rec.GoogleEmail == email:
			rec.GoogleEmail = email
			existing[name] = rec
			imported = append(imported, email)
		default:
			skipped = append(skipped, email)
		}
	}
	if len(imported) == 0 {
		return nil, skipped, nil
	}
	return imported, skipped, writeUsers(path, existing)
}

// ParseGameList reads a comma-separated list of game ids, lowercased, sorted
// and de-duplicated. An empty string is an empty list (every game).
func ParseGameList(s string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, id := range strings.Split(s, ",") {
		id = strings.ToLower(strings.TrimSpace(id))
		if id == "" {
			continue
		}
		if !usernamePattern.MatchString(id) {
			return nil, fmt.Errorf("invalid game id %q", id)
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out, nil
}

// SetGames sets (or, with none, clears) the games username is limited to.
// The user must already have an entry.
func SetGames(path, username string, games []string) error {
	list, err := ParseGameList(strings.Join(games, ","))
	if err != nil {
		return err
	}
	usersMu.Lock()
	defer usersMu.Unlock()
	existing, err := LoadUsers(path)
	if err != nil {
		return err
	}
	key := strings.ToLower(username)
	rec, ok := existing[key]
	if !ok {
		return fmt.Errorf("auth: no such user %q in %s", username, path)
	}
	rec.Games = list
	existing[key] = rec
	return writeUsers(path, existing)
}

// writeUsers rewrites path from scratch with entries sorted by username for
// a stable diff.
func writeUsers(path string, users Users) error {
	names := make([]string, 0, len(users))
	for name := range users {
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	for _, name := range names {
		rec := users[name]
		if rec.Hash != "" {
			fmt.Fprintf(&b, "%s%s=%s\n", strings.ToUpper(name), passwordHashSuffix, rec.Hash)
		}
		if rec.Role != "" {
			fmt.Fprintf(&b, "%s%s=%s\n", strings.ToUpper(name), roleSuffix, rec.Role)
		}
		if rec.GoogleEmail != "" {
			fmt.Fprintf(&b, "%s%s=%s\n", strings.ToUpper(name), googleEmailSuffix, rec.GoogleEmail)
		}
		if rec.OIDCEmail != "" {
			fmt.Fprintf(&b, "%s%s=%s\n", strings.ToUpper(name), oidcEmailSuffix, rec.OIDCEmail)
		}
		if len(rec.Games) > 0 {
			fmt.Fprintf(&b, "%s%s=%s\n", strings.ToUpper(name), gamesSuffix, strings.Join(rec.Games, ","))
		}
		if !rec.ValidAfter.IsZero() {
			fmt.Fprintf(&b, "%s%s=%d\n", strings.ToUpper(name), validAfterSuffix, rec.ValidAfter.Unix())
		}
	}

	// Temp file + sync + rename so a crash never leaves a truncated users file.
	if err := atomicfile.Write(path, []byte(b.String()), 0o600); err != nil {
		return fmt.Errorf("auth: write users file %s: %w", path, err)
	}
	return nil
}

// ClearPasswordHash removes username's password hash, so the stored hash can't be
// used to sign in any more. otherLogin says the user can still sign in some other
// way (Google); without it the call is refused, since the account would be locked
// out. The user's effective role is written down first: a password account with no
// role counts as an admin, and without the hash it would silently become a player.
func ClearPasswordHash(path, username string, otherLogin bool) error {
	usersMu.Lock()
	defer usersMu.Unlock()
	existing, err := LoadUsers(path)
	if err != nil {
		return err
	}
	key := strings.ToLower(username)
	rec, ok := existing[key]
	if !ok {
		return fmt.Errorf("auth: no such user %q in %s", username, path)
	}
	if rec.Hash == "" {
		return fmt.Errorf("auth: %q has no password to clear", username)
	}
	if !otherLogin && rec.GoogleEmail == "" {
		return fmt.Errorf("auth: %q has no other way to sign in (no Google account), so clearing the password would lock them out", username)
	}
	rec.Role = rec.EffectiveRole()
	rec.Hash = ""
	existing[key] = rec
	return writeUsers(path, existing)
}

// SetGoogleEmail sets (or, with "", clears) the Google account allowed to
// sign in as username. The user must already have an entry.
func SetGoogleEmail(path, username, email string) error {
	usersMu.Lock()
	defer usersMu.Unlock()
	existing, err := LoadUsers(path)
	if err != nil {
		return err
	}
	key := strings.ToLower(username)
	rec, ok := existing[key]
	if !ok {
		return fmt.Errorf("auth: no such user %q in %s", username, path)
	}
	rec.GoogleEmail = strings.ToLower(email)
	existing[key] = rec
	return writeUsers(path, existing)
}

// SetOIDCEmail sets (or, with "", clears) the email an OIDC provider may
// sign username in as. The user must already have an entry.
func SetOIDCEmail(path, username, email string) error {
	usersMu.Lock()
	defer usersMu.Unlock()
	existing, err := LoadUsers(path)
	if err != nil {
		return err
	}
	key := strings.ToLower(username)
	rec, ok := existing[key]
	if !ok {
		return fmt.Errorf("auth: no such user %q in %s", username, path)
	}
	rec.OIDCEmail = strings.ToLower(email)
	existing[key] = rec
	return writeUsers(path, existing)
}

// ErrSetupDone is returned by CreateFirstAdmin once the file has any user.
var ErrSetupDone = errors.New("auth: setup is already done")

// CreateFirstAdmin adds the first user, an admin, and fails with ErrSetupDone
// if any user exists. The check and the write share one lock, so two setup
// requests cannot both win.
func CreateFirstAdmin(path, username, hash, googleEmail string) error {
	username = strings.ToLower(username)
	if err := ValidateUsername(username); err != nil {
		return err
	}
	googleEmail = strings.ToLower(googleEmail)
	if hash == "" && googleEmail == "" {
		return fmt.Errorf("auth: a user needs a password or a Google email")
	}
	usersMu.Lock()
	defer usersMu.Unlock()
	existing, err := LoadUsers(path)
	if err != nil {
		return err
	}
	if len(existing) > 0 {
		return ErrSetupDone
	}
	return writeUsers(path, Users{username: {Hash: hash, Role: RoleAdmin, GoogleEmail: googleEmail}})
}
