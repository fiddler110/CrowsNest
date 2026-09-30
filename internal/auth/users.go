// Package auth implements CrowsNest's login system: a flat users file of
// bcrypt password hashes, stateless HMAC-signed session cookies, CSRF token
// verification, and per-IP login rate limiting. It has no server-side
// session store — everything needed to verify a request is in the request
// itself.
package auth

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	passwordHashSuffix = "_PASSWORD_HASH"
	validAfterSuffix   = "_VALID_AFTER"
)

// UserRecord is one user's stored credential plus revocation state.
type UserRecord struct {
	Hash string

	// ValidAfter is the earliest session IssuedAt time SessionManager.Decode
	// will accept for this user. Zero means no restriction. RevokeSessions
	// sets it to "now" to force every outstanding session for this user to
	// re-authenticate.
	ValidAfter time.Time
}

// Users maps username (lowercased) to their stored record.
type Users map[string]UserRecord

// LoadUsers reads a users file: one <NAME>_PASSWORD_HASH=<bcrypt hash> line
// per user, plus an optional <NAME>_VALID_AFTER=<unix seconds> line (written
// by RevokeSessions). Blank lines and lines starting with '#' are ignored. A
// missing file is not an error — it means no users have been created yet
// (run `crowsnest set-password <username>`).
func LoadUsers(path string) (Users, error) {
	f, err := os.Open(path)
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
		default:
			return nil, fmt.Errorf("auth: %s:%d: key %q must end with %s or %s", path, lineNo, key, passwordHashSuffix, validAfterSuffix)
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
// fail SessionManager.Decode from that point on. Like SetUserHash, this
// only takes effect once the running server reloads the file (i.e. on
// restart); there's no hot-reload.
func RevokeSessions(path, username string) error {
	existing, err := LoadUsers(path)
	if err != nil {
		return err
	}
	key := strings.ToLower(username)
	rec, ok := existing[key]
	if !ok {
		return fmt.Errorf("auth: no such user %q in %s", username, path)
	}
	rec.ValidAfter = time.Now().UTC()
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
		fmt.Fprintf(&b, "%s%s=%s\n", strings.ToUpper(name), passwordHashSuffix, rec.Hash)
		if !rec.ValidAfter.IsZero() {
			fmt.Fprintf(&b, "%s%s=%d\n", strings.ToUpper(name), validAfterSuffix, rec.ValidAfter.Unix())
		}
	}

	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return fmt.Errorf("auth: write users file %s: %w", path, err)
	}
	return nil
}
