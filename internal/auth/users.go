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
	"strings"
)

const passwordHashSuffix = "_PASSWORD_HASH"

// Users maps username (lowercased) to bcrypt hash.
type Users map[string]string

// LoadUsers reads a users file: one <NAME>_PASSWORD_HASH=<bcrypt hash> entry
// per line. Blank lines and lines starting with '#' are ignored. A missing
// file is not an error — it means no users have been created yet (run
// `crowsnest set-password <username>`).
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
		if !strings.HasSuffix(key, passwordHashSuffix) {
			return nil, fmt.Errorf("auth: %s:%d: key %q must end with %s", path, lineNo, key, passwordHashSuffix)
		}
		username := strings.ToLower(strings.TrimSuffix(key, passwordHashSuffix))
		users[username] = strings.TrimSpace(value)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("auth: read users file %s: %w", path, err)
	}
	return users, nil
}

// SetUserHash upserts username's password hash in the users file at path,
// creating the file if it doesn't exist. Other entries are preserved; the
// file is rewritten with entries sorted by username for a stable diff.
func SetUserHash(path, username, hash string) error {
	existing, err := LoadUsers(path)
	if err != nil {
		return err
	}
	existing[strings.ToLower(username)] = hash

	names := make([]string, 0, len(existing))
	for name := range existing {
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	for _, name := range names {
		fmt.Fprintf(&b, "%s%s=%s\n", strings.ToUpper(name), passwordHashSuffix, existing[name])
	}

	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return fmt.Errorf("auth: write users file %s: %w", path, err)
	}
	return nil
}
