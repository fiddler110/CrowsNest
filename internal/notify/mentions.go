package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"sync"

	"github.com/fiddler110/crowsnest/internal/atomicfile"
)

type gameKey struct{}

// WithGame marks a notice as being about one game, so the Discord channel can mention the people who asked to hear
// about it. Other channels ignore it.
func WithGame(ctx context.Context, game string) context.Context {
	return context.WithValue(ctx, gameKey{}, game)
}

// GameFrom is the game a notice is about, "" when it is not about one.
func GameFrom(ctx context.Context) string {
	g, _ := ctx.Value(gameKey{}).(string)
	return g
}

// discordID is a Discord user id (a snowflake): digits only, so it can't smuggle other markup into a message.
var discordID = regexp.MustCompile(`^[0-9]{15,22}$`)

// Mention is one person's choice: their Discord user id and the games they want to be pinged about.
type Mention struct {
	DiscordID string   `json:"discord_id"`
	Games     []string `json:"games"`
}

// Mentions is the per-person opt-in list, kept in a small JSON file. It lets a game's notices on the shared Discord
// webhook mention the people who asked, with no per-person webhook or secret to store.
type Mentions struct {
	path string
	mu   sync.Mutex
	m    map[string]Mention
}

// OpenMentions reads path; a missing file means nobody has opted in. An empty path keeps the list in memory.
func OpenMentions(path string) (*Mentions, error) {
	s := &Mentions{path: path, m: map[string]Mention{}}
	if path == "" {
		return s, nil
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- derives from the operator's config
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("notify: read %s: %w", path, err)
	}
	if err := json.Unmarshal(raw, &s.m); err != nil {
		return nil, fmt.Errorf("notify: parse %s: %w", path, err)
	}
	return s, nil
}

// Get is user's choice (the zero value when none). Nil-safe.
func (s *Mentions) Get(user string) Mention {
	if s == nil {
		return Mention{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[user]
}

// Set saves user's Discord id and games; an empty id or no games forgets the entry. valid names the games that
// exist, so a removed game does not linger.
func (s *Mentions) Set(user, id string, gameIDs []string, valid func(string) bool) error {
	if id != "" && !discordID.MatchString(id) {
		return fmt.Errorf("a Discord user id is 15 to 22 digits (Discord, Settings, Advanced, Developer Mode, then right-click your name, Copy User ID)")
	}
	seen := map[string]bool{}
	var keep []string
	for _, g := range gameIDs {
		if !seen[g] && valid(g) {
			seen[g] = true
			keep = append(keep, g)
		}
	}
	sort.Strings(keep)
	s.mu.Lock()
	defer s.mu.Unlock()
	next := make(map[string]Mention, len(s.m)+1)
	for k, v := range s.m {
		next[k] = v
	}
	if id == "" || len(keep) == 0 {
		delete(next, user)
		if id != "" { // keep the id so they need not retype it, with no games chosen
			next[user] = Mention{DiscordID: id}
		}
	} else {
		next[user] = Mention{DiscordID: id, Games: keep}
	}
	if s.path != "" {
		out, _ := json.MarshalIndent(next, "", "  ")
		if err := atomicfile.Write(s.path, append(out, '\n'), 0o600); err != nil {
			return err
		}
	}
	s.m = next
	return nil
}

// IDsFor lists the Discord ids of everyone who opted in to game, sorted. Nil-safe.
func (s *Mentions) IDsFor(game string) []string {
	if s == nil || game == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, m := range s.m {
		for _, g := range m.Games {
			if g == game && m.DiscordID != "" {
				out = append(out, m.DiscordID)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}
