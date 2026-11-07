package palworld

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/rcon"
)

const (
	maxMessage = 200
	maxUserID  = 100
	rconTimout = 8 * time.Second
)

var (
	msgField  = games.ConsoleField{Name: "message", Label: "Message"}
	optMsg    = games.ConsoleField{Name: "message", Label: "Message to the player (optional)", Optional: true}
	userField = games.ConsoleField{Name: "userid", Label: "User ID (see Players)"}
)

// Actions implements games.Console.
func (c *Client) Actions() []games.ConsoleAction {
	return []games.ConsoleAction{
		{ID: "players", Label: "Players"},
		{ID: "announce", Label: "Announce", Fields: []games.ConsoleField{msgField}},
		{ID: "save", Label: "Save world"},
		{ID: "kick", Label: "Kick", Fields: []games.ConsoleField{userField, optMsg}, Danger: true},
		{ID: "ban", Label: "Ban", Fields: []games.ConsoleField{userField, optMsg}, Danger: true},
		{ID: "unban", Label: "Unban", Fields: []games.ConsoleField{userField}},
	}
}

// Run implements games.Console through the REST API. There is deliberately no
// shutdown or stop action: starting and stopping belong to CrowsNest, which
// also handles the save, the backup and the restart cool-down.
func (c *Client) Run(ctx context.Context, action string, args map[string]string) (string, error) {
	msg := strings.TrimSpace(args["message"])
	uid := strings.TrimSpace(args["userid"])
	if err := checkText(msg, maxMessage, "message"); err != nil {
		return "", err
	}
	needUser := func() error {
		if uid == "" {
			return fmt.Errorf("%w: user id is required", games.ErrBadInput)
		}
		return checkText(uid, maxUserID, "user id")
	}
	switch action {
	case "players":
		return c.listPlayers(ctx)
	case "announce":
		if msg == "" {
			return "", fmt.Errorf("%w: message is required", games.ErrBadInput)
		}
		return "Announced.", c.post(ctx, "/v1/api/announce", map[string]string{"message": msg})
	case "save":
		return "World saved.", c.post(ctx, "/v1/api/save", nil)
	case "kick", "ban":
		if err := needUser(); err != nil {
			return "", err
		}
		if err := c.post(ctx, "/v1/api/"+action, map[string]string{"userid": uid, "message": msg}); err != nil {
			return "", err
		}
		return fmt.Sprintf("%s applied to %s.", strings.ToUpper(action[:1])+action[1:], uid), nil
	case "unban":
		if err := needUser(); err != nil {
			return "", err
		}
		return "Unbanned " + uid + ".", c.post(ctx, "/v1/api/unban", map[string]string{"userid": uid})
	}
	return "", fmt.Errorf("unknown action %q", action)
}

func checkText(s string, max int, what string) error {
	if len([]rune(s)) > max {
		return fmt.Errorf("%w: %s is longer than %d characters", games.ErrBadInput, what, max)
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: %s contains control characters", games.ErrBadInput, what)
		}
	}
	return nil
}

func (c *Client) listPlayers(ctx context.Context) (string, error) {
	var resp struct {
		Players []struct {
			Name   string  `json:"name"`
			UserID string  `json:"userId"`
			Level  int     `json:"level"`
			Ping   float64 `json:"ping"`
		} `json:"players"`
	}
	if err := c.get(ctx, "/v1/api/players", &resp); err != nil {
		return "", err
	}
	if len(resp.Players) == 0 {
		return "No players online.", nil
	}
	var b strings.Builder
	for _, p := range resp.Players {
		fmt.Fprintf(&b, "%s  [%s]  level %d  %.0f ms\n", p.Name, p.UserID, p.Level, p.Ping)
	}
	return strings.TrimRight(b.String(), "\n"), nil
}

// Raw implements games.RawConsole over RCON.
func (c *Client) Raw(ctx context.Context, command string) (string, error) {
	if c.RCONAddr == "" {
		return "", errors.New("rcon is not configured for this game")
	}
	command = strings.TrimSpace(command)
	if command == "" {
		return "", fmt.Errorf("%w: empty command", games.ErrBadInput)
	}
	if len(command) > 1000 || strings.ContainsAny(command, "\x00\r\n") {
		return "", fmt.Errorf("%w: command must be one line under 1000 characters", games.ErrBadInput)
	}
	return rcon.Exec(ctx, c.RCONAddr, c.RCONPassword, command, rconTimout)
}

// IsAuthError reports a rejected RCON/REST password.
func IsAuthError(err error) bool {
	var st errStatus
	return errors.Is(err, rcon.ErrAuth) || (errors.As(err, &st) && (st == http.StatusUnauthorized || st == http.StatusForbidden))
}
