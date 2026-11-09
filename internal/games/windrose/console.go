package windrose

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/fiddler110/crowsnest/internal/games"
)

const (
	maxPlayerName = 64
	maxReason     = 200
)

// Actions implements games.Console: the Windrose+ player-management commands
// (wp.players, wp.status, wp.listbans, wp.kick, wp.ban, wp.unban). Lifecycle
// (start/stop/save) deliberately stays with CrowsNest.
func (c *Client) Actions() []games.ConsoleAction {
	player := games.ConsoleField{Name: "player", Label: "Player name (no spaces; see Players)"}
	reason := games.ConsoleField{Name: "reason", Label: "Reason (optional)", Optional: true}
	return []games.ConsoleAction{
		{ID: "players", Label: "Players"},
		{ID: "status", Label: "Server status"},
		{ID: "listbans", Label: "Ban list"},
		{ID: "kick", Label: "Kick", Fields: []games.ConsoleField{player, reason}, Danger: true},
		{ID: "ban", Label: "Ban", Fields: []games.ConsoleField{player, reason}, Danger: true},
		{ID: "unban", Label: "Unban", Fields: []games.ConsoleField{player}},
	}
}

// Run implements games.Console by sending the matching wp.* command through
// Windrose+'s RCON-over-HTTP channel.
func (c *Client) Run(ctx context.Context, action string, args map[string]string) (string, error) {
	player := strings.TrimSpace(args["player"])
	reason := strings.TrimSpace(args["reason"])
	if err := checkLine(reason, maxReason, "reason"); err != nil {
		return "", err
	}
	needPlayer := func() error {
		if player == "" {
			return fmt.Errorf("%w: player is required", games.ErrBadInput)
		}
		if strings.IndexFunc(player, unicode.IsSpace) >= 0 {
			return fmt.Errorf("%w: player names with spaces are not supported", games.ErrBadInput)
		}
		return checkLine(player, maxPlayerName, "player")
	}
	var cmd string
	switch action {
	case "players":
		cmd = "wp.players"
	case "status":
		cmd = "wp.status"
	case "listbans":
		cmd = "wp.listbans"
	case "kick", "ban":
		if err := needPlayer(); err != nil {
			return "", err
		}
		cmd = "wp." + action + " " + player
		if reason != "" {
			cmd += " " + reason
		}
	case "unban":
		if err := needPlayer(); err != nil {
			return "", err
		}
		cmd = "wp.unban " + player
	default:
		return "", fmt.Errorf("unknown action %q", action)
	}
	msg, ok := c.rcon(ctx, cmd, defaultRCONTimeout)
	if !ok {
		return "", errors.New("Windrose+ did not answer (is the server running with Windrose+ enabled?)")
	}
	if strings.TrimSpace(msg) == "" {
		return "Done.", nil
	}
	return msg, nil
}

// Raw implements games.RawConsole: one command line sent as-is.
func (c *Client) Raw(ctx context.Context, command string) (string, error) {
	command = strings.TrimSpace(command)
	if command == "" {
		return "", fmt.Errorf("%w: empty command", games.ErrBadInput)
	}
	if len(command) > 1000 || strings.ContainsAny(command, "\x00\r\n") {
		return "", fmt.Errorf("%w: command must be one line under 1000 characters", games.ErrBadInput)
	}
	msg, ok := c.rcon(ctx, command, defaultRCONTimeout)
	if !ok {
		return "", errors.New("Windrose+ did not answer (is the server running with Windrose+ enabled?)")
	}
	return msg, nil
}

func checkLine(s string, max int, what string) error {
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
