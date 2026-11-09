package probes

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/rcon"
)

// RawRCON is the admin-only raw console over RCON (games.RawConsole).
type RawRCON struct {
	Addr, Password string
	// Exec is rcon.Exec; tests replace it.
	Exec func(ctx context.Context, addr, password, command string, timeout time.Duration) (string, error)
}

// Raw implements games.RawConsole.
func (r *RawRCON) Raw(ctx context.Context, command string) (string, error) {
	if r.Addr == "" {
		return "", errors.New("rcon is not configured for this game")
	}
	command = strings.TrimSpace(command)
	if command == "" {
		return "", fmt.Errorf("%w: empty command", games.ErrBadInput)
	}
	if len(command) > 1000 || strings.ContainsAny(command, "\x00\r\n") {
		return "", fmt.Errorf("%w: command must be one line under 1000 characters", games.ErrBadInput)
	}
	run := r.Exec
	if run == nil {
		run = rcon.Exec
	}
	return run(ctx, r.Addr, r.Password, command, 8*time.Second)
}
