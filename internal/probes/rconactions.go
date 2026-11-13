package probes

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/rcon"
)

// RCONActions is games.Console for fixed admin actions that run as RCON
// commands (kick, ban, whitelist ...). The manifest decides the command line;
// the admin only fills in the declared fields.
type RCONActions struct {
	Addr, Password string
	Defs           []Action
	// Exec is rcon.Exec; tests replace it.
	Exec func(ctx context.Context, addr, password, command string, timeout time.Duration) (string, error)
}

// Actions implements games.Console.
func (r *RCONActions) Actions() []games.ConsoleAction { return consoleActions(r.Defs) }

// Run implements games.Console.
func (r *RCONActions) Run(ctx context.Context, action string, args map[string]string) (string, error) {
	var a *Action
	for i := range r.Defs {
		if r.Defs[i].ID == action {
			a = &r.Defs[i]
		}
	}
	if a == nil {
		return "", fmt.Errorf("unknown action %q", action)
	}
	if r.Addr == "" {
		return "", errors.New("rcon is not configured for this game")
	}
	vals, err := actionArgs(a, args)
	if err != nil {
		return "", err
	}
	cmd := renderString(a.RCON, vals)
	run := r.Exec
	if run == nil {
		run = rcon.Exec
	}
	reply, err := run(ctx, r.Addr, r.Password, cmd, 8*time.Second)
	if err != nil {
		return "", err
	}
	if s := renderString(a.Result, vals); s != "" {
		return s, nil
	}
	if reply != "" {
		return reply, nil
	}
	return "Done.", nil
}
