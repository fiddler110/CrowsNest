// Package palworld implements Palworld's status and player-count detection
// against the dedicated server's built-in REST API (added upstream in
// v0.4.x; enabled in thijsvanloef/palworld-server-docker via
// REST_API_ENABLED=true, REST_API_PORT=8212). See
// docs/implementation-plan.md phase 10 — unlike Windrose, there is no
// original Python CrowsNest logic to port here; this is a fresh
// implementation against Palworld's own published REST API
// (https://docs.palworldgame.com/api/rest-api/), not yet exercised against
// a real running server.
package palworld

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/games"
)

const defaultTimeout = 5 * time.Second

// Client talks to a Palworld dedicated server's REST API. It implements
// games.StatusChecker and games.PlayerCounter. The zero value is not usable
// — build one with BaseURL, User, and Password set.
type Client struct {
	BaseURL  string // e.g. http://palworld:8212, no trailing slash
	User     string // typically "admin"
	Password string

	Docker *dockerctl.Client

	// HTTP overrides the http.Client used for requests. Intended for tests;
	// production callers should leave it unset.
	HTTP *http.Client
}

func (c *Client) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: defaultTimeout}
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.User, c.Password)

	resp, err := c.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errStatus(resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

type errStatus int

func (e errStatus) Error() string {
	return "palworld: unexpected HTTP status " + http.StatusText(int(e))
}

// Check implements games.StatusChecker: offline when the container isn't
// running; online once the REST API responds; starting in between (the
// server binary is up but the API hasn't bound yet, or is still loading the
// world save).
func (c *Client) Check(ctx context.Context, containerName string) (games.Status, error) {
	running, err := c.Docker.Running(ctx, containerName)
	if err != nil {
		return games.StatusUnknown, err
	}
	if !running {
		return games.StatusOffline, nil
	}
	if err := c.get(ctx, "/v1/api/info", nil); err != nil {
		return games.StatusStarting, nil
	}
	return games.StatusOnline, nil
}

type playersResponse struct {
	Players []struct {
		Name string `json:"name"`
	} `json:"players"`
}

// PlayerCount implements games.PlayerCounter: ok=false whenever the REST
// API can't be reached or parsed (server starting, wrong credentials,
// network error) — never assumed to mean zero players.
func (c *Client) PlayerCount(ctx context.Context) (count int, names []string, ok bool) {
	var resp playersResponse
	if err := c.get(ctx, "/v1/api/players", &resp); err != nil {
		return 0, nil, false
	}
	names = make([]string, 0, len(resp.Players))
	for _, p := range resp.Players {
		names = append(names, p.Name)
	}
	return len(names), names, true
}
