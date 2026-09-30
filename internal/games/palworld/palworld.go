// Package palworld implements Palworld's status and player-count detection
// against the dedicated server's built-in REST API (added upstream in
// v0.4.x; enabled in thijsvanloef/palworld-server-docker via
// REST_API_ENABLED=true, REST_API_PORT=8212). See
// docs/implementation-plan.md phase 10 — unlike Windrose, there is no
// original Python CrowsNest logic to port here; this is a fresh
// implementation against Palworld's own published REST API
// (https://docs.palworldgame.com/api/rest-api/), verified against a real
// palworld-server-docker container on 2026-09-30.
package palworld

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
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

type infoResponse struct {
	Version     string `json:"version"`
	ServerName  string `json:"servername"`
	Description string `json:"description"`
	WorldGUID   string `json:"worldguid"`
}

type metricsResponse struct {
	CurrentPlayers int     `json:"currentplayernum"`
	MaxPlayers     int     `json:"maxplayernum"`
	ServerFPS      float64 `json:"serverfps"`
	ServerFPSAvg   float64 `json:"serverfpsaverage"`
	FrameTimeMS    float64 `json:"serverframetime"`
	Days           int     `json:"days"`
	BaseCamps      int     `json:"basecampnum"`
	Uptime         int64   `json:"uptime"` // seconds
}

// Info implements games.InfoProvider from /v1/api/info (identity) and
// /v1/api/metrics (live performance). ok=false only when /info itself
// fails; a failed /metrics just leaves out the live fields so the panel
// still shows the server's identity.
func (c *Client) Info(ctx context.Context) (map[string]any, bool) {
	var info infoResponse
	if err := c.get(ctx, "/v1/api/info", &info); err != nil {
		return nil, false
	}
	out := map[string]any{
		"server_name": info.ServerName,
		"version":     info.Version,
	}
	if info.Description != "" {
		out["description"] = info.Description
	}
	if info.WorldGUID != "" {
		out["world_id"] = info.WorldGUID
	}

	var m metricsResponse
	if err := c.get(ctx, "/v1/api/metrics", &m); err == nil {
		out["players"] = fmt.Sprintf("%d / %d", m.CurrentPlayers, m.MaxPlayers)
		out["uptime"] = formatUptime(m.Uptime)
		out["server_fps"] = fmt.Sprintf("%.0f (avg %.0f)", m.ServerFPS, m.ServerFPSAvg)
		out["frame_time_ms"] = fmt.Sprintf("%.1f", m.FrameTimeMS)
		out["in_game_days"] = m.Days
		out["base_camps"] = m.BaseCamps
	}
	return out, true
}

func formatUptime(secs int64) string {
	d := time.Duration(secs) * time.Second
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%dd %dh", int(d.Hours())/24, int(d.Hours())%24)
	case d >= time.Hour:
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	case d >= time.Minute:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	default:
		return fmt.Sprintf("%ds", secs)
	}
}

// Startup drives Palworld's startup progress bar from the container's own
// log. The first boot spends most of its time in SteamCMD downloading the
// ~5GB server (steamcmd prints "Update state (0x61) downloading, progress:
// NN.NN"), which Parse maps onto 10-85%; the fixed milestones cover the
// entrypoint steps before and after it.
var Startup = &games.StartupMatcher{
	Milestones: []games.Milestone{
		{Pattern: regexp.MustCompile(`Checking Installation`), Pct: 5, Label: "Checking installation"},
		{Pattern: regexp.MustCompile(`Checking for new Palworld Server updates`), Pct: 8, Label: "Checking for updates"},
		{Pattern: regexp.MustCompile(`GENERATING CONFIG`), Pct: 86, Label: "Generating config"},
		{Pattern: regexp.MustCompile(`\*\*\*\*Starting Server\*\*\*\*`), Pct: 90, Label: "Launching server"},
		{Pattern: regexp.MustCompile(`Running Palworld dedicated server`), Pct: 96, Label: "Loading world"},
		{Pattern: regexp.MustCompile(`REST API\(\d+\) port is open`), Pct: 100, Label: "Server ready"},
	},
	Parse: parseDownload,
}

var downloadRe = regexp.MustCompile(`Update state \(0x61\) downloading, progress: (\d+(?:\.\d+)?)`)

func parseDownload(line string) (int, string, bool) {
	m := downloadRe.FindStringSubmatch(line)
	if m == nil {
		return 0, "", false
	}
	pct, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, "", false
	}
	return 10 + int(pct*0.75), fmt.Sprintf("Downloading server files (%.0f%%)", pct), true
}
