package windrose

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fiddler110/crowsnest/internal/dockerctl"
)

// This file is a direct port of the original Python CrowsNest's Windrose+
// HTTP API integration (app.py lines ~339-728): a cookie-session login,
// a short-TTL cache on /api/status (the plugin's own state snapshot), and
// concurrent RCON commands (via the same HTTP API) for the richer info
// panel. See docs/implementation-plan.md phase 10.
const (
	defaultHTTPTimeout = 5 * time.Second
	defaultRCONTimeout = 6 * time.Second
	statusCacheTTL     = 4 * time.Second
	startedAtCacheTTL  = 10 * time.Second
	cookieTTL          = 23 * time.Hour // Max-Age is 24h server-side; refresh a little early
)

var (
	timeOfDayRe   = regexp.MustCompile(`TimeOfDay\s*=\s*([\d.]+)`)
	dayDurRe      = regexp.MustCompile(`DayCycleDuration\s*=\s*([\d.]+)`)
	nightDurRe    = regexp.MustCompile(`NightCycleDuration\s*=\s*([\d.]+)`)
	windSpeedRe   = regexp.MustCompile(`WindSpeed\s*=\s*([\d.]+)`)
	waveHeightRe  = regexp.MustCompile(`WaveHeight\s*=\s*([\d.]+)`)
	temperatureRe = regexp.MustCompile(`TemperatureMultiplier\s*=\s*([\d.]+)`)
	activeRe      = regexp.MustCompile(`Active:\s*(\d+)`)
	zombiesRe     = regexp.MustCompile(`Zombie Controllers:\s*(\d+)`)
	connModeRe    = regexp.MustCompile(`Mode:\s*(\w+)`)
	lastPlayerRe  = regexp.MustCompile(`Last Player:\s*(.+)`)
	workingSetRe  = regexp.MustCompile(`Working Set:\s*([\d,]+\s*\w+)`)
	virtualRe     = regexp.MustCompile(`Virtual:\s*([\d,]+\s*\w+)`)
	pageFileRe    = regexp.MustCompile(`Page File:\s*([\d,]+\s*\w+)`)

	multiplierKeys = []string{"loot", "xp", "stack_size", "craft_efficiency", "crop_speed", "weight"}
)

// Client talks to the Windrose+ in-game HTTP API. It implements
// games.PlayerCounter and games.InfoProvider. The zero value is not usable —
// build one with BaseURL, Password, Docker, and ContainerName set.
type Client struct {
	BaseURL       string // e.g. http://host.docker.internal:8780, no trailing slash
	Password      string // Windrose+ RCON password; also used for HTTP login
	Docker        *dockerctl.Client
	ContainerName string

	// HTTP overrides the http.Client used for requests. Intended for tests;
	// production callers should leave it unset.
	HTTP *http.Client

	// mu guards every field below. A short-TTL cache shared across
	// concurrent dashboard requests avoids hammering the in-game plugin's
	// own HTTP server, mirroring the original's threading.Lock-protected
	// module-level cache.
	mu            sync.Mutex
	cookie        string
	cookieExpires time.Time
	statusCache   *wplusStatus
	statusCacheAt time.Time
	haveStatus    bool
	startedAt     time.Time
	startedAtAt   time.Time
	haveStartedAt bool
}

func (c *Client) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{
		Timeout: defaultHTTPTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

type wplusStatus struct {
	Mode      string  `json:"mode"`
	Timestamp float64 `json:"timestamp"`
	Server    struct {
		WindrosePlus string `json:"windrose_plus"`
		PlayerCount  int    `json:"player_count"`
	} `json:"server"`
	Players []struct {
		Name string   `json:"name"`
		X    *float64 `json:"x"`
		Y    *float64 `json:"y"`
		Z    *float64 `json:"z"`
	} `json:"players"`
	Multipliers map[string]float64 `json:"multipliers"`
	Error       string             `json:"error"`
}

// login POSTs the RCON password to /login and caches the resulting session
// cookie. Must be called with mu held.
func (c *Client) login(ctx context.Context) bool {
	if c.Password == "" {
		return false
	}
	form := url.Values{"password": {c.Password}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/login", strings.NewReader(form.Encode()))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.client().Do(req)
	if err != nil {
		c.cookie = ""
		return false
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	for _, ck := range resp.Cookies() {
		if ck.Name == "wp_session" && ck.Value != "" {
			c.cookie = ck.Value
			c.cookieExpires = time.Now().Add(cookieTTL)
			return true
		}
	}
	c.cookie = ""
	return false
}

// ensureCookie returns a valid session cookie, logging in if needed. Must be
// called with mu held.
func (c *Client) ensureCookie(ctx context.Context) bool {
	if c.cookie != "" && time.Now().Before(c.cookieExpires) {
		return true
	}
	return c.login(ctx)
}

type rconResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Error   string `json:"error"`
}

// sendRCON issues one RCON command over the HTTP API using the given
// cookie. rejected is true when the cookie was rejected (caller should
// re-login and retry once).
func (c *Client) sendRCON(ctx context.Context, cookie, command string, timeout time.Duration) (msg string, rejected bool, ok bool) {
	body, _ := json.Marshal(map[string]string{"command": command})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/api/rcon", bytes.NewReader(body))
	if err != nil {
		return "", false, false
	}
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "wp_session", Value: cookie})

	hc := c.client()
	if timeout > 0 {
		client := *hc
		client.Timeout = timeout
		hc = &client
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", false, false
	}
	defer resp.Body.Close()

	var data rconResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", false, false
	}
	if data.Error == "Authentication required" {
		return "", true, false
	}
	if data.Status == "ok" {
		return data.Message, false, true
	}
	return "", false, false
}

// rcon sends command via the HTTP API, re-authenticating once if the
// session cookie has been rejected.
func (c *Client) rcon(ctx context.Context, command string, timeout time.Duration) (string, bool) {
	c.mu.Lock()
	ok := c.ensureCookie(ctx)
	cookie := c.cookie
	c.mu.Unlock()
	if !ok {
		return "", false
	}

	msg, rejected, ok := c.sendRCON(ctx, cookie, command, timeout)
	if rejected {
		c.mu.Lock()
		c.cookie = ""
		ok = c.ensureCookie(ctx)
		cookie = c.cookie
		c.mu.Unlock()
		if !ok {
			return "", false
		}
		msg, _, ok = c.sendRCON(ctx, cookie, command, timeout)
	}
	if !ok {
		return "", false
	}
	return msg, true
}

func (c *Client) fetchStatus(ctx context.Context, cookie string) (*wplusStatus, bool, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/api/status", nil)
	if err != nil {
		return nil, false, false
	}
	req.AddCookie(&http.Cookie{Name: "wp_session", Value: cookie})

	resp, err := c.client().Do(req)
	if err != nil {
		return nil, false, false
	}
	defer resp.Body.Close()

	var data wplusStatus
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, false, false
	}
	if data.Error != "" {
		return nil, true, false
	}
	return &data, false, true
}

// status returns the cached (or freshly fetched) /api/status snapshot, or
// nil if it couldn't be obtained (login failed, request failed, or the
// cookie was rejected twice).
func (c *Client) status(ctx context.Context) *wplusStatus {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.haveStatus && time.Since(c.statusCacheAt) < statusCacheTTL {
		return c.statusCache
	}

	if !c.ensureCookie(ctx) {
		c.statusCache, c.haveStatus, c.statusCacheAt = nil, true, time.Now()
		return nil
	}

	data, rejected, ok := c.fetchStatus(ctx, c.cookie)
	if rejected {
		c.cookie = ""
		if !c.ensureCookie(ctx) {
			c.statusCache, c.haveStatus, c.statusCacheAt = nil, true, time.Now()
			return nil
		}
		data, _, ok = c.fetchStatus(ctx, c.cookie)
	}
	if !ok {
		data = nil
	}
	c.statusCache, c.haveStatus, c.statusCacheAt = data, true, time.Now()
	return data
}

// startedAtCached returns the container's current-run start time, cached
// briefly since `docker inspect` is a subprocess call per invocation.
func (c *Client) startedAtCached(ctx context.Context) (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.haveStartedAt && time.Since(c.startedAtAt) < startedAtCacheTTL {
		return c.startedAt, true
	}
	t, err := c.Docker.StartedAt(ctx, c.ContainerName)
	if err != nil {
		return time.Time{}, false
	}
	c.startedAt, c.startedAtAt, c.haveStartedAt = t, time.Now(), true
	return t, true
}

// isStale reports whether data predates the container's current run — e.g.
// Windrose+ hasn't written fresh data yet after a restart (stuck in boot
// mode). Player data from a stale snapshot must be ignored. Unknown start
// time (can't tell) is treated as "assume fresh", matching the original.
func (c *Client) isStale(ctx context.Context, data *wplusStatus) bool {
	if data == nil {
		return true
	}
	started, ok := c.startedAtCached(ctx)
	if !ok {
		return false
	}
	return data.Timestamp < float64(started.Unix())
}

// PlayerCount implements games.PlayerCounter.
func (c *Client) PlayerCount(ctx context.Context) (count int, names []string, ok bool) {
	data := c.status(ctx)
	if data == nil || c.isStale(ctx, data) {
		return 0, nil, false
	}
	if data.Mode == "" || data.Mode == "boot" {
		// Boot mode: the HTTP API can't query the game thread yet, so a
		// player count here would be a guess, not a reading.
		return 0, nil, false
	}

	names = make([]string, 0, len(data.Players))
	for _, p := range data.Players {
		name := p.Name
		if name == "" {
			name = "Player"
		}
		names = append(names, name)
	}
	count = data.Server.PlayerCount
	if len(names) > count {
		count = len(names)
	}

	// In degraded mode the game thread is starved; the API reports
	// player_count=0 even with active connections — fall back to RCON.
	if count == 0 && data.Mode == "degraded" {
		if msg, ok := c.rcon(ctx, "wp.connections", defaultRCONTimeout); ok {
			if m := activeRe.FindStringSubmatch(msg); m != nil {
				if n, err := strconv.Atoi(m[1]); err == nil {
					count = n
				}
			}
		}
	}
	return count, names, true
}

func coordStr(f *float64) string {
	if f == nil {
		return "?"
	}
	return strconv.Itoa(int(math.Round(*f)))
}

func uptimeString(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	var parts []string
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%dd", days))
	}
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%dh", hours))
	}
	if minutes > 0 || len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%dm", minutes))
	}
	return strings.Join(parts, " ")
}

// Info implements games.InfoProvider: world time/weather/connections/memory
// via concurrent RCON calls, plus player positions from /api/status.
func (c *Client) Info(ctx context.Context) (map[string]any, bool) {
	out := map[string]any{"available": false}

	if started, ok := c.startedAtCached(ctx); ok {
		out["uptime"] = uptimeString(time.Since(started))
	}

	data := c.status(ctx)
	if data == nil {
		return out, true
	}
	out["available"] = true
	out["mode"] = data.Mode
	out["version"] = data.Server.WindrosePlus

	mults := map[string]float64{}
	for _, key := range multiplierKeys {
		if v, ok := data.Multipliers[key]; ok {
			mults[key] = v
		}
	}
	out["multipliers"] = mults

	if !c.isStale(ctx, data) {
		players := make([]map[string]string, 0, len(data.Players))
		for _, p := range data.Players {
			name := p.Name
			if name == "" {
				name = "Player"
			}
			players = append(players, map[string]string{
				"name": name,
				"x":    coordStr(p.X),
				"y":    coordStr(p.Y),
				"z":    coordStr(p.Z),
			})
		}
		count := data.Server.PlayerCount
		if len(players) > count {
			count = len(players)
		}
		out["player_count"] = count
		out["players"] = players
	}

	if data.Mode == "boot" {
		return out, true
	}

	type result struct {
		cmd string
		msg string
		ok  bool
	}
	commands := []string{"wp.time", "wp.weather", "wp.connections", "wp.memory"}
	results := make([]result, len(commands))
	var wg sync.WaitGroup
	for i, cmd := range commands {
		wg.Add(1)
		go func(i int, cmd string) {
			defer wg.Done()
			msg, ok := c.rcon(ctx, cmd, defaultRCONTimeout)
			results[i] = result{cmd, msg, ok}
		}(i, cmd)
	}
	wg.Wait()

	var connectionsActive int
	haveConnectionsActive := false
	for _, r := range results {
		if !r.ok {
			continue
		}
		switch r.cmd {
		case "wp.time":
			if m := timeOfDayRe.FindStringSubmatch(r.msg); m != nil {
				if v, err := strconv.ParseFloat(m[1], 64); err == nil {
					out["time_of_day"] = v
				}
			}
			if m := dayDurRe.FindStringSubmatch(r.msg); m != nil {
				if v, err := strconv.ParseFloat(m[1], 64); err == nil {
					out["day_duration"] = int(v)
				}
			}
			if m := nightDurRe.FindStringSubmatch(r.msg); m != nil {
				if v, err := strconv.ParseFloat(m[1], 64); err == nil {
					out["night_duration"] = int(v)
				}
			}
		case "wp.weather":
			if m := windSpeedRe.FindStringSubmatch(r.msg); m != nil {
				if v, err := strconv.ParseFloat(m[1], 64); err == nil {
					out["wind_speed"] = v
				}
			}
			if m := waveHeightRe.FindStringSubmatch(r.msg); m != nil {
				if v, err := strconv.ParseFloat(m[1], 64); err == nil {
					out["wave_height"] = v
				}
			}
			if m := temperatureRe.FindStringSubmatch(r.msg); m != nil {
				if v, err := strconv.ParseFloat(m[1], 64); err == nil {
					out["temperature"] = v
				}
			}
		case "wp.connections":
			if m := activeRe.FindStringSubmatch(r.msg); m != nil {
				if v, err := strconv.Atoi(m[1]); err == nil {
					out["connections_active"] = v
					connectionsActive = v
					haveConnectionsActive = true
				}
			}
			if m := zombiesRe.FindStringSubmatch(r.msg); m != nil {
				if v, err := strconv.Atoi(m[1]); err == nil {
					out["connections_zombies"] = v
				}
			}
			if m := connModeRe.FindStringSubmatch(r.msg); m != nil {
				out["connections_mode"] = m[1]
			}
			if m := lastPlayerRe.FindStringSubmatch(r.msg); m != nil {
				out["connections_last_player"] = strings.TrimSpace(m[1])
			}
		case "wp.memory":
			if m := workingSetRe.FindStringSubmatch(r.msg); m != nil {
				out["memory_working_set"] = strings.TrimSpace(m[1])
			}
			if m := virtualRe.FindStringSubmatch(r.msg); m != nil {
				out["memory_virtual"] = strings.TrimSpace(m[1])
			}
			if m := pageFileRe.FindStringSubmatch(r.msg); m != nil {
				out["memory_page_file"] = strings.TrimSpace(m[1])
			}
		}
	}

	if pc, _ := out["player_count"].(int); pc == 0 && haveConnectionsActive && connectionsActive > 0 {
		out["player_count"] = connectionsActive
	}

	return out, true
}
