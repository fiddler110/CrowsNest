// Package probes holds the declarative player/status probes a module.yaml can
// ask for without writing Go: http_json (poll a JSON endpoint) and
// source_rcon (run an RCON command and parse its reply). Both follow the
// games.PlayerCounter contract: ok=false means "could not be determined",
// never zero players.
package probes

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/rcon"
)

const timeout = 4 * time.Second

// HTTPJSON polls a JSON endpoint. The endpoint answering 2xx means online
// (starting while the container runs but the endpoint does not answer).
type HTTPJSON struct {
	Docker *dockerctl.Client
	// URL is polled for status and for players (a module may point
	// PlayersURL elsewhere).
	URL        string
	PlayersURL string
	User, Pass string // optional basic auth
	// CountPath is a dotted path to a number ("metrics.players") or, if it
	// resolves to an array, its length. NamesPath/NameField optionally list
	// players: NamesPath is an array of strings or of objects whose NameField
	// is the name. With neither, the array at CountPath supplies the names.
	CountPath, NamesPath, NameField string
	HTTP                            *http.Client
}

func (p *HTTPJSON) client() *http.Client {
	if p.HTTP != nil {
		return p.HTTP
	}
	return &http.Client{Timeout: timeout}
}

func (p *HTTPJSON) get(ctx context.Context, url string) (any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if p.User != "" || p.Pass != "" {
		req.SetBasicAuth(p.User, p.Pass)
	}
	resp, err := p.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("http_json: status %d", resp.StatusCode)
	}
	var v any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// Check implements games.StatusChecker.
func (p *HTTPJSON) Check(ctx context.Context, containerName string) (games.Status, error) {
	running, err := p.Docker.Running(ctx, containerName)
	if err != nil {
		return games.StatusUnknown, err
	}
	if !running {
		return games.StatusOffline, nil
	}
	if _, err := p.get(ctx, p.URL); err != nil {
		return games.StatusStarting, nil
	}
	return games.StatusOnline, nil
}

// PlayerCount implements games.PlayerCounter.
func (p *HTTPJSON) PlayerCount(ctx context.Context) (int, []string, bool) {
	u := p.PlayersURL
	if u == "" {
		u = p.URL
	}
	doc, err := p.get(ctx, u)
	if err != nil {
		return 0, nil, false
	}
	return extract(doc, p.CountPath, p.NamesPath, p.NameField)
}

func extract(doc any, countPath, namesPath, nameField string) (int, []string, bool) {
	cv, found := lookup(doc, countPath)
	if !found {
		return 0, nil, false
	}
	count := -1
	var names []string
	switch v := cv.(type) {
	case float64:
		if v < 0 || v != float64(int(v)) {
			return 0, nil, false
		}
		count = int(v)
	case []any:
		count = len(v)
		if namesPath == "" {
			names = namesFrom(v, nameField)
		}
	default:
		return 0, nil, false
	}
	if namesPath != "" {
		if nv, ok := lookup(doc, namesPath); ok {
			if arr, ok := nv.([]any); ok {
				names = namesFrom(arr, nameField)
			}
		}
	}
	return count, names, true
}

func namesFrom(arr []any, field string) []string {
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		switch v := e.(type) {
		case string:
			out = append(out, v)
		case map[string]any:
			if s, ok := v[field].(string); ok && field != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

// lookup follows a dotted path through objects; array elements by index.
func lookup(doc any, path string) (any, bool) {
	if path == "" {
		return doc, true
	}
	cur := doc
	for _, key := range strings.Split(path, ".") {
		switch v := cur.(type) {
		case map[string]any:
			next, ok := v[key]
			if !ok {
				return nil, false
			}
			cur = next
		case []any:
			i, err := strconv.Atoi(key)
			if err != nil || i < 0 || i >= len(v) {
				return nil, false
			}
			cur = v[i]
		default:
			return nil, false
		}
	}
	return cur, true
}

// SourceRCON counts players by running a command over Source RCON and
// matching its reply. Every match of Pattern is one player; group 1, if the
// pattern has one, is the player's name.
type SourceRCON struct {
	Addr, Password string
	Command        string
	Pattern        *regexp.Regexp
	// Exec is rcon.Exec; tests replace it.
	Exec func(ctx context.Context, addr, password, command string, timeout time.Duration) (string, error)
}

// PlayerCount implements games.PlayerCounter.
func (p *SourceRCON) PlayerCount(ctx context.Context) (int, []string, bool) {
	run := p.Exec
	if run == nil {
		run = rcon.Exec
	}
	out, err := run(ctx, p.Addr, p.Password, p.Command, timeout)
	if err != nil {
		return 0, nil, false
	}
	var names []string
	for _, line := range strings.Split(out, "\n") {
		m := p.Pattern.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if len(m) > 1 {
			names = append(names, m[1])
		} else {
			names = append(names, "")
		}
	}
	return len(names), names, true
}
