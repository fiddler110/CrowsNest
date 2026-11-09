// Package probes holds the declarative player/status probes a module.yaml can
// ask for without writing Go: http_json (poll a JSON endpoint) and
// source_rcon (run an RCON command and parse its reply). Both follow the
// games.PlayerCounter contract: ok=false means "could not be determined",
// never zero players.
package probes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/rcon"
)

const timeout = 4 * time.Second

// HTTPJSON is a declarative client for a game's JSON-over-HTTP admin API
// (Palworld's REST API is the reference user). Beyond the player probe it can
// serve the info panel, a fixed set of console actions and a pre-stop
// sequence, all described in module.yaml; see rest.go.
//
// The endpoint answering 2xx means online (starting while the container runs
// but the endpoint does not answer).
type HTTPJSON struct {
	Docker *dockerctl.Client
	Name   string // module id, for log lines

	BaseURL    string // e.g. http://palworld:8212, no trailing slash
	User, Pass string // optional basic auth

	// StatusPath is polled for status; PlayersPath (default StatusPath)
	// for the count.
	StatusPath, PlayersPath string
	// CountPath is a dotted path to a number ("metrics.players") or, if it
	// resolves to an array, its length. NamesPath/NameField optionally list
	// players: NamesPath is an array of strings or of objects whose NameField
	// is the name. With neither, the array at CountPath supplies the names.
	CountPath, NamesPath, NameField string

	InfoSources []InfoSource
	InfoFields  []InfoField
	ActionDefs  []Action
	Steps       []Step

	HTTP *http.Client
	// Sleep replaces the pre-stop pause (tests).
	Sleep func(ctx context.Context, d time.Duration)

	authWarned atomic.Bool
}

func (p *HTTPJSON) client() *http.Client {
	if p.HTTP != nil {
		return p.HTTP
	}
	return &http.Client{Timeout: timeout}
}

// do sends one request and returns the decoded JSON body (nil when the body
// is empty or not wanted).
func (p *HTTPJSON) do(ctx context.Context, method, path string, body map[string]string) (any, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.BaseURL+path, rdr)
	if err != nil {
		return nil, err
	}
	if p.User != "" || p.Pass != "" {
		req.SetBasicAuth(p.User, p.Pass)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		_, _ = io.Copy(io.Discard, resp.Body)
		err := statusError(resp.StatusCode)
		p.noteAuth(err)
		return nil, err
	}
	p.noteAuth(nil)
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		if method != http.MethodGet {
			return nil, nil // action replies need not be JSON
		}
		return nil, err
	}
	return v, nil
}

func (p *HTTPJSON) get(ctx context.Context, path string) (any, error) {
	return p.do(ctx, http.MethodGet, path, nil)
}

type statusError int

func (e statusError) Error() string { return fmt.Sprintf("http_json: status %d", int(e)) }

// noteAuth logs once per failure streak that the credentials were rejected:
// otherwise a wrong password just looks like a server stuck on "starting".
func (p *HTTPJSON) noteAuth(err error) {
	var st statusError
	if errors.As(err, &st) && (st == 401 || st == 403) {
		if !p.authWarned.Swap(true) {
			log.Printf("%s: API at %s rejected the credentials (HTTP %d) - check the password env var; status stays \"starting\" and idle auto-stop is disabled until it matches", p.Name, p.BaseURL, int(st))
		}
		return
	}
	if err == nil {
		p.authWarned.Store(false)
	}
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
	if _, err := p.get(ctx, p.statusPath()); err != nil {
		return games.StatusStarting, nil
	}
	return games.StatusOnline, nil
}

// PlayerCount implements games.PlayerCounter.
func (p *HTTPJSON) PlayerCount(ctx context.Context) (int, []string, bool) {
	doc, err := p.get(ctx, p.playersPath())
	if err != nil {
		return 0, nil, false
	}
	return extract(doc, p.CountPath, p.NamesPath, p.NameField)
}

func (p *HTTPJSON) playersPath() string {
	if p.PlayersPath != "" {
		return p.PlayersPath
	}
	return p.StatusPath
}

func (p *HTTPJSON) statusPath() string {
	if p.StatusPath != "" {
		return p.StatusPath
	}
	return p.PlayersPath
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
// matching its reply. Every match of Pattern is one player; the first non-empty
// capture group, if the pattern has any, is the player's name.
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
		// The name is the first non-empty capture group, so one pattern can
		// alternate between several line formats (one group per format).
		name := ""
		for _, g := range m[1:] {
			if g != "" {
				name = g
				break
			}
		}
		names = append(names, name)
	}
	return len(names), names, true
}
