// Package execguard is a small filtering reverse proxy for the Docker API
// that allows `docker exec` only for an exact allowlist of (container,
// command) pairs. It sits in front of docker-socket-proxy, which can switch
// exec on or off but cannot say which commands may run: with EXEC=1 alone,
// anything that can reach the proxy can run any command in any container.
//
// Everything that is not an exec route is forwarded untouched, so the
// upstream proxy's own allowlist still decides those.
package execguard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

// Rule permits running exactly Cmd in the container named Container.
type Rule struct {
	Container string
	Cmd       []string
}

const (
	maxBody = 64 << 10
	idTTL   = 10 * time.Minute
	maxIDs  = 1024
	apiVer  = `(?:/v[0-9]+(?:\.[0-9]+)?)?`
)

var (
	createRe = regexp.MustCompile(`^` + apiVer + `/containers/([^/]+)/exec$`)
	execRe   = regexp.MustCompile(`^` + apiVer + `/exec/([^/]+)/(start|resize|json)$`)
	anyExec  = regexp.MustCompile(`(^|/)exec(/|$)`)

	// Fields an exec-create body may carry. Env, User, Privileged and
	// WorkingDir are allowed only at their zero value.
	allowedKeys = map[string]bool{
		"AttachStdin": true, "AttachStdout": true, "AttachStderr": true,
		"Tty": true, "Cmd": true, "DetachKeys": true, "ConsoleSize": true,
		"Env": true, "User": true, "Privileged": true, "WorkingDir": true,
	}
)

// Guard is an http.Handler enforcing the exec allowlist.
type Guard struct {
	// Logf, if set, receives one line per denied request.
	Logf func(format string, args ...any)

	rules []Rule
	proxy *httputil.ReverseProxy
	now   func() time.Time

	mu  sync.Mutex
	ids map[string]time.Time // exec ids this guard approved
}

type createdKey struct{}

// New builds a Guard forwarding to upstream, a tcp://host:port, http://… or
// unix:///path URL.
func New(upstream string, rules []Rule) (*Guard, error) {
	u, err := url.Parse(upstream)
	if err != nil {
		return nil, fmt.Errorf("execguard: upstream: %w", err)
	}
	g := &Guard{rules: rules, now: time.Now, ids: map[string]time.Time{}}
	var target *url.URL
	rt := http.DefaultTransport.(*http.Transport).Clone()
	switch u.Scheme {
	case "tcp", "http":
		target = &url.URL{Scheme: "http", Host: u.Host}
	case "unix":
		sock := u.Path
		target = &url.URL{Scheme: "http", Host: "docker"}
		rt.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		}
	default:
		return nil, fmt.Errorf("execguard: unsupported upstream scheme %q", u.Scheme)
	}
	g.proxy = httputil.NewSingleHostReverseProxy(target)
	g.proxy.Transport = rt
	g.proxy.FlushInterval = -1 // stream exec output as it arrives
	g.proxy.ModifyResponse = g.captureID
	return g, nil
}

func (g *Guard) deny(w http.ResponseWriter, r *http.Request, why string) {
	if g.Logf != nil {
		g.Logf("execguard: denied %s %s: %s", r.Method, r.URL.Path, why)
	}
	http.Error(w, "execguard: "+why, http.StatusForbidden)
}

func (g *Guard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Refuse anything whose path could be read two ways (encoding, dot
	// segments, doubled slashes) so the checks below see what upstream sees.
	if strings.Contains(r.URL.EscapedPath(), "%") || path.Clean(r.URL.Path) != r.URL.Path {
		g.deny(w, r, "non-canonical path")
		return
	}
	p := r.URL.Path

	if m := createRe.FindStringSubmatch(p); m != nil {
		if r.Method != http.MethodPost {
			g.deny(w, r, "method not allowed")
			return
		}
		g.create(w, r, m[1])
		return
	}
	if m := execRe.FindStringSubmatch(p); m != nil {
		if m[2] == "json" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			g.proxy.ServeHTTP(w, r) // read-only inspect
			return
		}
		if r.Method != http.MethodPost || !g.known(m[1]) {
			g.deny(w, r, "exec id not issued by this guard")
			return
		}
		g.proxy.ServeHTTP(w, r)
		return
	}
	if anyExec.MatchString(p) {
		g.deny(w, r, "unrecognised exec route")
		return
	}
	g.proxy.ServeHTTP(w, r)
}

func (g *Guard) create(w http.ResponseWriter, r *http.Request, container string) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		g.deny(w, r, "unreadable body")
		return
	}
	cmd, err := checkCreate(body)
	if err != nil {
		g.deny(w, r, err.Error())
		return
	}
	if !g.allowed(container, cmd) {
		g.deny(w, r, fmt.Sprintf("command not allowlisted for %q", container))
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.Header.Set("Content-Length", fmt.Sprint(len(body)))
	g.proxy.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), createdKey{}, true)))
}

// checkCreate validates an exec-create body and returns its Cmd.
func checkCreate(body []byte) ([]string, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, errors.New("malformed exec body")
	}
	for k := range raw {
		if !allowedKeys[k] {
			return nil, fmt.Errorf("exec option %q not allowed", k)
		}
	}
	zero := func(k string, ok ...string) error {
		v, present := raw[k]
		if !present {
			return nil
		}
		if s := strings.TrimSpace(string(v)); slices.Contains(ok, s) {
			return nil
		}
		return fmt.Errorf("exec option %q not allowed", k)
	}
	for k, ok := range map[string][]string{
		"Env": {"null", "[]"}, "User": {"null", `""`},
		"Privileged": {"null", "false"}, "WorkingDir": {"null", `""`},
	} {
		if err := zero(k, ok...); err != nil {
			return nil, err
		}
	}
	var cmd []string
	if err := json.Unmarshal(raw["Cmd"], &cmd); err != nil || len(cmd) == 0 {
		return nil, errors.New("exec body has no command")
	}
	return cmd, nil
}

func (g *Guard) allowed(container string, cmd []string) bool {
	for _, r := range g.rules {
		if r.Container == container && slices.Equal(r.Cmd, cmd) {
			return true
		}
	}
	return false
}

// captureID remembers the id of an exec we approved so only its start/resize
// calls are let through.
func (g *Guard) captureID(resp *http.Response) error {
	if v, _ := resp.Request.Context().Value(createdKey{}).(bool); !v || resp.StatusCode != http.StatusCreated {
		return nil
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	_ = resp.Body.Close()
	if err != nil {
		return err
	}
	resp.Body = io.NopCloser(bytes.NewReader(b))
	var out struct{ Id string }
	if json.Unmarshal(b, &out) == nil && out.Id != "" {
		g.remember(out.Id)
	}
	return nil
}

func (g *Guard) remember(id string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	if len(g.ids) >= maxIDs {
		for k, t := range g.ids {
			if now.Sub(t) > idTTL {
				delete(g.ids, k)
			}
		}
		if len(g.ids) >= maxIDs { // still full: drop everything rather than grow
			clear(g.ids)
		}
	}
	g.ids[id] = now
}

func (g *Guard) known(id string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	t, ok := g.ids[id]
	return ok && g.now().Sub(t) <= idTTL
}
