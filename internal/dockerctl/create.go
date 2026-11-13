package dockerctl

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// PortBinding publishes one container port on the host.
type PortBinding struct {
	HostIP        string
	HostPort      int
	ContainerPort int
	Proto         string // tcp or udp
}

// CreateSpec is everything the dashboard asks the engine to create for a
// game: deliberately only the fields the guard's policy envelope can admit.
// There is no way to ask for host networking or capabilities. Extra networks,
// pinned addresses and security options are for the one game a policy
// exception names; the guard refuses them for anything else.
type CreateSpec struct {
	Name        string
	Image       string // repository:tag
	Env         []string
	Labels      map[string]string
	Network     string
	StopTimeout int   // seconds the engine waits before killing the game
	MemoryBytes int64 // 0 = unlimited
	Ports       []PortBinding
	Binds       []string // host:container
	// Networks, when more than one or when an address is pinned, replaces
	// Network. The first is the games network; the one with the highest
	// GwPriority carries the default route.
	Networks []NetEndpoint
	SecOpts  []string
	// Entrypoint, when set, replaces the image's (a one-shot helper container).
	Entrypoint []string
	// NoRestart creates the container with restart policy "no" instead of
	// unless-stopped, for a run-once container.
	NoRestart bool
}

// NetEndpoint is one network to join.
type NetEndpoint struct {
	Name       string
	IPv4       string
	GwPriority int
}

func (s CreateSpec) body() ([]byte, error) {
	exposed := map[string]struct{}{}
	bindings := map[string][]map[string]string{}
	for _, p := range s.Ports {
		key := fmt.Sprintf("%d/%s", p.ContainerPort, p.Proto)
		exposed[key] = struct{}{}
		bindings[key] = append(bindings[key], map[string]string{"HostIp": p.HostIP, "HostPort": fmt.Sprint(p.HostPort)})
	}
	host := map[string]any{
		"Binds":         s.Binds,
		"PortBindings":  bindings,
		"NetworkMode":   s.Network,
		"RestartPolicy": map[string]any{"Name": "unless-stopped"},
	}
	if s.NoRestart {
		host["RestartPolicy"] = map[string]any{"Name": "no"}
	}
	if s.MemoryBytes > 0 {
		host["Memory"] = s.MemoryBytes
	}
	if len(s.SecOpts) > 0 {
		host["SecurityOpt"] = s.SecOpts
	}
	endpoints := map[string]any{s.Network: map[string]any{}}
	if len(s.Networks) > 0 {
		endpoints = map[string]any{}
		best, mode := -1<<31, s.Network
		for _, n := range s.Networks {
			ep := map[string]any{}
			if n.IPv4 != "" {
				ep["IPAMConfig"] = map[string]any{"IPv4Address": n.IPv4}
			}
			if n.GwPriority != 0 {
				ep["GwPriority"] = n.GwPriority
			}
			endpoints[n.Name] = ep
			if n.GwPriority > best {
				best, mode = n.GwPriority, n.Name
			}
		}
		host["NetworkMode"] = mode
	}
	body := map[string]any{
		"Image": s.Image, "Env": s.Env, "Labels": s.Labels, "ExposedPorts": exposed,
		"HostConfig":       host,
		"NetworkingConfig": map[string]any{"EndpointsConfig": endpoints},
	}
	if len(s.Entrypoint) > 0 {
		body["Entrypoint"] = s.Entrypoint
	}
	if s.StopTimeout > 0 {
		body["StopTimeout"] = s.StopTimeout
	}
	return json.Marshal(body)
}

// send issues a request and returns the response for 2xx; otherwise an *apiError.
func (c *Client) send(ctx context.Context, method, path string, q url.Values, body []byte) (*http.Response, error) {
	base, _, _ := c.target()
	u := base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("dockerctl: %s %s: %w", method, path, err)
	}
	if resp.StatusCode/100 != 2 {
		defer resp.Body.Close()
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		msg := strings.TrimSpace(string(data))
		var m struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(data, &m) == nil && m.Message != "" {
			msg = m.Message
		}
		return nil, &apiError{Status: resp.StatusCode, Message: msg, What: method + " " + path}
	}
	return resp, nil
}

// IsDenied reports whether err is the guard (or engine) refusing a request
// with 403, which for a freshly enabled game usually means the guard has not
// reloaded its scopes yet.
func IsDenied(err error) bool {
	var ae *apiError
	return asAPI(err, &ae) && ae.Status == http.StatusForbidden
}

// Create creates (does not start) the container.
func (c *Client) Create(ctx context.Context, s CreateSpec) error {
	b, err := s.body()
	if err != nil {
		return err
	}
	ctx, cancel := c.opCtx(ctx, 2*time.Minute)
	defer cancel()
	resp, err := c.send(ctx, http.MethodPost, "/containers/create", url.Values{"name": {s.Name}}, b)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// Remove deletes a stopped container; force is never used. Its data folder is
// left alone.
func (c *Client) Remove(ctx context.Context, name string) error {
	ctx, cancel := c.opCtx(ctx, time.Minute)
	defer cancel()
	resp, err := c.send(ctx, http.MethodDelete, "/containers/"+url.PathEscape(name), nil, nil)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// Pull pulls repository:tag and waits for it. The engine reports pull
// failures inside a 200 stream, so the stream is read for an error line.
func (c *Client) Pull(ctx context.Context, image string) error {
	repo, tag := image, "latest"
	if r, d, ok := strings.Cut(image, "@"); ok {
		repo, tag = r, d // by digest: the engine takes the digest as the tag parameter
	} else if i := strings.LastIndex(image, ":"); i > strings.LastIndex(image, "/") {
		repo, tag = image[:i], image[i+1:]
	}
	ctx, cancel := c.opCtx(ctx, 30*time.Minute)
	defer cancel()
	resp, err := c.send(ctx, http.MethodPost, "/images/create", url.Values{"fromImage": {repo}, "tag": {tag}}, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var line struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(sc.Bytes(), &line) == nil && line.Error != "" {
			return fmt.Errorf("dockerctl: pull %s: %s", image, line.Error)
		}
	}
	return sc.Err()
}

// ImageDigests is the RepoDigests of a local image ("repo@sha256:..." as the
// engine writes them): what a pulled tag resolved to.
func (c *Client) ImageDigests(ctx context.Context, image string) ([]string, error) {
	ctx, cancel := c.opCtx(ctx, 30*time.Second)
	defer cancel()
	resp, err := c.get(ctx, "/images/"+image+"/json", nil) // the engine reads the repository's slashes as part of the name
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out struct{ RepoDigests []string }
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("dockerctl: decode image inspect %s: %w", image, err)
	}
	return out.RepoDigests, nil
}
