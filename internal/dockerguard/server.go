// Package dockerguard is a filtering reverse proxy for the Docker Engine API
// for a service that manages a few named containers (a game-server panel that
// starts, stops, creates with compose, reads logs and stats of, and maybe
// execs into, its game servers). Each container is a scope, configured in
// GUARD_SCOPES; the guard refuses to start on anything it does not
// understand.
//
// A generic socket proxy filters by URL only, so anything allowed to POST
// /containers/create can ask for a bind mount of / or a privileged container.
// This guard also reads the create body and checks every field of it against
// the scope. What a client can do:
//
//   - start, stop, restart, inspect, read logs, stats and top of its scope
//     containers (by name or id); nothing else by id;
//   - create a scope container from an allowed image with an allow-listed host
//     config: every HostConfig, Mount, endpoint and container setting is either
//     checked against the scope or must be empty, and anything not known is
//     refused. Image pinning is what bounds the code that runs, so Env, Cmd,
//     Entrypoint and User are free: they act inside the container. Labels (read
//     by other tools) and network aliases (names other containers resolve) are
//     not;
//   - pull allowed images by tag or digest (never "all tags", never an import);
//   - exec (only scopes with "exec": true), then start/resize/inspect only exec
//     ids created here. Which commands may run is not decided here: put
//     execguard in front of this guard for that;
//   - see only its own world: container and image lists are filtered to the
//     scopes, network and volume lists and inspects to the scope networks and
//     volume prefixes, /info is reduced to the few fields compose and the CLI
//     read, /events is refused;
//   - remove only stopped scope containers (or the "<id12>_<scope>" copy
//     compose creates while recreating one), without volumes or links; rename
//     only that copy to the scope name.
//
// No network create/connect, volume create, build, attach, archive or system
// calls.
//
// Every request target is refused if it holds "#", ";", "%" in the path,
// non-ASCII or control characters, or an API version below 1.44, and is
// rebuilt from the checked path and query before it goes to the engine, so the
// engine sees exactly what was checked. Bodies are plain Content-Length JSON
// (no chunked, no forms, one Content-Type, no keys that differ only in case,
// bounded nesting). Buffered answers are capped; at most MaxConns clients are
// served at once, and a request's head and body must arrive within 20 seconds.
package dockerguard

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	minAPIMajor, minAPIMinor = 1, 44 // compose v5 and CLI 29 negotiate far above this; older versions have other create semantics
	maxBody                  = 1 << 20
	maxHead                  = 64 << 10
	maxHeaders               = 100
)

// Guard is the scoped Docker API guard.
type Guard struct {
	// Logf, if set, receives one line per denied request ("DENY METHOD path: reason").
	Logf func(format string, args ...any)
	// MaxResponse bounds a buffered engine answer (default 32 MiB).
	MaxResponse int64
	// MaxConns bounds the clients served at once (default 64).
	MaxConns int

	socket      string
	scopes      []*Scope
	scopeByName map[string]*Scope

	streamIdle      time.Duration // a stream with no traffic for this long is closed
	requestDeadline time.Duration // from a request's first byte to the end of its body
	idleTimeout     time.Duration // an idle keep-alive connection waits this long for its next request

	mu          sync.Mutex
	execSet     map[string]bool
	execOrder   []string
	lastHeaders map[string]string
}

// New builds a Guard for the scopes, talking to the engine on the unix socket.
func New(socket string, scopes []*Scope) *Guard {
	g := &Guard{
		MaxResponse: 32 << 20, MaxConns: 64,
		socket: socket, scopes: scopes, scopeByName: map[string]*Scope{},
		streamIdle: 300 * time.Second, requestDeadline: 20 * time.Second, idleTimeout: 120 * time.Second,
		execSet: map[string]bool{}, lastHeaders: map[string]string{},
	}
	for _, s := range scopes {
		g.scopeByName[s.Name] = s
	}
	return g
}

func (g *Guard) logf(format string, args ...any) {
	if g.Logf != nil {
		g.Logf(format, args...)
	}
}

// ---- engine access

func (g *Guard) dial() (net.Conn, error) {
	return net.DialTimeout("unix", g.socket, 30*time.Second)
}

// engine makes one request on a fresh engine connection and buffers the answer.
func (g *Guard) engine(method, target string, body []byte, hdr [][2]string) (int, string, []byte, error) {
	c, err := g.dial()
	if err != nil {
		return 0, "", nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Minute)) // a pull can take a while
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: docker\r\n", method, target)
	for _, h := range hdr {
		fmt.Fprintf(&b, "%s: %s\r\n", h[0], h[1])
	}
	if body != nil {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	}
	b.WriteString("Connection: close\r\n\r\n")
	b.Write(body)
	if _, err := c.Write(b.Bytes()); err != nil {
		return 0, "", nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: method})
	if err != nil {
		return 0, "", nil, err
	}
	defer resp.Body.Close()
	g.mu.Lock()
	for _, k := range []string{"Api-Version", "Docker-Experimental", "Ostype", "Builder-Version"} {
		if v := resp.Header.Get(k); v != "" && !strings.ContainsAny(v, "\r\n") {
			g.lastHeaders[k] = v
		}
	}
	g.mu.Unlock()
	data, err := io.ReadAll(io.LimitReader(resp.Body, g.MaxResponse+1))
	if err != nil {
		return 0, "", nil, err
	}
	if int64(len(data)) > g.MaxResponse { // e.g. a whole log without tail: never held in memory
		return 0, "", nil, fmt.Errorf("%w (over %d bytes)", errTooLarge, g.MaxResponse)
	}
	ctype := resp.Header.Get("Content-Type")
	if ctype == "" || strings.ContainsAny(ctype, "\r\n") {
		ctype = "application/json"
	}
	return resp.StatusCode, ctype, data, nil
}

// engineJSON is the decoded 200 answer to a GET, or nil.
func (g *Guard) engineJSON(path string) any {
	status, _, data, err := g.engine("GET", path, nil, nil)
	if err != nil || status != 200 {
		return nil
	}
	var v any
	if err := jsonUnmarshal(data, &v); err != nil {
		return nil
	}
	return v
}

// inspect is a container's inspect document by name or id, or nil.
func (g *Guard) inspect(ref string) map[string]any {
	m, _ := g.engineJSON("/containers/" + quotePath(ref) + "/json").(map[string]any)
	return m
}

// quotePath escapes everything but RFC 3986 unreserved characters.
func quotePath(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// ---- listening

// Serve accepts clients on l until it is closed.
func (g *Guard) Serve(l net.Listener) error {
	slots := make(chan struct{}, g.MaxConns)
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return err
		}
		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { <-slots }()
				g.ServeConn(c)
			}()
		default: // over the limit: a 503 and goodbye
			msg := `{"message": "crowsnest-guard: too many clients"}`
			_ = c.SetWriteDeadline(time.Now().Add(time.Second))
			_, _ = fmt.Fprintf(c, "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(msg), msg)
			_ = c.Close()
		}
	}
}

// ServeContext is Serve that also stops, closing l, when ctx is done.
func (g *Guard) ServeContext(ctx context.Context, l net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()
	return g.Serve(l)
}

// ServeConn serves one client connection until it ends.
func (g *Guard) ServeConn(c net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			g.logf("DENY - -: internal error in the connection handler: %v", r)
		}
		_ = c.Close()
	}()
	br := bufio.NewReaderSize(c, maxHead)
	for {
		// An idle keep-alive connection may wait for its next request; once the
		// first byte of one arrives, its head and body must all be in within
		// the request deadline (a client trickling a byte a minute can't hold
		// a slot for ever).
		_ = c.SetReadDeadline(time.Now().Add(g.idleTimeout))
		if _, err := br.Peek(1); err != nil {
			return
		}
		_ = c.SetReadDeadline(time.Now().Add(g.requestDeadline))
		req, err := readRequest(br)
		if err != nil {
			var ref *refusal
			if errors.As(err, &ref) {
				g.reply(c, ref.status, "application/json", jsonMessage(ref.msg), false, true)
				lingerClose(c)
			}
			return // a timeout or a client that went away
		}
		_ = c.SetReadDeadline(time.Time{})
		if !g.handle(c, br, req) {
			return
		}
	}
}

// lingerClose ends a connection we are refusing without resetting it under a
// client that is still sending (a reset can destroy the answer it has not read).
func lingerClose(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	_, _ = io.Copy(io.Discard, io.LimitReader(c, 1<<20))
	_ = c.Close()
}

// ---- requests

type refusal struct {
	status int
	msg    string
}

func (r *refusal) Error() string { return r.msg }

type request struct {
	method  string
	rawPath string // the path as sent, version included (what the log shows)
	version string // "/v1.52" or ""
	path    string // without the version
	query   query
	header  http.Header
	body    []byte
	close   bool // the connection ends after the answer
}

var (
	tokenRe   = regexp.MustCompile("^[!#$%&'*+\\-.^_`|~0-9A-Za-z]+$")
	routeVer  = regexp.MustCompile(`^[0-9.]+$`)
	versionRe = regexp.MustCompile(`^([0-9]{1,3})\.([0-9]{1,3})$`)
)

func readLine(br *bufio.Reader, used *int) (string, error) {
	line, err := br.ReadSlice('\n')
	if err == bufio.ErrBufferFull {
		return "", &refusal{431, "request header too long"}
	}
	if err != nil {
		return "", err
	}
	*used += len(line)
	if *used > maxHead {
		return "", &refusal{431, "request header too long"}
	}
	if len(line) < 2 || line[len(line)-2] != '\r' {
		return "", &refusal{400, "lines must end in CRLF"}
	}
	line = line[:len(line)-2]
	if bytes.ContainsAny(line, "\r\n\x00") {
		return "", &refusal{400, "unusual request refused"}
	}
	return string(line), nil
}

// readRequest reads and sanity-checks one request: its head, then its body.
// The request target the checks read is the one the engine gets: rebuilt from
// the checked path and parameters, so nothing in the client's spelling of it
// ("#", ";", raw bytes, repeated or oddly encoded parameters) can mean one
// thing to these checks and another to the engine.
func readRequest(br *bufio.Reader) (*request, error) {
	used := 0
	line, err := readLine(br, &used)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(line, " ")
	if len(parts) != 3 {
		return nil, &refusal{400, "bad request line"}
	}
	req := &request{method: parts[0], header: http.Header{}}
	target, proto := parts[1], parts[2]
	if !tokenRe.MatchString(req.method) {
		return nil, &refusal{400, "bad request line"}
	}
	if proto != "HTTP/1.1" && proto != "HTTP/1.0" {
		return nil, &refusal{505, "HTTP version not supported"}
	}
	req.close = proto == "HTTP/1.0"

	count := 0
	for {
		h, err := readLine(br, &used)
		if err != nil {
			return nil, err
		}
		if h == "" {
			break
		}
		if h[0] == ' ' || h[0] == '\t' {
			return nil, &refusal{400, "folded headers are refused"}
		}
		count++
		name, value, ok := strings.Cut(h, ":")
		if !ok || !tokenRe.MatchString(name) || count > maxHeaders {
			return nil, &refusal{400, "bad header"}
		}
		value = strings.Trim(value, " \t")
		for i := 0; i < len(value); i++ {
			if value[i] < 0x20 && value[i] != '\t' || value[i] >= 0x7f {
				return nil, &refusal{400, "bad header value"}
			}
		}
		req.header.Add(name, value)
	}

	if rf := req.parseTarget(target); rf != nil {
		return nil, rf
	}
	for _, tok := range strings.Split(strings.Join(req.header.Values("Connection"), ","), ",") {
		if strings.EqualFold(strings.TrimSpace(tok), "close") {
			req.close = true
		}
	}
	if len(req.header.Values("Transfer-Encoding")) > 0 || len(req.header.Values("Expect")) > 0 {
		return nil, &refusal{400, "only plain Content-Length bodies are accepted"}
	}
	length := 0
	lengths := req.header.Values("Content-Length")
	for _, l := range lengths {
		if l != lengths[0] || len(l) == 0 || len(l) > 8 || strings.Trim(l, "0123456789") != "" {
			return nil, &refusal{400, "only plain Content-Length bodies are accepted"}
		}
	}
	if len(lengths) > 0 {
		length, _ = strconv.Atoi(lengths[0])
	}
	if length > maxBody {
		return nil, &refusal{413, "request body too large"}
	}
	ctypes := req.header.Values("Content-Type")
	if len(ctypes) > 1 {
		return nil, &refusal{400, "more than one Content-Type"}
	}
	if len(ctypes) == 1 {
		ct, _, _ := strings.Cut(ctypes[0], ";")
		if strings.EqualFold(strings.TrimSpace(ct), "application/x-www-form-urlencoded") {
			// the engine would read its parameters from such a body, unchecked
			return nil, &refusal{400, "form bodies are refused"}
		}
	}
	if length > 0 {
		req.body = make([]byte, length)
		if _, err := io.ReadFull(br, req.body); err != nil {
			return nil, err
		}
	}
	return req, nil
}

func (req *request) parseTarget(target string) *refusal {
	unusual := &refusal{400, "unusual request target refused"}
	if !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") {
		return unusual
	}
	for i := 0; i < len(target); i++ {
		if c := target[i]; c >= 0x80 || c < 33 || c == 127 || c == '#' || c == ';' {
			return unusual
		}
	}
	rawPath, rawQuery, _ := strings.Cut(target, "?")
	req.rawPath = rawPath
	// A path that could be read two ways is refused rather than interpreted:
	// escapes, dot segments, doubled or trailing slashes.
	if strings.Contains(rawPath, "%") || strings.Contains(rawPath, "..") {
		return &refusal{400, "unusual path refused"}
	}
	if rawPath != "/" {
		for _, seg := range strings.Split(rawPath[1:], "/") {
			if seg == "" || seg == "." {
				return &refusal{400, "unusual path refused"}
			}
		}
	}
	path := rawPath
	if strings.HasPrefix(path, "/v") {
		seg, _, _ := strings.Cut(path[2:], "/")
		if routeVer.MatchString(seg) {
			v := versionRe.FindStringSubmatch(seg)
			if v == nil {
				return &refusal{400, fmt.Sprintf("API version %s refused (use %d.%d or later)", seg, minAPIMajor, minAPIMinor)}
			}
			major, _ := strconv.Atoi(v[1])
			minor, _ := strconv.Atoi(v[2])
			if major < minAPIMajor || (major == minAPIMajor && minor < minAPIMinor) {
				return &refusal{400, fmt.Sprintf("API version %s refused (use %d.%d or later)", seg, minAPIMajor, minAPIMinor)}
			}
			req.version = fmt.Sprintf("/v%d.%d", major, minor)
			path = path[2+len(seg):]
		}
	}
	req.path = path
	q, err := parseQuery(rawQuery) // the engine sees fromImage= as "", so must we
	if err != nil {
		return unusual
	}
	req.query = q
	return nil
}

func (req *request) target() string {
	t := req.version + req.path
	if len(req.query.pairs) > 0 {
		t += "?" + req.query.encode()
	}
	return t
}

// ---- answering

func (g *Guard) reply(c net.Conn, status int, ctype string, data []byte, head, closeAfter bool) {
	var b bytes.Buffer
	text := http.StatusText(status)
	if text == "" {
		text = "Status"
	}
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n", status, text, ctype, len(data))
	g.mu.Lock() // the docker client reads Api-Version from /_ping to pick its protocol
	for _, k := range []string{"Api-Version", "Docker-Experimental", "Ostype", "Builder-Version"} {
		if v := g.lastHeaders[k]; v != "" {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	g.mu.Unlock()
	if closeAfter {
		b.WriteString("Connection: close\r\n")
	}
	b.WriteString("\r\n")
	if !head {
		b.Write(data)
	}
	_ = c.SetWriteDeadline(time.Now().Add(5 * time.Minute))
	_, _ = c.Write(b.Bytes())
}

var (
	execCreateRe = regexp.MustCompile(`^/containers/[^/]+/exec$`)
	execStartRe  = regexp.MustCompile(`^/exec/[^/]+/start$`)
	logsRe       = regexp.MustCompile(`^/containers/[^/]+/logs$`)
	statsRe      = regexp.MustCompile(`^/containers/[^/]+/stats$`)
)

// jsonBodyEndpoint: requests whose JSON body the checks read, and the only ones
// that may carry a body at all.
func jsonBodyEndpoint(method, path string) bool {
	return method == "POST" && (path == "/containers/create" || execCreateRe.MatchString(path) || execStartRe.MatchString(path))
}

// streamKind says how a request that cannot be buffered is relayed, decided by
// the endpoint alone (never by the client's Upgrade or Connection headers):
// "hijack" for exec start, whose connection becomes a raw two-way stream once
// the engine answers 101; "oneway" for responses that stay open (log follow,
// streaming stats), where nothing the client sends afterwards is passed on;
// "" for everything else (buffered, on a fresh engine connection per request).
func streamKind(path string, q query) string {
	switch {
	case execStartRe.MatchString(path):
		return "hijack"
	case logsRe.MatchString(path) && q.bool("follow", false): // as the engine reads it: follow=TRUE, yes, 2 ...
		return "oneway"
	case statsRe.MatchString(path) && q.bool("stream", true):
		return "oneway"
	}
	return ""
}

type badBody struct{}

// handle checks one request and relays it. It reports whether the connection
// may serve another request.
func (g *Guard) handle(c net.Conn, br *bufio.Reader, req *request) (keep bool) {
	refuse := func(status int, msg string) bool {
		g.reply(c, status, "application/json", jsonMessage(msg), false, true)
		lingerClose(c)
		return false
	}
	if len(req.body) > 0 && !jsonBodyEndpoint(req.method, req.path) {
		return refuse(400, "this request may not carry a body")
	}
	var body any
	if len(req.body) > 0 {
		var err error
		if body, err = strictJSON(req.body); err != nil {
			body = badBody{} // not an object, so every check that reads a body refuses it
		}
	}
	hk, err := g.safeCheck(req, body)
	if err != nil {
		g.logf("DENY %s %s: %s", req.method, req.rawPath, oneLine(err.Error()))
		var d *denial
		if errors.As(err, &d) {
			g.reply(c, d.status, "application/json", jsonMessage(d.msg), req.method == "HEAD", req.close)
			return !req.close
		}
		// a body or answer shaped in a way the checks did not foresee: refused, never passed
		return refuse(400, "request refused (could not be checked)")
	}
	if kind := streamKind(req.path, req.query); kind != "" {
		g.tunnel(c, br, req, kind)
		return false
	}
	var hdr [][2]string
	var payload []byte
	if len(req.body) > 0 {
		hdr = append(hdr, [2]string{"Content-Type", "application/json"}) // every body that gets this far is JSON
		payload = req.body
	}
	if v := req.header.Get("X-Registry-Auth"); v != "" {
		hdr = append(hdr, [2]string{"X-Registry-Auth", v})
	}
	status, ctype, data, err := g.engine(req.method, req.target(), payload, hdr)
	if err != nil {
		g.reply(c, 502, "application/json", jsonMessage("docker socket: "+oneLine(err.Error())), req.method == "HEAD", req.close)
		return !req.close
	}
	if hk != nil {
		var herr error
		status, ctype, data, herr = runHook(hk, status, ctype, data)
		if herr != nil {
			g.logf("DENY %s %s: internal error on the answer: %s", req.method, req.rawPath, oneLine(herr.Error()))
			return refuse(502, "engine answer could not be checked")
		}
	}
	g.reply(c, status, ctype, data, req.method == "HEAD", req.close)
	return !req.close
}

// safeCheck is check that turns anything unforeseen (a panic) into a refusal.
func (g *Guard) safeCheck(req *request, body any) (hk *hook, err error) {
	defer func() {
		if r := recover(); r != nil {
			hk, err = nil, fmt.Errorf("internal error: %v", r)
		}
	}()
	return g.check(req.method, req.path, req.query, body)
}

// oneLine makes request-derived text safe to log.
func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return '?'
		}
		return r
	}, s)
}

// runHook applies a hook to the engine's answer; a panic is an error, never a
// pass-through.
func runHook(hk *hook, status int, ctype string, data []byte) (rs int, rc string, rd []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			rs, rc, rd, err = 0, "", nil, fmt.Errorf("internal error: %v", r)
		}
	}()
	switch {
	case hk.rewrite != nil:
		return hk.rewrite(status, ctype, data)
	case hk.remember != nil && status == 201:
		hk.remember(data)
	}
	return status, ctype, data, nil
}
