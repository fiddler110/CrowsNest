package dockerguard

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// query is a request's parameters in the order sent. The engine is sent
// exactly these, re-encoded, never the client's spelling of them.
type query struct {
	pairs [][2]string
	vals  map[string][]string
}

func parseQuery(raw string) (query, error) {
	q := query{vals: map[string][]string{}}
	for _, seg := range strings.Split(raw, "&") {
		if seg == "" {
			continue
		}
		k, v, _ := strings.Cut(seg, "=")
		key, err := url.QueryUnescape(k)
		if err != nil {
			return q, err
		}
		val, err := url.QueryUnescape(v)
		if err != nil {
			return q, err
		}
		q.pairs = append(q.pairs, [2]string{key, val})
		q.vals[key] = append(q.vals[key], val)
	}
	return q, nil
}

func (q query) encode() string {
	var b strings.Builder
	for i, p := range q.pairs {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(url.QueryEscape(p[0]))
		b.WriteByte('=')
		b.WriteString(url.QueryEscape(p[1]))
	}
	return b.String()
}

// one is the single value of a parameter (def when absent); given twice is a 400.
func (q query) one(key, def string) (string, error) {
	v, ok := q.vals[key]
	if !ok {
		return def, nil
	}
	if len(v) != 1 {
		return "", deny(400, "%s given more than once", quote(key))
	}
	return v[0], nil
}

// onlyParams refuses any parameter not in allowed, and any given twice.
func (q query) onlyParams(allowed []string, what string) error {
	var extra []string
	for k := range q.vals {
		if !contains(allowed, k) {
			extra = append(extra, k)
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		return deny(403, "%s: parameter %s is not allowed", what, quote(extra[0]))
	}
	keys := make([]string, 0, len(q.vals))
	for k := range q.vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if _, err := q.one(k, ""); err != nil {
			return err
		}
	}
	return nil
}

// bool reads a flag as the engine does (moby httputils.BoolValue): absent is
// the default, and anything but "", "0", "no", "false" or "none" (any case,
// spaces trimmed) is true. So follow=TRUE or follow=yes is a follow, and must
// stream.
func (q query) bool(key string, def bool) bool {
	v, ok := q.vals[key]
	if !ok {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(v[0])) {
	case "", "0", "no", "false", "none":
		return false
	}
	return true
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// hook is what a checked request needs after the engine has answered: either
// a rewrite of the answer or a note of what it created.
type hook struct {
	rewrite  func(status int, ctype string, data []byte) (int, string, []byte, error)
	remember func(data []byte)
}

// jsonRewrite builds a hook from a function over the decoded 200 answer.
func jsonRewrite(fn func(doc any) (int, any)) *hook {
	return &hook{rewrite: func(status int, ctype string, data []byte) (int, string, []byte, error) {
		if status != 200 {
			return status, ctype, data, nil
		}
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.UseNumber()
		var doc any
		if err := dec.Decode(&doc); err != nil {
			return 502, "application/json", jsonMessage("unreadable engine response"), nil
		}
		code, out := fn(doc)
		b, err := marshal(out)
		if err != nil {
			return 0, "", nil, err
		}
		return code, "application/json", b, nil
	}}
}

func marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}

func jsonMessage(msg string) []byte {
	b, _ := marshal(map[string]string{"message": "crowsnest-guard: " + msg})
	return b
}

func notFound(msg string) (int, any) { return 404, map[string]string{"message": msg} }

// ---- what the client may see

func (g *Guard) allImages() map[string]bool {
	out := map[string]bool{}
	for _, s := range g.cur().scopes {
		for r := range s.Images {
			out[r] = true
		}
	}
	return out
}

func (g *Guard) allNetworks() map[string]bool {
	out := map[string]bool{}
	for _, s := range g.cur().scopes {
		for n := range s.Networks {
			out[n] = true
		}
	}
	return out
}

func (g *Guard) imageInScope(img any) bool {
	m, ok := img.(map[string]any)
	if !ok {
		return false
	}
	images := g.allImages()
	for _, key := range []string{"RepoTags", "RepoDigests"} {
		list, _ := m[key].([]any)
		for _, r := range list {
			s, ok := r.(string)
			if !ok {
				continue
			}
			s, _, _ = strings.Cut(s, "@")
			if repo := repoOrNone(s); repo != "" && images[repo] {
				return true
			}
		}
	}
	return false
}

func (g *Guard) containerInScope(c any) bool {
	m, ok := c.(map[string]any)
	if !ok {
		return false
	}
	names, _ := m["Names"].([]any)
	for _, n := range names {
		s, ok := n.(string)
		if ok && strings.HasPrefix(s, "/") && g.cur().byName[s[1:]] != nil {
			return true
		}
	}
	return false
}

// networkView is a scope network with only the scope's containers listed, or nil.
func (g *Guard) networkView(net any) map[string]any {
	m, ok := net.(map[string]any)
	if !ok {
		return nil
	}
	name, _ := m["Name"].(string)
	if !g.allNetworks()[name] {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		if k != "Services" {
			out[k] = v
		}
	}
	if cs, ok := out["Containers"].(map[string]any); ok {
		kept := map[string]any{}
		for id, c := range cs {
			if cm, ok := c.(map[string]any); ok {
				if n, _ := cm["Name"].(string); g.cur().byName[n] != nil {
					kept[id] = c
				}
			}
		}
		out["Containers"] = kept
	}
	return out
}

func (g *Guard) volumeInScope(vol any) bool {
	m, ok := vol.(map[string]any)
	if !ok {
		return false
	}
	name, ok := m["Name"].(string)
	return ok && g.anyVolumeOK(name)
}

func (g *Guard) anyVolumeOK(name string) bool {
	for _, s := range g.cur().scopes {
		if s.volumeOK(name) {
			return true
		}
	}
	return false
}

// infoKeep is /info reduced to what compose and the CLI read: versions and
// platform (API negotiation, platform defaults), the storage driver and its
// status (compose looks for the containerd image store there), cgroup
// details, the default runtime and log driver, the security options, the
// index address, and a swarm that is "inactive" (so compose never takes the
// swarm paths). Host name, id, counts of other containers and images, paths,
// proxies, labels, registry mirrors, plugins and memory are left out.
var infoKeep = []string{"ServerVersion", "OSType", "Architecture", "KernelVersion", "Driver", "DriverStatus", "CgroupDriver",
	"CgroupVersion", "DefaultRuntime", "LoggingDriver", "SecurityOptions", "IndexServerAddress", "Isolation", "ExperimentalBuild"}

func redactInfo(doc any) map[string]any {
	out := map[string]any{}
	if m, ok := doc.(map[string]any); ok {
		for _, k := range infoKeep {
			if v, ok := m[k]; ok {
				out[k] = v
			}
		}
	}
	out["Swarm"] = map[string]any{"LocalNodeState": "inactive", "NodeID": "", "NodeAddr": "", "ControlAvailable": false, "Error": "", "RemoteManagers": nil}
	out["Warnings"] = []any{}
	return out
}

func filterList(doc any, keep func(any) bool) []any {
	out := []any{}
	list, _ := doc.([]any)
	for _, x := range list {
		if keep(x) {
			out = append(out, x)
		}
	}
	return out
}

// ---- scope lookups (through the engine)

func (g *Guard) scopeOf(ref string) *Scope {
	info := g.inspect(ref)
	if info == nil {
		return nil
	}
	name, ok := info["Name"].(string)
	if !ok {
		return nil
	}
	return g.cur().byName[strings.TrimLeft(name, "/")]
}

var tmpNameRe = regexp.MustCompile(`^([0-9a-f]{12})_(.+)$`)

// tmpScopeOf is the scope of a container holding compose's temporary recreate
// name "<first 12 of the old id>_<scope name>".
func (g *Guard) tmpScopeOf(ref string) *Scope {
	info := g.inspect(ref)
	if info == nil {
		return nil
	}
	name, ok := info["Name"].(string)
	if !ok {
		return nil
	}
	m := tmpNameRe.FindStringSubmatch(strings.TrimLeft(name, "/"))
	if m == nil {
		return nil
	}
	return g.cur().byName[m[2]]
}

// recreateCopy is true for the container compose created under its temporary
// name "<old id12>_<scope>" while the scope's current container still has that id.
func (g *Guard) recreateCopy(ref string) bool {
	info := g.inspect(ref)
	if info == nil {
		return false
	}
	name, _ := info["Name"].(string)
	m := tmpNameRe.FindStringSubmatch(strings.TrimLeft(name, "/"))
	if m == nil || g.cur().byName[m[2]] == nil {
		return false
	}
	old := g.inspect(m[2])
	if old == nil {
		return false
	}
	id, _ := old["Id"].(string)
	oldName, _ := old["Name"].(string)
	return strings.HasPrefix(id, m[1]) && strings.TrimLeft(oldName, "/") == m[2]
}

var netIDRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// networkOK is a scope network by name, or by its full id (looked up here:
// the name is what the scope lists).
func (g *Guard) networkOK(s *Scope, net any) bool {
	return g.scopeNetwork(s, net) != ""
}

// scopeNetwork resolves net (a name, or a full network id) to the scope
// network's name, or "" when the scope may not use it.
func (g *Guard) scopeNetwork(s *Scope, net any) string {
	name, ok := net.(string)
	if !ok || name == "" {
		return ""
	}
	if s.networkOK(name) {
		return name
	}
	if netIDRe.MatchString(name) {
		info, _ := g.engineJSON("/networks/" + name).(map[string]any)
		if info == nil {
			return ""
		}
		n, _ := info["Name"].(string)
		if info["Id"] == name && n != "" && s.networkOK(n) {
			return n
		}
	}
	return ""
}

// ---- create

func (g *Guard) checkCreate(q query, body any) error {
	if err := q.onlyParams([]string{"name", "platform"}, "create"); err != nil {
		return err
	}
	name, err := q.one("name", "")
	if err != nil {
		return err
	}
	scope := g.cur().byName[name]
	if m := tmpNameRe.FindStringSubmatch(name); scope == nil && m != nil && g.cur().byName[m[2]] != nil {
		// compose's recreate: the replacement is made as <old id12>_<scope> and renamed once the old one is gone.
		// Only while the current container of that name really has that id (and is that container, not an id prefix).
		old := g.inspect(m[2])
		if old != nil {
			id, _ := old["Id"].(string)
			oldName, _ := old["Name"].(string)
			if strings.HasPrefix(id, m[1]) && strings.TrimLeft(oldName, "/") == m[2] {
				scope = g.cur().byName[m[2]]
			}
		}
	}
	if scope == nil {
		return deny(403, "only %s may be created here", strings.Join(g.scopeNames(), ", "))
	}
	if _, ok := body.(map[string]any); !ok {
		return deny(400, "bad create body")
	}
	obj, err := checkObject(body, configRules(scope), "Config")
	if err != nil {
		return err
	}
	image := obj["Image"]
	if repo := repoOrNone(image); repo == "" || !scope.Images[repo] {
		return deny(403, "image %s is not allowed for %s", quote(image), quote(name))
	}
	host, err := checkObject(obj["HostConfig"], hostConfigRules(scope), "HostConfig")
	if err != nil {
		return err
	}
	mode := host["NetworkMode"]
	if mode == nil || mode == "" {
		mode = "default"
	}
	if !g.networkOK(scope, mode) {
		return deny(403, "network mode %s is not allowed for %s", quote(mode), quote(name))
	}
	endpoints := func(v any, where string) error {
		if v == nil {
			return nil
		}
		m, ok := v.(map[string]any)
		if !ok {
			return deny(400, "%s must be an object", where)
		}
		nets := make([]string, 0, len(m))
		for n := range m {
			nets = append(nets, n)
		}
		sort.Strings(nets)
		for _, n := range nets {
			resolved := g.scopeNetwork(scope, n)
			if resolved == "" {
				return deny(403, "%s may not join network %s", quote(name), quote(n))
			}
			if _, err := checkObject(m[n], endpointRules(scope, resolved), where+"["+n+"]"); err != nil {
				return err
			}
		}
		return nil
	}
	_, err = checkObject(obj["NetworkingConfig"], map[string]rule{"EndpointsConfig": endpoints}, "NetworkingConfig")
	return err
}

func (g *Guard) scopeNames() []string {
	names := make([]string, 0, len(g.cur().scopes))
	for _, s := range g.cur().scopes {
		names = append(names, s.Name)
	}
	sort.Strings(names)
	return names
}

// checkPull allows only the scope images, by tag or digest: never all tags
// (no tag), never an import (fromSrc / repo / changes).
func (g *Guard) checkPull(q query) error {
	if err := q.onlyParams([]string{"fromImage", "tag", "platform"}, "pull"); err != nil {
		return err
	}
	ref, err := q.one("fromImage", "")
	if err != nil {
		return err
	}
	tag, err := q.one("tag", "")
	if err != nil {
		return err
	}
	repo, ownTag, ownDigest, perr := parseRef(ref)
	if perr != nil {
		return deny(403, "pull not allowed: not an image reference")
	}
	if tag != "" && (ownTag != "" || ownDigest != "" || !(tagRe.MatchString(tag) || digestRe.MatchString(tag))) {
		return deny(403, "pull not allowed: bad tag")
	}
	if tag == "" && ownTag == "" && ownDigest == "" {
		return deny(403, "pull not allowed: name a tag or digest (pulling every tag is refused)")
	}
	if !g.allImages()[repo] {
		return deny(403, "pull not allowed: %s is not a scope image", quote(repo))
	}
	return nil
}

// ---- routing

var (
	imageInspectRe  = regexp.MustCompile(`^/images/.+/json$`)
	distributionRe  = regexp.MustCompile(`^/distribution/(.+)/json$`)
	networkRe       = regexp.MustCompile(`^/networks/([^/]+)$`)
	volumeRe        = regexp.MustCompile(`^/volumes/([^/]+)$`)
	pluginRe        = regexp.MustCompile(`^/plugins/[^/]+/json$`)
	containerReadRe = regexp.MustCompile(`^/containers/([^/]+)/(json|logs|stats|top)$`)
	execInspectRe   = regexp.MustCompile(`^/exec/([^/]+)/json$`)
	containerPostRe = regexp.MustCompile(`^/containers/([^/]+)/(start|stop|restart|exec)$`)
	renameRe        = regexp.MustCompile(`^/containers/([^/]+)/rename$`)
	execPostRe      = regexp.MustCompile(`^/exec/([^/]+)/(start|resize)$`)
	containerRe     = regexp.MustCompile(`^/containers/([^/]+)$`)
	psArgsRe        = regexp.MustCompile(`^[A-Za-z -]*$`)
)

func noSuchContainer(ref string) error { return deny(404, "No such container: %s", quote(ref)) }

// check decides one request. A nil hook with a nil error passes it on as it
// is. Any error is a refusal; anything check does not foresee is one too.
func (g *Guard) check(method, path string, q query, body any) (*hook, error) {
	switch method {
	case "HEAD":
		if path == "/_ping" {
			return nil, nil
		}
		return nil, deny(405, "method not allowed")
	case "GET":
		return g.checkGet(path, q)
	case "POST":
		return g.checkPost(path, q, body)
	case "DELETE": // a stopped scope container (or compose's temporary copy), never its volumes or links
		m := containerRe.FindStringSubmatch(path)
		if m == nil {
			return nil, deny(403, "delete not allowed")
		}
		if g.scopeOf(m[1]) == nil && g.tmpScopeOf(m[1]) == nil {
			return nil, noSuchContainer(m[1])
		}
		if err := q.onlyParams([]string{"v", "force", "link"}, "remove"); err != nil {
			return nil, err
		}
		for _, key := range []string{"v", "link"} {
			v, err := q.one(key, "0")
			if err != nil {
				return nil, err
			}
			if v != "0" && v != "false" {
				return nil, deny(403, "remove: %s is not allowed", key)
			}
		}
		info := g.inspect(m[1])
		if info == nil {
			return nil, deny(403, "could not inspect the container")
		}
		state, _ := info["State"].(map[string]any)
		if running, _ := state["Running"].(bool); running || state == nil {
			return nil, deny(403, "stop the container before removing it")
		}
		return nil, nil
	}
	return nil, deny(405, "method not allowed")
}

func (g *Guard) checkGet(path string, q query) (*hook, error) {
	switch path {
	case "/_ping", "/version":
		return nil, nil
	case "/info":
		return jsonRewrite(func(doc any) (int, any) { return 200, redactInfo(doc) }), nil
	case "/containers/json":
		return jsonRewrite(func(doc any) (int, any) { return 200, filterList(doc, g.containerInScope) }), nil
	case "/images/json":
		return jsonRewrite(func(doc any) (int, any) { return 200, filterList(doc, g.imageInScope) }), nil
	case "/networks":
		return jsonRewrite(func(doc any) (int, any) {
			out := []any{}
			list, _ := doc.([]any)
			for _, n := range list {
				if v := g.networkView(n); v != nil {
					out = append(out, v)
				}
			}
			return 200, out
		}), nil
	case "/volumes":
		return jsonRewrite(func(doc any) (int, any) {
			vols := []any{}
			if m, ok := doc.(map[string]any); ok {
				list, _ := m["Volumes"].([]any)
				vols = filterList(list, g.volumeInScope)
			}
			return 200, map[string]any{"Volumes": vols, "Warnings": nil}
		}), nil
	}
	if imageInspectRe.MatchString(path) {
		return jsonRewrite(func(doc any) (int, any) {
			if g.imageInScope(doc) {
				return 200, doc
			}
			return notFound("No such image")
		}), nil
	}
	if m := distributionRe.FindStringSubmatch(path); m != nil {
		if !g.allImages()[repoOrNone(m[1])] {
			return nil, deny(403, "only scope images")
		}
		return nil, nil
	}
	if m := networkRe.FindStringSubmatch(path); m != nil {
		return jsonRewrite(func(doc any) (int, any) {
			if v := g.networkView(doc); v != nil {
				return 200, v
			}
			return notFound("network " + m[1] + " not found")
		}), nil
	}
	if m := volumeRe.FindStringSubmatch(path); m != nil {
		if !g.anyVolumeOK(m[1]) {
			return nil, deny(404, "no such volume") // 404, not 403: `docker inspect NAME` only moves on past "not found"
		}
		return jsonRewrite(func(doc any) (int, any) {
			if g.volumeInScope(doc) {
				return 200, doc
			}
			return notFound("no such volume")
		}), nil
	}
	if pluginRe.MatchString(path) {
		return nil, deny(404, "plugin not found")
	}
	if m := containerReadRe.FindStringSubmatch(path); m != nil {
		// missing and out-of-scope look the same: neither is there for this client. The one extra thing visible, to inspect
		// only, is compose's replacement while it is being recreated (compose reads it back right after creating it).
		if g.scopeOf(m[1]) == nil && !(m[2] == "json" && g.recreateCopy(m[1])) {
			return nil, noSuchContainer(m[1])
		}
		if m[2] == "top" {
			args, err := q.one("ps_args", "")
			if err != nil {
				return nil, err
			}
			if !psArgsRe.MatchString(args) {
				return nil, deny(403, "ps_args may only hold ps options")
			}
		}
		return nil, nil
	}
	if m := execInspectRe.FindStringSubmatch(path); m != nil && g.knownExec(m[1]) {
		return nil, nil
	}
	return nil, deny(403, "read not allowed")
}

func (g *Guard) checkPost(path string, q query, body any) (*hook, error) {
	if path == "/containers/create" {
		return nil, g.checkCreate(q, body)
	}
	if path == "/images/create" {
		return nil, g.checkPull(q)
	}
	if m := containerPostRe.FindStringSubmatch(path); m != nil {
		scope := g.scopeOf(m[1])
		if scope == nil {
			return nil, noSuchContainer(m[1])
		}
		switch m[2] {
		case "start":
			return nil, q.onlyParams([]string{"detachKeys"}, "start") // never checkpoint / checkpoint-dir
		case "stop", "restart":
			return nil, q.onlyParams([]string{"t", "signal"}, m[2])
		}
		if !scope.Exec {
			return nil, deny(403, "exec is not enabled for %s", scope.Name)
		}
		if err := q.onlyParams(nil, "exec"); err != nil {
			return nil, err
		}
		if _, ok := body.(map[string]any); !ok {
			return nil, deny(400, "bad exec body")
		}
		if m, err := checkObject(body, execBodyRules, "Exec"); err != nil {
			return nil, err
		} else if _, has := m["Cmd"]; !has { // stricter than the Python guard: an exec without a command is not a request to forward
			return nil, deny(403, "Exec.Cmd is required")
		}
		return &hook{remember: func(data []byte) {
			var out struct{ Id string }
			if json.Unmarshal(data, &out) == nil && out.Id != "" {
				g.rememberExec(out.Id)
			}
		}}, nil
	}
	if m := renameRe.FindStringSubmatch(path); m != nil { // only the last step of compose's recreate: <old id12>_<scope> -> <scope>
		scope := g.tmpScopeOf(m[1])
		if scope == nil {
			return nil, noSuchContainer(m[1])
		}
		if err := q.onlyParams([]string{"name"}, "rename"); err != nil {
			return nil, err
		}
		n, err := q.one("name", "")
		if err != nil {
			return nil, err
		}
		if n != scope.Name {
			return nil, deny(403, "rename is only allowed as part of a recreate")
		}
		return nil, nil
	}
	if m := execPostRe.FindStringSubmatch(path); m != nil && g.knownExec(m[1]) {
		if m[2] == "resize" {
			return nil, q.onlyParams([]string{"h", "w"}, "resize")
		}
		if err := q.onlyParams(nil, "exec start"); err != nil {
			return nil, err
		}
		if body == nil {
			body = map[string]any{}
		}
		_, err := checkObject(body, execStartRules, "ExecStart")
		return nil, err
	}
	return nil, deny(403, "write not allowed")
}

// ---- exec ids

// execsKept bounds how many exec ids created through the guard are remembered.
const execsKept = 256

func (g *Guard) rememberExec(id string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.execSet[id] {
		return
	}
	g.execSet[id] = true
	g.execOrder = append(g.execOrder, id)
	for len(g.execOrder) > execsKept {
		delete(g.execSet, g.execOrder[0])
		g.execOrder = g.execOrder[1:]
	}
}

func (g *Guard) knownExec(id string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.execSet[id]
}

var errTooLarge = errors.New("engine answer is too large")
