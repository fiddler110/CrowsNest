package managed

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/dockerguard"
	"github.com/fiddler110/crowsnest/internal/modules"
	"gopkg.in/yaml.v3"
)

const mcRef = "itzg/minecraft-server:latest"

var mcReq = Request{ID: "minecraft", Module: "minecraft", Options: map[string]string{"eula": "TRUE"},
	Secrets: map[string]string{"rcon_password": "x"}}

func info(t *testing.T, m *Manager, id string) Info {
	t.Helper()
	for _, in := range m.List() {
		if in.ID == id {
			return in
		}
	}
	t.Fatalf("%s not listed", id)
	return Info{}
}

func (f *fakeDocker) lastCreate() (string, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.created) == 0 {
		return "", 0
	}
	return f.created[len(f.created)-1].Image, len(f.created)
}

func (f *fakeDocker) point(ref, digest string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.digests[ref] = digest
}

func TestEnablePinsTheDigest(t *testing.T) {
	m, fd := newManager(t)
	if err := m.Enable(mcReq); err != nil {
		t.Fatal(err)
	}
	waitState(t, m, "minecraft", StateReady)
	d1 := defaultDigest(mcRef)
	if img, n := fd.lastCreate(); n != 1 || img != "itzg/minecraft-server@"+d1 {
		t.Fatalf("created %d, image %q: want the pinned digest", n, img)
	}
	in := info(t, m, "minecraft")
	if in.Digest != d1 || in.Image != mcRef || in.PreviousDigest != "" {
		t.Errorf("list: %+v", in)
	}
	// stored in games.json, and the rendered compose service names the digest
	var st stateFile
	b, _ := os.ReadFile(filepath.Join(m.Dir, "games.json"))
	if err := json.Unmarshal(b, &st); err != nil || st.Games[0].Digest != d1 || st.Games[0].Image != mcRef {
		t.Fatalf("games.json: %s %v", b, err)
	}
	svc, _ := yaml.Marshal(m.find("minecraft").rendered.Service)
	if !strings.Contains(string(svc), "image: itzg/minecraft-server@"+d1) {
		t.Errorf("rendered service:\n%s", svc)
	}
	// the scope still names the repository only
	if sc, _ := os.ReadFile(filepath.Join(m.Dir, "scopes.json")); strings.Contains(string(sc), "sha256") {
		t.Errorf("scopes.json carries a digest: %s", sc)
	}
	// a restart keeps the pin
	m2, fd2 := newManagerAt(t, m)
	if in := info(t, m2, "minecraft"); in.Digest != d1 {
		t.Errorf("after restart: %+v", in)
	}
	// an edit recreates on the pinned digest, without following the tag
	fd2.point(mcRef, "sha256:"+strings.Repeat("9", 64))
	if err := m2.Update(Request{ID: "minecraft", Options: map[string]string{"eula": "TRUE", "motd": "x"}}); err != nil {
		t.Fatal(err)
	}
	waitState(t, m2, "minecraft", StateReady)
	if img, _ := fd2.lastCreate(); img != "itzg/minecraft-server@"+d1 {
		t.Errorf("edit followed the tag: %q", img)
	}
}

func TestRefreshOnlyRecreatesForANewDigest(t *testing.T) {
	m, fd := newManager(t)
	if err := m.Enable(mcReq); err != nil {
		t.Fatal(err)
	}
	waitState(t, m, "minecraft", StateReady)
	d1, d2 := defaultDigest(mcRef), "sha256:"+strings.Repeat("2", 64)

	// nothing new upstream: pulled, but the container is left alone
	if err := m.Refresh("minecraft"); err != nil {
		t.Fatal(err)
	}
	waitState(t, m, "minecraft", StateReady)
	if _, n := fd.lastCreate(); n != 1 || len(fd.removed) != 0 || len(fd.pulled) != 2 {
		t.Errorf("no-op refresh: creates %d, removed %v, pulled %v", n, fd.removed, fd.pulled)
	}
	if in := info(t, m, "minecraft"); in.Refresh != RefreshUpToDate || in.Digest != d1 || in.PreviousDigest != "" {
		t.Errorf("no-op refresh: %+v", in)
	}
	if _, ok := m.Registry.Get("minecraft"); !ok {
		t.Error("game left the dashboard after a no-op refresh")
	}

	// a push to the tag: recreated on the new digest, the old one kept for a rollback
	fd.point(mcRef, d2)
	if err := m.Refresh("minecraft"); err != nil {
		t.Fatal(err)
	}
	waitState(t, m, "minecraft", StateReady)
	if img, n := fd.lastCreate(); n != 2 || img != "itzg/minecraft-server@"+d2 {
		t.Errorf("refresh: creates %d, image %q", n, img)
	}
	if in := info(t, m, "minecraft"); in.Refresh != RefreshUpdated || in.Digest != d2 || in.PreviousDigest != d1 {
		t.Errorf("refresh: %+v", in)
	}
}

func TestRollbackSwapsDigests(t *testing.T) {
	m, fd := newManager(t)
	if err := m.Enable(mcReq); err != nil {
		t.Fatal(err)
	}
	waitState(t, m, "minecraft", StateReady)
	if err := m.Rollback("minecraft"); !errors.Is(err, ErrNoPrevious) {
		t.Errorf("rollback with nothing before: %v", err)
	}
	d1, d2 := defaultDigest(mcRef), "sha256:"+strings.Repeat("2", 64)
	fd.point(mcRef, d2)
	if err := m.Refresh("minecraft"); err != nil {
		t.Fatal(err)
	}
	waitState(t, m, "minecraft", StateReady)

	fd.mu.Lock()
	fd.running["minecraft"] = true
	fd.mu.Unlock()
	if err := m.Rollback("minecraft"); err == nil {
		t.Error("rolled back a running game")
	}
	fd.mu.Lock()
	fd.running["minecraft"] = false
	fd.mu.Unlock()
	m.Busy = func(id string) bool { return id == "minecraft" }
	if err := m.Rollback("minecraft"); !errors.Is(err, errBusy) {
		t.Errorf("rolled back a game that is starting or stopping: %v", err)
	}
	m.Busy = nil
	if in := info(t, m, "minecraft"); in.Digest != d2 || in.PreviousDigest != d1 {
		t.Fatalf("a refused rollback changed the pins: %+v", in)
	}

	if err := m.Rollback("minecraft"); err != nil {
		t.Fatal(err)
	}
	waitState(t, m, "minecraft", StateReady)
	if img, n := fd.lastCreate(); n != 3 || img != "itzg/minecraft-server@"+d1 {
		t.Errorf("rollback: creates %d, image %q", n, img)
	}
	if in := info(t, m, "minecraft"); in.Digest != d1 || in.PreviousDigest != d2 {
		t.Errorf("rollback did not swap: %+v", in)
	}
	if _, ok := m.Registry.Get("minecraft"); !ok {
		t.Error("game missing from the dashboard after a rollback")
	}
	// and back again
	if err := m.Rollback("minecraft"); err != nil {
		t.Fatal(err)
	}
	waitState(t, m, "minecraft", StateReady)
	if img, _ := fd.lastCreate(); img != "itzg/minecraft-server@"+d2 {
		t.Errorf("second rollback: %q", img)
	}
}

// A game installed before pinning keeps running as it is, and is pinned (with the image it had as the
// rollback target) on its next image update.
func TestUnpinnedInstallIsPinnedOnRefresh(t *testing.T) {
	m, _ := newManager(t)
	if err := m.Enable(mcReq); err != nil {
		t.Fatal(err)
	}
	waitState(t, m, "minecraft", StateReady)
	// strip the pin, as games.json looked before this change
	path := filepath.Join(m.Dir, "games.json")
	b, _ := os.ReadFile(path)
	var raw map[string][]map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	for _, g := range raw["games"] {
		delete(g, "digest")
		delete(g, "image")
	}
	b, _ = json.Marshal(raw)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}

	m2, fd2 := newManagerAt(t, m)
	if in := info(t, m2, "minecraft"); in.Digest != "" || in.Image != mcRef {
		t.Fatalf("legacy install: %+v", in)
	}
	if _, ok := m2.Registry.Get("minecraft"); !ok {
		t.Fatal("legacy install not on the dashboard")
	}
	if err := m2.Rollback("minecraft"); !errors.Is(err, ErrNoPrevious) {
		t.Errorf("legacy rollback: %v", err)
	}
	old, d2 := defaultDigest(mcRef), "sha256:"+strings.Repeat("2", 64)
	// The fake answers the pre-pull inspect with the old digest, then the tag moves.
	fd2.point(mcRef, old)
	if err := m2.Refresh("minecraft"); err != nil {
		t.Fatal(err)
	}
	waitState(t, m2, "minecraft", StateReady)
	in := info(t, m2, "minecraft")
	if img, n := fd2.lastCreate(); n != 1 || img != "itzg/minecraft-server@"+old || in.Digest != old || in.Refresh != RefreshUpToDate {
		t.Errorf("pinning the same image: creates %d image %q, %+v", n, img, in)
	}
	fd2.point(mcRef, d2)
	if err := m2.Refresh("minecraft"); err != nil {
		t.Fatal(err)
	}
	waitState(t, m2, "minecraft", StateReady)
	if in := info(t, m2, "minecraft"); in.Digest != d2 || in.PreviousDigest != old || in.Refresh != RefreshUpdated {
		t.Errorf("after an upstream change: %+v", in)
	}
}

// pin_digests is shown, kept when a save leaves it out, and changed only when a save sends it.
func TestPolicyKeepsPinDigests(t *testing.T) {
	m, _ := newManager(t)
	if err := os.WriteFile(m.PolicyFile, []byte(policy+"pin_digests: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m.PolicyEditable = true
	st, err := m.Policy()
	if err != nil || st.Policy.PinDigests == nil || !*st.Policy.PinDigests {
		t.Fatalf("not shown: %+v %v", st.Policy, err)
	}
	doc := st.Policy
	doc.PinDigests = nil // an older form that does not know the setting
	doc.Names = append(doc.Names, "pal-*")
	if err := m.SetPolicy(doc); err != nil {
		t.Fatal(err)
	}
	if again, _ := m.Policy(); again.Policy.PinDigests == nil || !*again.Policy.PinDigests {
		t.Errorf("a save without it dropped pin_digests: %+v", again.Policy)
	}
	off := false
	doc.PinDigests = &off
	if err := m.SetPolicy(doc); err != nil {
		t.Fatal(err)
	}
	if again, _ := m.Policy(); *again.Policy.PinDigests {
		t.Error("turning pin_digests off did not stick")
	}
}

// Through the real guard, under pin_digests, with the panel's own client: the tag pull, the digest lookup
// and the create by digest pass; a create by tag is refused.
func TestPinnedCreateThroughRealGuard(t *testing.T) {
	const d = "sha256:4242424242424242424242424242424242424242424242424242424242424242"
	sock := filepath.Join(t.TempDir(), "engine.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ver := regexp.MustCompile(`^/v[0-9.]+`)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("API-Version", "1.47")
		switch p := ver.ReplaceAllString(r.URL.Path, ""); {
		case p == "/_ping":
			_, _ = w.Write([]byte("OK"))
		case p == "/containers/create":
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"Id":"abc","Warnings":[]}`))
		case p == "/images/itzg/minecraft-server:latest/json":
			_, _ = w.Write([]byte(`{"Id":"sha256:` + strings.Repeat("f", 64) + `","RepoTags":["itzg/minecraft-server:latest"],"RepoDigests":["itzg/minecraft-server@` + d + `"]}`))
		default:
			_, _ = w.Write([]byte(`{"status":"done"}` + "\n"))
		}
	})}
	go srv.Serve(l)
	defer srv.Close()

	m, _ := newManager(t)
	if err := os.WriteFile(m.PolicyFile, []byte(policy+"pin_digests: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	g, mf, err := m.validate(mcReq, false)
	if err != nil {
		t.Fatal(err)
	}
	rd, err := m.renderAndFit(g, mf)
	if err != nil {
		t.Fatal(err)
	}
	js, _ := modules.ScopesJSON([]*modules.Rendered{rd})
	scopesFile := filepath.Join(t.TempDir(), "scopes.json")
	if err := os.WriteFile(scopesFile, js, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := dockerguard.Sources{ManagedFile: scopesFile, PolicyFile: m.PolicyFile}.Load()
	if err != nil || res.Managed != 1 {
		t.Fatalf("load: %+v %v", res, err)
	}
	guard := dockerguard.New(sock, res.Scopes)
	gl, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go guard.ServeContext(ctx, gl)
	client := &dockerctl.Client{Host: "tcp://" + gl.Addr().String()}
	m.Docker = client

	if err := client.Pull(ctx, rd.Ref()); err != nil {
		t.Fatalf("pull by tag: %v", err)
	}
	got, err := m.digestOf(ctx, rd.Ref(), rd.Repo)
	if err != nil || got != d {
		t.Fatalf("digest through the guard: %q %v", got, err)
	}
	byTag, _ := rd.Spec(func(string) (string, bool) { return "", false })
	if err := client.Create(ctx, byTag); !dockerctl.IsDenied(err) {
		t.Errorf("create by tag under pin_digests: want a denial, got %v", err)
	}
	rd.Pin(got)
	byDigest, _ := rd.Spec(func(string) (string, bool) { return "", false })
	if err := client.Create(ctx, byDigest); err != nil {
		t.Errorf("create by digest: %v", err)
	}
}
