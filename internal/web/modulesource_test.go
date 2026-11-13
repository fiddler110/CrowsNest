package web

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fiddler110/crowsnest/internal/auth"
	"github.com/fiddler110/crowsnest/internal/modules"
)

type sourceEnv struct {
	h      *testHarness
	srv    *httptest.Server
	body   []byte
	dir    string
	signed *bool
	seed   *string // the key the test server signs with
}

func newSourceEnv(t *testing.T) *sourceEnv {
	t.Helper()
	h := newHarness(t, nil)
	hash, _ := auth.HashPassword("s3cret-pw")
	h.App.Auth.Sessions.Users = auth.Users{"tester": {Role: auth.RoleAdmin, Hash: hash}}
	h.App.Auth.Users = h.App.Auth.Sessions.Users
	h.App.Managed = &fakeManaged{}

	seed, pub, _ := modules.GenerateKey()
	_ = seed
	keys, err := modules.ParseTrustedKeys([]modules.TrustedKey{{Name: "publisher", Key: pub}})
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join("..", "..", "docs", "examples", "mygame", "module.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	signed := true
	e := &sourceEnv{signed: &signed, seed: &seed}
	e.body = body
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/mygame/module.yaml":
			w.Write(e.body)
		case "/index.json":
			fmt.Fprintf(w, `{"modules":[{"id":"mygame","name":"My game","url":"https://%s/mygame/module.yaml","version":1},{"id":"other","url":"https://%s/other/module.yaml"},{"id":"palworld","url":"https://%s/p.yaml"}]}`, r.Host, r.Host, r.Host)
		case "/mygame/module.yaml.sig":
			if signed {
				sig, _ := modules.Sign(seed, e.body) // always signs what is served now
				w.Write(sig)
			} else {
				http.NotFound(w, r)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	e.h, e.srv, e.dir = h, srv, t.TempDir()
	h.App.Modules = modules.Bundled()
	h.App.ModulesDir = e.dir
	h.App.TrustedKeys = keys
	h.App.CatalogueURL = srv.URL + "/index.json"
	h.App.ModuleClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} // #nosec G402 -- test server
	return e
}

func (e *sourceEnv) post(path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	e.h.mux().ServeHTTP(rec, e.h.authedReq("POST", path, []byte(body)))
	return rec
}

func (e *sourceEnv) url() string { return e.srv.URL + "/mygame/module.yaml" }

func TestRemoteModule_PreviewInstallAndRemove(t *testing.T) {
	e := newSourceEnv(t)
	rec := e.post("/api/managed/modules/remote/preview", `{"url":"`+e.url()+`"}`)
	if rec.Code != 200 {
		t.Fatalf("preview = %d %s", rec.Code, rec.Body)
	}
	var raw map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &raw)
	id, sum := raw["id"].(string), raw["sha256"].(string)
	if id == "" || len(sum) != 64 || raw["signed_by"] != "publisher" || len(raw["review"].([]any)) == 0 {
		t.Fatalf("preview body = %s", rec.Body)
	}
	if _, ok := e.h.App.Modules.Manifest(id); ok {
		t.Fatal("previewing installed the module")
	}

	// A wrong password installs nothing.
	if rec := e.post("/api/managed/modules/remote/install", `{"url":"`+e.url()+`","sha256":"`+sum+`","password":"nope"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("wrong password = %d", rec.Code)
	}
	if _, ok := e.h.App.Modules.Manifest(id); ok {
		t.Fatal("installed with a wrong password")
	}
	// The preview's hash must match what is downloaded now.
	if rec := e.post("/api/managed/modules/remote/install", `{"url":"`+e.url()+`","sha256":"`+strings.Repeat("0", 64)+`","password":"s3cret-pw"}`); rec.Code != http.StatusConflict {
		t.Fatalf("changed module = %d %s", rec.Code, rec.Body)
	}
	if rec := e.post("/api/managed/modules/remote/install", `{"url":"`+e.url()+`","sha256":"`+sum+`","password":"s3cret-pw"}`); rec.Code != 200 {
		t.Fatalf("install = %d %s", rec.Code, rec.Body)
	}
	if _, ok := e.h.App.Modules.Manifest(id); !ok {
		t.Fatal("module not available after install")
	}
	lock, _ := modules.ReadLock(e.dir)
	if en, ok := lock.Find(id); !ok || en.SignedBy != "publisher" || en.SHA256 != sum {
		t.Fatalf("lock = %+v", lock)
	}
	// Installing it again is refused, not replaced.
	if rec := e.post("/api/managed/modules/remote/preview", `{"url":"`+e.url()+`"}`); rec.Code != http.StatusConflict {
		t.Errorf("preview of an installed module = %d", rec.Code)
	}

	// The list shows it.
	rec = httptest.NewRecorder()
	e.h.mux().ServeHTTP(rec, e.h.req("GET", "/api/managed/modules/sources", nil))
	var sv sourceView
	_ = json.Unmarshal(rec.Body.Bytes(), &sv)
	if !sv.Enabled || len(sv.Installed) != 1 || sv.Installed[0].SignedBy != "publisher" || sv.Keys[0].Name != "publisher" || len(sv.Keys[0].Modules) != 1 || len(sv.Keys[0].Fingerprint) != 16 {
		t.Fatalf("sources = %s", rec.Body)
	}

	// Remove needs the password too, and takes it out of the set and the lock.
	if rec := e.post("/api/managed/modules/remote/"+id+"/remove", `{"password":"nope"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("remove with a wrong password = %d", rec.Code)
	}
	if rec := e.post("/api/managed/modules/remote/"+id+"/remove", `{"password":"s3cret-pw"}`); rec.Code != http.StatusNoContent {
		t.Fatalf("remove = %d %s", rec.Code, rec.Body)
	}
	if _, ok := e.h.App.Modules.Manifest(id); ok {
		t.Error("module still loaded after removal")
	}
	if l, _ := modules.ReadLock(e.dir); len(l.Modules) != 0 {
		t.Errorf("lock after removal = %+v", l)
	}
	// A bundled module is not removable.
	if rec := e.post("/api/managed/modules/remote/palworld/remove", `{"password":"s3cret-pw"}`); rec.Code == http.StatusNoContent {
		t.Error("removed a bundled module")
	}
}

func TestRemoteModule_RefusesUnsignedAndBadURLs(t *testing.T) {
	e := newSourceEnv(t)
	*e.signed = false
	rec := e.post("/api/managed/modules/remote/preview", `{"url":"`+e.url()+`"}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "not signed") {
		t.Fatalf("unsigned = %d %s", rec.Code, rec.Body)
	}
	for _, u := range []string{"http://example.com/m.yaml", "file:///etc/passwd", "https://user:pw@example.com/m.yaml", "https://example.com/m.yaml?x=1", "ftp://x/y", ""} {
		if rec := e.post("/api/managed/modules/remote/preview", `{"url":"`+u+`"}`); rec.Code != http.StatusBadRequest {
			t.Errorf("url %q = %d", u, rec.Code)
		}
	}
	// Without the signature an install with a valid password still installs nothing.
	if rec := e.post("/api/managed/modules/remote/install", `{"url":"`+e.url()+`","sha256":"`+strings.Repeat("a", 64)+`","password":"s3cret-pw"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("unsigned install = %d", rec.Code)
	}
	if l, _ := modules.ReadLock(e.dir); len(l.Modules) != 0 {
		t.Error("an unsigned module was installed")
	}
}

func TestRemoteModule_OffWithoutKeysAndAdminOnly(t *testing.T) {
	e := newSourceEnv(t)
	e.h.App.TrustedKeys = nil
	if rec := e.post("/api/managed/modules/remote/preview", `{"url":"`+e.url()+`"}`); rec.Code != http.StatusNotFound {
		t.Errorf("with no trusted keys = %d", rec.Code)
	}
	rec := httptest.NewRecorder()
	e.h.mux().ServeHTTP(rec, e.h.req("GET", "/api/managed/modules/sources", nil))
	if !strings.Contains(rec.Body.String(), `"enabled":false`) {
		t.Errorf("sources = %s", rec.Body)
	}
	e.h.App.Auth.Sessions.Users = auth.Users{"tester": {Role: auth.RolePlayer}}
	if rec := e.post("/api/managed/modules/remote/preview", `{"url":"x"}`); rec.Code != http.StatusForbidden {
		t.Errorf("a player previewing = %d", rec.Code)
	}
}

func TestRemoteModule_PanelDoesNotFetchPrivateAddresses(t *testing.T) {
	e := newSourceEnv(t)
	e.h.App.ModuleClient = nil                                                    // the real, address-checking client
	rec := e.post("/api/managed/modules/remote/preview", `{"url":"`+e.url()+`"}`) // a test server on loopback
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "private") {
		t.Fatalf("loopback fetch = %d %s", rec.Code, rec.Body)
	}
}

func TestRemoteModule_UpdateShowsWhatChangedAndNeedsPassword(t *testing.T) {
	e := newSourceEnv(t)
	install := func() string {
		rec := e.post("/api/managed/modules/remote/preview", `{"url":"`+e.url()+`"}`)
		var v map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &v)
		if rec := e.post("/api/managed/modules/remote/install", `{"url":"`+e.url()+`","sha256":"`+v["sha256"].(string)+`","password":"s3cret-pw"}`); rec.Code != 200 {
			t.Fatalf("install = %d %s", rec.Code, rec.Body)
		}
		return v["id"].(string)
	}
	id := install()
	up := "/api/managed/modules/remote/" + id + "/update"

	// Nothing new at the source.
	if rec := e.post(up+"/preview", `{}`); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"up_to_date":true`) {
		t.Fatalf("unchanged preview = %d %s", rec.Code, rec.Body)
	}

	// The publisher changes the module (a new port) and signs it.
	orig := string(e.body)
	e.body = []byte(strings.Replace(orig, "\n", "\n# a later version\n", 1))
	rec := e.post(up+"/preview", `{}`)
	var pv map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &pv)
	if rec.Code != 200 || pv["signed_by"] != "publisher" || pv["sha256"] == pv["was_sha256"] || pv["sha256"] == nil {
		t.Fatalf("preview = %d %s", rec.Code, rec.Body)
	}
	sum := pv["sha256"].(string)
	if rec := e.post(up, `{"sha256":"`+sum+`","password":"nope"}`); rec.Code != http.StatusForbidden {
		t.Errorf("wrong password = %d", rec.Code)
	}
	if rec := e.post(up, `{"sha256":"`+strings.Repeat("0", 64)+`","password":"s3cret-pw"}`); rec.Code != http.StatusConflict {
		t.Errorf("a hash other than the preview's = %d", rec.Code)
	}
	if l, _ := modules.ReadLock(e.dir); l.Modules[0].SHA256 == sum {
		t.Fatal("updated before being confirmed")
	}
	if rec := e.post(up, `{"sha256":"`+sum+`","password":"s3cret-pw"}`); rec.Code != 200 {
		t.Fatalf("update = %d %s", rec.Code, rec.Body)
	}
	if l, _ := modules.ReadLock(e.dir); l.Modules[0].SHA256 != sum || l.Modules[0].SignedBy != "publisher" {
		t.Errorf("lock after update = %+v", l.Modules[0])
	}
	if rec := e.post(up+"/preview", `{}`); !strings.Contains(rec.Body.String(), `"up_to_date":true`) {
		t.Errorf("after updating, preview = %s", rec.Body)
	}

	// An update that is no longer signed is refused outright.
	e.body = []byte(strings.Replace(orig, "\n", "\n# unsigned\n", 1))
	*e.signed = false
	if rec := e.post(up+"/preview", `{}`); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "not signed") {
		t.Errorf("unsigned update preview = %d %s", rec.Code, rec.Body)
	}
	// A module nobody installed from a source has no update.
	if rec := e.post("/api/managed/modules/remote/palworld/update/preview", `{}`); rec.Code != http.StatusNotFound {
		t.Errorf("update of a bundled module = %d", rec.Code)
	}
}

func TestRemoteModule_UpdateRefusesAnotherModuleID(t *testing.T) {
	e := newSourceEnv(t)
	rec := e.post("/api/managed/modules/remote/preview", `{"url":"`+e.url()+`"}`)
	var v map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	id := v["id"].(string)
	e.post("/api/managed/modules/remote/install", `{"url":"`+e.url()+`","sha256":"`+v["sha256"].(string)+`","password":"s3cret-pw"}`)
	e.body = []byte(strings.Replace(string(e.body), "id: "+id, "id: other-game", 1))
	rec = e.post("/api/managed/modules/remote/"+id+"/update/preview", `{}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("a source that now serves another id = %d %s", rec.Code, rec.Body)
	}
}

func TestModuleCatalogue(t *testing.T) {
	e := newSourceEnv(t)
	get := func() map[string]string {
		rec := httptest.NewRecorder()
		e.h.mux().ServeHTTP(rec, e.h.authedReq("GET", "/api/managed/modules/catalogue", nil))
		if rec.Code != 200 {
			t.Fatalf("catalogue = %d %s", rec.Code, rec.Body)
		}
		var v struct {
			Modules []struct{ ID, State string }
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &v)
		out := map[string]string{}
		for _, m := range v.Modules {
			out[m.ID] = m.State
		}
		return out
	}
	st := get()
	if st["mygame"] != "available" || st["other"] != "available" || st["palworld"] != "loaded" {
		t.Fatalf("states = %v", st)
	}
	rec := e.post("/api/managed/modules/remote/preview", `{"url":"`+e.url()+`"}`)
	var raw map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &raw)
	if rec := e.post("/api/managed/modules/remote/install", `{"url":"`+e.url()+`","sha256":"`+raw["sha256"].(string)+`","password":"s3cret-pw"}`); rec.Code != 200 {
		t.Fatalf("install = %d %s", rec.Code, rec.Body)
	}
	if st := get(); st["mygame"] != "installed" && st["mygame"] != "update" {
		t.Errorf("after install = %v", st)
	}
	// Not an admin, or no catalogue set.
	e.h.App.CatalogueURL = ""
	rec = httptest.NewRecorder()
	e.h.mux().ServeHTTP(rec, e.h.authedReq("GET", "/api/managed/modules/catalogue", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("no catalogue = %d", rec.Code)
	}
}

// A module whose signing key was removed from trusted_keys is flagged, and a trusted key may take it over.
func TestRemoteModule_KeyRotation(t *testing.T) {
	e := newSourceEnv(t)
	rec := e.post("/api/managed/modules/remote/preview", `{"url":"`+e.url()+`"}`)
	var raw map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &raw)
	if rec := e.post("/api/managed/modules/remote/install", `{"url":"`+e.url()+`","sha256":"`+raw["sha256"].(string)+`","password":"s3cret-pw"}`); rec.Code != 200 {
		t.Fatalf("install = %d %s", rec.Code, rec.Body)
	}
	id := raw["id"].(string)

	// The publisher moves to a new key; the operator trusts it and keeps the old one for now.
	seed2, pub2, _ := modules.GenerateKey()
	old := e.h.App.TrustedKeys
	both, _ := modules.ParseTrustedKeys([]modules.TrustedKey{{Name: "publisher", Key: old[0].Key}, {Name: "publisher-2", Key: pub2}})
	e.h.App.TrustedKeys = both
	*e.seed = seed2
	if rec := e.post("/api/managed/modules/remote/"+id+"/update/preview", `{}`); rec.Code != http.StatusConflict {
		t.Fatalf("new signer while the old key is trusted = %d %s", rec.Code, rec.Body)
	}

	// The operator drops the old key: the module is flagged and the new key may take over.
	e.h.App.TrustedKeys, _ = modules.ParseTrustedKeys([]modules.TrustedKey{{Name: "publisher-2", Key: pub2}})
	rec = httptest.NewRecorder()
	e.h.mux().ServeHTTP(rec, e.h.req("GET", "/api/managed/modules/sources", nil))
	var sv sourceView
	_ = json.Unmarshal(rec.Body.Bytes(), &sv)
	if len(sv.Installed) != 1 || !sv.Installed[0].SignerRetired {
		t.Fatalf("sources = %s", rec.Body)
	}
	e.body = append(e.body, []byte("\n# re-signed\n")...)
	rec = e.post("/api/managed/modules/remote/"+id+"/update/preview", `{}`)
	var pv map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &pv)
	if rec.Code != 200 || pv["rekeyed"] != true || pv["signed_by"] != "publisher-2" {
		t.Fatalf("preview = %d %s", rec.Code, rec.Body)
	}
	if rec := e.post("/api/managed/modules/remote/"+id+"/update", `{"sha256":"`+pv["sha256"].(string)+`","password":"s3cret-pw"}`); rec.Code != 200 {
		t.Fatalf("update = %d %s", rec.Code, rec.Body)
	}
	if l, _ := modules.ReadLock(e.dir); l.Modules[0].SignedBy != "publisher-2" {
		t.Errorf("lock = %+v", l)
	}
}
