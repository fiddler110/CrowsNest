package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fiddler110/crowsnest/internal/auth"
	"github.com/fiddler110/crowsnest/internal/modules"
)

// Installing a module from a URL from the dashboard. It is deliberately narrower than the command line:
//   - the module must carry a signature (<url>.sig) from a key the operator listed in config.yaml (a hash alone
//     is not enough from a browser);
//   - the panel fetches only https from public addresses (modules.PublicClient);
//   - the admin's password is asked again, and the install is of the exact bytes they were shown (sha256);
//   - it can only add a module, never replace one games already use (that is the command line's `update`).
// A module still has to fit the operator's policy before any game from it can run: installing it grants nothing.

func (a *App) remoteOn(w http.ResponseWriter) bool {
	if !a.managedOn(w) {
		return false
	}
	if a.Modules == nil || a.ModulesDir == "" || len(a.TrustedKeys) == 0 {
		http.Error(w, "installing modules from a source is not set up: it needs managed.dir, modules_dir and managed.trusted_keys in config.yaml", http.StatusNotFound)
		return false
	}
	return true
}

func (a *App) moduleClient() *http.Client {
	if a.ModuleClient != nil {
		return a.ModuleClient
	}
	return modules.PublicClient()
}

type sourceView struct {
	Enabled   bool           `json:"enabled"`
	Keys      []string       `json:"keys,omitempty"`
	Installed []installedMod `json:"installed"`
}

type installedMod struct {
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	Source      string `json:"source"`
	SignedBy    string `json:"signed_by,omitempty"`
	SHA256      string `json:"sha256"`
	InstalledAt string `json:"installed_at"`
	InUse       bool   `json:"in_use"`
}

func (a *App) handleModuleSources(w http.ResponseWriter, r *http.Request) {
	v := sourceView{Installed: []installedMod{}}
	if a.Managed == nil || a.Modules == nil || a.ModulesDir == "" || len(a.TrustedKeys) == 0 {
		writeJSON(w, http.StatusOK, v)
		return
	}
	v.Enabled = true
	for _, k := range a.TrustedKeys {
		v.Keys = append(v.Keys, k.Name)
	}
	lock, err := modules.ReadLock(a.ModulesDir)
	if err != nil {
		http.Error(w, "reading the module lock: "+err.Error(), http.StatusInternalServerError)
		return
	}
	inUse := map[string]bool{}
	for _, g := range a.Managed.List() {
		inUse[g.Module] = true
	}
	for _, e := range lock.Modules {
		im := installedMod{ID: e.ID, Source: e.Source, SignedBy: e.SignedBy, SHA256: e.SHA256, InstalledAt: e.InstalledAt.Format(time.RFC3339), InUse: inUse[e.ID]}
		if m, ok := a.Modules.Manifest(e.ID); ok {
			im.Name = m.Name
		}
		v.Installed = append(v.Installed, im)
	}
	writeJSON(w, http.StatusOK, v)
}

type remoteBody struct {
	URL      string `json:"url"`
	SHA256   string `json:"sha256"`
	Password string `json:"password"`
}

func readRemoteBody(w http.ResponseWriter, r *http.Request) (remoteBody, bool) {
	var b remoteBody
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		http.Error(w, "invalid request: "+err.Error(), http.StatusBadRequest)
		return b, false
	}
	b.URL = strings.TrimSpace(b.URL)
	return b, true
}

// fetchSignedModule downloads, verifies and parses the module at rawURL. The error text is safe to show.
func (a *App) fetchSignedModule(ctx context.Context, rawURL string) ([]byte, *modules.Manifest, string, error) {
	if u, err := url.Parse(rawURL); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, nil, "", errors.New("give a plain https:// address of a module.yaml (no password, query or fragment in it)")
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	body, by, err := modules.FetchSigned(ctx, rawURL, a.moduleClient(), a.TrustedKeys)
	if err != nil {
		if errors.Is(err, modules.ErrNotSigned) {
			return nil, nil, "", errors.New("this module is not signed by a key you trust (" + err.Error() + "). From the dashboard only signed modules can be installed; the command line can install one by its hash")
		}
		return nil, nil, "", err
	}
	m, err := modules.Parse(bytes.NewReader(body))
	if err != nil {
		return nil, nil, "", errors.New("the file is not a valid module: " + err.Error())
	}
	return body, m, by, nil
}

func (a *App) handleRemotePreview(w http.ResponseWriter, r *http.Request) {
	if !a.remoteOn(w) {
		return
	}
	b, ok := readRemoteBody(w, r)
	if !ok {
		return
	}
	body, m, by, err := a.fetchSignedModule(r.Context(), b.URL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if _, loaded := a.Modules.Manifest(m.ID); loaded {
		http.Error(w, "a module with the id "+m.ID+" is already loaded. Replacing one is done with `crowsnest module update` and a restart", http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": m.ID, "name": m.Name, "description": m.Description, "sha256": modules.Hash(body), "signed_by": by,
		"review": m.Review(),
	})
}

// stepUp asks for the signed-in admin's password again, like the other policy-widening actions.
func (a *App) stepUp(w http.ResponseWriter, r *http.Request, password, what string) bool {
	session, _ := auth.FromContext(r.Context())
	ok, have, limited := a.Auth.ConfirmPassword(r, session.Username, password)
	switch {
	case !have:
		http.Error(w, "set a password for your account first (Settings, Users): this asks for it, even if you sign in with Google", http.StatusForbidden)
	case limited:
		http.Error(w, "too many attempts, try again later", http.StatusTooManyRequests)
	case !ok:
		a.record(r, "", "refused to "+what+": wrong password")
		http.Error(w, "that password is not right", http.StatusForbidden)
	default:
		return true
	}
	return false
}

func (a *App) handleRemoteInstall(w http.ResponseWriter, r *http.Request) {
	if !a.remoteOn(w) {
		return
	}
	b, ok := readRemoteBody(w, r)
	if !ok {
		return
	}
	if len(b.SHA256) != 64 {
		http.Error(w, "preview the module first: the install is of exactly what the preview showed", http.StatusBadRequest)
		return
	}
	if !a.stepUp(w, r, b.Password, "install a module") {
		return
	}
	body, m, by, err := a.fetchSignedModule(r.Context(), b.URL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !strings.EqualFold(modules.Hash(body), b.SHA256) {
		http.Error(w, "the module changed since you previewed it; preview it again", http.StatusConflict)
		return
	}
	if _, loaded := a.Modules.Manifest(m.ID); loaded {
		http.Error(w, "a module with the id "+m.ID+" is already loaded", http.StatusConflict)
		return
	}
	installed, err := modules.Install(a.ModulesDir, b.URL, body, b.SHA256, false, by)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := a.Modules.AddRemote(installed); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	a.record(r, installed.ID, "installed the "+installed.ID+" module from "+b.URL+", signed by "+by+" (sha256 "+modules.Hash(body)[:12]+")")
	writeJSON(w, http.StatusOK, map[string]string{"id": installed.ID, "signed_by": by})
}

func (a *App) handleRemoteRemove(w http.ResponseWriter, r *http.Request) {
	if !a.remoteOn(w) {
		return
	}
	b, ok := readRemoteBody(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	for _, g := range a.Managed.List() {
		if g.Module == id {
			http.Error(w, "the game "+g.ID+" still uses this module: disable it first", http.StatusConflict)
			return
		}
	}
	if !a.stepUp(w, r, b.Password, "remove a module") {
		return
	}
	if err := modules.Uninstall(a.ModulesDir, id); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := a.Modules.RemoveRemote(id); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a.record(r, id, "removed the "+id+" module")
	w.WriteHeader(http.StatusNoContent)
}

// updateTarget finds the lock entry for id and fetches its newer signed version from the source recorded when it was
// installed. The address never comes from the browser: an update can only come from where the install did.
func (a *App) updateTarget(w http.ResponseWriter, r *http.Request) (e modules.LockEntry, body []byte, m *modules.Manifest, by string, ok bool) {
	id := r.PathValue("id")
	lock, err := modules.ReadLock(a.ModulesDir)
	if err != nil {
		http.Error(w, "reading the module lock: "+err.Error(), http.StatusInternalServerError)
		return
	}
	e, found := lock.Find(id)
	if !found {
		http.Error(w, id+" was not installed from a source (it is bundled or hand-placed)", http.StatusNotFound)
		return
	}
	body, m, by, err = a.fetchSignedModule(r.Context(), e.Source)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if m.ID != id {
		http.Error(w, "the source now serves module "+m.ID+", not "+id+"; refusing", http.StatusConflict)
		return
	}
	return e, body, m, by, true
}

func (a *App) handleRemoteUpdatePreview(w http.ResponseWriter, r *http.Request) {
	if !a.remoteOn(w) {
		return
	}
	e, body, m, by, ok := a.updateTarget(w, r)
	if !ok {
		return
	}
	sum := modules.Hash(body)
	if sum == e.SHA256 {
		writeJSON(w, http.StatusOK, map[string]any{"id": m.ID, "up_to_date": true})
		return
	}
	var old []string
	if cur, ok := a.Modules.Manifest(m.ID); ok {
		old = cur.Review()
	}
	added, removed := modules.DiffLines(old, m.Review())
	writeJSON(w, http.StatusOK, map[string]any{
		"id": m.ID, "name": m.Name, "sha256": sum, "was_sha256": e.SHA256, "signed_by": by,
		"added": added, "removed": removed, "review": m.Review(),
	})
}

func (a *App) handleRemoteUpdate(w http.ResponseWriter, r *http.Request) {
	if !a.remoteOn(w) {
		return
	}
	b, ok := readRemoteBody(w, r)
	if !ok {
		return
	}
	if len(b.SHA256) != 64 {
		http.Error(w, "preview the update first: it installs exactly what the preview showed", http.StatusBadRequest)
		return
	}
	if !a.stepUp(w, r, b.Password, "update a module") {
		return
	}
	e, body, m, by, ok := a.updateTarget(w, r)
	if !ok {
		return
	}
	if !strings.EqualFold(modules.Hash(body), b.SHA256) {
		http.Error(w, "the module changed since you previewed it; preview it again", http.StatusConflict)
		return
	}
	installed, err := modules.Install(a.ModulesDir, e.Source, body, b.SHA256, true, by)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := a.Modules.ReplaceRemote(installed); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	a.record(r, m.ID, "updated the "+m.ID+" module from "+e.Source+", signed by "+by+" (sha256 "+modules.Hash(body)[:12]+", was "+e.SHA256[:12]+")")
	writeJSON(w, http.StatusOK, map[string]any{"id": m.ID, "signed_by": by,
		"note": "Games already set up from it keep their old wiring until you save their settings or restart CrowsNest."})
}
