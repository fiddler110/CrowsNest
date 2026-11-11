package web

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// Templates holds the dashboard's parsed page templates.
type Templates struct {
	Dashboard *template.Template
	Login     *template.Template
	Setup     *template.Template
	Games     *template.Template
	Settings  *template.Template
	Account   *template.Template
}

// layoutFile holds the partials every page shares: the icon sprite, the top
// bar, and the toast/confirm chrome.
const layoutFile = "templates/_layout.html"

// LoadTemplates parses the embedded HTML templates. Every page is parsed with
// the shared layout partials and the asset func, which turns "app.js" into a
// content-hashed /static URL.
func LoadTemplates() (*Templates, error) {
	assets, err := loadAssets()
	if err != nil {
		return nil, err
	}
	funcs := template.FuncMap{"asset": assets.url}
	parse := func(page string) (*template.Template, error) {
		t, err := template.New(page).Funcs(funcs).ParseFS(templateFS, "templates/"+page, layoutFile)
		if err != nil {
			return nil, fmt.Errorf("web: parse %s: %w", page, err)
		}
		return t, nil
	}
	var t Templates
	for _, p := range []struct {
		dst  **template.Template
		file string
	}{{&t.Dashboard, "dashboard.html"}, {&t.Login, "login.html"}, {&t.Setup, "setup.html"}, {&t.Games, "games.html"}, {&t.Settings, "settings.html"}, {&t.Account, "account.html"}} {
		if *p.dst, err = parse(p.file); err != nil {
			return nil, err
		}
	}
	return &t, nil
}

// render executes a page template into a buffer first, so a template error
// becomes a clean 500 instead of half a page with a 200.
func render(w http.ResponseWriter, t *template.Template, data any, what string) {
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		log.Printf("web: render %s: %v", what, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

// asset is one embedded static file, prepared once at startup.
type asset struct {
	body        []byte
	gz          []byte // nil when the type does not compress or it would not shrink
	hash        string // short content hash, the ?v= of its URL
	contentType string
}

type assetSet struct {
	files map[string]*asset
}

var (
	assetsOnce   sync.Once
	assetsLoaded *assetSet
	assetsErr    error
)

// loadAssets reads, hashes and (for text types) gzips every embedded static
// file. It runs once per process.
func loadAssets() (*assetSet, error) {
	assetsOnce.Do(func() {
		assetsLoaded, assetsErr = buildAssets(staticFS)
	})
	return assetsLoaded, assetsErr
}

func buildAssets(fsys fs.FS) (*assetSet, error) {
	sub, err := fs.Sub(fsys, "static")
	if err != nil {
		return nil, fmt.Errorf("web: sub static fs: %w", err)
	}
	set := &assetSet{files: map[string]*asset{}}
	err = fs.WalkDir(sub, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		body, err := fs.ReadFile(sub, name)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(body)
		a := &asset{body: body, hash: hex.EncodeToString(sum[:])[:12], contentType: mime.TypeByExtension(path.Ext(name))}
		if a.contentType == "" {
			a.contentType = http.DetectContentType(body)
		}
		if compressible(a.contentType) {
			var buf bytes.Buffer
			zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
			if _, err := zw.Write(body); err != nil {
				return err
			}
			if err := zw.Close(); err != nil {
				return err
			}
			if buf.Len() < len(body) {
				a.gz = buf.Bytes()
			}
		}
		set.files[name] = a
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("web: load static assets: %w", err)
	}
	return set, nil
}

func compressible(contentType string) bool {
	return strings.HasPrefix(contentType, "text/") ||
		strings.Contains(contentType, "javascript") ||
		strings.Contains(contentType, "json") ||
		strings.Contains(contentType, "svg")
}

// url is the template func {{asset "app.js"}}: the file's /static URL with its
// content hash, so a release changes the URL and browsers may cache it forever.
func (s *assetSet) url(name string) (string, error) {
	a, ok := s.files[name]
	if !ok {
		return "", fmt.Errorf("web: no static asset %q", name)
	}
	return "/static/" + name + "?v=" + a.hash, nil
}

// unversionedMaxAge is how long a browser may reuse an asset requested without
// (or with a stale) ?v= hash, such as the texture the stylesheet points at.
const unversionedMaxAge = 3600

// ServeHTTP serves an asset (the path has /static/ stripped). A request whose
// ?v= matches the content hash is cacheable for a year; anything else gets an
// hour plus an ETag to revalidate against. Text types go out gzipped when the
// client accepts it.
func (s *assetSet) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a, ok := s.files[strings.TrimPrefix(r.URL.Path, "/")]
	if !ok {
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	h.Set("Content-Type", a.contentType)
	h.Set("X-Content-Type-Options", "nosniff")
	if r.URL.Query().Get("v") == a.hash {
		h.Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		h.Set("Cache-Control", "public, max-age="+strconv.Itoa(unversionedMaxAge))
	}
	body := a.body
	etag := `"` + a.hash + `"`
	if a.gz != nil {
		h.Set("Vary", "Accept-Encoding")
		if acceptsGzip(r.Header.Get("Accept-Encoding")) {
			body = a.gz
			etag = `"` + a.hash + `-gz"`
			h.Set("Content-Encoding", "gzip")
		}
	}
	h.Set("ETag", etag)
	if inm := r.Header.Get("If-None-Match"); inm != "" && etagMatches(inm, etag) {
		h.Del("Content-Type")
		h.Del("Content-Encoding")
		w.WriteHeader(http.StatusNotModified)
		return
	}
	h.Set("Content-Length", strconv.Itoa(len(body)))
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body)
}

// acceptsGzip reports whether an Accept-Encoding header allows gzip (a q of 0
// refuses it).
func acceptsGzip(header string) bool {
	gzipOK, starOK := -1, -1 // -1 unset, 0 refused, 1 accepted
	for _, part := range strings.Split(header, ",") {
		name, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		name = strings.ToLower(strings.TrimSpace(name))
		ok := 1
		if q := strings.ReplaceAll(strings.ToLower(params), " ", ""); strings.HasPrefix(q, "q=") {
			if v, err := strconv.ParseFloat(q[2:], 64); err == nil && v == 0 {
				ok = 0
			}
		}
		switch name {
		case "gzip", "x-gzip":
			gzipOK = ok
		case "*":
			starOK = ok
		}
	}
	if gzipOK >= 0 {
		return gzipOK == 1
	}
	return starOK == 1
}

func etagMatches(header, etag string) bool {
	for _, t := range strings.Split(header, ",") {
		t = strings.TrimPrefix(strings.TrimSpace(t), "W/")
		if t == etag || t == "*" {
			return true
		}
	}
	return false
}

// staticHandler serves the embedded static assets rooted at "/".
func staticHandler() (http.Handler, error) {
	return loadAssets()
}
