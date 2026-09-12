package web

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// Templates holds the dashboard's parsed page templates.
type Templates struct {
	Dashboard *template.Template
	Login     *template.Template
}

// LoadTemplates parses the embedded HTML templates.
func LoadTemplates() (*Templates, error) {
	dashboard, err := template.ParseFS(templateFS, "templates/dashboard.html")
	if err != nil {
		return nil, fmt.Errorf("web: parse dashboard template: %w", err)
	}
	login, err := template.ParseFS(templateFS, "templates/login.html")
	if err != nil {
		return nil, fmt.Errorf("web: parse login template: %w", err)
	}
	return &Templates{Dashboard: dashboard, Login: login}, nil
}

// staticHandler serves the embedded static assets (CSS/JS) rooted at "/".
func staticHandler() (http.Handler, error) {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, fmt.Errorf("web: sub static fs: %w", err)
	}
	return http.FileServerFS(sub), nil
}
