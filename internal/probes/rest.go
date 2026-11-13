package probes

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/fiddler110/crowsnest/internal/games"
)

// Request is one HTTP call a module declares. Body values and Path may use
// {field} placeholders filled from the console action's arguments.
type Request struct {
	Method string            `yaml:"method"` // default GET
	Path   string            `yaml:"path"`
	Body   map[string]string `yaml:"body"`
}

// Field is one argument of a console action. Max is in characters (default
// 200); control characters are always rejected.
type Field struct {
	Name     string `yaml:"name"`
	Label    string `yaml:"label"`
	Optional bool   `yaml:"optional"`
	Max      int    `yaml:"max"`
}

// List renders a JSON array from the reply as one text line per element.
type List struct {
	Path  string `yaml:"path"`  // dotted path to the array
	Line  string `yaml:"line"`  // template over the element's keys
	Empty string `yaml:"empty"` // shown when the array is empty
}

// Action is one fixed admin command: the manifest decides what is sent, the
// admin only fills in the declared fields.
type Action struct {
	ID      string  `yaml:"id"`
	Label   string  `yaml:"label"`
	Danger  bool    `yaml:"danger"`
	Fields  []Field `yaml:"fields"`
	Request Request `yaml:"request"`
	// RCON, instead of Request, is one command line sent over RCON, with
	// {field} placeholders filled from the validated arguments.
	RCON   string `yaml:"rcon"`
	Result string `yaml:"result"` // template over the arguments
	List   *List  `yaml:"list"`
}

// InfoSource is one GET whose reply feeds the info panel. Fields address it
// as {name.path}. A Required source that fails makes the whole panel
// unavailable; an optional one just drops the fields that need it.
type InfoSource struct {
	Name     string `yaml:"name"`
	Path     string `yaml:"path"`
	Required bool   `yaml:"required"`
}

// InfoField is one entry of the info panel. Template may mix text and
// {source.path} or {source.path|format} placeholders; a format is `duration`
// (seconds as 1d 2h) or a printf verb such as %.1f. A field whose placeholders
// cannot be resolved, or that renders empty, is left out.
type InfoField struct {
	Key      string `yaml:"key"`
	Template string `yaml:"template"`
}

// Step is one stage of the pre-stop sequence. IfPlayers skips the step when
// nobody is online (or the count is unknown is treated as nobody is not
// assumed: an unknown count runs the step). BestEffort ignores its error.
// Pause waits after a successful step.
type Step struct {
	IfPlayers  bool          `yaml:"if_players"`
	BestEffort bool          `yaml:"best_effort"`
	Pause      time.Duration `yaml:"pause"`
	Request    Request       `yaml:"request"`
}

// ---- games.InfoProvider ----

// Info implements games.InfoProvider.
func (p *HTTPJSON) Info(ctx context.Context) (map[string]any, bool) {
	docs := map[string]any{}
	for _, s := range p.InfoSources {
		d, err := p.get(ctx, s.Path)
		if err != nil {
			if s.Required {
				return nil, false
			}
			continue
		}
		docs[s.Name] = d
	}
	out := map[string]any{}
	for _, f := range p.InfoFields {
		if v, ok := renderValue(f.Template, func(name string) (any, bool) {
			src, path, _ := strings.Cut(name, ".")
			d, ok := docs[src]
			if !ok {
				return nil, false
			}
			return lookup(d, path)
		}); ok {
			out[f.Key] = v
		}
	}
	return out, true
}

// ---- games.Console ----

// Actions implements games.Console.
func (p *HTTPJSON) Actions() []games.ConsoleAction { return consoleActions(p.ActionDefs) }

// Run implements games.Console. Only declared actions run; arguments are
// validated before anything is sent.
func (p *HTTPJSON) Run(ctx context.Context, action string, args map[string]string) (string, error) {
	var a *Action
	for i := range p.ActionDefs {
		if p.ActionDefs[i].ID == action {
			a = &p.ActionDefs[i]
		}
	}
	if a == nil {
		return "", fmt.Errorf("unknown action %q", action)
	}
	vals, err := actionArgs(a, args)
	if err != nil {
		return "", err
	}
	doc, err := p.send(ctx, a.Request, vals)
	if err != nil {
		return "", err
	}
	if a.List != nil {
		return renderList(doc, a.List), nil
	}
	if s := renderString(a.Result, vals); s != "" {
		return s, nil
	}
	return "Done.", nil
}

// actionArgs validates the admin's arguments against the action's declared fields.
func actionArgs(a *Action, args map[string]string) (map[string]string, error) {
	vals := map[string]string{}
	for _, f := range a.Fields {
		v := strings.TrimSpace(args[f.Name])
		max := f.Max
		if max == 0 {
			max = 200
		}
		if len([]rune(v)) > max {
			return nil, fmt.Errorf("%w: %s is longer than %d characters", games.ErrBadInput, f.Name, max)
		}
		for _, r := range v {
			if unicode.IsControl(r) {
				return nil, fmt.Errorf("%w: %s contains control characters", games.ErrBadInput, f.Name)
			}
		}
		if v == "" && !f.Optional {
			return nil, fmt.Errorf("%w: %s is required", games.ErrBadInput, f.Name)
		}
		vals[f.Name] = v
	}
	return vals, nil
}

func consoleActions(defs []Action) []games.ConsoleAction {
	out := make([]games.ConsoleAction, 0, len(defs))
	for _, a := range defs {
		ca := games.ConsoleAction{ID: a.ID, Label: a.Label, Danger: a.Danger}
		for _, f := range a.Fields {
			ca.Fields = append(ca.Fields, games.ConsoleField{Name: f.Name, Label: f.Label, Optional: f.Optional})
		}
		out = append(out, ca)
	}
	return out
}

func (p *HTTPJSON) send(ctx context.Context, r Request, vals map[string]string) (any, error) {
	method := r.Method
	if method == "" {
		method = http.MethodGet
	}
	sub := func(s string) string { return renderString(s, vals) }
	var body map[string]string
	if len(r.Body) > 0 {
		body = make(map[string]string, len(r.Body))
		for k, v := range r.Body {
			body[k] = sub(v)
		}
	}
	return p.do(ctx, method, sub(r.Path), body)
}

func renderList(doc any, l *List) string {
	v, _ := lookup(doc, l.Path)
	arr, _ := v.([]any)
	if len(arr) == 0 {
		return l.Empty
	}
	lines := make([]string, 0, len(arr))
	for _, e := range arr {
		s, _ := renderValue(l.Line, func(n string) (any, bool) { return lookup(e, n) })
		lines = append(lines, fmt.Sprint(s))
	}
	return strings.Join(lines, "\n")
}

// ---- games.StopPreparer ----

// PrepareStop implements games.StopPreparer by running the declared steps.
func (p *HTTPJSON) PrepareStop(ctx context.Context) error {
	var last error
	for _, s := range p.Steps {
		if s.IfPlayers {
			if n, _, ok := p.PlayerCount(ctx); ok && n == 0 {
				continue
			}
		}
		_, err := p.send(ctx, s.Request, nil)
		if err != nil {
			if !s.BestEffort {
				last = err
			}
			continue
		}
		if s.Pause > 0 {
			if p.Sleep != nil {
				p.Sleep(ctx, s.Pause)
			} else {
				select {
				case <-time.After(s.Pause):
				case <-ctx.Done():
				}
			}
		}
	}
	return last
}

// ---- templates ----

// renderString fills placeholders from vals; unknown ones render empty, so an
// optional argument left blank becomes "".
func renderString(tpl string, vals map[string]string) string {
	return placeholder.ReplaceAllStringFunc(tpl, func(tok string) string {
		return vals[placeholder.FindStringSubmatch(tok)[1]]
	})
}

var placeholder = regexp.MustCompile(`\{([^{}|]+)(?:\|([^{}]+))?\}`)

// renderValue fills {name} / {name|format} placeholders. A template that is a
// single bare placeholder keeps the value's native type (whole numbers become
// int). ok is false when a placeholder cannot be resolved or the result is
// empty.
func renderValue(tpl string, get func(string) (any, bool)) (any, bool) {
	if m := placeholder.FindStringSubmatch(tpl); m != nil && m[0] == tpl && m[2] == "" {
		v, ok := get(m[1])
		if !ok {
			return nil, false
		}
		v = native(v)
		if s, isStr := v.(string); isStr && s == "" {
			return nil, false
		}
		return v, true
	}
	failed := false
	out := placeholder.ReplaceAllStringFunc(tpl, func(tok string) string {
		m := placeholder.FindStringSubmatch(tok)
		v, ok := get(m[1])
		if !ok {
			failed = true
			return ""
		}
		return format(native(v), m[2])
	})
	if failed || out == "" {
		return "", false
	}
	return out, true
}

func native(v any) any {
	if f, ok := v.(float64); ok && f == float64(int64(f)) {
		return int(f)
	}
	return v
}

func format(v any, f string) string {
	switch {
	case f == "":
		return fmt.Sprint(v)
	case f == "duration":
		n, _ := toFloat(v)
		return duration(int64(n))
	case strings.HasPrefix(f, "%"):
		n, ok := toFloat(v)
		if !ok {
			return fmt.Sprint(v)
		}
		if strings.HasSuffix(f, "d") {
			return fmt.Sprintf(f, int64(n))
		}
		return fmt.Sprintf(f, n)
	}
	return fmt.Sprint(v)
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case float64:
		return n, true
	case string:
		f, err := strconv.ParseFloat(n, 64)
		return f, err == nil
	}
	return 0, false
}

func duration(secs int64) string {
	d := time.Duration(secs) * time.Second
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%dd %dh", int(d.Hours())/24, int(d.Hours())%24)
	case d >= time.Hour:
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	case d >= time.Minute:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	default:
		return fmt.Sprintf("%ds", secs)
	}
}
