package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/fiddler110/crowsnest/internal/config"
	"github.com/fiddler110/crowsnest/internal/modules"
)

// runRender writes the compose file and GUARD_SCOPES for every configured game
// whose module has a runtime section, so the two cannot drift apart:
//
//	crowsnest render --config config.yaml --compose games.compose.yaml --scopes scopes.json --env env.example
func runRender(args []string) error {
	fs := flag.NewFlagSet("render", flag.ExitOnError)
	cfgPath := fs.String("config", envOr("CROWSNEST_CONFIG", "/app/config.yaml"), "config.yaml")
	composeOut := fs.String("compose", "-", "compose file to write (- = stdout)")
	scopesOut := fs.String("scopes", "", "GUARD_SCOPES JSON to write (default: not written)")
	envOut := fs.String("env", "", "list of .env variables the services read (default: not written)")
	_ = fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	set, err := modules.ForConfig(cfg, func(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) })
	if err != nil {
		return err
	}
	plat := modules.PlatformFrom(cfg.Platform)
	var out []*modules.Rendered
	for _, g := range cfg.Games {
		id := g.ID
		if g.Module != "" {
			id = g.Module
		}
		m, ok := set.Manifest(id)
		if !ok || (m.Runtime.Image == "" && g.Options["image"] == "") {
			fmt.Fprintf(os.Stderr, "render: skipping %s (module %q has no runtime.image; keep its compose service by hand)\n", g.ID, id)
			continue
		}
		r, err := m.Render(g, plat)
		if err != nil {
			return err
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		return fmt.Errorf("render: no configured game has a renderable module")
	}
	compose, err := modules.ComposeFile(out, plat.Network)
	if err != nil {
		return err
	}
	if err := writeOut(*composeOut, compose); err != nil {
		return err
	}
	if *scopesOut != "" {
		b, err := modules.ScopesJSON(out)
		if err != nil {
			return err
		}
		if err := writeOut(*scopesOut, append(b, '\n')); err != nil {
			return err
		}
	}
	if *envOut != "" {
		var sb strings.Builder
		sb.WriteString("# Variables the generated compose file reads. Secrets have no default.\n")
		for _, r := range out {
			fmt.Fprintf(&sb, "\n# %s\n", r.ID)
			for _, v := range r.EnvVars {
				if v.Name == "TZ" {
					continue
				}
				if v.Secret {
					fmt.Fprintf(&sb, "%s=   # secret\n", v.Name)
				} else {
					fmt.Fprintf(&sb, "#%s=%s\n", v.Name, v.Default)
				}
			}
		}
		if err := writeOut(*envOut, []byte(sb.String())); err != nil {
			return err
		}
	}
	return nil
}

func writeOut(path string, b []byte) error {
	if path == "-" {
		_, err := os.Stdout.Write(b)
		return err
	}
	return os.WriteFile(path, b, 0o644) // #nosec G306 -- generated config, no secrets (secrets are .env references)
}
