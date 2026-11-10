package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/fiddler110/crowsnest/internal/auth"
	"github.com/fiddler110/crowsnest/internal/config"
	"github.com/fiddler110/crowsnest/internal/dockerguard"
	"github.com/fiddler110/crowsnest/internal/hoststats"
	"github.com/fiddler110/crowsnest/internal/modules"
)

// Doctor levels. Only a failure makes `crowsnest doctor` exit non-zero.
const (
	docOK   = "ok"
	docInfo = "info"
	docWarn = "WARN"
	docFail = "FAIL"
)

type doctorReport struct {
	w     io.Writer
	warns int
	fails int
}

// add prints one line, and a fix underneath unless it is empty.
func (r *doctorReport) add(level, what, fix string) {
	switch level {
	case docWarn:
		r.warns++
	case docFail:
		r.fails++
	}
	fmt.Fprintf(r.w, "  %-4s  %s\n", level, what)
	if fix != "" && level != docOK {
		fmt.Fprintf(r.w, "        -> %s\n", fix)
	}
}

// dockerPinger is the slice of dockerctl.Client that doctor needs.
type dockerPinger interface {
	Ping(ctx context.Context) error
}

// writable reports whether files can be created in dir, the way the panel
// does (a temp file, then a rename).
func writable(dir string) error {
	f, err := os.CreateTemp(dir, ".doctor-*")
	if err != nil {
		return err
	}
	name := f.Name()
	f.Close()
	return os.Remove(name)
}

// runDoctor checks the install and says what to fix. It changes nothing.
// The exit status is 1 when something would stop CrowsNest working, 0 for
// warnings and notes.
func runDoctor(cfg *config.Config, docker dockerPinger, w io.Writer) int {
	r := &doctorReport{w: w}
	fmt.Fprintln(w, "CrowsNest doctor")

	fmt.Fprintln(w, "\nDocker")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := docker.Ping(ctx); err != nil {
		r.add(docFail, "Docker did not answer: "+err.Error(),
			"mount the socket (or point server.docker_host at the guard) and check the container can reach it")
	} else {
		r.add(docOK, "Docker answers", "")
	}
	if h := cfg.Server.DockerHost; h == "" || strings.HasPrefix(h, "unix://") {
		r.add(docWarn, "the panel talks to the raw Docker socket, which is root on the host if the panel is ever compromised",
			"put the scoped guard in front of it and set server.docker_host (see compose.yaml.example)")
	} else {
		r.add(docOK, "Docker is reached through "+h+", not the raw socket", "")
	}

	fmt.Fprintln(w, "\nFiles")
	for _, f := range []struct{ what, path string }{
		{"users file", cfg.UsersFile},
		{"session secret", cfg.Server.SessionSecretFile},
		{"settings file", cfg.Server.SettingsFile},
		{"activity log", cfg.Server.HistoryFile},
	} {
		dir := filepath.Dir(f.path)
		if err := writable(dir); err != nil {
			r.add(docFail, fmt.Sprintf("%s: cannot write in %s (%v)", f.what, dir, err),
				"mount that directory read-write into the panel; the file is replaced in place, so the folder must be writable, not just the file")
		} else {
			r.add(docOK, fmt.Sprintf("%s: %s is writable", f.what, dir), "")
		}
	}

	fmt.Fprintln(w, "\nAccounts")
	users, err := auth.LoadUsers(cfg.UsersFile)
	switch {
	case err != nil:
		r.add(docFail, "users file does not parse: "+err.Error(), "fix or remove the bad line")
	case len(users) == 0:
		r.add(docInfo, "no users yet", "start CrowsNest and open /setup (the setup code is in the log), or run `crowsnest set-password <name>`")
	case !hasAdmin(users):
		r.add(docWarn, "no admin account", "run `crowsnest set-role <username> admin`")
	default:
		r.add(docOK, fmt.Sprintf("%d user(s), at least one admin", len(users)), "")
	}
	if err == nil && !cfg.Auth.PasswordLoginEnabled() {
		var stale []string
		for name, rec := range users {
			if rec.Hash != "" {
				stale = append(stale, name)
			}
		}
		if len(stale) > 0 {
			sort.Strings(stale)
			r.add(docWarn, "password login is off but these users still have a stored password hash: "+strings.Join(stale, ", "),
				"run `crowsnest clear-password <name>` for each, so a leaked users file holds nothing to crack")
		}
	}

	fmt.Fprintln(w, "\nNetwork")
	if !cfg.Server.SecureCookies {
		r.add(docWarn, "server.secure_cookies is off",
			"turn it on when CrowsNest is served over HTTPS (it also adds HSTS); leave it off only for plain-HTTP LAN use")
	} else {
		r.add(docOK, "secure cookies are on", "")
	}
	if len(cfg.Server.TrustedProxies) == 0 {
		r.add(docInfo, "no trusted_proxies: every visitor is seen at their direct address",
			"behind a reverse proxy, list its address so the sign-in rate limit counts real visitors")
	} else {
		r.add(docOK, fmt.Sprintf("%d trusted proxy range(s)", len(cfg.Server.TrustedProxies)), "")
	}

	fmt.Fprintln(w, "\nGames")
	mods, err := modules.ForConfig(cfg, func(f string, a ...any) { r.add(docWarn, fmt.Sprintf(f, a...), "") })
	if err != nil {
		r.add(docFail, "modules did not load: "+err.Error(), "fix the module.yaml named in the message")
	} else {
		r.add(docOK, fmt.Sprintf("%d module(s) loaded, %d game(s) in config.yaml", len(mods.Manifests()), len(cfg.Games)), "")
	}
	if cfg.Managed.Dir == "" {
		r.add(docInfo, "dashboard games are off (managed.dir is not set)", "set managed.dir and managed.policy_file to add games from the Games page")
	} else {
		doctorManaged(r, cfg)
	}

	fmt.Fprintln(w, "\nHost")
	snap := hoststats.Read(cfg.Server.HostDiskPaths)
	if snap.MemTotal == 0 {
		r.add(docWarn, "host memory could not be read; starts are not checked against free memory", "")
	} else {
		r.add(docOK, fmt.Sprintf("%d MiB of memory, %d MiB available", snap.MemTotal>>20, snap.MemAvailable>>20), "")
	}
	for _, d := range snap.Disks {
		if d.Free < 5<<30 {
			r.add(docWarn, fmt.Sprintf("%s has only %d GiB free", d.Path, d.Free>>30), "game images and backups are large; free some space")
		}
	}
	if cfg.Server.MaxActiveGames == 1 {
		r.add(docInfo, "max_active_games is 1, so memory admission only matters once you raise it", "")
	}

	fmt.Fprintf(w, "\n%d failure(s), %d warning(s)\n", r.fails, r.warns)
	if r.fails > 0 {
		return 1
	}
	return 0
}

func doctorManaged(r *doctorReport, cfg *config.Config) {
	if err := writable(cfg.Managed.Dir); err != nil {
		r.add(docFail, fmt.Sprintf("managed.dir %s is not writable (%v)", cfg.Managed.Dir, err), "mount it read-write into the panel")
	} else {
		r.add(docOK, "managed.dir is writable", "")
	}
	pol, err := dockerguard.LoadPolicyWith(cfg.Managed.PolicyFile, modules.PolicyDefaults(modules.PlatformFrom(cfg.Platform)))
	if err != nil {
		r.add(docFail, "policy file: "+err.Error(), "copy policy.yaml.example, edit it, and mount it at managed.policy_file")
		return
	}
	r.add(docOK, "policy file loads: "+cfg.Managed.PolicyFile, "")
	if fi, err := os.Stat(pol.GamesRoot); err != nil || !fi.IsDir() {
		r.add(docWarn, fmt.Sprintf("the policy's games_root %s is not a folder this process can see", pol.GamesRoot),
			"that path is the host's; it need not exist inside the panel, but check it exists on the host")
	}
	if cfg.Managed.PolicyEditable {
		r.add(docWarn, "managed.policy_editable is on: the panel can tighten (and remove entries from) the policy", "turn it off unless you use the Settings editor")
	}
	if len(pol.Images) == 0 {
		r.add(docWarn, "the policy allows no images, so no dashboard game can start", "list the images you trust under images:")
	}
}
