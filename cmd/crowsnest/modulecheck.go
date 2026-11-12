package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/fiddler110/crowsnest/internal/config"
	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/logtrack"
	"github.com/fiddler110/crowsnest/internal/modules"
)

// runModuleCheck is `crowsnest module check <module.yaml|dir> [--log FILE]`: the
// loop a module author needs. It validates the manifest and, given a captured
// container log, shows what CrowsNest would have made of it: when the server
// counted as ready, which startup milestones fired, and who joined and left.
// It never touches Docker. Exit status 1 means the manifest is not valid.
func runModuleCheck(args []string, out io.Writer) int {
	var path, logFile string
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--log" && i+1 < len(args):
			logFile = args[i+1]
			i++
		case path == "" && !strings.HasPrefix(args[i], "-"):
			path = args[i]
		default:
			fmt.Fprintln(out, "usage: crowsnest module check <module.yaml|dir> [--log container.log]")
			return 2
		}
	}
	if path == "" {
		fmt.Fprintln(out, "usage: crowsnest module check <module.yaml|dir> [--log container.log]")
		return 2
	}
	if fi, err := os.Stat(path); err == nil && fi.IsDir() { // #nosec G703 -- the operator names the module on their own command line
		path = filepath.Join(path, "module.yaml")
	}
	f, err := os.Open(path) // #nosec G304 G703 -- the operator names the module on their own command line
	if err != nil {
		fmt.Fprintln(out, "FAIL ", err)
		return 1
	}
	defer f.Close()
	m, err := modules.Parse(f)
	if err != nil {
		fmt.Fprintln(out, "FAIL ", err)
		return 1
	}

	fmt.Fprintf(out, "ok    %s (%s) is a valid module, api_version %d\n", m.Name, m.ID, m.APIVersion)
	if base := filepath.Base(filepath.Dir(path)); base != "." && base != m.ID && base != "/" {
		fmt.Fprintf(out, "WARN  the folder is named %q but the id is %q; a module folder is named after its id\n", base, m.ID)
	}
	if m.Description == "" {
		fmt.Fprintln(out, "WARN  no description: the Games page shows it in the catalogue")
	}
	rt := m.Runtime
	switch {
	case rt.Image == "" && len(rt.Ports) == 0 && len(rt.Data) == 0:
		fmt.Fprintln(out, "info  no runtime: section, so it cannot be enabled from the dashboard (config.yaml games only)")
	default:
		fmt.Fprintf(out, "info  runtime: image %q, %d published port(s), %d data mount(s), %d option(s)\n", rt.Image, len(rt.Ports), len(rt.Data), len(m.Options))
		if rt.RAM == "" && rt.Memory == "" {
			fmt.Fprintln(out, "WARN  no runtime.ram: starts are never checked against free memory until the game has run once")
		}
		if m.Backup == nil {
			fmt.Fprintln(out, "info  no backup: block, so the Backups panel is off for this game")
		}
	}
	if m.Players.Type == "log_markers" && m.Status.ReadyLog == "" {
		fmt.Fprintln(out, "WARN  players.type log_markers without status.ready_log: the game would never count as online")
	}

	if logFile == "" {
		fmt.Fprintln(out, "info  pass --log <captured container log> to see how it would be read")
		return 0
	}
	lf, err := os.Open(logFile) // #nosec G304 G703 -- the operator names the log on their own command line
	if err != nil {
		fmt.Fprintln(out, "FAIL ", err)
		return 1
	}
	defer lf.Close()
	replayLog(out, m, lf)
	return 0
}

// replayLog feeds r through the manifest's log probes line by line.
func replayLog(out io.Writer, m *modules.Manifest, r io.Reader) {
	var def games.GameDef
	runners := m.Wire()(&def, modules.Env{Config: config.GameConfig{ID: m.ID}})
	var tr *logtrack.Tracker
	for _, rn := range runners {
		if t, ok := rn.(*logtrack.Tracker); ok {
			tr = t
		}
	}
	if tr == nil && def.Startup == nil {
		fmt.Fprintln(out, "info  this module reads no log (no players.type log_markers, startup or startup_progress), so there is nothing to replay")
		return
	}
	ctx := context.Background()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lines, readyAt, peak, last := 0, 0, 0, -1
	startupSeen := map[string]bool{}
	for sc.Scan() {
		lines++
		line := sc.Text()
		if def.Startup != nil {
			if def.Startup.Parse != nil {
				if pct, label, ok := def.Startup.Parse(line); ok && !startupSeen[label] {
					startupSeen[label] = true
					fmt.Fprintf(out, "      line %-5d startup %3d%%  %s\n", lines, pct, label)
				}
			}
			for _, ms := range def.Startup.Milestones {
				if ms.Pattern.MatchString(line) && !startupSeen[ms.Label] {
					startupSeen[ms.Label] = true
					fmt.Fprintf(out, "      line %-5d startup %3d%%  %s\n", lines, ms.Pct, ms.Label)
				}
			}
		}
		if tr == nil {
			continue
		}
		tr.Replay(strings.NewReader(line + "\n"))
		if readyAt == 0 && tr.Ready() {
			readyAt = lines
			fmt.Fprintf(out, "      line %-5d READY: %s\n", lines, trim(line))
		}
		if n, names, ok := tr.PlayerCount(ctx); ok && n != last {
			if last >= 0 {
				fmt.Fprintf(out, "      line %-5d players %d -> %d %v\n", lines, last, n, names)
			}
			last = n
			if n > peak {
				peak = n
			}
		}
	}
	fmt.Fprintf(out, "info  read %d lines\n", lines)
	if tr != nil {
		if readyAt == 0 {
			fmt.Fprintln(out, "WARN  the ready marker never matched: the game would stay in \"starting\"")
		}
		fmt.Fprintf(out, "info  peak players %d\n", peak)
	}
}

func trim(s string) string {
	if len(s) > 90 {
		return s[:90] + "…"
	}
	return s
}
