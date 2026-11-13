# Modularization plan

Goal: add a game server to CrowsNest by dropping in a module (a directory), with no change to the Go core,
and with the Docker guard, exec allowlist, secrets and UI form all derived from that one module.

Status: **Phase 0 done** (golden tests, `buildGameDefs` seam, PR #22). **Phase 1 done** (module registry,
manifest loader, shared log engine and probes, `modules_dir`). **Phase 2 done**: Valheim, Palworld and Windrose are bundled `module.yaml` files, the typed config blocks are folded into `options`, Windrose+ is a Go extension, and Minecraft is the fourth-game test (a manifest and a fixture, no Go; `internal/modules/bundled/minecraft`), followed by a shared `source` module (the `module:` key lets many games use one manifest) and Don't Starve Together; see [`modules.md`](modules.md). `runtime:` sections plus `crowsnest render` generate the compose file and `GUARD_SCOPES` from a module (first slice of Phase 3). The Tier 2 adapter-sidecar contract is deferred until a module needs it. Phases 3-6 are not started.
Progress and the related accounts/settings and verification work are tracked in [`roadmap.md`](../roadmap.md);
this file holds the design only.
This document is the plan referenced from `cmd/crowsnest/gamewiring.go` and `cmd/crowsnest/golden_test.go`.

## 1. Where modularity breaks today

The per-game interfaces in `internal/games/types.go` (`StatusChecker`, `PlayerCounter`, `InfoProvider`,
`Console`, `StopPreparer`, `StartupMatcher`) are already the right shape. The wiring is the problem.

1. Wiring was a hard-coded switch on game ID that imported each game package (`buildGameDefs`, now replaced by
   `internal/modules`, see 2a). A new game still means new Go code, a rebuild and a release until manifests land.
2. `config.GameConfig` has typed `Windrose` and `Palworld` fields, so the config schema changes per game.
3. Every game is described three times, and the copies must match: `games.compose.yaml`, the `GUARD_SCOPES` JSON in
   `compose.yaml`, and `config.yaml`. Adding a game touches about eight places: compose service, guard scope,
   config entry, `.env`, the panel's env passthrough for `connect_secrets`, CSS accent colour, an execguard
   restart, and the Tailscale policy. A mismatch fails at runtime (a guard DENY).
4. The Valheim and Windrose trackers are the same state machine (follow logs, latch a marker, reset on restart).
   Milestones, join/leave regexes and ready markers are compiled in but could be data. Palworld's 30s restart
   cooldown is hard-coded in the wiring.
5. One shared compose file and one shared `.env`: a missing `${VAR}` for game A can block game B, and the panel
   can read every game's admin and RCON passwords.

## 2. Target architecture

**Core** (unchanged in role): auth and roles, dashboard and API, lifecycle, exclusivity/resource policy,
idle/night/scheduled shutdown, notifications, activity log, backup runner, guard and execguard, module loader.

**Module** = a directory (later also a signed archive):

```
modules/valheim/
  module.yaml        identity, runtime, params, probes, console, backup, connect info
  compose.yaml       service fragment (template rendered by the core)
  icon.svg / theme   card accent colour (removes the CSS leak)
  adapter/           optional sidecar for games that need real code
```

Three capability tiers, so most games need no code:

- **Tier 1, declarative probes** built into the core: `docker_state`, `log_markers` (ready/join/leave regexes,
  startup milestones), `http_json`, `source_rcon`, `a2s_query`, `tcp_ping`. Covers Valheim fully and Palworld
  almost fully.
- **Tier 2, adapter sidecar**: a small container speaking a fixed JSON-over-HTTP contract (`GET /status`,
  `/players`, `/info`, `POST /action`, `/prepare-stop`) on the games network, with no Docker access and its own
  scoped secrets. Windrose+ (cookie login then polling) is the first adapter.
- **Tier 3, built-in Go** for bundled modules only, if ever needed.

No Go `plugin` package and no in-process plugins: they would run inside the panel's trust boundary.

Example `module.yaml` (Valheim):

```yaml
api_version: 1
id: valheim
name: Valheim
runtime:
  image: lloesche/valheim-server        # optional digest / version policy
  ports: [{udp: 2456}, {udp: 2457}]
  data_dirs: [config, data]             # under GAMES_ROOT/<instance>/
  stop_grace: 2m
  memory: 4g
  restart_cooldown: 0s
  privileges: []                        # host_network / seccomp_unconfined / cap_add need approval
params:
  - {key: SERVER_NAME, label: Server name}
  - {key: WORLD_NAME,  label: World}
  - {key: SERVER_PASS, label: Password, secret: true, show_players: true}
status:
  ready_log: 'Loading: Done\.|Opened Steam server'
players:
  type: log_markers
  join:  'Got handshake from client (\S+)'
  leave: 'Closing socket (\S+)'
startup:
  - {match: 'Load world:', pct: 80, label: Loading world}
backup:
  exec: [/bin/sh, -c, "tar czf /config/backups/manual-$(date +%s).tar.gz -C /config worlds_local"]
  list_dir: /config/backups
  before_stop: true
connect: {address: "{{host}}:2456", note: "Turn on Tailscale first"}
```

One source of truth: from the manifest the core derives the rendered compose fragment, the guard scope, the
execguard rules, the secrets handed to the container, and the UI form. The "three files that must match" problem
and the eight-step checklist go away.

**Trust boundary.** A panel that can write guard policy can grant itself anything, so:

- The operator owns a read-only `policy.yaml` envelope: games root (binds only under `<root>/<id>`), allowed port
  range, allowed networks, no privileges by default.
- A module inside the envelope may be installed from the dashboard; the core hot-reloads the guard.
- A module outside it (host networking, extra caps, exec beyond declared commands) is staged only. An operator
  applies it out of band with `crowsnest module apply <id>` after reviewing a diff; the approved hash goes in a
  lock file.
- The guard reads a mounted scopes file and reloads on signal; a bad file keeps the old policy and logs.

**Sources.** Bundled (the three existing games, embedded), local directory, then git/OCI with cosign signature and
pinned digest. `api_version` is checked; the core refuses a major mismatch.

**Profiles.** A module is the template; a profile is the module plus your values. Two Valheim worlds are two
profiles of one module.

## 2a. Current implementation: `internal/modules` (phase 1, step 1)

`cmd/crowsnest` no longer knows which games exist. The seam that Phase 0 carved out (`buildGameDefs`) is now a
registry:

- `modules.Set` maps a game ID to a `WireFunc(def *games.GameDef, env Env) []Runner`. `Env` carries the docker
  client and that game's `config.GameConfig`.
- `Set.Build(cfg, docker)` starts from `games.FromConfig` (the config-driven baseline: docker-state status, unknown
  player count) and applies the module registered for each game's ID. A game with no module keeps the baseline.
  Output order matches `config.yaml`.
- A `Runner` is a background worker (today the Valheim and Windrose log followers). `serve()` starts every Runner
  `Build` returns with `go r.Run(ctx)`, so adding a game that needs a follower needs no change in `main.go`.
- `modules.Bundled()` registers Palworld, Valheim and Windrose. Their wiring is the Phase 0 code moved unchanged
  (`internal/modules/bundled.go`); the golden tests in `cmd/crowsnest` pin it and must not change in this step.
- `Register` panics on an empty or duplicate ID or a nil function: those are mistakes in the bundled set, not runtime
  conditions.

Steps 2-3 added `manifest.go` (strict `module.yaml` v1 parser; `Set.LoadDir` registers each manifest's `WireFunc`),
`internal/logtrack` (the one log-follow engine behind Valheim, Windrose and `players.type: log_markers`) and
`internal/probes` (`http_json`: dotted-path count/names with optional basic auth; `source_rcon`: a command plus a
line regexp). Manifest URLs and addresses are operator-trusted today; Phase 3's `policy.yaml` envelope must
constrain them. Step 4: `config.yaml` has `modules_dir`; `modules.ForConfig` builds bundled + local modules, and the legacy games
block selects them by id. Until Phase 2 a manifest game still needs its container/compose entry in `config.yaml`.

### Phase 2 additions

- `internal/modules/bundled/<id>/module.yaml` are embedded (`go:embed`) and registered by `registerEmbedded`. Valheim
  and Palworld ship this way; `internal/games/valheim` and `internal/games/palworld` are gone.
- Manifest sections added for REST-style games: `options` (per-game settings, `${key}` substitution), `api`
  (base URL, basic auth from an env var), `players.type: http_json`, `info` (sources + templated fields), `actions`
  (fixed admin commands with validated fields, a request template and a result or list template), `pre_stop`
  (ordered requests with `if_players`, `best_effort`, `pause`), `rcon` (admin-only raw console) and
  `startup_progress` (a percentage read from the log and scaled onto the startup bar).
- A game's `config.yaml` entry carries its settings under `options:`. The old `windrose:` / `palworld:` blocks are
  deprecated and folded into `options` at load time (explicit options win), so existing files keep working.
- Windrose: status, startup and players come from `log_markers` on the game's own log (join = `LogNet: Login request`,
  leave = `UNetDriver::RemoveClientConnection`, both keyed by `BLPlayerSessionId`; fixture
  `internal/modules/testdata/windrose_session.log`). Windrose+ is optional: through a Go extension (`extensions` in `embed.go`) it adds the info panel, player
  names (only while its count agrees with the log, so names never flap and cause phantom join/leave notices), the admin
  console (players, status, ban list, kick, ban, unban) and the raw console. While the markers are new, `comparingCounter` checks the log count against
  Windrose+ and logs any disagreement; `players_source: windrose_plus` flips the primary back. A trap worth knowing:
  `R5TurnProtocol::Disconnect` looks like a leave but fires 9 s into every join.
- If a required option is unset the API half of a module is left unwired (logged) and the game keeps the baseline;
  restart cooldown and startup milestones still apply.

### Phase 4a: state hub (landed)

- `internal/statehub`: one observer goroutine per registered game (reconciled against the registry every 5 s and on a
  poke for an unknown id, so managed games come and go). Cadence: 2 s while starting or stopping (exclusivity's
  `Starting || Stopping`), 10 s online, 30 s offline or unknown. Players are probed only when the status is online or
  unknown. `Poke` observes now (coalesced); `Get` is non-blocking; `Current` waits for the first observation or for one
  begun after a poke; `Fresh` is poke-then-wait. Subscribers get a buffered(1) channel, signalled only when an
  observation differs or `Busy` flips (or on `Signal`), so a slow reader never blocks an observer.
- Consumers: the web handlers read the hub (the per-request snapshot memo is gone; actions poke instead of forget);
  playerwatch re-checks on each hub change; idle and night shutdown keep their decision ticks, read the hub, and take
  one `Fresh` reading before stopping. Exclusivity still does its own fresh checks during transitions and reports
  changes through `OnChange`, which pokes the hub.
- `GET /api/events` (session required): SSE with `games` (the caller's `/api/games` body, role-filtered) and `health`
  (the `/api/health` body), sent on connect and on change, at most once a second, plus a 25 s heartbeat. The dashboard
  uses it for cards and the docker banner and falls back to polling while it is down.
- Not done: memory-budget admission (still `max_active_games`).

## 3. Performance work that rides along

1. Central state hub: poll each game once on an adaptive cadence, keep one snapshot, push to browsers over one SSE
   stream (today each tab and each of idle/playerwatch probes separately).
2. Optional: drop the docker CLI and compose plugin from the image and create containers through the Engine API
   behind the guard. Biggest simplification, riskiest phase.
3. Memory-budget admission instead of `max_active_games` as a RAM proxy.
4. One log-follow engine for all `log_markers` games.

## 4. Phases

| Phase | Work | Done when |
|---|---|---|
| 0. Safety net | Golden tests for the three games (strategies, exec rules, guard scopes); `buildGameDefs` seam. **Done.** | Fixtures pass on today's code. |
| 1. Manifest and loader | `module.yaml` v1 and a loader producing `GameDef`. Replace the `buildGameDefs` switch (done, step 1). Shared log-follow engine, `http_json` and `source_rcon` probes. Legacy `config.yaml` games block still read and mapped to built-in modules. | The three games behave identically (goldens unchanged); `cmd/crowsnest` has no game names. |
| 2. Dogfood | Re-express Valheim, Palworld, then Windrose+ as bundled modules. Adapter contract v0 with Windrose+ as first adapter. Remove typed per-game config fields. | A fourth game (e.g. Minecraft or a Source game) added with a manifest only, in under 30 minutes, no core change. |
| 3. Derived security | Generate guard scopes, execguard rules and compose fragments from manifests. Per-module secrets. Scopes file with reload. `policy.yaml` envelope, privilege approval, lock file. Fuzz the guard. | Adding a game touches one directory plus `.env`; an out-of-envelope module cannot be applied from the UI. Gets its own security review. |
| 4. State hub | Central poller, single SSE stream, adaptive cadence, memory-budget admission. | Dashboard load makes no per-tab probes. |
| 5. Modules in the UI | Install, enable, configure, remove modules and profiles from the dashboard (inside the envelope); signed remote sources. | A profile is created and started with no file edits. |
| 6. Optional | Drop docker CLI/compose from the image (**done**: every Docker call is an Engine API call); scheduling, slash commands, backup retention/offsite, metrics. | Image has no docker binary. |

## 5. Risks

- Windrose+'s cookie session and Palworld's RCON edge cases are the hardest to express declaratively (hence Tier 2).
- Valheim join/leave markers were verified on 2026-11-07 against a real player session (anonymised fixture in
  `internal/logtrack/testdata`). Other games' markers need the same treatment before they are trusted.
- Keep the legacy config path for at least one minor release; production runs on it.
- Phase 3 changes the security model and needs a dedicated review.

## 6. Related findings from the design review

- Game images are `:latest` and the guard allows any tag of the repo; modules should pin a digest or version range.
- The panel mounts the whole `.env`; per-module secrets files fix that (Phase 3).
- The guard is the root-equivalent component; add Go fuzz targets for path and body parsing (Phase 3).
- Exec rules should be generated from the manifest so execguard and guard scopes cannot drift.
