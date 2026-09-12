# CrowsNest — Implementation Plan

Go rewrite of the original single-game (Windrose-only) Python/Flask CrowsNest,
expanded to control three independent game server containers — Windrose,
Valheim, Palworld — from one dashboard, with a guard that keeps at most one
running at a time.

Decisions below were made explicitly (not defaults) on 2026-09-11:

| Decision | Choice |
|---|---|
| Docker control | Shell out to `docker` / `docker compose` CLI (matches the Dockerfile, which already stages the Docker CLI + compose plugin; mirrors the proven Python `subprocess` approach) |
| Auth | Multi-user login, one password hash per user (same shape as the original) |
| Game registry config | Declarative `config.yaml`, one entry per game |
| Idle auto-stop | In scope now: stop a game after **15 minutes** with 0 players. Time-window ("night shutdown") and Discord notifications are deferred. |
| Night shutdown + Discord (Phase 11, decided 2026-09-12) | Both added: a config-driven nightly window (`night_shutdown`, off by default, per-game opt-out) stops an online-but-empty game immediately once inside the window, independent of and in addition to idle-shutdown; a Discord webhook (`notifications.discord_webhook_url_env`, off by default) is notified whenever either mechanism stops a game. |

## Package layout

```
cmd/crowsnest/          entrypoint: serve, healthcheck, set-password
internal/games/          GameDef + strategy interfaces (exists) + Registry
internal/games/windrose/ Windrose GameDef: status, players, logs, startup, info
internal/games/valheim/  Valheim GameDef
internal/games/palworld/ Palworld GameDef
internal/dockerctl/      docker/compose CLI wrapper (start/stop/status/inspect/logs/stats)
internal/config/         config.yaml loading + validation
internal/auth/           users, bcrypt, signed-cookie sessions, CSRF, rate limiting
internal/exclusivity/    "only one game running" guard + switch orchestration
internal/idleshutdown/   auto-stop-when-empty manager
internal/nightshutdown/  time-window ("night curfew") auto-stop manager (Phase 11)
internal/notify/         Discord webhook notifier, shared by idle/night shutdown (Phase 11)
internal/sse/            SSE writer + keepalive helper, shared by logs/startup streams
internal/web/            HTTP handlers, routes, templates (embed.FS), middleware
```

`internal/games/types.go` (already scaffolded) is the contract every per-game
package implements against: `StatusChecker`, `PlayerCounter`,
`LogLineFormatter`, `StartupMatcher`, `InfoProvider`, assembled into a
`GameDef`. Nothing in `internal/web` or `internal/exclusivity` should need to
know which game it's talking to beyond that interface.

## Dependencies

Keep the current zero-third-party-deps posture as much as possible, matching
the project's existing minimalism (stdlib `net/http` with method+path
patterns, Docker CLI instead of the Engine SDK). Only add:

- `gopkg.in/yaml.v3` — config parsing
- `golang.org/x/crypto/bcrypt` — password hashing

Sessions, CSRF, rate limiting, and SSE are hand-rolled stdlib, same as the
Python version's design but without a framework underneath it.

## Config model (`config.yaml`)

```yaml
server:
  addr: ":5000"
  session_secret_file: /app/.session_secret   # generated on first run if absent
  tz: "America/New_York"

idle_shutdown:
  enabled: true
  idle_minutes: 15
  check_interval_seconds: 60

night_shutdown:               # Phase 11 — off by default, see decisions table
  enabled: false
  start_hour: 23               # 0-23, local to server.tz; wraps midnight if > end_hour
  end_hour: 5
  check_interval_minutes: 30

notifications:                # Phase 11 — Discord webhook on idle/night auto-stop
  discord_webhook_url_env: DISCORD_WEBHOOK_URL   # names an env var; unset/empty = disabled

users_file: /app/users.env   # <NAME>_PASSWORD_HASH entries, set via `crowsnest set-password`

games:
  - id: windrose
    display_name: Windrose
    container_name: windrose
    compose_file: /windrose/compose.yaml
    compose_profile: windrose
    compose_service: windrose
    env_file: /windrose/.env
    windrose:
      http_api_url: http://host.docker.internal:8780
      rcon_password_env: WINDROSE_PLUS_RCON_PASSWORD

  - id: valheim
    display_name: Valheim
    container_name: valheim
    compose_file: /valheim/compose.yaml
    compose_profile: valheim
    compose_service: valheim
    env_file: /valheim/.env
    night_shutdown: false     # e.g. a remote friend group spanning time zones

  - id: palworld
    display_name: Palworld
    container_name: palworld
    compose_file: /palworld/compose.yaml
    compose_profile: palworld
    compose_service: palworld
    env_file: /palworld/.env
    palworld:
      rest_api_url: http://palworld:8212
      rest_api_user: admin
      rest_api_password_env: PALWORLD_ADMIN_PASSWORD
```

Adding a 4th game later means adding a registry entry + a new
`internal/games/<name>` package — no changes to `internal/web`,
`internal/exclusivity`, or `internal/idleshutdown`.

## Auth

Direct port of the original design, generalized to N users:

- Passwords: bcrypt (`golang.org/x/crypto/bcrypt`), one `<NAME>_PASSWORD_HASH`
  entry per user in `users_file`. `crowsnest set-password <username>` writes
  the hash (replaces `set_password.py`).
- Sessions: stateless signed cookie — `base64(json{user, issued_at, expiry})`
  + HMAC-SHA256 tag, verified on every request. No server-side session store.
- CSRF: token carried in the session payload, required on state-changing
  POSTs via `X-CSRF-Token` header or hidden field, compared with
  `hmac.Equal`. `/login` is exempt (it creates the token).
- Rate limiting: in-memory sliding window per IP, honoring `X-Forwarded-For`
  only from trusted proxy CIDRs (same list as the original).
- Security headers (CSP w/ per-request nonce, X-Frame-Options, etc.) applied
  as middleware, same policy as the original.

## Docker control (`internal/dockerctl`)

Thin wrapper around `exec.CommandContext`, one function per operation, all
with timeouts and structured errors — no bespoke logic anywhere else in the
codebase shells out directly:

```go
Start(ctx, GameDef) error   // docker start <name>, or
                             // docker compose -f <file> --profile <p> up -d <svc>
                             // if the container doesn't exist yet
Stop(ctx, GameDef) error    // docker stop <name>
Running(ctx, name) (bool, error)
StartedAt(ctx, name) (time.Time, error)   // docker inspect .State.StartedAt
Exec(ctx, name, args...) (stdout string, err error)  // e.g. grep a log marker in-container
Logs(ctx, name, since string) (io.ReadCloser, error)  // docker logs -f --since
Stats(ctx, name) (CPUPercent, MemUsed, MemTotal string, err error)
```

`StatusChecker` implementations call `Running` + (optionally) `Exec` for a
log-marker grep, same pattern as the original Windrose status check.

## Exclusivity guard (`internal/exclusivity`)

- `Manager` wraps a `sync.Mutex`, the `games.Registry`, and `dockerctl`.
- `ActiveGame(ctx) (id string, ok bool)` — which registered game (if any) is
  currently running/starting.
- `RequestStart(ctx, id) error` — if another game is active, returns a typed
  `*ConflictError{Active: otherID}`; the handler surfaces this as HTTP 409
  with `{"conflict": true, "active_game": "valheim"}` so the frontend can
  prompt "Valheim is running — stop it and start Palworld?" (per the README's
  stated behavior).
- `ConfirmSwitch(ctx, from, to)` — stop `from`, poll until it's actually
  offline (bounded wait), then start `to`. Serialized by the mutex so two
  concurrent requests (two browser tabs) can't race into both containers
  running at once.
- `Stop(ctx, id)` — plain stop, no guard needed.

## Idle auto-stop (`internal/idleshutdown`)

Simpler than the original's overnight cron window — runs continuously,
triggers 15 minutes after a game goes empty, not tied to time of day:

1. Ticker every `check_interval_seconds` (default 60s).
2. For each `GameDef` that is `StatusOnline` and has a `PlayerCounter`:
   - `ok=false` (count undeterminable) → treat as "can't tell," never assume
     zero, skip this tick. Same safety rule as the original.
   - count > 0 → record `lastNonZero[id] = now`.
   - count == 0 and `now - lastNonZero[id] >= idle_minutes` → call
     `exclusivity.Stop(id)`, log it.
3. On a game's transition to `StatusOnline`, seed `lastNonZero[id] = now` so a
   freshly started empty server gets the full grace period, not an instant
   shutdown.
4. A game whose `PlayerCounter` always returns `ok=false` (not yet wired,
   see Phase 10) simply never idle-shuts-down — safe by construction.

Discord notification on auto-stop is deferred (tracked in Phase 11 below);
the manager should log at `info` level so it's not silent in the meantime.

## HTTP surface

```
GET   /login                          POST /login          POST /logout
GET   /                               dashboard — cards for all games
GET   /api/games                      summaries + live status, for polling
GET   /api/games/{id}/status
POST  /api/games/{id}/start           409 + conflict payload if another game active
POST  /api/games/{id}/switch          body: {from}; stop `from`, start `id`
POST  /api/games/{id}/stop
GET   /api/games/{id}/logs            SSE
GET   /api/games/{id}/startup-progress SSE
GET   /api/games/{id}/stats           docker stats (+ GPU via nvidia-smi if present)
GET   /api/games/{id}/players         {"available", "count", "names"} — Phase 10
GET   /api/games/{id}/info            optional rich panel — Windrose only as of Phase 10;
                                       {"available": false} for any game without one wired
GET   /healthz                        (exists)
```

## Per-game strategy plan

Windrose is a direct port of proven Python logic — low risk. Valheim and
Palworld were new integrations built in Phase 10 against public
documentation rather than the original app (which is Windrose-only) —
flagged below where that's still unverified against a real running server.

| | Windrose | Valheim (`lloesche/valheim-server`) | Palworld (`thijsvanloef/palworld-server-docker`) |
|---|---|---|---|
| **Status** | ✅ Done (Phase 7): ported from the original's actual logic — `docker ps` running, then in-container `grep -q "Host server is ready for owner to connect" R5.log` for starting-vs-online. (Earlier draft of this row said `WaitingForFirstAccount`; corrected after reading the real source.) | ⚠️ Still the Phase 3 baseline (`games.DockerStatusChecker`: docker-ps only, no starting/online nuance) — no ready-log-line marker has been confirmed for this image, so Phase 10 did not guess one. Spike still open. | ✅ Done (Phase 10): `palworld.Client.Check` — offline when the container isn't running, online once `GET /v1/api/info` responds, starting in between. Not yet exercised against a real Palworld server. |
| **Players** | ✅ Done (Phase 10): `windrose.Client` — direct port of the original's Windrose+ HTTP API (`/api/status`) with RCON (`wp.connections`) fallback in degraded mode, 4s-TTL cached, stale-snapshot detection via `docker inspect` StartedAt. Live-verified against a fake Windrose+ server. | ✅ Done (Phase 10), **unverified against a real server**: `valheim.Tracker` tails `docker logs -f` continuously, tracking `"Got handshake from client <id>"` (join) / `"Closing socket <id>"` (leave) — log lines documented by the `lloesche/valheim-server-docker` community, not confirmed firsthand. `ok=false` until a log stream is attached; a restart resets tracked state (no way to know who was connected before attaching). | ✅ Done (Phase 10): REST API (`REST_API_ENABLED=true`) → `GET /v1/api/players`, basic auth. Not yet exercised against a real Palworld server. |
| **Logs** | ✅ Done (Phase 6): plain pass-through, same as every other game — **correction:** the original has no UE-specific log-line regex parser; `/api/logs` there is just `docker logs -f` piped straight through. This row previously overstated what exists to port. | Pass-through initially, refine after log samples | Pass-through initially, refine after log samples |
| **Startup milestones** | ✅ Done (Phase 7): single milestone (0% → 100% "Host server ready" on the same grep marker above) — **correction:** the original has no 11-step table; it only ever shows a pulsing "starting" badge. This row previously overstated what exists to port. | Placeholder 2–3 step table until log samples collected | Placeholder 2–3 step table until log samples collected |
| **Extra info panel** | ✅ Done (Phase 10): `windrose.Client.Info` — world time/weather/multipliers/connections/memory via concurrent RCON, uptime via `docker inspect`, generic key/value UI panel (`GET /api/games/{id}/info`). | None | None |

## Phased delivery

1. ~~Scaffolding~~ — done: `/healthz`, `games.GameDef` types, Dockerfile with
   Docker CLI + compose plugin staged, CI.
2. ~~`internal/config` (YAML load/validate) + `internal/dockerctl` (CLI
   wrapper with unit tests against a fake `docker` script on `PATH`).~~ —
   done.
3. ~~Wire all 3 games into a `games.Registry` with minimal `StatusChecker`s
   (docker-ps-only: offline/online, no "starting" nuance yet) — start/stop
   works end-to-end for all three, no rich data yet.~~ — done.
4. ~~`internal/auth` (users file, bcrypt, signed-cookie sessions, CSRF, rate
   limit) + `crowsnest set-password` subcommand.~~ — done.
5. ~~Dashboard UI (`html/template` + `embed.FS`) — game cards, start/stop,
   status polling; exclusivity guard + switch-confirmation flow wired
   end-to-end.~~ — done.
6. ~~SSE log streaming — generic pass-through formatter for all games, then
   Windrose's real UE log parser.~~ — done, see correction above: no real
   per-game log parser exists to port, so it's pass-through for all three
   (`internal/sse`, `games.PassthroughFormatter`,
   `GET /api/games/{id}/logs`).
7. ~~Startup-progress SSE + Windrose's real milestone table; placeholders for
   the other two.~~ — done, see correction above: Windrose gets one real
   milestone (not 11), Valheim/Palworld get a clean `unsupported` SSE event
   instead of a placeholder table since there's nothing real to place there
   yet (`internal/games/windrose`, `GET /api/games/{id}/startup-progress`).
8. ~~`docker stats` resource panel (+ GPU via `nvidia-smi` if present).~~ —
   done: ported from `_get_stats_uncached()` in
   `/home/plex/projects/Windrose/CrowsNest/app.py` (lines ~1107-1181),
   generalized to per-game containers with host-wide GPU stats
   (`internal/dockerctl.GPUStats`, `GET /api/games/{id}/stats`). No TTL
   cache — unlike the original, nothing else in this Go rewrite caches
   docker calls yet, and the panel only polls while open.
9. ~~`internal/idleshutdown` (15-minute-empty auto-stop).~~ — done. Currently
   a safe no-op for all three games since every `PlayerCounter` is still
   `games.UnknownPlayerCounter{}` (`ok=false` always) until Phase 10 wires
   real ones in.
10. ~~Real per-game integrations: Windrose+ HTTP/RCON port, Palworld REST
    API, Valheim log-based player tracking.~~ — done, with one spike still
    open: Valheim's real status/startup log markers were not confirmed (see
    table above), so it still uses the Phase 3 baseline `StatusChecker`.
    Everything else landed: `internal/games/windrose.Client` (players +
    info), `internal/games/palworld.Client` (status + players),
    `internal/games/valheim.Tracker` (players via log tailing), plus the
    new `GET /api/games/{id}/players` and `GET /api/games/{id}/info`
    endpoints and a dashboard player-count badge + generic Info panel.
11. ~~Discord webhook notification on auto-stop (original's
    `send_discord_notification()`, app.py lines ~731-748); revisit whether a
    time-window ("night shutdown") mode is still wanted alongside idle-stop
    (original has a full APScheduler-based night-shutdown window, app.py
    lines ~774-916).~~ — done: the earlier "not planned" decision was
    revisited on 2026-09-12 and reversed — both landed. `internal/notify`
    (a small `Discord.Notify`, inert until a webhook URL resolves) is shared
    by `internal/idleshutdown` and the new `internal/nightshutdown`.
    Night-shutdown re-checks a configured hour window on its own ticker
    (no cron dependency) and stops an online, empty, night-shutdown-eligible
    game on the spot — no grace period, unlike idle-stop, since the window
    itself is the grace period. Both mechanisms can cover the same game
    independently; a game opts out of night-shutdown alone via
    `games[].night_shutdown: false`.
12. ~~Polish: `config.yaml.example`, `compose.yaml.example` for the new
    multi-game stack, docs.~~ — done, with one correction: the "Docker Hub
    publish workflow (mirrors the original `dockerhub-publish.yml`)" item
    was dropped. That file was never real — the original's Docker Hub
    references (`app.py` ~1255-1319) are an unrelated feature (checking for
    a newer *game server* image, not publishing CrowsNest's own), and no
    such workflow exists anywhere in either repo's git history. Asked the
    user on 2026-09-12 whether to build a from-scratch publish workflow
    anyway; they chose to skip it for now rather than commit to a Docker Hub
    namespace/secrets setup that wasn't otherwise called for.

## Where things stand (last updated 2026-09-12)

Phases 1-12 are implemented and tested (`go build/vet/gofmt/test` clean
across all packages, including the three per-game packages from Phase 10
and the two new packages from Phase 11 — see below). Phase 10
was manually smoke-tested end-to-end against real Docker containers plus
small fake HTTP servers standing in for the Windrose+ and Palworld REST
APIs (neither real game image was available in this environment):
`/api/games` correctly reported `player_count: 2` for Windrose (from a fake
`/api/status`) and `1` for Palworld (from a fake `/v1/api/players`);
`/api/games/windrose/info` returned the full RCON-derived panel (time,
weather, connections, memory, multipliers, per-player coordinates); killing
the fake Palworld server made both its status correctly degrade to
`starting` and its players correctly report `available: false` (never a
guessed zero); and — the one test using a real, unmodified container — a
busybox container had lines echoed directly onto its own stdout
(`docker exec ... >> /proc/1/fd/1`, so they appear in `docker logs -f` like
a real process would emit them), and `valheim.Tracker`'s live count moved
from 0 → 1 → 0 across a real `Got handshake from client` / `Closing socket`
pair, tailed through the actual `docker logs -f` subprocess. All smoke-test
containers, fake servers, and scratch files were removed afterward.

**Two things remain explicitly unverified** because no real Valheim or
Palworld server was available to test against (see the strategy table
above): Valheim's status detection is still the Phase 3 docker-ps-only
baseline (no confirmed ready-log marker, so Phase 10 didn't guess one), and
both new integrations' request/response shapes come from public
documentation rather than a firsthand-observed server. Anyone standing
these up for real should watch the logs on first run.

Phase 11 is also done (`go build/vet/gofmt/test` clean, including the two
new packages) — not smoke-tested against real Discord or a running game
server, since it needs no live game integration to exercise: unit tests
cover the window math (midnight wrap, same-day window), the safety rules
(never stop on an undeterminable player count or a not-confirmed-online
game), per-game opt-out, and the webhook's URL-prefix guard and no-op
behavior when unconfigured.

Phase 12 is done: `config.yaml.example` and `compose.yaml.example` give a
runnable starting point for the multi-game stack (single shared compose file
with per-game profiles, matching `internal/dockerctl`'s
`docker compose -f ... --profile ... up -d ...` invocation), and the README
was rewritten from its "early scaffolding" placeholder to describe the
finished feature set, running instructions, and HTTP API table. All 12
originally-scoped phases are now complete.

Key new pieces from phase 11, for orientation:
- `internal/notify.Discord` — direct port of the original's
  `send_discord_notification()` (app.py lines ~731-748): POSTs
  `{"content": message}` to a webhook URL, validated against the
  `https://discord.com/api/webhooks/` prefix, silently a no-op on a nil
  receiver, an empty URL, or a request/response failure — a broken or
  unconfigured notifier must never fail the stop it's reporting on. Shared
  by both shutdown managers via a small `Notifier` interface each package
  declares locally (avoids a dependency between idleshutdown and
  nightshutdown just for one method's shape).
- `internal/nightshutdown.Manager` — generalizes the original's
  Windrose-only APScheduler cron job (app.py lines ~774-916) to every
  registered game: a plain ticker (`check_interval_minutes`, default 30)
  re-checks an hour window (`start_hour`/`end_hour`, wrapping midnight when
  `start_hour > end_hour`) local to `server.tz`; inside the window, an
  online game with a confirmed zero player count is stopped immediately
  (no grace period — the window itself is the grace period) and, on
  success, `Notifier.Notify`'d. A confirmed-nonzero count or an
  undeterminable one (`PlayerCounter` ok=false) both skip the game for that
  tick, same safety rule as idle-shutdown. Off by default
  (`night_shutdown.enabled: false`) — see the decisions table: a preset
  curfew is a stronger, more surprising behavior than idle-stop, and this
  app's multi-game/multi-timezone households don't share the original's
  single-user assumption that made an always-on curfew safe to default to.
  A game opts out individually via `games[].night_shutdown: false`
  (`games.GameDef.NightShutdown`, already scaffolded in Phase
  1's `types.go` ahead of this phase landing it).
- `internal/idleshutdown.Manager` gained an optional `Notifier` field, used
  the same way — notified once per triggered stop, right after a
  successful `Stop`, with the game's `DisplayName` and idle duration in the
  message.
- `internal/config` — new `night_shutdown` and `notifications` top-level
  blocks (see the Config model above) plus `server.tz` is now validated at
  load time (`time.LoadLocation`) instead of only being resolved later,
  since both shutdown windows now depend on it being correct.
- `cmd/crowsnest/main.go`'s `serve()` constructs one `*notify.Discord` (its
  `WebhookURL` empty unless `notifications.discord_webhook_url_env` names a
  set env var) and hands it to both managers; night-shutdown is launched as
  its own goroutine exactly like idle-shutdown, independently gated on
  `night_shutdown.enabled`.

Key new pieces from phase 10, for orientation:
- `internal/games/windrose.Client` — direct port of the original's
  Windrose+ HTTP API integration (app.py lines ~339-728): cookie-session
  `/login`, 4s-TTL-cached `/api/status`, concurrent RCON (`/api/rcon`) for
  the info panel, stale-snapshot detection against the container's
  `docker inspect` StartedAt. Implements both `games.PlayerCounter` and
  `games.InfoProvider`. Wired in `main.go` only when the game's config has
  a `windrose:` block (`http_api_url` + `rcon_password_env`, the latter
  naming an env var rather than embedding the secret in YAML).
- `internal/games/palworld.Client` — implements both `games.StatusChecker`
  (docker-ps for offline, `GET /v1/api/info` reachability for
  online-vs-starting) and `games.PlayerCounter` (`GET /v1/api/players`,
  basic auth). Wired in `main.go` only when the game's config has a
  `palworld:` block.
- `internal/games/valheim.Tracker` — implements `games.PlayerCounter` by
  running its own `Run(ctx)` goroutine (launched unconditionally for the
  `valheim` game ID in `main.go`) that tails `docker logs -f` forever,
  re-attaching after any gap and resetting tracked state on every
  re-attach (a fresh attach can't know who connected before it started
  watching). `PlayerCount` reports `ok=false` until a stream is attached.
- `internal/web/app.go` — `GET /api/games/{id}/players`
  (`{"available", "count", "names"}`) and `GET /api/games/{id}/info`
  (whatever map `games.InfoProvider.Info` returns, or `{"available":
  false}`); `/api/games` gained a nullable `player_count` field. Dashboard
  gained a player-count badge next to the status pill (hidden when
  undeterminable) and a generic toggleable Info panel — a flat key/value
  list built from whatever fields the response has, deliberately not
  Windrose-specific markup, so it works unchanged for any future
  `InfoProvider`.

Key new pieces from phase 9, for orientation:
- `internal/idleshutdown.Manager` — `New(registry, stopper, idleDuration,
  checkInterval)`, `Run(ctx)` (ticks forever) and `Tick(ctx)` (one pass,
  exported for tests). `Stopper` is a 1-method interface
  (`Stop(ctx, id) error`) satisfied directly by `*exclusivity.Manager` — no
  adapter needed. Tracks only `lastNonZero map[string]time.Time`; a game's
  entry is seeded the tick it's first observed online and deleted the
  moment it's not confirmedly online, so a restarted game always gets a
  fresh grace period rather than inheriting stale idle time.
- Wired in `cmd/crowsnest/main.go`'s `serve()`: launched as its own
  goroutine (`go idle.Run(context.Background())`) whenever
  `idle_shutdown.enabled` is true (the config default); the process has no
  graceful-shutdown machinery yet, so the goroutine simply ends with the
  process — matches the rest of the codebase's current lifecycle handling.

Key pieces from phase 8, for orientation:
- `internal/dockerctl.Client.GPUStats` — host-level (not per-container)
  nvidia-smi query; `ok=false` on any failure (no GPU, binary missing,
  unparseable output) rather than an error, matching the original's silent
  try/except. Configurable via `NvidiaSmiBin` for tests, same pattern as
  `DockerBin`.
- `internal/web/app.go` — `handleStats` / `statsResponse`, routed as
  `GET /api/games/{id}/stats`. Each field is a `*string`, nil when
  undeterminable (container not running, no GPU), never an error — the
  dashboard renders "N/A" per-field instead of failing the whole panel.
- Dashboard (`dashboard.html`/`style.css`/`app.js`) has a per-card toggleable
  Stats panel (CPU/Mem always shown, GPU rows hidden when absent) that polls
  every 3s while open; bar fill color follows a good/warn/danger threshold
  (70%/90%, reusing the existing `--online`/`--starting`/`--danger` tokens)
  — no charting library, just the same thin-bar pattern as the startup
  progress bar.

Key pieces from phases 6-7, for orientation:
- `internal/sse` — `Writer` (`NewWriter`, `WriteEvent`, `WriteComment`), used
  by both streaming endpoints.
- `internal/web/streaming.go` — `handleLogs` and `handleStartupProgress`,
  both routed in `internal/web/app.go`'s `Routes()`.
- `internal/games/windrose` — `StatusChecker` + `Startup` matcher, wired
  in only for `id == "windrose"` in `cmd/crowsnest/main.go`'s `serve()`
  (import-cycle reasons: `internal/games` can't import
  `internal/games/windrose`, so the per-game override lives in `main.go`,
  which can import both).
