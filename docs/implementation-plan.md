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
GET   /api/games/{id}/players
GET   /api/games/{id}/info            optional rich panel; empty until wired (Phase 10)
GET   /healthz                        (exists)
```

## Per-game strategy plan

Windrose is a direct port of proven Python logic — low risk. Valheim and
Palworld are new integrations and need a short log/API spike each before
Phase 10 can be implemented for real; flagged below.

| | Windrose | Valheim (`lloesche/valheim-server`) | Palworld (`thijsvanloef/palworld-server-docker`) |
|---|---|---|---|
| **Status** | ✅ Done (Phase 7): ported from the original's actual logic — `docker ps` running, then in-container `grep -q "Host server is ready for owner to connect" R5.log` for starting-vs-online. (Earlier draft of this row said `WaitingForFirstAccount`; corrected after reading the real source.) | ⚠️ Spike: confirm the log line the image emits on "ready" (candidate: watchdog "connected" message) | ⚠️ Spike: confirm ready log line, or poll the REST API once reachable |
| **Players** | Port directly: Windrose+ HTTP API (`/api/status`) with RCON (`wp.connections`) fallback, TTL-cached | ⚠️ Spike: no first-party API; default plan is parsing join/leave lines from `docker logs` (same technique as status detection) rather than A2S UDP query, since A2S support on non-Source engines needs verification first | REST API (`REST_API_ENABLED=true`) → `GET /v1/api/players`, basic auth |
| **Logs** | ✅ Done (Phase 6): plain pass-through, same as every other game — **correction:** the original has no UE-specific log-line regex parser; `/api/logs` there is just `docker logs -f` piped straight through. This row previously overstated what exists to port. | Pass-through initially, refine after log samples | Pass-through initially, refine after log samples |
| **Startup milestones** | ✅ Done (Phase 7): single milestone (0% → 100% "Host server ready" on the same grep marker above) — **correction:** the original has no 11-step table; it only ever shows a pulsing "starting" badge. This row previously overstated what exists to port. | Placeholder 2–3 step table until log samples collected | Placeholder 2–3 step table until log samples collected |
| **Extra info panel** | Port directly: world time/weather/multipliers/memory via RCON | None initially | None initially |

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
8. `docker stats` resource panel (+ GPU via `nvidia-smi` if present). The
   original app already has this fully built and directly portable:
   `_get_stats_uncached()` in
   `/home/plex/projects/Windrose/CrowsNest/app.py` (lines ~1107-1181).
9. `internal/idleshutdown` (15-minute-empty auto-stop), active for whichever
   games have a working `PlayerCounter` at that point. Currently a safe
   no-op for all three games since every `PlayerCounter` is still
   `games.UnknownPlayerCounter{}` until Phase 10.
10. Real per-game integrations: Windrose+ HTTP/RCON port (original's
    `get_player_info()` / `get_windrose_info()` / RCON functions, app.py
    lines ~557-728), Palworld REST API, Valheim log-based player tracking +
    real status/startup log markers — the two ⚠️ spikes above happen here,
    against the actual running images.
11. Deferred: Discord webhook notification on auto-stop (original's
    `send_discord_notification()`, app.py lines ~731-748); revisit whether a
    time-window ("night shutdown") mode is still wanted alongside idle-stop
    (original has a full APScheduler-based night-shutdown window, app.py
    lines ~774-916 — currently NOT planned to be ported, per explicit
    earlier decision).
12. Polish: Docker Hub publish workflow (mirrors the original
    `dockerhub-publish.yml`), `config.yaml.example`, `compose.yaml.example`
    for the new multi-game stack, docs.

## Where things stand (last updated 2026-09-11)

Phases 1-7 are implemented, tested (`go build/vet/gofmt/test` clean across
all 9 packages), and manually smoke-tested end-to-end against a real Docker
container (busybox standing in for a game server, writing to Windrose's real
log path) — starting→online transition timing, plain log passthrough,
milestone-matched `progress` SSE event, and the `unsupported` fallback for
games without a `StartupMatcher` were all confirmed working, then fully
cleaned up.

**Phase 8 (`docker stats` panel) is the natural next step.** No code for it
exists yet. The repo has zero git commits so far (by design — commits only
happen on explicit request); `git status` shows only untracked top-level
dirs/files, nothing partially done or in a broken state.

Key new pieces from phases 6-7, for orientation:
- `internal/sse` — `Writer` (`NewWriter`, `WriteEvent`, `WriteComment`), used
  by both new endpoints.
- `internal/web/streaming.go` — `handleLogs` and `handleStartupProgress`,
  both routed in `internal/web/app.go`'s `Routes()`.
- `internal/games/windrose` — `StatusChecker` + `Startup` matcher, wired
  in only for `id == "windrose"` in `cmd/crowsnest/main.go`'s `serve()`
  (import-cycle reasons: `internal/games` can't import
  `internal/games/windrose`, so the per-game override lives in `main.go`,
  which can import both).
- Dashboard (`dashboard.html`/`style.css`/`app.js`) now has a live progress
  bar (visible only while a game's status is "starting") and a toggleable
  live log panel per game card.
