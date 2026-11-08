# CrowsNest — Roadmap / Hit List

Findings from a full-repo review (2026-09-12), covering the whole app —
auth, web, dockerctl, per-game integrations, and deploy story. Items are
grouped by priority, not phase; check them off as they land.

## Done

- [x] **Pinned container addresses in guard scopes; game wiring extracted;
  golden tests (2026-11-08).** A `GUARD_SCOPES` entry may carry
  `"ipv4": {"<network>": ["a.b.c.d"]}`: the exact addresses that container may
  take on that network (needed for a macvlan container that a host firewall
  rule must name). Without a pin every fixed address is still refused; bad pins
  (unspecified, loopback, multicast, link-local, non-canonical, network not in
  `networks`) stop the guard starting. Network ids resolve to the scope's
  network name before the pin is checked. Also: the per-game wiring in
  `serve()` moved unchanged into `buildGameDefs`, and `cmd/crowsnest` has
  golden tests (`testdata/*.golden.json`, regenerate with `-update`) pinning the
  production games' strategies, exec rules and guard scopes. This is phase 0 of
  the modular-games rework.

- [x] **Go scoped Docker API guard (2026-11-08).** `crowsnest guard` is a
  port of the Python guard's scoped mode (`GUARD_SCOPES`: per-container image,
  exact bind, volume, network, port, label, alias, secopt, cap_add and exec
  allowlists), so the stack no longer needs the labdash-worker image. It
  refuses to start without a valid config, validates create bodies against an
  allowlist, filters container/image/network/volume lists and inspects,
  redacts `/info`, tracks exec ids, rebuilds every request target for the
  engine, and tunnels exec start and log-follow streams. It also supports
  compose's recreate (create `<old id12>_<name>`, delete the stopped old
  container, rename), which the Python guard refused. Stricter than the Python
  in a few places (see `internal/dockerguard` tests). execguard stays a
  separate layer in front of it.

- [x] **Log-followed Windrose status, non-blocking dashboard, quiet tabs
  (2026-11-08).** Windrose readiness now comes from a `windrose.Tracker`
  following `docker logs -f` (like Valheim's), so the Windrose `docker exec`
  rule is gone from the exec guard (only backup commands remain). The
  dashboard page renders from the last cached snapshot (`memo.Peek`) or a
  neutral "checking..." badge instead of waiting on every game probe; the JS
  refreshes statuses on load. All network pollers in `app.js` go through a
  `poll()` helper that skips hidden tabs and refreshes on return. Removed the
  unused `env_file` config field (old configs still load).

- [x] **Docker reads over the Engine API; Windrose+ 1.3 player counts
  (2026-11-08).** `dockerctl` Ping/Exists/Running/StartedAt/FinishedAt/
  Stats/Logs talk HTTP to the daemon or proxy instead of running the docker
  CLI (compose up/pull, stop and exec stay on the CLI). Measured through
  execguard + the scoped guard: ~3 ms per status call (CLI: ~61 ms), stats
  ~6 ms after the first reading (CLI: 1-2 s, it samples twice). Windrose+
  1.3.x leaves `mode` out of normal status snapshots, which CrowsNest read as
  "boot" and so never counted Windrose players (idle shutdown never stopped
  it); an empty mode now counts as a live reading (stale snapshots are still
  rejected). Verified against a real Windrose+ 1.3.28 server.

- [x] **Roles, activity log, host health, backups (2026-11-07).** Roles:
  `<NAME>_ROLE=admin|player` in the users file (no role = admin),
  `crowsnest set-role`, players can't open settings or backups, role looked up
  per request so demotion is immediate. Activity log: `internal/history`
  JSONL (`server.history_file`, 180-day retention), logbook + playtime on the
  dashboard, `/api/activity`. Host strip: memory/load/disk
  (`server.host_disk_paths`, `/api/host`). Backups: per-game
  `backup: {exec, list_dir, before_stop}` run via `docker exec`
  (`internal/backup`), admin-only panel, optional backup after the pre-stop
  save. **Untested against real containers:** the Palworld `backup` command and
  `/palworld/backups` path in the example are from memory; the socket proxy
  needs `EXEC=1`.
  Still open from the review list: scheduled starts and Discord slash commands
  (both deferred).

- [x] **Exec guard and admin console (2026-11-07).** `crowsnest execguard`
  allowlists `docker exec` to exactly the commands config implies, in front of
  docker-socket-proxy. Palworld gets an admin-only Console tab: fixed REST
  actions plus a raw RCON box behind an admin setting (`raw_console`, off by
  default); every command is audited. **Untested against a real daemon/server:**
  exec upgrade through the guard, Palworld RCON replies.

- [x] **Review follow-up (2026-11-07).** (1) Stop and Switch are background
  operations like Start (`RequestStop`/`RequestSwitch`, new `stopping` status,
  the decision lock is no longer held across `docker stop`, switch target is
  reserved so a third game can't take its slot). (2) Night shutdown spares a
  game up for less than `night_shutdown.min_uptime_minutes` (30). (3) Status,
  players, stats and info probes are shared per game for 2s across tabs
  (`internal/memo`). (4) `/api/health` + dashboard banner when Docker is
  unreachable; clients no longer get raw docker/compose errors. (5) Users file
  hot-reloads (`set-password`/`revoke-sessions` apply in seconds), settings
  saves are atomic (`Store.Modify`), games with no player counter log a
  warning, shutdown waits for background operations. Features: Palworld
  announces and saves before any stop (`games.StopPreparer`); Discord
  join/leave messages (`internal/playerwatch`, `notifications.player_events`).

- [x] **Production blockers for running compose from inside the container
  (2026-11-06).** Confirmed with `docker compose config` run the way
  CrowsNest runs it: (1) `${VALHEIM_SERVER_PASS:?}` aborted *every* game's
  start, because compose interpolates the whole file; (2) `.env` wasn't
  mounted, so `USERDIR` was blank (saves at `/Palworld` on the host root)
  and the Palworld server password was empty; (3) the project name
  defaulted to `data`, putting games on a different network than
  crowsnest, so `http://palworld:8212` never resolved. Fixed in
  `compose.yaml.example` / `.env.example` (`name:`, `.env` mounted at
  `/data/.env`, no `:?`, 8212 no longer published, 60s Palworld grace
  period, `COMMUNITY=false`, backup pruning).
- [x] **Async start, decoupled from the HTTP request (2026-11-06).**
  `exclusivity.Manager` runs `docker.Start` in the background under
  `BaseContext` (30 min limit); in-flight starts count as active, Stop
  cancels them, results show on `/api/games` (`start_error`) and as a
  dashboard toast. Replaces "consider a longer start timeout".
- [x] **Start always uses `compose up` when a compose file is configured**,
  so compose/.env changes are applied instead of `docker start` silently
  keeping a stale container.
- [x] **Restart cooldown counts every stop**: also reads the container's
  `State.FinishedAt`, so crashes, external `docker stop`s and stops from
  before a CrowsNest restart count. (Idle/night auto-stops already went
  through `Manager.Stop`.)
- [x] **Stop timeout 60s → 5m**, above every game's `stop_grace_period`
  (Valheim's is 2m, which used to make its Stop/Switch report a failure).
- [x] **Palworld REST credential failures are logged** once per failure
  streak, instead of silently leaving the game on "starting" with idle stop
  disabled.
- [x] **Security pipeline + gated releases (2026-11-06).** `ci.yml` (PRs,
  weekly, and the gate inside `publish.yml`) runs gosec, govulncheck,
  gitleaks, Trivy fs and a Trivy image scan, with SARIF to code scanning;
  CodeQL stays in `codeql.yml`. `publish.yml` replaces `docker-publish.yml`
  with an auto-versioned release scheme: scan before push (fixable HIGH/CRITICAL
  blocks the release), multi-arch, SBOM + provenance, cosign keyless
  signature, attestation, GitHub Release. See `docs/publishing.md`.
  Supersedes the earlier "not gating on Trivy" decision.
- [x] **Vulnerabilities fixed (2026-11-06).** Go 1.23.5 → 1.26.10 (13
  reachable stdlib CVEs), `golang.org/x/crypto` v0.38.0 → v0.58.0 (20
  advisories, not reached), docker CLI 27 → 29.9.3, alpine 3.20 → 3.24.4,
  and the compose plugin rebuilt from v5.7.0 source with x/net v0.62.0
  (CVE-2026-78661 HIGH, CVE-2026-97045 MEDIUM). Image: 0 known vulns at any
  severity. gosec's 8 medium findings were all false positives, annotated
  with `#nosec Gxxx -- reason`.
- [x] **Pick which game to stop at the limit; connect details on cards;
  Discord on manual start/stop/switch and failed starts; windrose test race
  fixed (2026-11-06).**

- [x] **Configurable concurrent-server limit (2026-09-30).** The
  one-game-at-a-time guard is now `exclusivity.Manager.MaxActive`, default 1,
  set from `server.max_active_games` or the `CROWSNEST_MAX_ACTIVE_GAMES`
  env var (`.env` → compose → CrowsNest; env wins). At the limit, Start
  returns 409 listing the active games and the UI offers to switch. Verified
  against real containers: Start with Valheim up → 409; Switch Valheim →
  Palworld stopped one and started the other. Files:
  `internal/exclusivity/exclusivity.go`, `internal/config/config.go`,
  `cmd/crowsnest/main.go`, `.env.example`, `compose.yaml.example`.

- [x] **Palworld restart cooldown (2026-09-30).** `GameDef.RestartCooldown`
  (30s for Palworld) makes Start return 429 + `Retry-After` shortly after a
  Stop; the UI toasts it. Guards against the segfault seen when Palworld is
  restarted seconds after stopping.

- [x] **Valheim status, progress bar and log scoping (2026-09-30).** Read
  from a real `lloesche/valheim-server` run (Valheim l-1.0.16): `Tracker` now
  implements `StatusChecker` (starting until `Loading: Done.`, then online),
  `valheim.Startup` drives the progress bar (SteamCMD download lines plus
  world-load milestones), and log tailing is scoped to the current run via
  `--since StartedAt` so a previous run's lines can't leak in.

- [x] **Palworld `/info` panel and startup progress; UI redesign
  (2026-09-30).** See commits `b3e0458` and `416ebbb`.

- [x] **`exclusivity.ActiveGame` fail-open on a status-check error let two
  games start concurrently.** Found during a 2026-09-12 deeper pass over
  cross-service interactions (auth/web/exclusivity/idle-night-shutdown).
  `ActiveGame` used to swallow a `Status.Check` error by treating that game
  as not active and continuing the scan — the opposite failure direction
  from idleshutdown/nightshutdown, which both already treat an
  undeterminable status as "assume active, never touch it." A transient
  docker/status hiccup (docker-socket-proxy blip, or Windrose's two-step
  `docker ps` + `docker exec` check racing a container that's mid-restart)
  on the currently-running game could make `RequestStart` for a *different*
  game see no conflict and start it too, defeating the single-active-game
  guarantee. `ActiveGame` now returns an error instead of silently skipping
  the failed check, and `startLocked` refuses to start (rather than
  proceeding) when it can't confirm no other game is active — fail closed,
  matching the rest of the codebase's philosophy. Files:
  `internal/exclusivity/exclusivity.go`,
  `internal/exclusivity/exclusivity_test.go`.

- [x] **Docker socket proxy support.** `dockerctl.Client.Host` (wired from
  the new `server.docker_host` config field) prepends `-H <host>` to every
  docker/compose invocation, so CrowsNest can run against a
  [Tecnativa docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy)
  instead of a raw `/var/run/docker.sock` mount, without touching anything
  else. `compose.yaml.example` has a commented-out `dockerproxy` service
  with the minimal permission set CrowsNest needs (documented there,
  including the EXEC caveat for Windrose's status check). Verified
  end-to-end against a real Tecnativa proxy on this machine: read-only ops
  (ps/inspect/stats) succeed, and a denied op (stop, with `POST=0`) comes
  back as a real 403 through the same code path. This is opt-in — the raw
  socket mount stays the default so nobody's existing setup breaks.

- [x] **CSP nonce is generated but never used — broke CSRF in real
  browsers.** The inline `<script>window.CROWSNEST_CSRF = ...</script>` in
  `dashboard.html` had no `nonce`, so `script-src 'self' 'nonce-<x>'` would
  have silently blocked it in any standards-compliant browser, leaving
  `window.CROWSNEST_CSRF` unset and every Start/Stop/Switch POST rejected
  with 403. Fixed by dropping the inline script entirely: the CSRF token is
  now delivered via `<meta name="csrf-token" content="{{.CSRFToken}}">` and
  read in `app.js` via `document.querySelector('meta[name=csrf-token]').content`
  — sidesteps CSP nonces, no per-template nonce plumbing needed.
  Files: `internal/web/templates/dashboard.html`, `internal/web/static/app.js`.

- [x] **`SecureCookies` is now wired up.** Added a `server.secure_cookies`
  config bool (`internal/config/config.go`), passed into
  `auth.Service.SecureCookies` in `main.go`, and `auth.SecurityHeaders` now
  takes an `hsts bool` param that sets `Strict-Transport-Security` when
  enabled. Documented in `config.yaml.example`. Still opt-in/off by default
  since most deployments are plain-HTTP LAN setups where a `Secure` cookie
  would never come back from the browser.
  Files: `internal/config/config.go`, `cmd/crowsnest/main.go`,
  `internal/auth/middleware.go`.

- [x] **Graceful shutdown.** `serve()` now derives a context from
  `signal.NotifyContext(os.Interrupt, syscall.SIGTERM)`, passes it to
  `idleshutdown.Run`, `nightshutdown.Run`, and `valheim.Tracker.Run` instead
  of `context.Background()`, and runs the HTTP server via `http.Server` so
  `docker stop crowsnest` triggers `srv.Shutdown` (10s timeout) instead of
  waiting out the grace period and getting SIGKILLed.
  Files: `cmd/crowsnest/main.go`.

- [x] **Request body size limits on unauthenticated/JSON endpoints.**
  `ServeLogin` and `handleSwitch` both now wrap `r.Body` with
  `http.MaxBytesReader` (4KB — both request shapes are a couple of short
  fields) before decoding, so an oversized body fails fast with 400 instead
  of letting `json.Decode` buffer arbitrarily large input.
  Files: `internal/auth/login.go`, `internal/web/app.go`.

- [x] **Capped concurrent SSE log streams.** `handleLogs` and
  `handleStartupProgress` each hold a `docker logs -f` subprocess open for
  the life of the connection; `App` now tracks an atomic counter and caps
  both handlers combined at `MaxConcurrentStreams` (default 20), returning
  503 once the cap is hit instead of letting forgotten tabs or a slow
  client accumulate subprocesses without bound.
  Files: `internal/web/streaming.go`.

- [x] **`auth.Limiter` prunes stale keys.** Added `Limiter.Prune` (drops
  every key with no hits inside the current window) and `RunPruner`, which
  calls it on a ticker until its context is cancelled; wired up in
  `main.go` as a background goroutine (10-minute interval) tied to the
  same shutdown context as everything else, so a long-lived process being
  probed from many distinct source IPs no longer accumulates map entries
  forever.
  Files: `internal/auth/ratelimit.go`, `cmd/crowsnest/main.go`.

- [x] **Audit log line per start/stop/switch action.** `handleStart`,
  `handleStop`, and `handleSwitch` now log
  `audit: <username> started/stopped/switched <game>` (or `... failed: err`
  on the error path) via the existing session in request context — enough
  to answer "who did what, when" from the process log without adding a
  datastore.
  Files: `internal/web/app.go`.

- [x] **Session revocation via per-user `ValidAfter` marker; shorter default
  TTL.** Given this deployment's actual scale (a couple of trusted users,
  short-lived sessions used only to start/stop/check a game server), a full
  server-side session store was overkill — instead: `DefaultSessionTTL`
  dropped from 24h to 3h, and `Users` gained an optional `ValidAfter`
  timestamp per user (`<NAME>_VALID_AFTER=<unix seconds>` in the users
  file). `SessionManager.Decode` rejects any session whose `IssuedAt`
  predates its user's `ValidAfter`. New CLI command
  `crowsnest revoke-sessions <username>` sets it to now, forcing that one
  user to re-authenticate everywhere without touching anyone else's
  session — takes effect on the next restart, same as `set-password`.
  Rotating the session-secret file remains the blunter "log out everyone"
  option. See `README.md`'s new "Sessions" section.
  Files: `internal/auth/session.go`, `internal/auth/users.go`,
  `internal/auth/login.go`, `cmd/crowsnest/main.go`.

- [x] **`healthcheck` ignored `server.addr`.** The Dockerfile's
  `HEALTHCHECK` invokes `crowsnest healthcheck`, which hardcoded
  `http://localhost:5000/healthz` regardless of the (documented,
  user-editable) `server.addr` config field — changing it to anything but
  `:5000` would leave the container permanently reporting unhealthy despite
  serving traffic fine. `healthcheck()` now loads config.yaml and derives
  the loopback host:port from `cfg.Server.Addr` (`healthcheckAddr`, handling
  `""`/`0.0.0.0`/`::` bind-all hosts by substituting `localhost`), falling
  back to `localhost:5000` only if config can't be loaded at all. Also
  closes the coverage gap that let this ship unnoticed: `cmd/crowsnest` was
  at 4.0% coverage (only the `/healthz` mux route was tested, not
  `healthcheck`/`setPassword`/`revokeSessions` themselves); new tests cover
  `healthcheckAddr`'s parsing, a same-process end-to-end regression test
  against a non-default port, the unhealthy/unreachable-backend paths, and
  `setPassword`/`revokeSessions` round-tripped through a real temp users
  file (29.4% coverage now).
  Files: `cmd/crowsnest/main.go`, `cmd/crowsnest/main_test.go`.

- [x] **CI didn't enforce `gofmt`.** `go vet`/`go build`/`go test` ran on
  every push, but nothing failed the build on unformatted code, despite
  "gofmt clean" being cited repeatedly as this project's quality bar.
  Added a `gofmt -l .` step ahead of `go vet` that fails the job and lists
  the offending files if any exist.
  Files: `.github/workflows/ci.yml`.

## High priority

(none currently — see Done)

## Medium priority

(none currently — see Done)

## Low priority / hygiene

(none currently — see Done)

## Considered, not doing

(none currently)

## Next up (picked up from the 2026-09-30 session)

- [ ] **Verify Windrose end-to-end in the new stack.** A three-game test
  stack is built, but the `indifferentbroccoli/windrose-server-docker` image
  was never pulled there, so Start timed out at the 120s `docker compose up`
  limit. Pull the image first, then check starting→online, logs, stats, and
  the Windrose+ player count/info panel (needs the RCON password from
  `windrose_plus.json`).
- [ ] **Migration from the Python version.** That stack uses
  `seccomp:unconfined` and `network_mode: host` for Windrose, a
  docker-socket-proxy and `127.0.0.1:5000`. The compose example now carries
  `seccomp:unconfined`; the rest is config.
- [ ] **Real player joins** for Valheim (join/leave log markers) and
  Palworld, plus a real Start→Switch between two games from the browser UI.
- [ ] **Multi-game behind a scoped Docker API guard.** A deployment can put
  CrowsNest behind a Docker API filter that allows only one container name
  and denies network create, container delete and rename. Running all three
  games that way needs the guard to accept a list of scopes (name →
  images/binds/netmodes/secopts). Windrose also needs `network_mode: host` +
  `seccomp:unconfined` in its scope, and Valheim a bind under its own dir.
- [ ] **Drop the compose-from-source Dockerfile stage** once a docker/compose
  release ships `golang.org/x/net` >= v0.62.0.
- [ ] Idle/night auto-stop and Discord notifications are still untested
  against real servers; firewall for `:5001`/game ports not checked.
- [ ] **Player access without router port forwards**, documented in
  [`docs/connecting.md`](docs/connecting.md): Palworld over a private overlay
  network (e.g. Tailscale), Valheim via `-crossplay` join codes, Windrose via
  its invite code. Follow-up idea: read the Valheim/Windrose codes out of the
  server logs and show them on the game cards.

## Tracking, not new — already flagged in `docs/implementation-plan.md`

- [ ] Valheim's join/leave log markers (`Got handshake from client` /
  `Closing socket`) are still unverified with a real player.
