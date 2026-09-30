# CrowsNest — Roadmap / Hit List

Findings from a full-repo review (2026-09-12), covering the whole app —
auth, web, dockerctl, per-game integrations, and deploy story. Items are
grouped by priority, not phase; check them off as they land.

## Done

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

- **Gating `docker-publish.yml` on the Trivy scan.** The scan currently
  runs after the image is already pushed to GHCR — a CRITICAL/HIGH finding
  is reported to code scanning but doesn't block the publish. Raised during
  a 2026-09-12 review; kept as awareness-only rather than a release gate by
  explicit choice.

## Next up (picked up from the 2026-09-30 session)

- [ ] **Verify Windrose end-to-end in the new stack.** The three-game test
  stack (`~/projects/crowsnest-test`, scratch copy of the Windrose server
  files) is built, but the `indifferentbroccoli/windrose-server-docker`
  image was never pulled there, so Start timed out at the 120s
  `docker compose up` limit. Pull the image first, then check
  starting→online, logs, stats, and the Windrose+ player count/info panel
  (needs the RCON password supplied by hand — deliberately not copied out of
  the real server's `windrose_plus.json`).
- [ ] **Consider a longer start timeout (or a separate pull step).** A first
  start that has to pull a multi-GB image exceeds `defaultStartTimeout`
  (120s) and returns 502 even though compose may still be working.
- [ ] **Migration from the Python lab setup**
  (`/home/plex/docker/compose_includes/CrowsNest`). That stack uses
  `seccomp:unconfined` and `network_mode: host` for Windrose, a
  docker-socket-proxy (`dockerproxy-privileged`) and `127.0.0.1:5000`; the
  compose example now carries `seccomp:unconfined`, the rest is config.
- [ ] **Real player joins** for Valheim (join/leave log markers) and
  Palworld, plus a real Start→Switch between two games from the browser UI.
- [ ] **Restart cooldown only tracks stops made through the panel** and is
  in-memory; a stop via `docker stop` or idle/night auto-stop isn't counted.
  Could read the container's `FinishedAt` instead.
- [ ] Idle/night auto-stop and Discord notifications are still untested
  against real servers; firewall for `:5001`/game ports not checked.

## Tracking, not new — already flagged in `docs/implementation-plan.md`

- [ ] Valheim's join/leave log markers (`Got handshake from client` /
  `Closing socket`) are still unverified with a real player.
