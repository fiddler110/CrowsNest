# CrowsNest — Roadmap / Hit List

Findings from a full-repo review (2026-09-12), covering the whole app —
auth, web, dockerctl, per-game integrations, and deploy story. Items are
grouped by priority, not phase; check them off as they land.

## Done

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

## High priority

(none currently — see Done)

## Medium priority

(none currently — see Done)

## Low priority / hygiene

- [ ] **No request body size limits.** `ServeLogin` and `handleSwitch` both
  `json.NewDecoder(r.Body).Decode(&req)` with no cap. `/login` is
  unauthenticated, so this is a cheap memory-pressure DoS vector before
  rate limiting even applies.
  - Fix: wrap with `http.MaxBytesReader(w, r.Body, 4096)` (or similar)
    before decoding on both handlers.
  - Files: `internal/auth/login.go`, `internal/web/app.go`.

- [ ] **No rate limiting beyond `/login`; unbounded concurrent SSE
  streams.** Every authenticated route is otherwise unlimited, and
  `handleLogs`/`handleStartupProgress` spawn a new `docker logs -f`
  subprocess per open connection with no per-user/global cap. Low severity
  for a small trusted friend group; worth a cap before exposing this more
  broadly.
  - Files: `internal/web/streaming.go`, `internal/dockerctl/dockerctl.go`.

- [ ] **`auth.Limiter.hits` map grows unboundedly.** Keys for IPs with no
  recent hits are never pruned, so a long-lived process getting probed by
  many distinct source IPs (e.g. an internet-facing `/login`) accumulates
  map entries forever.
  - Fix: periodic sweep (e.g. on each `Allow` call, or a ticker) that drops
    keys whose most recent hit is outside the window.
  - Files: `internal/auth/ratelimit.go`.

- [ ] **Session revocation is all-or-nothing.** Stateless HMAC cookies mean
  the only way to invalidate a session (compromised device, offboarding a
  user) is rotating the session-secret file, which logs out everyone at
  once. Acceptable at current scale; worth a lightweight server-side
  denylist (or moving to a small server-side session store) if this ever
  grows past a single trusted household.

- [ ] **No audit trail of start/stop/switch actions.** Multi-user + shared
  infra + no "who did what, when" logging is a minor gap if more than one
  person uses this at a time. Even a structured log line per action
  (`log.Printf` already has the shape) would cover most of the value.

## Tracking, not new — already flagged in `docs/implementation-plan.md`

- [ ] Valheim's status detection is still the Phase 3 docker-ps-only
  baseline (no confirmed ready-log marker), so idle/night-shutdown can
  never distinguish "starting" from "online" for it via `StatusChecker`
  the way Windrose/Palworld can.
- [ ] Valheim's and Palworld's integrations (log markers, REST shapes) are
  built from public docs/community knowledge, not verified against a real
  running server — watch the logs on first real use of either.
