# CrowsNest — Roadmap

Single source of truth for what is done and what is left. The design detail
behind the modular-games rework lives in
[`docs/modularization-plan.md`](docs/modularization-plan.md); everything that
is *work to do* is tracked here. Check items off as they land and move them
into **Done** with a date.

Origin: a full-repo review (2026-09-12), the modular-games design review and
the accounts/settings review (2026-11-08/09).

## Active roadmap

Three tracks that share one path: **A. Modular games** (the phased rework),
**B. Accounts and settings** (largely rides on the modules), and **C. Verify
and harden** (open checks against real servers). Phase numbers match
`docs/modularization-plan.md`. Phase 0 is done (see Done).

### A. Modular games

Goal: add a game by dropping in a `module.yaml` directory with no core change;
guard scopes, exec rules, compose fragment, secrets and settings form are all
derived from it.

- [x] **Phase 1: manifest and loader (done 2026-11-09).** `module.yaml` v1 and a loader that
  produces `GameDef`; replace the `buildGameDefs` switch
  (done in step 1, now `internal/modules`). Shared log-follow engine (replaces the
  duplicate Valheim/Windrose trackers), `http_json` and `source_rcon` probes.
  Legacy `config.yaml` games block still works, mapped to built-in modules.
  Done when the golden tests are unchanged and `cmd/crowsnest` names no game.
  - [x] Step 1 (2026-11-09): `internal/modules` registry; Palworld, Valheim
    and Windrose wiring moved into `modules.Bundled()`; `cmd/crowsnest` names
    no game; goldens unchanged.
  - [x] Step 2 (2026-11-09): `module.yaml` v1 schema + strict loader
    (`modules.Parse`, `Set.LoadDir`): identity, restart cooldown, startup
    milestones; unknown keys and unsupported probe types are refused. Not yet
    called from `main` (needs a modules-dir setting; do with step 4).
  - [x] Step 3 (2026-11-09): shared log-follow engine `internal/logtrack`
    replaces the duplicate Valheim/Windrose trackers (goldens differ only in
    the recorded type name); `internal/probes` adds `http_json` and
    `source_rcon`; all three are usable from `module.yaml` (`players.type`).
    Valheim join/leave markers now verified against a real session
    (2026-11-07 logs, anonymised fixture in `internal/logtrack/testdata`).
  - [x] Step 4 (2026-11-09): `modules_dir` in `config.yaml`; `main` builds the
    set with `modules.ForConfig` (bundled + local `<id>/module.yaml`). The
    legacy games block is unchanged and still selects modules by game id, so
    bundled games and manifest games share one path. A local module may not
    shadow a bundled id; unused local modules log a warning. A manifest game
    still needs a `config.yaml` entry for its container/compose until Phase 2.
- [ ] **Phase 2: dogfood.** (done: Valheim and Palworld are embedded `module.yaml` files with REST info/actions/pre-stop in the manifest, `options:` replaces the typed config blocks (legacy blocks still read); Windrose is an embedded module too: status, startup and player count come from the game log, Windrose+ stays optional but is fully used when on: info panel, player names, admin console and raw console; fourth-game test done: Minecraft is a manifest plus fixture with no Go change, plus a shared `source` module (TF2/CS2/L4D2 etc. via `module: source`) and Don't Starve Together, documented in docs/modules.md; remaining: verify the Windrose markers on a graceful quit, and the Tier 2 adapter contract is deferred) Re-express Valheim, Palworld, then Windrose+ as
  bundled modules; adapter-sidecar contract v0 (Windrose+ first); remove the
  typed per-game fields from `config`. Done when a fourth game (Minecraft or a
  Source game) is added with a manifest only, in under 30 minutes.
- [x] **Phase 3: derived security.** (done: `runtime:` + `crowsnest render` generate
  compose and guard scopes; per-game secrets in `secrets.json` (0600, never rendered);
  the guard reads a managed scopes file and reloads; `policy.yaml` envelope with
  per-game exceptions; guard forwards resolved container ids; fuzz targets for path
  and body parsing (2026-11-10); dashboard games pinned by image digest, with
  `pin_digests` in `policy.yaml` making the guard refuse a managed create by tag,
  and one-step rollback to the previous digest; exec rules derived at runtime
  (execguard builds them from config.yaml backups plus each managed game's
  module, reloaded from the managed dir, so they cannot drift); privilege
  approval is covered by operator-only policy exceptions (only policy.yaml on
  the host can grant one), and the lock file moves to Phase 5 with remote module
  sources; dedicated security review 2026-11-10: managed binds may not nest in
  one another or in a base bind, and a game reads only `TZ` and its own
  `<ID>_<OPTION>` names from the panel's environment. The residuals
  it listed are closed: with `policy_editable: true` the dashboard may only
  tighten policy.yaml (and a startup warning says it is on); execguard issues a
  dashboard game's backup rule only for a container name the policy allows
  (execguard now mounts the policy directory); /api/events also has a
  per-user cap of 4.) Generate guard scopes, execguard rules and
  compose fragments from manifests; per-module secrets (the panel stops
  reading every game's `.env` values); guard reads a scopes file and reloads;
  `policy.yaml` envelope, privilege approval (`crowsnest module apply`) and a
  lock file; Go fuzz targets for the guard's path/body parsing; pin game
  images by digest or version range. Needs its own security review.
- [x] **Phase 4: state hub.** (done: one poller per game on an adaptive
  cadence in `internal/statehub`, feeding the dashboard, playerwatch and both
  auto-stop loops, and one SSE stream to browsers, `/api/events`; memory-budget admission (done
  2026-11-10): modules declare `runtime.ram`, the measured peak replaces it,
  and a start needs host free RAM less `server.memory_reserve_mb`;
  `max_active_games` stays as an optional cap.) One poller per game on an adaptive cadence, one
  SSE stream to browsers, memory-budget admission instead of
  `max_active_games` as a RAM proxy.
- [ ] **Phase 5: modules in the UI.** (done: the Games page enables, edits,
  refreshes and disables games from bundled modules inside the policy envelope,
  with preview, host-setup steps and install progress; Settings shows the policy.
  Remaining: profiles, installing modules from signed remote sources with a
  lock file of what was installed, moved here from Phase 3.) Install, enable, configure and remove
  modules and profiles from the dashboard (inside the policy envelope);
  signed remote sources. Done when a profile is created and started with no
  file edits.
- [ ] **Phase 6 (optional):** drop the docker CLI and compose from the image
  (create containers through the Engine API behind the guard); also removes
  the compose-from-source Dockerfile stage and its x/net CVE churn.

- [ ] **Policy you don't have to maintain** (planned 2026-11-10). The policy should hold only what protects the
  host (`games_root`, `exec`, exceptions); the rest comes from the modules.
  1. [x] **Ownership instead of a names list.** Dashboard games carry `crowsnest.managed=true`; with no `names` in
     the policy the guard only acts on labelled containers (lists, inspect, start/stop/remove, create).
     A policy that still lists `names` behaves as before.
  2. [x] Images and the games network come from the bundled modules and `platform.games_network`, not the policy
     (`images` and `networks` are optional; `"@modules"` adds the module images to an explicit list; the dashboard
     editor cannot empty a list). A module installed from a URL still needs its image listed.
  3. [x] A per-module **Allow** switch on the Games page (admin password again, audit-logged), and each game's
     published ports shown with the module's reason (`why:` on a module port). `ports` in the policy is optional.
     A password is required to allow (a Google-only admin gets a banner until they set one). A second server of a
     game gets the next free host port the policy admits; a typed clash is refused naming the game. Not done: a
     switch for URL-installed modules (needs the guard to read the lock file); the extra range is edited in
     `policy.yaml`; the clash on *start* is Docker's own error. A fixed LAN or games-network address another game already holds is refused naming that game.
  4. [x] Host address as three plain choices (my network, this machine only, a specific address) in the policy pane;
     the dashboard can still only narrow it. "Servers allowed at once" was already a number field starting at 1
     (Settings, General); the policy's `max_scopes` is now labelled "Most games that can be set up".

### B. Accounts and settings

Today: Google sign-in with an allowlist, admin/player roles looked up per
request, user create/update/delete (`/api/users`), per-user session
revocation, and global runtime settings (idle, night, max games, auto-update,
raw console) in `settings.json`. Expansion, tied to the phase it depends on:

- [x] **First-run setup in the UI (done 2026-11-10).** With no users the
  login page redirects to `/setup`, which creates the first admin from a
  one-time setup code printed in the log and kept in `setup-token` (so only
  someone with host access can claim the panel). It closes for good once a
  user exists. Unused password hashes: `crowsnest clear-password <user>` drops one (refused without a
  Google login, keeps the role, revokes sessions) and `doctor` flags hashes left while password login is off.
- [x] **Hardening for other people's hosts (done 2026-11-10):** `crowsnest
  doctor` (Docker access, writable state, policy, cookies, memory), a
  `quickstart/` stack with the guards and no preset games, a history and
  fixture audit (no secrets found; personal details removed from fixtures).
  License is PolyForm Noncommercial 1.0.0 with a `SECURITY.md`. A module-authoring guide
  (`docs/writing-modules.md`) and `crowsnest module check <dir> --log` (validates a manifest and replays a
  captured log) are done. The author email stays in git history by decision. Still to do before going public:
  the real-server checks in track C. Hash-pinned remote install is done (`crowsnest module
  install|update|remove|list`, a lock file, an approval summary and re-approval on change); a web
  UI for it and signed catalogs are not built.
- [ ] **Per-game settings** (done 2026-11-11: idle timeout, restart cooldown
  and night opt-in/out per game, as overrides in `settings.json` (`per_game`),
  edited under Settings, General; each falls back to the global value or the
  module's default, applies at once, and is audit-logged. Not built: max
  players, which needs a per-module way to push the limit into the game's own
  config.)
- [ ] **Per-user, per-game permissions** (a friend can start Palworld but not
  see Windrose). Needs stable game/profile ids: Phase 2, UI in Phase 5.
- [ ] **Profile page**: display name, "my sessions", sign out of all
  devices. Needs a **server-side session store** (today revocation is one
  `ValidAfter` timestamp per user) to offer "revoke this device".
- [x] **Admin audit view (done 2026-11-11).** Settings, Audit log: filter the
  activity log by game, kind, user, text and date range, paged 50 at a time
  (`GET /api/audit`, admin only, shows the admin kinds the logbook hides from
  players). No export yet.
- [ ] **Per-user Discord notices** (opt in per game).
- [ ] **Scheduled starts/stops** (deferred from the 2026-11-07 review) and
  **Discord slash commands** (deferred). Land after the Phase 4 state hub.
- [ ] **Whitelist, ban and kick actions**, declared per module and run via
  RCON or the adapter (Phase 2+).
- [ ] **Backup retention, restore button and offsite copy** (restic/rclone).
  Done 2026-11-11: retention (`backup.keep`), and a **shared backups folder**: `platform.backups_root` binds
  `<root>/<game id>` into each dashboard game at its module's `backup.dir` and into the panel read-write; the panel
  lists and prunes it directly (no exec), the policy has a matching `backups_root`, and a marker file plus a remembered
  token refuse a folder that is not the one used before (unmounted external drive). The watch-outs (permissions, the
  panel being able to delete, ids as folder names, nothing deleted on disable, retention counts files) are in the
  README under "A shared backups folder". Not built:
  - **Restore: done** for Minecraft, Valheim and Windrose (a Restore button per file; a one-shot `<id>-restore`
    container runs the module's `restore:` command while the game is stopped). Open: Palworld (confirm what its image's
    `backup` archives contain before writing a command), a restore for config-file games, and trying each command on
    a real world (Minecraft was tried live on the test stack 2026-11-11: backup, restore and safety backup work).
  - **Disable and delete: done.** `DELETE /api/managed/games/{id}` takes `delete_data` / `delete_backups` (id typed +
    password); data goes through a one-shot `<id>-clean` container, backups are removed by the panel through `os.Root`.
  - **Offsite copy.** A restic/rclone sidecar reading the same folder; CrowsNest itself should not hold the credentials.
  - **Config-file games** (hand-written compose) still back up inside their own data; they would need the bind added by hand.
  - **Backups-folder detail in the UI** (last backup per game, orphan folders): the dashboard shows a banner and
    `GET /api/backups/health` has the detail, but there is no page for it yet.
  - **First-use guard:** done, see `platform.backups_confirm_new`; a host-side mount check remains optional.
  Also done 2026-11-11: a one-minute folder monitor (marker, 1 GiB free, per-game writability) with one alert per
  change, a dashboard banner and metrics; refused scheduled backups are recorded and notified; a backup must leave a
  new non-empty file or it counts as failed; permission errors carry a hint.
- [x] **Crash-loop detection and Prometheus `/metrics` (done 2026-11-11).** `internal/crashwatch` reads each
  container's last exit; non-zero exits other than a stop (0, 143, and 137 unless OOM-killed) are crashes,
  and `crash_loop.crashes` within `window_minutes` raises one alert (activity log + Discord). `GET /metrics`
  (bearer token from `server.metrics_token_env`) exposes game up/players/crashes and host memory, load and disk.
  ntfy is not wired (Discord only). Untested against a real crashing container.
- [ ] **Mod and config file editing**, files declared in the manifest.

### C. Verify and harden (against real servers)

- [ ] **Real player joins** for Valheim (`Got handshake from client` /
  `Closing socket` markers are unverified) and Palworld; record the logs as
  fixtures for the Phase 1 loader.
- [ ] **A real Start→Switch between two games** from the browser UI.
- [ ] **Windrose invite-code join** from the LAN and from outside, on the
  macvlan setup (the server itself runs and Windrose+ answers).
- [ ] **Idle/night auto-stop and Discord notifications** against real
  servers (still untested); check firewall for `:5001`/game ports.
- [ ] **Palworld `backup` command, the exec path through the guard and the
  console replies** against real containers (flagged untested 2026-11-07).
- [ ] **Show Valheim/Windrose join codes on the game cards** by reading them
  from the server logs (follow-up to `docs/connecting.md`).

### Considered, not doing

- Go `plugin` package or in-process plugins: they would run inside the
  panel's trust boundary. WASM (wazero) stays an option once the adapter
  contract is stable.

### Resolved from the old "Next up" list (2026-09-30)

- Multi-game behind a scoped Docker API guard: done by the Go guard
  (2026-11-08, see Done).
- Migration from the Python version: done; production runs the Go image and
  the old tree is archived.
- Verify Windrose in the new stack: running in production with Windrose+
  player counts verified (2026-11-08); only the invite-code join remains (C).


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

- [x] **One guard container (2026-11-10).** `crowsnest guard --exec` runs the exec allowlist in front of the
  guard in a single process (the guard on loopback, nothing else listening), so the quickstart is two
  containers, the panel and the guard, instead of three. `crowsnest execguard` still works on its own.
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
