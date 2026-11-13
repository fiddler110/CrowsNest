# CrowsNest — Changelog (completed work)

Everything that has landed, moved out of [`roadmap.md`](roadmap.md) so the roadmap lists only what is still to do.
Newest first within each part. Design detail for the modular-games rework is in
[`docs/modularization-plan.md`](docs/modularization-plan.md).

## Accounts (P3)

- [x] **Allow switch for signed URL-installed modules (done 2026-11-12).** A module installed from a URL and signed
  by a key listed in `policy.yaml` (`trusted_keys`) is admitted like a bundled one: switching it on makes the guard
  check the saved signature (`module.yaml.sig`, written at install) and take the image and ports from the
  manifest, so no `policy.yaml` lines are pasted. The guard reads the modules folder read-only
  (`GUARD_MODULES_DIR`), re-checks on every reload, and ignores anything unsigned, edited, signed by another key, or
  filed under another id. Tested in the modules, guard and managed packages; **not run against a real guard
  container or a published signed module.** Modules installed before this have no saved signature and need one
  update.

- [x] **Passkeys (done 2026-11-12).** Sign in with WebAuthn passkeys (`auth.passkeys.rp_id` and `origins`),
  added and removed on the Account page, usernameless on the login page. User verification is required, a
  ceremony is single-use, and a passkey counts as the second step. Tested end to end with a software
  authenticator (register, sign in, wrong origin, no user verification, replay, removed user); **not tried with
  a real browser or device.**

- [x] **Mod and config file editing (done 2026-11-12).** A module can declare `files:` (id, label, absolute path,
  size limit, restart hint, `stop_first`, `redact`). Admins get a Files tab on the card: edit, then Save with the
  password. Files are read and written with `docker exec` in the game's container; the exec guard allowlists exactly
  two fixed commands per file (a read, and a write that copies the old file for its owner and mode, writes stdin
  beside it and renames it over). The API names a file by id, never by path. A save is refused with 409 if the file
  changed since it was opened (sha256), the last 10 versions are kept panel-side (0600) and can be loaded back, and
  redacted values stay hidden and are restored on save. Saves go to the activity feed and the audit file (hashes,
  not content). Modules: Valheim's three player lists (bundled) and Minecraft's `server.properties` and
  `ops.json` (modules repo, re-signed). Tested with a fake container and the two scripts on a real shell; not tried
  against a live container, and the Files tab was not looked at in a browser. Not built: a Save-and-restart button,
  per-format validation, directories or globs, binary files.

- [x] **Editing files of a stopped game (done 2026-11-12).** A dashboard-enabled game that is stopped has its declared
  files read and written by a one-shot helper container, `<id>-files`: the game's image and data folders only (no
  ports, no exec), the same fixed scripts as the exec path as its entrypoint, new content in an environment variable.
  It has its own guard scope (policy admits it by the game's name; ids ending in `-files` are refused) and only
  reaches files inside the data folders; the panel serialises helpers and refuses while the game is starting or
  stopping. Redaction now handles several secrets on one line. Tested with fakes and the real scripts on a shell, and the guard's admission and
  scope generation; not run against a live Docker daemon. Games set up in `config.yaml` have no helper, so their
  files still need the game running. Palworld and Windrose are not declared: Palworld's image rebuilds the whole
  `PalWorldSettings.ini` from environment variables on every start, and Windrose's `ServerDescription.json` holds
  only what the module's options already set (the real world settings are in a per-world file under an id and version
  folder, which `files:` cannot name).

- [x] **Module catalogue and key-rotation view (done 2026-11-12).** `managed.catalogue_url` points at an
  `index.json`; Games, Game modules from a source lists it ("Look at it" fills in the address and runs the usual
  signed preview, password and exact-bytes install). The same section now shows each trusted key with a fingerprint
  and the modules it signed, flags modules whose signing key was removed from `trusted_keys`, and lets an update
  signed by a still-trusted key take over from a retired one (dashboard and `module update`; release-number checks
  still apply). Keys stay in `config.yaml`, so the dashboard still cannot widen who is trusted. The modules repo has
  an `index.json`. Not built: an Allow switch for URL-installed modules (needs the guard to read the lock file).

- [x] **Google sign-in bound to the account subject, and ID-token signature checks (done 2026-11-12).** The first
  Google sign-in with a listed, verified address links the person to Google's subject id; after that the subject
  decides (a different account with the same address is refused), and changing or removing their Google email
  drops the link. Providers' discovery documents now give a `jwks_uri` (stored as `jwks_url`; Google's is built
  in) and every ID token's RS256 or ES256 signature is checked against those keys, cached for an hour and
  refreshed once a minute at most when a key id is unknown. Providers saved earlier have no key address until they
  are saved again. Tested with generated keys and a fake provider; not tried against Google itself.

- [x] **Require MFA for admins (done 2026-11-12).** Settings, General has a switch (`require_admin_mfa`). While it is
  on, an admin who signs in with a password and has no authenticator app is held on their Account page: pages
  redirect there, API calls get a 403, and a banner says why (`web.MFAGate`, wrapped around the mux). Admins who sign
  in through Google or an OIDC provider are not asked. Not covered: players, and WebAuthn/passkeys.

- [x] **Backups page (done 2026-11-12).** Settings, Backups lists every game with a backup set up: how many are
  kept and the newest (age, size, name), plus the shared folder's health, any offsite failure and the folders no game
  uses (`GET /api/backups/overview`, admin). A game whose backups live inside its own container can only be listed
  while it runs. The audit-log export was already done (R21).

- [x] **Per-game max players (closed 2026-11-12).** Nothing new to build: a module declares a `max_players` option
  and passes it to the game's own setting (`MAX_PLAYERS=${max_players}`), and the dashboard edits it per game. Palworld,
  Windrose and Minecraft do this, and `_template` shows it. Valheim's image has no player-cap setting, so it has none.

- [x] **Per-user Discord pings (done 2026-11-12).** Account, Discord pings: a person saves their Discord user id and
  ticks games (`GET/PUT /api/account/mentions`, stored in `mentions.json`). Game-scoped notices (start, stop,
  switch, failure, crash loop, idle and night stop) carry the game in their context (`notify.WithGame`), and the
  Discord channel prefixes `<@id>` for everyone who opted in, with `allowed_mentions` limited to those ids. It uses
  the shared webhook, so no per-person webhook or secret is stored. Tested with a fake Discord endpoint; not tried
  on a real server.

- [x] **Join codes and player names from the server log (done 2026-11-12).** A module's `connect:` entry can take
  `log:` (a regexp) instead of `option:`; the match shows on the card while the game is online, via
  `join_codes` in `/api/games` and the live event stream. `players.name` shows display names instead of ids.
  Valheim now declares both (`join code (\d+)` and `Got character ZDOID from ...`). The patterns come from
  Valheim's known log format, not from a captured crossplay session, so check them on a real server. Windrose's
  invite code is set by the operator, so it already shows. The copy buttons use one delegated handler now.

- [x] **Kick, ban, pardon and whitelist for Minecraft (done 2026-11-12).** The Minecraft module (in
  crowsnest-modules, re-signed) declares `rcon:` actions: players, announce, save, kick, ban, pardon, whitelist add,
  remove and list. Checked with `module check`; not run against a live server. Valheim has no live command channel
  (its ban and permitted lists are files), so it gets none.

- [x] **Scheduled starts and stops (done 2026-11-12).** `internal/schedule`: entries (game, start or stop, days,
  HH:MM, on/off, "only if empty" for stops) in `schedules.json`, edited under Settings, Schedule
  (`GET/PUT /api/schedules`, admin). A runner checks every 15 s and fires an entry once in its minute, acting as
  `schedule` through the normal start and stop path, so memory admission and exclusivity still apply. Failures and
  skips go to the activity feed and notifications. Times missed while down are not made up. Tested with a fake
  controller; not tried against a real game or in a browser.

- [x] **Self-service password change (done 2026-11-12).** The Account page has a "password" form (current
  password, new one twice). `POST /api/account/password` re-checks the current password against the sign-in
  limiter, applies the 8 to 72 byte rule, refuses a repeat of the old password, writes the hash and signs every
  other device out while keeping this one. Audit and activity record it. Only shown to accounts that have a
  password (Google-only users have nothing to change).

- [x] **RCON actions in modules (done 2026-11-12).** An action in `module.yaml` can use `rcon: "whitelist add {player}"`
  instead of `request:`; arguments pass the same checks (length, no control characters, required) and only declared
  commands run. A module uses one kind throughout and needs `rcon.addr`. Palworld (REST) and Windrose (console)
  already had kick, ban and unban. Tested with a fake RCON executor only.

## Modular games (track A)

- [x] **Phase 5: modules in the UI (done 2026-11-12).** The Games page enables, edits, refreshes and disables
  games from bundled modules inside the policy envelope, with preview, host-setup steps and install progress;
  Settings shows the policy. **Profiles:** "Make a copy" on a game's card opens the add form from that game's
  settings (own id, folder, backups and next free ports; secrets copied by the server through `copy_from`, never
  shown). **Signed remote sources:** `managed.trusted_keys` (ed25519, in config.yaml) + `<url>.sig`;
  `crowsnest module keygen/sign`; install/update record the signing key in the lock and an update that drops the
  signature is refused; the Games page installs a signed module from a URL (https, public addresses only, password
  again, the exact bytes previewed), updates one from its recorded source (diff shown, same id, signed) and removes an
  unused one. Not built: a catalogue/index of modules (one URL per module), key rotation UI,
  and an install for a module whose image the policy does not list (still shown as "needs policy lines").

- [x] **Phase 4: state hub.** (done: one poller per game on an adaptive
  cadence in `internal/statehub`, feeding the dashboard, playerwatch and both
  auto-stop loops, and one SSE stream to browsers, `/api/events`; memory-budget admission (done
  2026-11-10): modules declare `runtime.ram`, the measured peak replaces it,
  and a start needs host free RAM less `server.memory_reserve_mb`;
  `max_active_games` stays as an optional cap.) One poller per game on an adaptive cadence, one
  SSE stream to browsers, memory-budget admission instead of
  `max_active_games` as a RAM proxy.

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

### Policy you don't have to maintain (done)

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

## Accounts and settings (track B)

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
- [x] **Per-user, per-game permissions (done 2026-11-11).** A player can be limited to chosen games
  (`<NAME>_GAMES=palworld,valheim` in the users file; Settings, Users has a checkbox per game; empty means all,
  admins always see all). Hidden games are absent from the dashboard, `/api/games`, the live stream, the
  activity feed and playtime, and every per-game route answers 404 for them. Starting a game while a hidden one
  is running says only "another server is running" and offers no switch. Not built: a CLI command for it
  (edit the users file or use the panel), and per-game *actions* (a friend who may start but not stop).
- [x] **Profile page (done 2026-11-12).** Account page: display name (display only; the sign-in name stays the
  identity), the user's signed-in devices (browser/system, address, signed-in and last-seen times), sign out one
  device, the others, or everywhere. Needs the new server-side session store (`auth.SessionStore`,
  `sessions.json`): a cookie must carry a session id still in the store, so a revoked device ends at once, a restart
  keeps people signed in, and cookies from before the store (no id) are ended once. `revoke-sessions` (the
  `ValidAfter` marker) still works. Not built: the user's email/avatar, naming a device, an admin view of other
  people's sessions, and a "new sign-in" notice.
- [x] **Admin audit view (done 2026-11-11).** Settings, Audit log: filter the
  activity log by game, kind, user, text and date range, paged 50 at a time
  (`GET /api/audit`, admin only, shows the admin kinds the logbook hides from
  players). No export yet.
- [x] **Google sign-in from the dashboard (done 2026-11-11).** Settings, Sign-in: client ID, client secret (encrypted
  in `auth.json`, key in `auth-key`), redirect URL and an on/off switch, applied live; saving asks for the admin's
  password; Google-allowlist users now get a users-file entry so they can be managed. Not built: the
  password-sign-in switch (still `auth.password_login` in config.yaml), editing the `name=email` env allowlist
  (use the per-user Google email instead), and other OIDC providers (Google only).
- [x] **Sign-in methods and secrets at rest (done 2026-11-11).** `internal/vault` (AES-256-GCM, master key from
  `CROWSNEST_MASTER_KEY` or a key file) seals the Google/OIDC client secrets, TOTP secrets, game `secrets.json` and
  the session key, migrating old plain files. Password sign-in switch with lock-out analysis, double confirmation and
  a `crowsnest enable-password-login` break-glass. TOTP (RFC 6238: replay guard, lockout, bcrypt recovery codes,
  step-up on changes, admin reset, Account page). Generic OIDC providers (discovery, PKCE, subject-bound linking).
  Not built: requiring MFA for admins or everyone (needs a limited "enrol first" session), WebAuthn/passkeys, ID-token
  signature checks against the provider's JWKS (relying on TLS to the token endpoint, as OIDC Core 3.1.3.7 allows),
  and encrypting the users file. MFA stays optional per person; Google and OIDC sign-ins skip it because the provider
  is the second factor. The Google login now runs on the same OIDC code as other providers (built-in provider
  `google`, still matched by the Google email allowlist rather than a linked subject).
## Verified against real servers (track C)

- [x] **Real player joins** (done 2026-11-12, test stack). Valheim: `Got handshake from client` /
  `Closing socket` markers fire on a real join and leave, `join`/`leave` events recorded. Palworld: the REST list
  and the card count follow a real join and leave (its log lines are not parsed). Found and fixed: the last
  named player leaving was never recorded (`internal/playerwatch`). Gap: Valheim players show as Steam IDs.
- [x] **A real Start→Switch between two games** (2026-11-12, via the API on the test stack, both directions,
  from a game that was actually running). Still to do from the browser UI itself.
- [x] **Palworld `backup` command, the exec path through the guard and the
  console replies** against real containers (done 2026-11-12). Idle auto-stop fired on the test stack
  (done); Discord notices still untested (no webhook on the test stack).

- [x] **Crash-loop detection and Prometheus `/metrics` (done 2026-11-11).** `internal/crashwatch` reads each
  container's last exit; non-zero exits other than a stop (0, 143, and 137 unless OOM-killed) are crashes,
  and `crash_loop.crashes` within `window_minutes` raises one alert (activity log + Discord). `GET /metrics`
  (bearer token from `server.metrics_token_env`) exposes game up/players/crashes and host memory, load and disk.
  ntfy is not wired (Discord only). Untested against a real crashing container.

## P0 security fixes (2026-11-12)

- [x] **R1. Restore needs the password and always has an undo.** `POST /api/games/{id}/restore` asks for the
  admin's password (`stepUp`) and a running game is always backed up before it is stopped, whether or not the module
  backs up before every stop (a failed safety backup stops the restore before anything changes). A stopped game
  cannot be backed up from outside: the request is refused (428) until the caller sends `without_backup`, which the
  dashboard asks as a second confirmation. The confirm dialog gained an optional password field (`askPassword`).
- [x] **R2. Step-up for user management.** Creating an admin, changing a role, setting a password (including your
  own), resetting an authenticator, deleting a user, and changing a linked Google/SSO email all need
  `confirm_password` (the signed-in admin's own password). Games and sign-outs do not.
- [x] **R3. The Discord webhook token no longer reaches the log.** Send failures are logged without the
  `*url.Error` URL.

## P1 (2026-11-12)

- [x] **R6. Module signatures: no rollback, signer pinned.** `module.yaml` has an optional `version` (inside the
  signed bytes, recorded in the lock). `modules.CheckUpdate`, used by `Install`, the dashboard's update preview and
  `crowsnest module update`, refuses an update of a signed module that lowers it, reuses it for different bytes,
  drops the signature, or is signed by a different trusted key than the install (that is a remove and re-install
  with its own review). Unversioned modules keep the old behaviour; publishers should add `version`.

- [x] **R7. The panel's own state can be backed up.** `crowsnest state export [-o file]` writes one `.tar.gz` of
  the users file, settings, sign-in settings, authenticator apps, SSO links, profiles, the activity log, the managed
  `games.json`/`secrets.json` and the module lock with its modules; `crowsnest state restore <file> [--force]` puts
  it back, naming only files the panel owns (a snapshot with anything else is refused whole). The vault key and
  session secret are left out on purpose. Documented in docs/backups.md.

- [x] **R8. `Cache-Control: no-store` on signed-in pages and JSON** (`render` and `writeJSON`).

- [x] **R9. Tighter headers and cookie.** The CSP adds `frame-ancestors 'none'`, `base-uri 'none'` and
  `form-action 'self'`; responses carry a `Permissions-Policy` and `Cross-Origin-Opener-Policy: same-origin`; with
  `secure_cookies` on the session cookie is named `__Host-crowsnest_session` (`auth.UseSecureCookieName`), so a
  sibling subdomain cannot set it. Turning `secure_cookies` on or off signs everyone out once (the name changes).

- [x] **R10. Sign-in throttling.** Only wrong passwords and codes count against the limits now (correct sign-ins
  and step-up confirmations no longer use them up), and a per-username throttle (10 failures in 15 minutes, from any
  address) sits beside the per-address one (`auth.Service.UserLimiter`). New hashes use bcrypt cost 12
  (`auth.PasswordCost`); an older hash is replaced with a cost-12 one the next time its owner signs in. **New sign-in
  notice:** a sign-in from a browser/system the person had not used before (and they had used another) is written to
  the activity log and shown on their Account page until they dismiss it (`profiles.json` remembers up to 50 devices).

- [x] **R11. Atomic writes fsync.** One shared helper, `internal/atomicfile` (temp file in the same folder, sync,
  rename, sync the folder), replaces the copies in `auth` (users, sessions, sign-in settings, profiles), `mfa`,
  `modules` (lock), `settings`, `managed` (games, secrets, scopes, policy), `history` and `memadmit`, and is used by
  `crowsnest state restore`.

- [x] **R12. Per-user cap on log and startup streams** (6 each by default, `App.MaxStreamsPerUser`), taken before the
  shared cap of 20, so one player cannot hold every slot.

- [x] **R14. `golang.org/x/crypto` v0.58.0 → v0.59.0.** `govulncheck` no longer lists GO-2026-5932.

- [x] **R13. Vault key.** New values are sealed `enc:v2:` with an AES key derived from the master key by Argon2id
  (a typed `CROWSNEST_MASTER_KEY`) or HKDF (the random key file) instead of one SHA-256; `enc:v1:` values still open
  and are rewritten as they are saved. `crowsnest rekey` (with `CROWSNEST_NEW_MASTER_KEY`) re-seals the session
  secret, Google/SSO client secrets, authenticator apps and `secrets.json` under a new key (or the newest scheme),
  resumable if interrupted. docs/accounts.md names the environment key as the recommended setup and gives the steps.

## P2 (2026-11-12)

- **R15. Browser end-to-end tests.** `e2e/` holds Playwright specs that drive the real dashboard over a fake
  docker (`internal/web/e2e_server_test.go`): sign in and out, start/stop, switching games, adding a game, the
  restore dialogs (password, then the no-safety-backup warning) and the account and settings pages. They run in
  CI (`e2e` job) and locally with `./e2e/run-docker.sh`, using the official Playwright image. Writing them found a
  real bug, now fixed: after Start/Stop the dashboard fetched `/api/games` itself, and the live stream, which only
  sends what changed, never repeated a state the card was already wrongly showing, so a quick stop could leave the
  card on "stopping". With the stream open the buttons are now re-derived from the card's state instead.

- **R16. Coverage where it was thin.** `internal/probes` 33% → 90% (REST info, console actions with argument
  validation, pre-stop steps, templates, raw RCON), `internal/logtrack` 41% → 95% (Check, Info, Run against a
  fake docker), `cmd/crowsnest` 44% → 56% (`state` CLI, `clear-password`, `enable-password-login`, legacy
  Google import, `render`, memory budget). What is left in `cmd/crowsnest` is `main` and `serve`, which the
  browser end-to-end suite (R15) exercises.

- **R17. CI.** `staticcheck` (pinned v0.8.2) runs in the test job; it found a dead assignment, a self-comparing
  condition and an unescaped bidi character in tests, all fixed. `ST1005` is off in `staticcheck.conf` because
  several errors are whole sentences or usage text. A new `integration` job (`internal/integration`, build tag
  `integration`) creates, starts, stops and removes a busybox container through the scoped guard on the runner's
  real Docker daemon, and checks the guard refuses another image, a host bind, another network, another name and
  a security option. The image scan is now a matrix over amd64 and arm64 (QEMU for the final stage), each with
  its own SARIF category. The integration test passes locally; the new workflow jobs have not run on GitHub yet.

- **R18. Quickstart pins a version.** `quickstart/compose.yaml` now requires `CROWSNEST_TAG` (no `:latest`
  fallback; the error tells you to copy `.env.example`), and `.env.example` pins 0.9.0. The release job
  attaches `quickstart.tar.gz` with `CROWSNEST_TAG` set to that release's own version. The quickstart README
  has an Upgrading section (bump the tag, pull, up, doctor; back up first; how to roll back), and
  `docs/publishing.md` matches. The release workflow change has not run on GitHub yet.

- **R19. Notifications.** A shared delivery path retries network errors, 429 (honouring `Retry-After`) and 5xx
  with 1 s / 2 s backoff, and never retries other refusals; messages are cut to the channel's limit (Discord
  2,000 characters, by character). New channels: ntfy (`ntfy_url_env`, `ntfy_token_env`) and a generic JSON
  webhook (`webhook_url_env`); every channel that is set gets every message, and webhook URLs stay out of logs
  and errors. The latest outcome per channel feeds `/api/health` (`notify`) and an admin-only
  `/api/notify/status`; the dashboard shows a banner naming the failing channel until the next good send.
  Docs: "Notifications" in `docs/operating.md`. Per-user Discord notices (P3) build on this. Tested against
  fake servers only; no real Discord, ntfy or webhook receiver was used.

- **R20. Sliding sessions.** `server.session_idle_minutes` (default 180) and `server.session_max_hours`
  (default 12) replace the fixed 3 hours. A session in use for a quarter of its idle period is re-signed with
  another idle period, capped at the absolute limit after sign-in; the sign-in time (so revocation) and CSRF token
  do not change, and the session list's expiry moves with it. An open, visible dashboard sends a keepalive every
  10 minutes because the live stream cannot refresh the cookie. A maximum at or below the idle time turns renewal
  off. Unit and middleware tests cover renewal, the cap and the off switch; no browser run.

- **R21. Structured logging and audit.** `internal/logging` installs a `log/slog` default with `server.log_level`
  and `server.log_format` (`text` or `json`); the ~130 existing `log.Printf` calls are routed through it with a
  level guessed from the message (failure, refusal or "disabled" wording is a warning) rather than being
  rewritten one by one. `internal/audit` writes the 22 `audit:` lines to their own file (`server.audit_file`,
  default `/app/data/audit.jsonl`) with a SHA-256 hash chain; `crowsnest audit verify` names the first line that
  was edited, removed, added or moved, `crowsnest audit export` and Settings → Audit log → Export download it,
  the panel refuses to start on a broken chain, and `state export` includes it. Not covered: entries cut off the
  end (the verify output's last hash is for the operator to keep), and `guard`/`execguard`, which still print
  plain text. Audit lines are now free text rather than structured fields.

- **R22. Docs.** `cleanup.md` and `docs/implementation-plan.md` moved to `docs/archive/` with a note on top
  (README, `config.yaml.example` and a Windrose source comment now point there). This file is the changelog the
  roadmap asked for: the Done section had already moved into `releases.md` earlier, which is now `CHANGELOG.md`.
  New `docs/threat-model.md`: assets, the trust boundaries (browser, panel, guard, Docker, game containers, module
  sources, outbound, disk), and a threat/answer/residual-risk table. It is written from the code and the
  2026-11-12 review, not from a fresh audit.

- **R23. Large files split.** Pure moves, no logic changes: `internal/managed/managed.go` (1,778 lines) is now
  `managed.go` (types and lookups, 218), `catalogue.go`, `request.go` (validation, defaults, port and bind checks,
  preview), `install.go` (enable, install, update, refresh, rollback, disable), `state.go` (the saved state, sealed
  secrets, restore at start-up) and `policy.go` (policy loading, exec rules, editing). `internal/web/app.go`
  (1,260) is now `app.go` (607: the `App`, routes, auth wrappers, shared helpers) plus `pages.go`, `backups.go`,
  `activity.go` (activity and audit feeds and export), `settingsapi.go`, `health.go` and `control.go` (start,
  stop, switch). The moves were scripted by declaration, and `go vet` and the full test suite pass unchanged.

## Earlier work

- [x] **Modules moved out (2026-11-12).** Minecraft, Source and Don't Starve Together are no longer bundled; they are
  published, signed, in [crowsnest-modules](https://github.com/fiddler110/crowsnest-modules) with `sevendtd`.
  Valheim, Palworld and Windrose stay in the binary. The engine tests keep copies under
  `internal/modules/modtest/` (registered through `modules.AddBundled`, only in test binaries). Upgrade note in
  `docs/modules.md`.

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
  option. See `docs/accounts.md`, "Sessions".
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
