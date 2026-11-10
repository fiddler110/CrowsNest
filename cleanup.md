# CrowsNest cleanup (review of 2026-11-10)

Findings from a full-repo review of the `games-page` branch at `d8e57a6`. `go vet` was
clean and `go test -race ./...` passed at the time. Check items off as they land. S3 decided: default to player. S8 decided: logs admin-only. IDs
are stable so commits and agents can refer to them.

## B. Bugs

- [ ] **B1. The "add a game" form hides itself.** `games.html` uses `id="setup"` on both
  the `<form>` (line 62) and the host-steps `<section>` inside it (line 91).
  `renderSetup()` in `games.js` sets `$("setup").hidden`, which matches the form, so
  every module without host steps (and every preview error, `games.js:271`) hides the
  whole form about 350 ms after a game is picked. The two `.setup` CSS rules
  (`style.css:507`, `:574`) also style both elements. Rename the section, e.g.
  `host-setup`.
- [x] **B2. Goroutine leak on log stream disconnect.** `streaming.go:211` sends on an
  unbuffered channel. If the client leaves while a line is pending, the reader goroutine
  and its scanner buffer (up to 1 MB) block forever. Select on `ctx.Done()`.
- [x] **B3. A switch into a cooling-down game stops the source and starts nothing.**
  `runSwitch` stops `from`, then `startLocked` (`exclusivity.go:711`) refuses the target
  with a `CooldownError`. Check the cooldown in `beginSwitch`, before anything stops.
- [x] **B4. Playtime keeps counting after a crash.** When a game goes offline,
  `playerwatch.go:74` drops its last state without recording `leave` events, so a
  session only closes on a panel stop. Crashes, external stops and players who leave
  while CrowsNest is down leave sessions open forever. Record leaves for the last known
  names when a game is confirmed not online.
- [ ] **B5. Danger console actions with no fields run without confirmation.** The
  confirm only happens on form submit (`app.js:843`).

## S. Security

- [x] **S1 (medium). The activity log shows admin-only events to players.**
  `/api/activity` (`app.go:433`) only needs a session. Players see `users` events
  (other people's Google emails), `console` commands with their arguments, `settings`
  and `games` changes. Filter those kinds out for non-admins.
- [x] **S2 (medium). Discord mention injection.** Player names come from the game and
  are posted as plain `content` (`discord.go:49`), so a player called `@everyone` pings
  the channel. Send `"allowed_mentions": {"parse": []}`.
- [x] **S3 (medium). Google env-allowlist users are admins by default.** A name with
  no users-file entry gets admin (`roles.go:33`). Dashboard-created users already
  default to player. **Needs a decision:** the owner may be a Google-only user with no
  entry, so they must be pinned to admin before the default flips.
- [x] **S4 (low). Raw docker/compose errors reach every user.** `StartResult.Err`
  (`exclusivity.go:470`) is full compose stderr (command lines, host paths). It is shown
  to all users via `/api/games` toasts and sent to Discord. `streaming.go:85` and `:163`
  return raw errors too. Show public text and log the details.
- [x] **S5 (low). The rate limiter trusts the left-most `X-Forwarded-For` entry**
  (`ratelimit.go:114`). Behind an appending proxy a client can rotate it. Prod's Caddy
  overwrites the header, but use the right-most untrusted address.
- [x] **S6 (low). `writeUsers` is not atomic** (`users.go:274`). A crash mid-write
  truncates the users file. Use temp file plus rename, like settings and history.
- [x] **S7 (low). The guard checks a container by name but forwards that name, not the
  resolved ID**, so the engine resolves it again. Rewrite the target to the full ID.
  Fuzz targets for the guard's path and body parsing are already on the roadmap.
- [ ] **S8 (low). Players can read every game's full live log**, including anything an
  image prints at boot. **Needs a decision:** make logs admin-only, or add a per-module
  redaction pattern.

## J. Seams between components

- [x] **J1. Managed games ignore the start/stop manager.** `Disable` and `reinstall`
  check `Running` and then remove or recreate (`managed.go:781`). A start still pulling
  (no container yet), or one that begins in between, races the removal. Refuse while
  the game is starting or stopping.
- [ ] **J2. Three independent pollers per game** (web snapshot memo, playerwatch, idle
  shutdown) each run `Status.Check` and the player probe. Phase 4's state hub is the full
  fix. Interim: share one memoised observation.
- [x] **J3. Shutdown doesn't wait for backups** (`backups.Wait()` is never called).
- [ ] **J4. CI only syntax-checks `app.js` and `login.js`** (`ci.yml:42`). `games.js` and
  `settings.js` are skipped, and nothing checks templates for duplicate ids (that check
  would have caught B1).

## P. Performance

- [ ] **P1. Static assets are uncached and uncompressed.** The embedded FS has no
  modification times, so there is no ETag or Last-Modified, and there is no
  Cache-Control or gzip. About 190 KB is re-downloaded per page load. Hash the asset
  URLs, cache them for a long time, and gzip.
- [x] **P2. `nvidia-smi` runs per game per stats refresh** (`app.go:619`), although the
  GPU figures are host-wide. It also retries on hosts without a GPU. Cache per host and
  remember when it is missing.
- [x] **P3. Playtime is recomputed from the full history** under the store lock on
  every `/api/activity` call. Keep it incrementally, or cache it until the next
  `Record`.
- [ ] **P4. The dashboard polls four endpoints on separate timers.** Fold `/api/health`
  into `/api/games`. Use one SSE stream with Phase 4.
- [ ] **P5. The console output box grows forever**, and each line rewrites all of its
  text (`app.js:803`). Cap it like the log panel.

## M. Menus and features: implementation

- [ ] **M1. The top bar differs on every page.** The dashboard has Games, Settings and
  Log out. Settings and Games have no Log out. No page marks the current one. The SVG
  sprite and header are copied into three templates. Use one shared nav partial with
  the current page marked and Log out everywhere.
- [ ] **M2. Card tabs show features a game lacks.** The Info tab is on every card
  (`dashboard.html:110`). Add a `HasInfo` flag like Backups and Console. Stats keeps
  polling while the game is offline.
- [ ] **M3. Wrong icons.** Backups uses the Info icon and Console uses the Logs icon.
- [ ] **M4. Duplicated JS helpers.** `toast` and `callAPI` are copied three times, 401
  handling is inconsistent, and every 403 says "reload the page" even when the cause is
  the player role. Use one shared `api.js`.
- [ ] **M5. Mixed confirmations.** Disable, Delete user and danger console actions use
  `confirm()`, while the switch prompt is a themed dialog. Make one themed confirm
  dialog. "Update image" (which recreates the container) has no confirmation.
- [ ] **M6. The toast has one slot, no close button, and no success/error style.** When
  a log stream ends because the container stopped, the panel says nothing.
- [ ] **M7. Unclear empty states.** The empty dashboard says "add to config.yaml"; it
  should link admins to `/games`. The overnight hours don't say which timezone they use
  (`server.tz`).

## L. Look and feel

- [ ] **L1. Accent colours are hardcoded for three games** (`style.css:227`). Let
  `module.yaml` declare an `accent` and pass it to the card as `--vessel`.
- [ ] **L2. The fleet banner only names the first active game** when more than one is
  running.
- [ ] **L3. Card panels stack.** Logs, Stats, Info, Backups and Console can all be open
  at once. Use a real tab group: one panel open, arrow-key navigation, `role="tablist"`.
- [ ] **L4. Text inputs remove the focus outline** (`outline: none`). Give them a
  `:focus-visible` ring like the buttons.
- [ ] **L5. The Settings modules pane duplicates the catalogue verdicts.** Link each
  entry to its card on the Games page instead.
