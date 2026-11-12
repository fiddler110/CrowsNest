# Running it day to day

How games start, stop and shut down by themselves, what the settings do, and what the activity log, metrics, admin console and join details show.

Back to the [README](../README.md).

## One server at a time

The dashboard shows a card for every game, and any of them can be started or stopped from it. By default only one
game may run at once. Pressing Start on a second game is refused, and the dashboard offers to switch instead: stop
the running game, wait for it to go offline, then start the new one.

To allow more than one at a time, set `CROWSNEST_MAX_ACTIVE_GAMES` in `.env` or `server.max_active_games` in
`config.yaml` (the environment variable wins). When the limit is reached, Start still offers to switch away from
the first running game.

Palworld has a 30 second pause between a stop and the next start, because bringing it back up within seconds
crashed the server.

## Memory

Before a start, CrowsNest compares what the game needs with the host's available memory, minus a reserve
(`server.memory_reserve_mb`, 1024 by default, negative turns the check off). A game's need is its measured peak once
it has run, and the module's `runtime.ram` figure before that (an option on the game can override it). If it
doesn't fit, the start is refused with a message that says so. If the need or the host's memory isn't known, the
start is allowed.

With the default of one game at a time this rarely matters. It starts to matter once you raise
`max_active_games`.

## Starting is asynchronous

Start (and the start half of Switch) returns as soon as the limit, cooldown and memory checks pass. The
`docker compose up` itself, which includes pulling a multi-GB image the first time, runs in the background with a
30 minute limit. While it runs the game shows as **starting**, counts toward the limit, and its progress bar reads
"Pulling image / creating container" until the container exists. A failed start shows up as a toast on the
dashboard and as an `exclusivity: start ... failed` line in the log. Stop cancels a start that's still running.

With a compose file configured, Start always runs `compose up -d`, so edits to the compose file or `.env` take
effect on the next start (compose recreates the container). Behind a Docker API proxy that denies container delete
and rename, that recreate fails. Run `docker rm <game>` on the host, then Start again.

## Automatic shutdown and settings

By default a game with zero players for 15 minutes is stopped. It stays stopped until someone starts it again. A
game whose player count can't be read is never stopped automatically. An optional overnight window
(`night_shutdown`) stops empty servers during set hours.

Any signed-in user can change these from **Settings** on the dashboard, and the change applies immediately:

| Setting | Meaning |
|---|---|
| Stop a server when nobody is on it / minutes | the idle auto-stop and its timeout (1 to 1440 minutes) |
| Stop empty servers overnight / from / until | the overnight window, in `server.tz` hours |
| Servers allowed at once | how many games may run together |
| Per game: idle minutes / restart wait / overnight shutdown | override the idle timeout, the pause required between stopping and restarting, and whether the game is included in the overnight stop, for one game; an empty box uses the global value or the module's default |
| Update on start | run `docker compose pull` for the game each time it starts, so a restart picks up new server versions (a failed pull is logged and the old image is used) |

`config.yaml` holds the defaults. Whatever is saved from the dashboard is written to `server.settings_file`
(default `/app/data/settings.json`) and takes precedence from then on. Mount a directory there so it survives
container recreation (`${USERDIR}/crowsnest/config:/app/data` in `compose.yaml.example`; it must be writable by uid
1000). Delete the file to go back to the `config.yaml` values.

## Activity log, playtime and host health

Everything notable is appended to `server.history_file` (default `/app/data/events.jsonl`, one JSON object per
line): who started, stopped or switched a game, automatic stops, failed starts, settings changes, backups, and
players joining and leaving. The dashboard's logbook shows the latest entries and the total time each player has
spent in each game. That comes from join and leave events, so it only covers games whose player names CrowsNest can
read. Entries older than `server.history_retention_days` (default 180) are pruned. Keep the file on the same
persistent mount as the settings file.

Settings has an **Audit log** pane (admins) that filters the same log by game, kind, user, text and date.

**Crash loops.** Every 30 seconds CrowsNest reads each game container's last exit from Docker. A run that ended with
an exit code other than 0 or 143 (a normal stop) counts as a crash; 137 counts only when Docker says the kernel
killed it for memory, because `docker stop` produces 137 too when a game outlasts its grace period. Each crash is
logged. A game that crashes `crash_loop.crashes` times (default 3) within `crash_loop.window_minutes` (default 15) is
reported once as a crash loop, in the log and in Discord when a webhook is set, and again only after it has gone a
full window below the threshold. Crashes from before CrowsNest started are not counted.

**Metrics.** Set `server.metrics_token_env` to the name of an environment variable holding a token, and
`GET /metrics` serves Prometheus metrics (game up/players/crashes/crash-looping, host memory, load and disk) to a
scraper sending `Authorization: Bearer <token>`. With no token the route does not exist. It is outside the login
session, so if the panel is reachable from the internet, treat the token like a password.

A strip under the fleet banner shows host memory, load and free disk space for the paths in
`server.host_disk_paths`, and turns red when a disk is under 10% free or memory is nearly full. Mount the disk your
game data and images live on (read-only is fine) and list its path to watch it.

## Admin console

Admins get a Console tab on games that support it (Palworld today). It has two parts.

- **Fixed actions**, always available to admins: Players (names and user ids), Announce, Save world, Kick, Ban and
  Unban. They go through the game's REST API and CrowsNest validates the arguments. There is deliberately no
  shutdown action. Use Stop, which also saves and backs up.
- **A raw RCON box**, off by default. Set `rcon_addr` (for example `palworld:25575`, with `RCON_ENABLED=true` on the
  game) and an admin turns on "Allow the raw RCON console" in Settings. It then sends any command to the server, so
  only enable it if you're comfortable with every admin being able to do that. The RCON password is
  `rcon_password_env`, defaulting to the REST API password.

Players never see the console, and the API refuses them. Every command, and any attempt on the raw console while
it's off, goes to the audit log and the activity feed.

## Showing join details on the cards

A game's card can show where to connect and what to type, each with a copy button. In `config.yaml`:

```yaml
games:
  - id: palworld
    connect_address: "10.0.0.2:8211"
    connect_note: "Turn on Tailscale first"
    connect_secrets:
      - {label: Join password, env: PALWORLD_SERVER_PASSWORD}
```

`connect_secrets` values come from environment variables, so they stay in `.env`. Pass each one to the crowsnest
service in `compose.yaml`. An unset or empty variable is left out (and logged by name). Everything here is shown to
every signed-in user, so list only what any player should see, such as a join password or invite code, and never
the admin or REST password. Modules can declare the same thing with `connect:`.
