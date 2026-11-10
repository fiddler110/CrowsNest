# CrowsNest

A self-hosted web dashboard for controlling game server Docker containers —
start/stop, live logs, status, resource stats — with a built-in guard that
keeps at most **one** game server running at a time and prompts before
switching between them.

This is a ground-up Go rewrite of the original Python/Flask CrowsNest
(single-game, Windrose-only), generalized to control multiple games from one
dashboard. See the [implementation plan](docs/implementation-plan.md) for
the full design rationale and phase-by-phase history.
Supported games and how to configure them (including the shared Source-engine module for TF2, CS2, L4D2 and
others) are listed in [docs/modules.md](docs/modules.md).

## Status

Feature-complete for its initial scope (phases 1-11): login, dashboard,
start/stop/switch with the one-game-at-a-time guard, live log streaming,
startup progress, resource stats, per-game player counts, idle and
night-window auto-stop, and Discord notifications. See "Two things remain
explicitly unverified" in the [implementation plan](docs/implementation-plan.md#where-things-stand-last-updated-2026-09-12)
for the parts that haven't been smoke-tested against a real server.

## Supported games (day one)

- Windrose (`indifferentbroccoli/windrose-server-docker`) — status, start/stop,
  logs, stats; player count/world info/night-shutdown eligibility additionally
  require the optional Windrose+ HTTP/RCON integration
- Valheim (`lloesche/valheim-server`) — status (starting vs. online, read
  from the log), startup progress, start/stop, logs, stats, player count
  (via log tailing)
- Palworld (`thijsvanloef/palworld-server-docker`) — status, start/stop, logs,
  stats, player count (via its REST API)

Adding another game means a new `internal/games/<name>` package plus a
registry entry — no changes to the web, auth, exclusivity, or auto-stop
layers.

## Running

Pre-built images are published to `ghcr.io/fiddler110/crowsnest` (`:latest`,
`:X.Y.Z`, `:X.Y`, `:dev`). Every push to `main` passes the CI and security
gate, then cuts a release: patch by default, `#minor`/`#major` in a commit
message to bump higher, `[skip release]` to skip. Images are scanned before
they're pushed, signed with cosign and shipped with an SBOM. See
[docs/publishing.md](docs/publishing.md). No local Go toolchain needed.

**Fastest start:** [`quickstart/`](quickstart/README.md) is a ready stack (the panel plus the two guards that keep it away
from the raw Docker socket) with no games preconfigured; you add them from the web page. Run
`docker compose exec crowsnest crowsnest doctor` at any time: it checks Docker access, file permissions, the policy
and a few safety settings, and says what to fix. The steps below are the fuller, hand-configured setup.

1. Copy [`config.yaml.example`](config.yaml.example) to `config.yaml`,
   [`compose.yaml.example`](compose.yaml.example) to `compose.yaml`, and
   [`.env.example`](.env.example) to `.env`. Edit all three for your setup —
   `config.yaml` for paths/timezone/integrations, `compose.yaml` for
   volumes/ports, `.env` for secrets and host-specific values (it's
   git-ignored; everything else here is meant to be committed as-is or with
   your own edits).
   CrowsNest runs `docker compose` against that same compose file from
   *inside* its container (mounted at `/data/compose.yaml`, with `.env`
   mounted next to it as `/data/.env`), so keep the top-level `name:`, use
   absolute `${USERDIR}/...` host paths in game services, and don't use
   `${VAR:?}` there — compose interpolates the whole file, so one missing
   variable for one game would block starting any game. The header of
   `compose.yaml.example` explains each point.
2. Start just the controller: `docker compose up -d crowsnest`. CrowsNest
   starts/stops the game containers itself via the Docker socket — you don't
   run `--profile <game> up` by hand.
3. Open `http://<host>:5000`. With no users yet it shows the **first-run setup** page: read the setup code from
   `docker compose logs crowsnest` (it is also saved as `setup-token` next to the session secret), then choose the
   admin username and passphrase. The page closes as soon as the first account exists, and there are no default
   credentials. Prefer the command line? `docker compose exec crowsnest crowsnest set-password <username>` works too.

### One server at a time

The dashboard shows a card for every game in `config.yaml`, and any of them
can be started or stopped from it. By default only **one** game may run at a
time: pressing Start on a second game is refused and the dashboard offers to
*switch* — stop the running game, wait for it to go offline, then start the
new one. To allow more than one at once (a host with headroom), set
`CROWSNEST_MAX_ACTIVE_GAMES` in `.env` (passed through by
`compose.yaml.example`) or `server.max_active_games` in `config.yaml`; the
environment variable wins. When the limit is reached, Start still offers to
switch away from the first running game.

Palworld additionally enforces a 30-second pause between a stop and the next
start, because bringing it back up within seconds crashed the server.

### Starting is asynchronous

Start (and the start half of Switch) returns as soon as the request has
passed the limit and cooldown checks. The `docker compose up` itself, which
includes pulling a multi-GB image on first run, runs in the background
with a 30-minute limit, so a closed tab or a reverse-proxy timeout can't
kill it partway through. While it runs the game shows as **starting**,
counts toward the concurrent limit, and its progress bar reads "Pulling
image / creating container" until the container exists. A failed start
shows up as a toast on the dashboard and as an `exclusivity: start ...
failed` line in the CrowsNest log. Stop cancels a start that's still in
flight.

With a compose file configured, Start always runs `compose up -d`, so
edits to the compose file or `.env` take effect on the next start (compose
recreates the container). Behind a restrictive Docker API proxy that denies
container delete/rename, that recreate fails; `docker rm <game>` on the
host, then Start again.

### Automatic shutdown and settings

By default a game that has had zero players for 15 minutes is stopped. It then
stays stopped: someone has to start it again from CrowsNest. A game whose player
count can't be read is never stopped automatically. An optional overnight
window (`night_shutdown`) stops empty servers during set hours.

Every signed-in user can change these from the **Settings** button on the
dashboard, and the change applies immediately:

| Setting | Meaning |
|---|---|
| Stop a server when nobody is on it / minutes | the idle auto-stop and its timeout (1-1440 minutes) |
| Stop empty servers overnight / from / until | the overnight window, in `server.tz` hours |
| Servers allowed at once | how many games may run together |
| Update on start | run `docker compose pull` for the game each time it starts, so a restart picks up new server versions (a failed pull is logged and the old image is used) |

`config.yaml` holds the defaults; whatever is saved from the dashboard is written
to `server.settings_file` (default `/app/data/settings.json`) and takes
precedence from then on. Mount a **directory** there so it survives container
recreation (`${USERDIR}/crowsnest/config:/app/data` in `compose.yaml.example`; it must be
writable by uid 1000). Delete the file to go back to the `config.yaml` values.

### Adding your own game

A game is one `module.yaml` file, no code. [docs/writing-modules.md](docs/writing-modules.md) walks through writing
one, and `crowsnest module check` replays a captured log through it so you can see it work before you run the game.

### Roles

Two roles: **admin** can do everything; **player** can start, stop and switch
games and see status, players, stats and activity on the dashboard, but can't
open Settings or the Games page, read container logs, use the console or touch
backups. A role is set per user in the users file (`<NAME>_ROLE=admin|player`),
usually through `docker compose exec crowsnest crowsnest set-role <user> <admin|player>`.
A password account with no role is an admin, so existing accounts behave as
before until you demote them. A Google sign-in user with no role is a
**player**: promote yourself with `crowsnest set-role <you> admin` before
relying on Google sign-in (CrowsNest logs a warning at startup when no user
resolves to admin). Role changes apply
within seconds, and a demotion takes effect on the user's very next request.

### Activity log, playtime and host health

Everything notable is appended to `server.history_file` (default
`/app/data/events.jsonl`, one JSON object per line): who started, stopped or
switched a game, automatic stops, failed starts, settings changes, backups and
players joining and leaving. The dashboard's **logbook** shows the latest
entries and total time each player has spent in each game (from join/leave
events, so it only covers games whose player names CrowsNest can read).
Entries older than `server.history_retention_days` (default 180) are pruned.
Keep the file on the same persistent mount as the settings file.

A strip under the fleet banner shows host memory, load and free disk space
for the paths in `server.host_disk_paths`; it turns red when a disk is under
10% free or memory is nearly full. Mount the disk your game data and images
live on (read-only is fine) and list its path to watch it.

### Backups

A game with a `backup:` block in `config.yaml` gets a **Backups** panel
(admins only) with a "Back up now" button and the list of backup files.
Backups run inside the game's container with `docker exec`, so they use
whatever the image provides (see the Palworld example in `config.yaml.example`).
`exec` needs the docker-socket-proxy's `EXEC=1`, and because the proxy cannot
limit *which* commands run, put the bundled **exec guard** in front of it
(`crowsnest execguard`; see the `execguard` service in `compose.yaml.example`).
It allows exactly the commands your config implies (each `backup.exec`, the
`list_dir` listing, Windrose's readiness check), refuses exec options such as
`Privileged`, `User` and `Env`, and only lets `exec/<id>/start` through for ids
it approved itself. Restart it after changing `backup:` settings. For the Docker API
itself, `crowsnest guard` replaces the generic socket proxy: a scoped filter that
lets CrowsNest see and control only the containers named in `GUARD_SCOPES` (see
the `guard` service in `compose.yaml.example`). With `before_stop: true`
CrowsNest also takes a backup every time it stops that game on purpose, after
the world is saved, so an "update on start" pull always has a fresh backup
behind it. A failed backup is logged and never stops the game from stopping.

### Admin console

Admins get a **Console** tab on games that support it (Palworld today). It has
two parts:

- **Fixed actions**, always available to admins: Players (names and user ids),
  Announce, Save world, Kick, Ban and Unban. They go through the game's REST
  API and CrowsNest validates the arguments. There is deliberately no shutdown
  action; use Stop, which also saves and backs up.
- **A raw RCON box**, off by default. Set `rcon_addr` (for example
  `palworld:25575`, with `RCON_ENABLED=true` on the game) and an admin turns on
  "Allow the raw RCON console" in Settings. It then sends any command to the
  server, so only enable it if you are comfortable with every admin being able
  to do that. The RCON password is `rcon_password_env`, defaulting to the REST
  API password.

Players never see the console, and the API refuses them. Every command, and any
attempt on the raw console while it is off, is written to the audit log and the
activity feed.

### Sessions

Login sessions are stateless signed cookies, valid for `auth.DefaultSessionTTL`
(3 hours) after login — no "remember me," just log back in once it expires.
There's no server-side session store to revoke a single device from, but
`docker compose exec crowsnest crowsnest revoke-sessions <username>` forces
every outstanding session for that user to fail on their next request; it
edits the users file, which a running crowsnest watches, so it takes effect
within a few seconds (as does `set-password`).
It works for Google sign-in users too (any name on the allowlist), even
though they have no password entry. To remove someone entirely, take them
off the Google allowlist (restart to apply) or delete their password entry (applies
within seconds): a
session only stays valid while its username still has a way to sign in.
Rotating/deleting the session-secret file logs out every user at once, if
you ever need that blunter option.

### Signing in with Google

CrowsNest can do "Sign in with Google" itself (OpenID Connect, server side),
with its own allowlist, so it doesn't need a separate auth proxy and a
Google account only gets in if you listed it.

1. In Google Cloud Console, go to APIs & Services, then Credentials. Create
   an OAuth client ID of type **Web application**, with the authorized
   redirect URI `https://<your host>/auth/google/callback`. On the OAuth
   consent screen, the `openid` and `email` scopes are all CrowsNest asks for.
2. In `.env`, set `CROWSNEST_GOOGLE_CLIENT_ID`, `CROWSNEST_GOOGLE_CLIENT_SECRET`
   and the allowlist, e.g.
   `CROWSNEST_GOOGLE_USERS=alice=alice@gmail.com,bob=bob@example.org`.
   The name before each `=` is the CrowsNest username that Google account
   signs in as (in the audit log, and for `revoke-sessions`).
3. In `config.yaml`, add `auth.google.redirect_url` with the same URL, and
   `auth.password_login: false` if Google should be the only way in. An
   https redirect URL also needs `server.secure_cookies: true`.
   CrowsNest refuses to start if a value is missing or malformed. Addresses
   must be plain ASCII and match the Google account's exactly (case aside):
   `j.doe@gmail.com` and `jdoe@gmail.com` are different entries here.

The flow uses a signed 10-minute state cookie (state, nonce and PKCE), and
exchanges the code with Google's token endpoint directly over TLS. Once
signed in, it's the same 3-hour session as a password login. Requests to
Google need outbound HTTPS from the container. If the login page is
reached on another hostname that proxies to CrowsNest, the Google button
still goes through the redirect URL's host, and you land there.

### Showing join details on the cards

A game's card can show where to connect and what to type, each with a copy
button. In `config.yaml`:

```yaml
games:
  - id: palworld
    connect_address: "10.0.0.2:8211"
    connect_note: "Turn on Tailscale first"
    connect_secrets:
      - {label: Join password, env: PALWORLD_SERVER_PASSWORD}
```

`connect_secrets` values come from environment variables, so they stay in
`.env`; pass each variable to the crowsnest service in `compose.yaml`. An
unset or empty variable is left out (and logged by name). Everything here
is shown to every signed-in user, so list only what any player should see:
the join password or an invite code, never the admin or REST password.

### Docker socket access

By default `compose.yaml.example` mounts `/var/run/docker.sock` straight
into the crowsnest container so it can control the game containers. That's
the simplest setup, but it's worth knowing what it grants: anything that
ever runs arbitrary code inside the crowsnest container has root-equivalent
control of the whole host through that socket.

If you'd rather not hand over the raw socket, `compose.yaml.example` also
has a commented-out [docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy)
service that sits between crowsnest and the socket, allowlisting only the
Docker API calls crowsnest actually makes (list/inspect/start/stop/logs/stats,
`docker compose up`, and — only if you want Windrose's fine-grained
starting/online status — `exec`). Point crowsnest at it with
`server.docker_host: tcp://dockerproxy:2375` in `config.yaml` instead of
the socket mount; see the comments in both example files for the swap.

## HTTP API

All `/api/*` routes require an active session cookie (log in via `/login`
first); state-changing routes also require the session's CSRF token.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/games` | List all configured games and their current status |
| `GET` | `/api/games/{id}/status` | Single game's status: `online` / `starting` / `offline` / `unknown` |
| `GET` | `/api/games/{id}/logs` | SSE stream of `docker logs -f` |
| `GET` | `/api/games/{id}/startup-progress` | SSE stream of startup milestones |
| `GET` | `/api/games/{id}/stats` | CPU, memory, and (if available) GPU usage |
| `GET` | `/api/games/{id}/players` | Player count/names, where available |
| `GET` | `/api/games/{id}/info` | Rich per-game info panel (currently: Windrose+ only) |
| `POST` | `/api/games/{id}/start` | Start the game's container |
| `POST` | `/api/games/{id}/switch` | Stop whichever game is running, then start this one |
| `POST` | `/api/games/{id}/stop` | Stop the game's container (accepted; runs in the background, status shows `stopping`) |
| `GET` | `/api/activity` | Recent activity events and playtime per player (`?limit=`, `?game=`) |
| `GET` | `/api/host` | Host memory, load and disk space |
| `GET` | `/api/health` | Whether CrowsNest can reach Docker |
| `GET`/`PUT` | `/api/settings` | Runtime settings (**admin only**) |
| `GET` | `/api/games/{id}/console` | Console actions and raw-console state (**admin only**) |
| `POST` | `/api/games/{id}/console/action` | Run a fixed console action (**admin only**) |
| `POST` | `/api/games/{id}/console/raw` | Send a raw RCON command; refused unless enabled in Settings (**admin only**) |
| `GET` | `/api/games/{id}/backups` | Backup files (**admin only**) |
| `POST` | `/api/games/{id}/backup` | Start a backup in the background (**admin only**) |

## Development

```bash
go build ./...
go vet ./...
go test ./...

# Run locally (needs a config.yaml — see config.yaml.example)
go run ./cmd/crowsnest serve
```

## License

[PolyForm Noncommercial 1.0.0](LICENSE). In plain words (the license text is what counts):

- **Free** to self-host for yourself, your friends and family, a club or community, a school or a charity, and to
  change and share, with the license and the notice in [NOTICE](NOTICE) kept.
- **Not free** for commercial use: a company or service that runs CrowsNest as part of a business, such as a
  game-server hosting provider, needs a separate license from the author.
- Splitting the server bill with friends is fine; running it as a paid service is not.

This is a source-available license, not an OSI-approved open-source one. Contributions are accepted under the same
terms.
