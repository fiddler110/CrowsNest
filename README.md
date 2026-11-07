# CrowsNest

A self-hosted web dashboard for controlling game server Docker containers —
start/stop, live logs, status, resource stats — with a built-in guard that
keeps at most **one** game server running at a time and prompts before
switching between them.

This is a ground-up Go rewrite of the original Python/Flask CrowsNest
(single-game, Windrose-only), generalized to control multiple games from one
dashboard. See the [implementation plan](docs/implementation-plan.md) for
the full design rationale and phase-by-phase history.

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
3. Create at least one login: `docker compose exec crowsnest crowsnest set-password <username>`.
4. Open `http://<host>:5000`.

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

### Sessions

Login sessions are stateless signed cookies, valid for `auth.DefaultSessionTTL`
(3 hours) after login — no "remember me," just log back in once it expires.
There's no server-side session store to revoke a single device from, but
`docker compose exec crowsnest crowsnest revoke-sessions <username>` forces
every outstanding session for that user to fail on their next request; it
edits the users file, so it takes effect the next time crowsnest restarts.
It works for Google sign-in users too (any name on the allowlist), even
though they have no password entry. To remove someone entirely, take them
off the Google allowlist (or delete their password entry) and restart: a
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
| `POST` | `/api/games/{id}/stop` | Stop the game's container |

## Development

```bash
go build ./...
go vet ./...
go test ./...

# Run locally (needs a config.yaml — see config.yaml.example)
go run ./cmd/crowsnest serve
```

## License

GPLv3 — see [LICENSE](LICENSE).
