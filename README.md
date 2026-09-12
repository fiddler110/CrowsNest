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
- Valheim (`lloesche/valheim-server`) — status, start/stop, logs, stats,
  player count (via log tailing)
- Palworld (`thijsvanloef/palworld-server-docker`) — status, start/stop, logs,
  stats, player count (via its REST API)

Adding another game means a new `internal/games/<name>` package plus a
registry entry — no changes to the web, auth, exclusivity, or auto-stop
layers.

## Running

1. Copy [`config.yaml.example`](config.yaml.example) to `config.yaml` and
   [`compose.yaml.example`](compose.yaml.example) to `compose.yaml`, and edit
   both for your setup (paths, timezone, which integrations to enable).
2. Build and start just the controller: `docker compose up -d crowsnest`.
   CrowsNest starts/stops the game containers itself via the Docker socket —
   you don't run `--profile <game> up` by hand.
3. Create at least one login: `docker compose exec crowsnest crowsnest set-password <username>`.
4. Open `http://<host>:5000`.

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
