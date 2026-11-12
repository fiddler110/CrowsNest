# HTTP API

The routes behind the dashboard.

Back to the [README](../README.md).

All `/api/*` routes need a session cookie (log in at `/login` first). State-changing routes also need the session's
CSRF token. The dashboard itself uses `GET /api/events`, one stream of state changes, instead of polling.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/games` | All games and their current status |
| `GET` | `/api/events` | SSE stream of state changes (a few streams per user) |
| `GET` | `/api/games/{id}/status` | One game's status: `online`, `starting`, `offline` or `unknown` |
| `GET` | `/api/games/{id}/startup-progress` | SSE stream of startup milestones |
| `GET` | `/api/games/{id}/stats` | CPU, memory and (if available) GPU use |
| `GET` | `/api/games/{id}/players` | Player count and names, where available |
| `GET` | `/api/games/{id}/info` | Per-game info panel, where the module provides one |
| `POST` | `/api/games/{id}/start` | Start the game's container |
| `POST` | `/api/games/{id}/switch` | Stop whichever game is running, then start this one |
| `POST` | `/api/games/{id}/stop` | Stop the game (accepted, runs in the background; status shows `stopping`) |
| `GET` | `/api/activity` | Recent activity and playtime per player (`?limit=`, `?game=`) |
| `GET` | `/api/audit` | The full activity log, filtered and paged (**admin only**; `?game=`, `?kind=`, `?actor=`, `?q=`, `?since=`, `?until=`, `?offset=`, `?limit=`) |
| `GET` | `/metrics` | Prometheus metrics, only when `server.metrics_token_env` is set; bearer token, no session |
| `GET` | `/api/host` | Host memory, load and disk space |
| `GET` | `/api/health` | Whether CrowsNest can reach Docker |
| `GET` | `/api/games/{id}/logs` | SSE stream of `docker logs -f` (**admin only**) |
| `GET`/`PUT` | `/api/settings` | Runtime settings (**admin only**) |
| `GET` | `/api/games/{id}/console` | Console actions and raw-console state (**admin only**) |
| `POST` | `/api/games/{id}/console/action` | Run a fixed console action (**admin only**) |
| `POST` | `/api/games/{id}/console/raw` | Send a raw RCON command, refused unless enabled in Settings (**admin only**) |
| `GET` | `/api/games/{id}/backups` | Backup files (**admin only**) |
| `POST` | `/api/games/{id}/backup` | Start a backup in the background (**admin only**) |
| `GET`/`POST`/`PUT`/`DELETE` | `/api/users`, `/api/users/{name}` | Manage users (**admin only**) |
| various | `/api/managed/...` | The Games page: modules, policy, preview, enable, edit, refresh, roll back and disable games (**admin only**) |
