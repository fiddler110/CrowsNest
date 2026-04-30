# Windrose — Docker Stack & CrowsNest

Docker Compose stack for the Windrose dedicated game server alongside the **CrowsNest** — a Flask web application that lets authorised users start, stop, and monitor the server from a browser, with optional Windrose+ integration for live player counts, world state, and automated night-time shutdown.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Directory Structure](#directory-structure)
3. [Windrose Server Image](#windrose-server-image)
4. [Prerequisites](#prerequisites)
5. [First-Time Setup](#first-time-setup)
6. [Environment Variables Reference](#environment-variables-reference)
7. [Starting the Stack](#starting-the-stack)
8. [CrowsNest Web UI](#crowsnest-web-ui)
9. [Windrose+ Integration](#windrose-integration)
10. [Night Shutdown](#night-shutdown)
11. [Discord Notifications](#discord-notifications)
12. [Security](#security)
13. [Ports Reference](#ports-reference)
14. [Common Operations](#common-operations)
15. [Troubleshooting](#troubleshooting)

---

## Architecture Overview

```
  Browser  ──────────────► CrowsNest  (port 5000)
                                    │
                    ┌───────────────┼──────────────────────┐
                    │               │                      │
             Docker socket    Windrose+ HTTP API     docker inspect
             (start/stop/     port 8780              (uptime via
              logs)           /api/status            StartedAt)
                              /api/rcon
                                    │
                            windrose container
                            (Unreal Engine, host network)
                            ports: 7777/UDP, 7778/UDP, 8780/TCP
```

The `crowsnest` container:
- Talks to the **Docker socket** to start/stop the `windrose` container, stream its logs, and read its start time for accurate uptime display.
- Integrates with **Windrose+** exclusively through its **HTTP API** at port 8780:
  - `GET /api/status` — live player count, names, server info, multipliers, and mode (`boot` / `active` / `idle` / `degraded`).
  - `POST /api/rcon` — dynamic world data: time of day, weather, connection stats, and memory. All four RCON commands are dispatched **concurrently** so the panel loads in parallel rather than serially.
- No shared filesystem volumes are required between the two containers.

---

## Directory Structure

```
Windrose/
├── compose.yaml                    # Docker Compose stack (both services)
├── .env                            # Windrose server env vars (not committed — copy from .env.example)
├── .env.example                    # Template for the root .env
├── .gitignore
├── README.md                       # This file
└── CrowsNest/
    ├── app.py                      # Flask application
    ├── Dockerfile                  # Python 3.12-slim + Docker CLI
    ├── requirements.txt            # Python dependencies
    ├── set_password.py             # CLI tool to set user passwords
    ├── .env                        # Controller env vars (not committed — copy from .env.example)
    ├── .env.example                # Template for CrowsNest/.env
    └── templates/
        ├── index.html              # Main dashboard
        └── login.html              # Login page
```

---

## Windrose Server Image

The `windrose` service in this stack uses the Docker image maintained by **indifferentbroccoli**:

> **[github.com/indifferentbroccoli/windrose-server-docker](https://github.com/indifferentbroccoli/windrose-server-docker)**

Refer to that project for the full list of supported environment variables, volume layout, Windrose+ plugin setup, and any game-server-specific configuration beyond what is documented here.

---

## Prerequisites

- **Docker Engine** ≥ 24 with the `compose` plugin (`docker compose`)
- **Python 3.10+** on the host (only for the one-time `set_password.py` step)
- **Windrose+** installed in the server files (optional — controller works without it)
- The host Docker socket group GID (run `stat -c '%g' /var/run/docker.sock` to find it)

---

## First-Time Setup

### 1 — Clone the repo and copy the env templates

```bash
git clone https://github.com/<your-username>/CrowsNest.git
cd CrowsNest
cp .env.example .env
cp CrowsNest/.env.example CrowsNest/.env
```

All commands below assume you are running from the directory that contains `compose.yaml` (the repo root).

> **Using with an existing Docker stack**: This `compose.yaml` can be pulled into a parent stack using the [`include:` top-level key](https://docs.docker.com/compose/how-tos/multiple-compose-files/include/) (requires Docker Compose ≥ v2.20):
>
> ```yaml
> include:
>   - path: ./Windrose/compose.yaml
> ```
>
> `crowsnest` has no profile and will start normally with `docker compose up -d` from the parent project. The `windrose` game server service uses `profiles: ["windrose"]`, so it will **not** start automatically — it must be started explicitly or via the CrowsNest web UI. This means working on other containers in the parent stack won't inadvertently touch the game server.

### 2 — Configure the Windrose server `.env`

Copy and edit the root `.env` (used by the `windrose` container):

```env
TZ=America/New_York           # IANA timezone — see https://en.wikipedia.org/wiki/List_of_tz_database_time_zones
PUID=1000                     # UID of the user that will own server files on the host
PGID=1000                     # GID of that user
DOCKER_GID=999                # GID of /var/run/docker.sock on your host
                              # Run: stat -c '%g' /var/run/docker.sock
USERDIR=/path/to/server-files # Host base path; Windrose files stored at $USERDIR/Windrose
P2P_PROXY_ADDRESS=192.168.1.x # LAN IP of the host NIC used for P2P proxy
INVITE_CODE=YourInviteCode
SERVER_NAME=MyServer
SERVER_PASSWORD=YourPassword
MAX_PLAYERS=4
UPDATE_ON_START=false
WINDROSE_PLUS_ENABLED=true    # Set to false if not using Windrose+
```

> **Note**: `USERDIR` must point to an existing host directory. Server files are stored at `$USERDIR/Windrose/` and mounted into the container at `/home/steam/server-files`. This directory must be writable by the UID/GID specified in `PUID`/`PGID`.

### 3 — Configure the CrowsNest `.env`

Edit `CrowsNest/.env`. The password hashes are generated in the next step, but all other values should be set now:

```env
# User password hashes — one entry per user defined in VALID_USERS in app.py
# Populated by set_password.py (see step 4). Example for a user named "alice":
ALICE_PASSWORD_HASH=

# Flask session secret — auto-generated on first run if not set
SESSION_SECRET=

# Windrose+ RCON and HTTP API password — must match the rcon.password
# field in $USERDIR/Windrose/windrose_plus.json on the host
WINDROSE_PLUS_RCON_PASSWORD=YourRconPassword

# Windrose+ HTTP API base URL (Windrose+ listens on host network, port 8780)
WPLUS_HTTP_URL=http://host.docker.internal:8780

# Discord webhook URL for night shutdown notifications (optional)
DISCORD_WEBHOOK_URL=

# Night shutdown — auto-stops the server if empty during the configured window
NIGHT_SHUTDOWN_ENABLED=true
NIGHT_SHUTDOWN_START=23      # Hour (0-23) checks begin (default: 11 pm)
NIGHT_SHUTDOWN_END=5         # Hour (0-23) checks stop  (default: 5 am)
NIGHT_SHUTDOWN_INTERVAL=30   # Minutes between checks   (default: 30)
```

### 4 — Set user passwords

Users are defined by the `VALID_USERS` set in `app.py`. Before running, edit that set to include the usernames you want, then run `set_password.py` for each one:

```bash
cd CrowsNest
python3 set_password.py alice
# Enter and confirm password when prompted

python3 set_password.py bob
# Enter and confirm password when prompted
cd ..
```

This writes `ALICE_PASSWORD_HASH` and `BOB_PASSWORD_HASH` into `CrowsNest/.env`. If you add or remove a username from `VALID_USERS`, rebuild the container afterward. Password-only changes take effect immediately — no rebuild needed.

### 5 — Verify the Docker socket GID

The container runs as a non-root user and needs access to `/var/run/docker.sock`. The compose file uses `group_add` with `${DOCKER_GID:-999}` to grant this at runtime:

```bash
stat -c '%g' /var/run/docker.sock
# e.g. 988
```

Set `DOCKER_GID=<that value>` in the root `.env` (not `CrowsNest/.env`).

### 6 — Configure Windrose+ (optional but recommended)

Windrose+ is a open-source plugin that runs inside the `windrose` container and exposes a local HTTP API on port 8780.

WindrosePlus is a server-side mod framework for the Windrose dedicated server that adds extensive customization, administration tools, and performance optimizations without requiring clients to install any mods. 

It functions similarly to Valheim+ but for the Windrose game engine, providing over 2,400 settings to adjust gameplay via simple INI files.

Key features of the WindrosePlus mod framework include:

- Live Sea Chart (Real-time Map): A browser-based map that automatically generates upon player connection, showing real-time player positions and creature locations.
- Web-Based Admin Console (RCON): A dedicated interface with over 30 built-in commands for managing the server, including monitoring performance, checking online players, and managing bans/kicks.
- Comprehensive Gameplay Multipliers: Allows admins to adjust XP rates, loot drops, stack sizes, crafting costs, crop speeds, and inventory/backpack sizes via configuration files.
- Massive Setting Configuration: Enables editing of 2,400+ server settings, including player health, stamina, armor, weapon damage, food effects, and creature stats.
- Server Query Support: Fixes default Windrose server limitations, ensuring the server is visible in standard monitoring tools and server browsers.
- Lua Mod Support: Allows for the hot-reloading of Lua scripts without needing to restart the server.
- CPU Optimization: Automatically reduces server CPU usage when no players are connected.
- Event Logging: Logs every player join/leave event, featuring a live filter for server management

#### Finding the RCON password

Windrose+ stores its configuration in `windrose_plus.json`, located inside your server files directory:

```
$USERDIR/Windrose/windrose_plus.json
```

On first run, Windrose+ generates this file with a random RCON password. To retrieve it:

1. Start the `windrose` container at least once to let Windrose+ initialise:
   ```bash
   docker compose --profile windrose up -d windrose
   ```
2. Once the server has booted (check `docker logs -f windrose`), open the generated config file on the host:
   ```bash
   cat "$USERDIR/Windrose/windrose_plus.json"
   ```
3. Copy the value of `rcon.password` from that file.

#### Connecting CrowsNest to Windrose+

Paste the RCON password into `CrowsNest/.env`:

```env
WINDROSE_PLUS_RCON_PASSWORD=<paste value from windrose_plus.json here>
```

Alternatively you can set a custom password yourself — edit `windrose_plus.json` directly and set `WINDROSE_PLUS_RCON_PASSWORD` to the same value:

```json
{
  "rcon": {
    "enabled": true,
    "password": "YourChosenPassword"
  }
}
```

> This same password authenticates to the Windrose+ HTTP dashboard at `http://<host-ip>:8780` and is used by CrowsNest for all API calls.

---

## Environment Variables Reference

### Root `.env` — Windrose server

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `TZ` | Yes | — | IANA timezone, e.g. `America/New_York` |
| `PUID` | Yes | — | Host UID to run the server process as |
| `PGID` | Yes | — | Host GID to run the server process as |
| `USERDIR` | Yes | — | Host base path; server files stored at `$USERDIR/Windrose` |
| `DOCKER_GID` | Yes | `999` | GID of `/var/run/docker.sock` on the host |
| `P2P_PROXY_ADDRESS` | Yes | — | Host NIC IP used for P2P proxy routing |
| `INVITE_CODE` | No | — | In-game invite code for players to join |
| `SERVER_NAME` | No | — | Server name shown in the browser |
| `SERVER_PASSWORD` | No | — | Password players need to connect |
| `MAX_PLAYERS` | No | `4` | Maximum concurrent players |
| `UPDATE_ON_START` | No | `false` | If `true`, SteamCMD updates the server on each start |
| `WINDROSE_PLUS_ENABLED` | No | `true` | Enable/disable the Windrose+ plugin |

### `CrowsNest/.env`

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `<NAME>_PASSWORD_HASH` | Yes | — | PBKDF2-SHA256 hash for each user listed in `VALID_USERS` in `app.py`. Generated by `set_password.py`. One entry per user, e.g. `ALICE_PASSWORD_HASH`. |
| `SESSION_SECRET` | No | auto-generated | Flask session signing key; auto-created on first run |
| `TZ` | No | `UTC` | IANA timezone for night shutdown scheduling and timestamps, e.g. `America/New_York`. Forwarded automatically from the root `.env` to the controller via `compose.yaml`. |
| `WINDROSE_PLUS_RCON_PASSWORD` | No | — | Must match `rcon.password` in `windrose_plus.json`; enables Windrose+ integration |
| `WPLUS_HTTP_URL` | No | `http://host.docker.internal:8780` | Windrose+ HTTP API base URL |
| `DISCORD_WEBHOOK_URL` | No | — | Discord webhook for night shutdown notifications |
| `NIGHT_SHUTDOWN_ENABLED` | No | `true` | Set to `false` to fully disable night shutdown |
| `NIGHT_SHUTDOWN_START` | No | `23` | Hour (0–23) the shutdown window opens |
| `NIGHT_SHUTDOWN_END` | No | `5` | Hour (0–23) the shutdown window closes |
| `NIGHT_SHUTDOWN_INTERVAL` | No | `30` | Minutes between idle checks (must divide evenly into 60) |

---

## Starting the Stack

All `docker compose` commands must be run from the **project root** (the directory that contains the top-level `docker-compose.yml` or wherever `INCLUDES` points). If you are running this as a standalone stack, run from the `Windrose/` directory.

```bash
# Build the CrowsNest image and start it (controller only — no game server yet)
docker compose up -d --build crowsnest

# Start the Windrose game server (requires the "windrose" profile)
docker compose --profile windrose up -d windrose

# Or start everything at once
docker compose --profile windrose up -d --build
```

The `windrose` service is behind a **profile** (`profiles: ["windrose"]`) so it is not started by default with a bare `docker compose up`. This allows the controller to remain running even when the game server is stopped, and lets the controller itself manage the server lifecycle.

### Rebuild after code changes

```bash
docker compose build crowsnest && docker compose up -d --no-deps crowsnest
```

---

## CrowsNest Web UI

Access the dashboard at `http://<host-ip>:5000` (or through your reverse proxy).

### Features

| Feature | Description |
|---------|-------------|
| **Status badge** | Shows `online` / `starting` / `offline` / `unknown` — `online` requires the UE log line "Host server is ready for owner to connect" |
| **Start / Stop** | Starts or stops the `windrose` container via Docker |
| **Check Now** | Polls the current container status immediately |
| **Live logs** | Streams `docker logs -f windrose` as Server-Sent Events in-browser |
| **System stats** | Shows container CPU, memory, and GPU utilisation (requires `nvidia-smi` for GPU) |
| **Windrose+ panel** | Live player count, player names + coordinates, server uptime, world time/weather, connection info, memory usage, and multipliers |
| **Update on start** | Toggles `UPDATE_ON_START` in the Windrose `.env` so SteamCMD runs on the next server start |
| **Night shutdown** | Shows next scheduled check time; configurable from `.env` |

### Server status states

| State | Meaning |
|-------|---------|
| `online` | Container is running **and** the UE log confirms the server is ready for connections |
| `starting` | Container is running but the server is still loading (UE log line not yet seen) |
| `offline` | Container is not running |
| `unknown` | Docker socket query timed out or errored |

### HTTP API endpoints (authenticated)

All endpoints require a valid session cookie (log in via the web UI first).

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/status` | Container status string |
| `POST` | `/api/start` | Start the `windrose` container |
| `POST` | `/api/stop` | Stop the `windrose` container |
| `GET` | `/api/logs` | SSE stream of `docker logs -f windrose` |
| `GET` | `/api/stats` | CPU, memory, GPU usage |
| `GET` | `/api/players` | Player count, names, availability |
| `GET` | `/api/windrose-info` | Full Windrose+ data (players, world, multipliers, memory) |
| `GET` | `/api/update-on-start` | Current `UPDATE_ON_START` value |
| `POST` | `/api/update-on-start` | Toggle `UPDATE_ON_START` |
| `GET` | `/api/night-shutdown` | Night shutdown config and next run time |
| `POST` | `/api/night-shutdown` | Enable/disable and reconfigure the shutdown window |

---

## Windrose+ Integration

Windrose+ is a server-side plugin that runs inside the `windrose` container and exposes an **HTTP API** on port 8780 (host network).

### How the controller uses Windrose+

All data is fetched over HTTP — no shared volumes or filesystem coupling:

```
1. GET  /api/status   → player count, names, multipliers, server info, mode
        │  mode == "boot" → skip RCON (plugin not yet connected)
        │  mode == "degraded" → wp.connections fallback for player count
        ▼
2. POST /api/rcon     → time of day, weather, connections, memory
   (wp.time / wp.weather / wp.connections / wp.memory — dispatched concurrently)
        │  always available
        ▼
3. docker inspect StartedAt  → server uptime (always accurate)
```

**Mode field**: `/api/status` returns a `mode` value that drives all behaviour:

| Mode | Meaning | RCON behaviour |
|------|---------|----------------|
| `boot` | Plugin hooks not yet connected | RCON skipped entirely |
| `active` | Server fully running, game thread healthy | Full RCON available |
| `idle` | No players, server idle | Full RCON available |
| `degraded` | Game thread starved (high load) | RCON responds but `wp.time`/`wp.weather` return UObject addresses instead of values; `wp.connections` used as player-count fallback |

**Data staleness detection**: The `/api/status` `timestamp` field is compared against `docker inspect StartedAt`. If the timestamp predates the container start, player data is suppressed (stale data from a previous session).

**Degraded mode**: When the game thread is starved, `/api/status` reports `player_count: 0` even with active connections. The controller falls back to `POST /api/rcon` with `wp.connections` to get the real connection count.

### Windrose+ HTTP API authentication

The API uses cookie-based sessions. The controller:
1. POSTs the RCON password to `http://host.docker.internal:8780/login`
2. Caches the returned `wp_session` cookie for 23 hours
3. Re-authenticates automatically when the cookie expires or is rejected

The `extra_hosts: host.docker.internal:host-gateway` entry in `compose.yaml` enables the container to reach the host's port 8780 via the `host.docker.internal` hostname.

> **No shared volumes required.** The `crowsnest` container does not mount `windrose_plus_data`. All communication with Windrose+ is over HTTP.

---

## Night Shutdown

The controller runs a background job (APScheduler cron) that checks whether the game server is online but empty during a configurable overnight window. If it finds zero players, it stops the container and optionally sends a Discord notification.

### Configuration

All settings live in `CrowsNest/.env` and take effect on the next scheduled check (no container restart needed — the scheduler is re-armed when values are toggled via the API):

| Variable | Default | Description |
|----------|---------|-------------|
| `NIGHT_SHUTDOWN_ENABLED` | `true` | Set to `false` to completely disable |
| `NIGHT_SHUTDOWN_START` | `23` | Hour the check window opens (11 pm) |
| `NIGHT_SHUTDOWN_END` | `5` | Hour the check window closes (5 am) |
| `NIGHT_SHUTDOWN_INTERVAL` | `30` | Minutes between checks |

The window wraps midnight: a start of `23` and end of `5` covers 11 pm → 5 am.

### Safety guard

The shutdown job treats Windrose+ being unreachable as a reason to **skip** the shutdown, not trigger it. If `get_player_info()` returns `available: False` (e.g. Windrose+ in boot mode, no RCON password configured), the job logs a warning and does nothing. This prevents an accidental shutdown if the integration layer is temporarily unavailable.

---

## Discord Notifications

Set `DISCORD_WEBHOOK_URL` in `CrowsNest/.env` to receive a message whenever the server is automatically shut down by the night shutdown job.

The message format is:
```
🌙 Windrose Server is shutting down for the night (no players active at HH:MM).
```

To create a webhook: Discord server → channel settings → Integrations → Webhooks → New Webhook → copy URL.

---

## Security

- **Passwords** are stored as PBKDF2-SHA256 hashes with a random 16-byte salt, 260,000 iterations — never in plaintext.
- **Rate limiting**: login attempts are capped at 10 per IP per 60-second window.
- **Session cookies** have `HttpOnly`, `SameSite=Strict`, and `Secure` flags. The `Secure` flag can be disabled for local plain-HTTP development by setting `INSECURE_COOKIE=true` in the container environment.
- **Security headers** are set on every response: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy`, `Referrer-Policy`.
- The app runs as a **non-root user** (`appuser`, UID 1000) inside the container; Docker socket access is granted only via `group_add` at runtime.
- The Windrose+ RCON password is used as-is for the HTTP API login — keep it strong and treat it the same as any service password.

---

## Ports Reference

| Port | Protocol | Service | Description |
|------|----------|---------|-------------|
| `5000` | TCP | crowsnest | Web UI / API |
| `7777` | UDP | windrose | Game traffic |
| `7778` | UDP | windrose | Query port |
| `8780` | TCP | windrose (Windrose+) | HTTP dashboard / API (host network) |

The `windrose` container uses `network_mode: host`, so ports 7777, 7778, and 8780 are bound directly on the host network interface.

---

## Common Operations

### Start the game server

```bash
# From the web UI: click Start
# Or from the host CLI:
docker start windrose
```

### Stop the game server

```bash
# From the web UI: click Stop
# Or from the host CLI:
docker stop windrose
```

### Restart the controller only (after .env changes)

```bash
docker restart crowsnest
```

### Rebuild and redeploy the controller after code changes

```bash
# From the Docker Compose project root:
docker rm -f crowsnest && \
docker compose build crowsnest && \
docker compose up -d --no-deps crowsnest
```

### Change a user's password

```bash
cd CrowsNest
python3 set_password.py <username>
# Enter the new password at the prompt
```

Then restart the controller so it picks up the new hash:
```bash
docker restart crowsnest
```

### View live container logs

```bash
docker logs -f windrose
docker logs -f crowsnest
```

Or use the **Logs** button in the web UI for the game server.

### Update the game server to the latest version

Either set `UPDATE_ON_START=true` in the root `.env` and restart the container, or toggle it on via the web UI's **Update on start** switch before clicking Start.

---

## Troubleshooting

### Web UI shows "offline" but the container is running

The controller checks the Unreal Engine log for the line `"Host server is ready for owner to connect"`. If the server is still loading (can take 1–3 minutes on first start), the status will show `starting`. Wait for the full boot or check `docker logs -f windrose` for progress.

### Player count shows 0 even when players are online

**Check the mode** from the Windrose+ API:
```bash
curl -s http://localhost:8780/api/status
# Should return {"error":"Authentication required"} — if connection refused, Windrose+ HTTP is not running
```

Once authenticated, check the `mode` field in the response:
- `"boot"` — plugin hooks haven't connected yet. The controller suppresses player data in this state. Wait for the server to fully start.
- `"degraded"` — game thread is starved. The controller falls back to `wp.connections` for player count, so the count should still work.
- `"active"` / `"idle"` — API should be returning correct data. Verify `WINDROSE_PLUS_RCON_PASSWORD` matches `windrose_plus.json`.

### Windrose+ stats panel shows no data

1. Confirm `WINDROSE_PLUS_RCON_PASSWORD` in `CrowsNest/.env` matches `windrose_plus.json`
2. Confirm `host.docker.internal` resolves and the API is reachable from the container:
   ```bash
   docker exec crowsnest python3 -c "import socket; print(socket.gethostbyname('host.docker.internal'))"
   docker exec crowsnest curl -s http://host.docker.internal:8780/api/status
   ```
3. Check the Windrose+ mode — if `"boot"`, time/weather/memory fields are intentionally blank (plugin not yet connected to the game thread).

### Night shutdown triggered even with players online

The shutdown job reads from `get_player_info()`. If Windrose+ is unreachable, it returns `available: False` and **skips** the shutdown. If it returns `count: 0` with `available: True`, that means the API genuinely reported no players. Check whether the session data was stale (see above).

### "Permission denied" accessing the Docker socket

The container's `appuser` must be in the Docker socket's group. Find the correct GID:

```bash
stat -c '%g' /var/run/docker.sock
```

Set `DOCKER_GID=<that number>` in the root `.env`, then rebuild:

```bash
docker compose up -d --build crowsnest
```

### Sessions expire unexpectedly

The `SESSION_SECRET` in `CrowsNest/.env` is used to sign session cookies. If it changes (e.g. the file is recreated), all existing sessions are invalidated. If you're seeing unexpected logouts, ensure `SESSION_SECRET` is pinned to a fixed value in the `.env` rather than being regenerated.
