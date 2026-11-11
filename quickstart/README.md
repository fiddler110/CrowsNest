# Quickstart

A working CrowsNest in five minutes, with the Docker socket kept away from the panel. You add games from the web
page afterwards, so nothing here is specific to one game.

```sh
cd quickstart
cp .env.example .env                       # set DOCKER_GID: stat -c '%g' /var/run/docker.sock
sudo mkdir -p /srv/games && sudo chown 1000:1000 /srv/games
mkdir -p data/managed && sudo chown -R 1000:1000 data
docker compose up -d
docker compose exec crowsnest crowsnest doctor     # checks the install and says what to fix
docker compose logs crowsnest                       # shows the setup code
```

Open <http://localhost:5000>. With no users yet it shows the first-run page: enter the setup code from the log,
then pick the admin username and passphrase. Then open **Games**, choose a game, and add it.

## What is in here

| File | Purpose |
|---|---|
| `compose.yaml` | two containers: the panel, and the `guard` (a scoped Docker API filter that also runs the exec allowlist) |
| `config.yaml` | the panel's settings; no games, dashboard games switched on |
| `policy/policy.yaml` | what the dashboard may create: host ports, exec, where game data lives (images and networks come from the modules) |
| `.env.example` | timezone, the docker group id, where the panel listens |

## Things to know

- **The limits live in `policy/policy.yaml`**, not in the web page. To allow another image or port, edit it on
  the host; the guard picks the change up within a few seconds. A game that needs something the policy does not
  allow is refused with the reason.
- **`/srv/games` appears in two places** (`config.yaml` and `policy/policy.yaml`). Change both together if you
  keep game data elsewhere, and create the folder.
- **Backups on another drive**: three commented lines switch on a shared backups folder, one sub-folder per game
  (see "A shared backups folder" in the [README](../README.md#a-shared-backups-folder), including what to watch:
  an unmounted drive, folder permissions, and that the panel can delete what it can write).
- **Serving it beyond this machine**: put HTTPS in front (Caddy, nginx, Cloudflare Tunnel), set
  `server.secure_cookies: true`, list the proxy under `trusted_proxies`, and set `CROWSNEST_BIND`.
- **Sign in with Google, Discord notices, backups, memory limits**: see the main
  [README](../README.md) and [docs/modules.md](../docs/modules.md).
- **Something is off?** `docker compose exec crowsnest crowsnest doctor`.
