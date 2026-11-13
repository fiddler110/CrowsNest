# Setting it up

The fastest start is the [quickstart](../quickstart/README.md); this page is the longer, hand-configured setup and the notes on how CrowsNest reaches Docker.

Back to the [README](../README.md).

## Hand-configured setup

Images are published to `ghcr.io/fiddler110/crowsnest` (`:latest`, `:X.Y.Z`, `:X.Y`, `:dev`). Every push to `main`
passes the CI and security gate before a release is cut. Images are scanned, signed with cosign and shipped with an
SBOM; see [publishing.md](publishing.md). You don't need a Go toolchain.

**The fastest start** is [`quickstart/`](../quickstart/README.md): the panel plus the guard, with no games
configured. You add games from the web page. At any point,
`docker compose exec crowsnest crowsnest doctor` checks Docker access, file permissions, the policy and a few safety
settings, and tells you what to fix.

The steps below are the longer, hand-configured setup, where games are defined in `config.yaml` and a compose file.

1. Copy [`config.yaml.example`](../config.yaml.example) to `config.yaml`, [`compose.yaml.example`](../compose.yaml.example)
   to `compose.yaml` and [`.env.example`](../.env.example) to `.env`, and edit them. `config.yaml` holds paths,
   timezone and integrations, `compose.yaml` holds volumes and ports, and `.env` holds secrets and host-specific
   values (it's git-ignored).

   CrowsNest no longer runs `docker compose` itself (there is no docker CLI or compose in its image): it starts
   and stops existing containers through the Docker Engine API. Create each game's container once on the host,
   without starting it: `docker compose --profile <game> up --no-start` (or `create`). After that CrowsNest
   starts and stops them on demand. A game whose container does not exist fails to start with a message that
   says so. Games you add from the dashboard are created by CrowsNest and need no compose file at all.
2. Start only the controller: `docker compose up -d crowsnest`. It starts and stops the game containers itself, so
   you never run `--profile <game> up` by hand once they exist.
3. Open `http://<host>:5000`. With no users yet you get the first-run setup page. Read the setup code from
   `docker compose logs crowsnest` (it's also saved as `setup-token` next to the session secret), then choose an
   admin username and passphrase. The page closes once the first account exists, and there are no default
   credentials. If you'd rather use the command line,
   `docker compose exec crowsnest crowsnest set-password <username>` works too.

## Docker socket access

`compose.yaml.example` mounts `/var/run/docker.sock` straight into the crowsnest container by default. That's the
simplest setup, but anything that runs arbitrary code inside the container then has root-equivalent control of the
host. I'd only use it on a machine where that's acceptable.

The better options, in order:

- The [quickstart](../quickstart/README.md) stack, which puts the guard (with the exec allowlist built in) in front of the socket and uses
  the policy file. This is what I'd recommend.
- The commented-out [docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy) service in
  `compose.yaml.example`, allowing only the API calls CrowsNest makes. Point `server.docker_host` at it
  (`tcp://dockerproxy:2375`) instead of mounting the socket. The comments in both example files cover the swap.

If the panel is exposed to the internet, put it behind HTTPS, set `server.secure_cookies: true`, and list your
reverse proxy in `server.trusted_proxies` so the sign-in rate limit counts real visitors. `crowsnest doctor` checks
these.
