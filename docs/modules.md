# Bundled modules

A module tells CrowsNest how to read one kind of game server (status, players, startup progress, consoles).
Bundled modules ship inside the binary; your own go in `modules_dir` as `<id>/module.yaml` (same format).
A game in `config.yaml` uses the module whose id equals the game's `id`, or the one named by `module:`.

| Module id | Covers | Players come from |
|---|---|---|
| `valheim` | Valheim (lloesche/valheim-server) | container log |
| `palworld` | Palworld (thijsvanloef/palworld-server-docker) | REST API |
| `windrose` | Windrose (+ optional Windrose+ mod) | container log, mod cross-check |
| `minecraft` | Minecraft Java (itzg/minecraft-server; vanilla, Paper, Fabric, Forge) | container log |
| `source` | Source/GoldSrc family: TF2, CS2, CS:S, CS 1.6, L4D, L4D2, DoD:S, HL2DM and similar | RCON `status` |
| `dontstarve` | Don't Starve Together | container log |

Markers for Valheim and Windrose were checked against real sessions. Minecraft, Source and Don't Starve Together
were written from the games' documented log/`status` formats and fixtures in `internal/modules/testdata`; confirm
on the first real session and adjust a local copy of the module if a line differs.

## Using a module

Add a game to `config.yaml` (container and compose entries as for any game), then give it options:

```yaml
- id: minecraft            # module "minecraft" is picked by id
  display_name: Minecraft
  container_name: minecraft
  compose_file: /data/compose.yaml
  compose_profile: minecraft
  compose_service: minecraft
  options:                 # optional: enables the admin raw console
    rcon_addr: "minecraft:25575"
    rcon_password_env: MINECRAFT_RCON_PASSWORD
```

Passwords are never written in `config.yaml`: an option ending in `_env` names an environment variable.

## One module, many games: `source`

Games with their own id pick the shared module with `module: source`. Each gets its own card, container and
settings; only the RCON address and password differ:

```yaml
- id: tf2
  display_name: Team Fortress 2
  container_name: tf2
  module: source
  compose_file: /data/compose.yaml
  compose_profile: tf2
  compose_service: tf2
  connect_address: "10.0.0.2:27015"
  options:
    rcon_addr: "tf2:27015"            # container name and RCON port on the games network
    rcon_password_env: TF2_RCON_PASSWORD

- id: cs2
  display_name: Counter-Strike 2
  container_name: cs2
  module: source
  # ... compose fields ...
  options:
    rcon_addr: "cs2:27015"
    rcon_password_env: CS2_RCON_PASSWORD
```

The game server needs RCON on (`rcon_password` set, and for CS2 `-usercon`/the image's RCON setting), the port
reachable from the panel over the games network, and `sv_rcon` not blocking the panel after bad passwords.
`source` is the right choice for any Source or GoldSrc server whose `status` command lists players as
`# id "name" STEAM_...`, `# id "name" [U:...]`, `# id idx "name" STEAM_...` (Left 4 Dead) or the CS2 table.
Bots are never counted. Without `rcon_addr` the game still starts and stops, but the player count stays unknown.

## Writing a new module

Copy `internal/modules/bundled/minecraft/module.yaml` (log-based) or `source` (RCON-based) into
`<modules_dir>/<id>/module.yaml`, change the regexes, and add the game to `config.yaml`. Unknown keys are an
error, so a typo cannot silently disable a setting. Add a fixture of real log lines and test it the way
`internal/modules/minecraft_test.go` does.

## Rendering containers from a module (`crowsnest render`)

A module's `runtime:` section describes its container: image, published ports, data folders, stop grace, memory
and environment. `crowsnest render` turns the games in `config.yaml` into the compose file **and** the guard's
`GUARD_SCOPES` from that one description, so the two can no longer disagree (the usual cause of a guard DENY).

```yaml
# config.yaml
platform:
  games_root: ${USERDIR}        # where each game's data folder lives; written as-is
  host_ip: 10.0.0.2             # address game ports are published on (default 0.0.0.0)
  host_games_root: /srv/games   # games_root as a literal path, for the guard (only if games_root is a variable)
  games_network: crowsnest-games-net
games:
  - id: minecraft
    container_name: minecraft
    ...
    options: {eula: "TRUE", motd: "Friday night", max_players: "6"}
```

```
crowsnest render --config config.yaml --compose games.compose.yaml --scopes scopes.json --env env.example
```

- Game settings come from `options:`. A setting you leave out becomes a compose variable such as
  `${MINECRAFT_MOTD:-A CrowsNest Minecraft server}`, so an existing `.env` keeps working.
  **Secret options are never written into a file**: they always render as `${MINECRAFT_RCON_PASSWORD:-}`.
- Reserved options for any game: `image`, `tag` (default `latest`), `ports` (`27015/udp,27016:27015/tcp`),
  `data_dir` (a plain folder name under `games_root`). A shared module such as `source` has no image of its own,
  so every game using it sets `image` (and `ports`).
- A module can only ask for what the guard allows by default: its own image, bind folders under `games_root`, the
  games network, published ports, no privileges. Windrose needs a macvlan address and `seccomp=unconfined`, so it
  has no `runtime:` and keeps its hand-written service and scope.
- Rendered Valheim and Palworld services are checked in tests against the hand-written production ones.

Runtime sections today: `valheim`, `palworld`, `minecraft`, and `source` (image required per game).
`dontstarve` has none yet, because I haven't verified an image's ports and data layout.

## The policy envelope and managed scopes (guard)

The guard has two scope sources:

- `GUARD_SCOPES`: the operator's own JSON, trusted, read at start. Unchanged.
- `GUARD_SCOPES_FILE`: a **managed** scopes file the dashboard may rewrite. Needs `GUARD_POLICY`, a `policy.yaml`
  mounted read-only into the guard and not writable by the panel. Every managed scope must fit the policy or it is
  **not loaded** (the others still are); the guard enforces this itself, so a compromised panel that writes a bad
  scope gains nothing.

The guard reloads when either file changes (checked every 2s) or on `SIGHUP`. A reload that fails to parse keeps the
scopes in force exactly as they were; a tighter policy drops managed scopes that no longer fit. Either variable alone
is enough to start (`GUARD_SCOPES_FILE` with no `GUARD_SCOPES` is fine); with a managed file but no policy it refuses.

```yaml
# policy.yaml: every list is required, so no limit is ever implied
games_root: /srv/games                 # managed binds must be exact paths inside this folder
names: [valheim, minecraft, "gs-*"]    # container names the panel may manage (trailing * = prefix)
images: [lloesche/valheim-server, "docker.io/itzg/*"]   # "*" alone = any image; prefixes are fully qualified
networks: [crowsnest-games-net]
ports: ["27000-28999/udp", "25565/tcp"]  # host ports and protocol
host_ips: [10.0.0.2]                   # optional: limits the address ports are published on
exec: false                            # may managed scopes use docker exec (save-on-stop hooks need it)
labels: []                             # extra labels they may require (the watchtower opt-out is always fine)
max_scopes: 32
```

- `names` matters: the guard lets a scope manage the container of the same name, so without it a scope called
  `caddy` would let the panel stop your reverse proxy.
- A managed scope can never carry volumes, security options, capabilities, aliases or fixed addresses, host
  networking, or exec unless the policy allows it. Windrose-style needs stay in the operator's own `GUARD_SCOPES`.
- Official Docker Hub images are fully qualified in a scope (`itzg/minecraft-server` is `docker.io/itzg/minecraft-server`),
  so policy prefixes are written that way.
- `Policy.Admit` is the same check the dashboard will use to preview "does this fit?" before enabling a game.

## Enabling games from the dashboard (API)

Turn it on in `config.yaml`:

```yaml
platform: {games_root: /srv/games, host_ip: 10.0.0.2}
managed:
  dir: /app/data/managed            # the panel writes here; mount it read-only into the guard
  policy_file: /etc/crowsnest/policy.yaml   # read-only for the panel as well
```

and run the guard with `GUARD_SCOPES_FILE=<dir>/scopes.json` (mount the **directory**, files are replaced by rename)
and `GUARD_POLICY=<policy file>`. A config with no `games:` is valid when `managed.dir` is set.

Admin-only endpoints (the page that uses them is step 4):

| Request | What it does |
|---|---|
| `GET /api/managed/modules` | modules that can be enabled, with their options (secret ones flagged) |
| `GET /api/managed/games` | dashboard-enabled games and their state: `installing`, `ready`, `failed` |
| `POST /api/managed/preview` | dry run: the rendered compose service, the guard scope, and whether it fits the policy (and why not) |
| `POST /api/managed/games` | enable: `{id, module, display_name, options, secrets}` |
| `PUT /api/managed/games/{id}` | change a **stopped** game's settings (`display_name`, `connect_address`, `options`, `secrets`); the container is recreated, the module cannot change, secrets left out keep their stored value |
| `POST /api/managed/games/{id}/refresh` | pull the image again and recreate the container with the same settings |
| `DELETE /api/managed/games/{id}` | disable a **stopped** game: removes the container, scope and secrets; the data folder is kept |

How enabling works: validate against the module (unknown options, secrets sent as plain options, missing required
values and control characters are refused) → render → check against the policy (refused if outside it) → write the
secrets and state → write `scopes.json` → pull the image and create the container **through the guard** (retrying a
403 for up to 30s while the guard picks up the new scope) → the game appears on the dashboard. This is idempotent,
so a game that did not finish installing is finished on the next start.

- The panel creates containers itself over the Docker API: no compose CLI is involved. Games from `config.yaml`
  keep working as before and win any id clash.
- Secrets are kept in `secrets.json` (mode 0600) in the panel's state directory and are never in `games.json`,
  `scopes.json`, a preview or a list. A module option such as `rcon_password_env` next to a secret `rcon_password`
  is pointed at the stored value automatically. Modules receive them through a lookup, not the process environment.
- The panel cannot widen what it may do: the guard re-checks every scope against the policy, so a panel that wrote an
  out-of-policy scope would simply not have it loaded.
- Updates and edits recreate the container (the data folder is a bind mount, so nothing is lost). An unreachable
  registry is tolerated on an edit if the image is already local, but not on a refresh. Pull-on-start for managed
  games is not wired: use refresh.
- Not yet: the Games page (step 4).

## Where this is heading: enable games from the dashboard

Agreed direction: the dashboard renders and **applies** a game itself, but only inside a read-only policy file the
operator owns (games folder, port range, allowed networks, no privileges). Anything outside that envelope is staged
for the operator to approve outside the dashboard. Steps, each shippable on its own:

1. Runtime sections and `crowsnest render` (done, above).
2. `policy.yaml` envelope plus a check that a rendered game fits it; the guard reads managed scopes from a mounted
   file and reloads on change or `SIGHUP` (done, below).
3. The dashboard enables, installs and removes games itself, admin only (done, below).
4. A Games page: pick a module, fill in its options, see the rendered compose and what falls outside the policy,
   enable.
5. Remote module sources with signature checks.
