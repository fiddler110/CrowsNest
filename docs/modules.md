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

See the step-by-step [guide to writing a module](writing-modules.md), and check yours with
`crowsnest module check <dir> --log <captured log>`.

A module may also carry a `backup:` block (`exec`, `list_dir`, `before_stop`, `keep`, same meaning as the config.yaml block).
`keep: N` (needs `list_dir`) makes CrowsNest delete all but the newest N files in `list_dir` after each successful
backup, with one more fixed `docker exec` (`sh`, GNU `find`, `sort`, `tail`, `cut` in the image; `rm -f` on direct
children only). It counts files, so a backup that writes two files per run keeps N/2 runs. A failed prune is logged
and shown in the activity log and never fails the backup.
It applies to games enabled from the dashboard only; games in `config.yaml` keep their own.
`dir: /path` (instead of `list_dir`) names where the backup command writes inside the container. With
`platform.backups_root` set, each dashboard game gets `<backups_root>/<game id>` bound there (so two servers of one
module never share a folder), and the panel lists and prunes it itself: no listing or prune `docker exec`, so the
exec guard allows only the backup command. Without `backups_root`, `dir` behaves exactly like `list_dir`. Give
`dir` or `list_dir`, not both. See the README's "A shared backups folder" for what to watch.

`restore: [argv...]` (inside `backup:`, needs `dir`) makes each backup restorable from the dashboard: the argv is the
entrypoint of a one-shot container, `<game id>-restore`, created from the game's pinned image with the game's data
folders and its backup folder read-only, run while the game is stopped. The chosen file's full path arrives in
`$CROWSNEST_RESTORE_FILE` (quote it in scripts; it is not substituted into the command). The command must replace
the game's saves with the archive's contents and fix ownership; write it to match exactly what `exec` archives. Exit
status 0 is success. The scope for that container is generated from the game's own, so it adds no ports, exec,
folders or image. It is shown in the approval summary. See the README's "Restoring a backup".

An optional `accent: "#rrggbb"` sets the colour of the game's dashboard card. Without one the card uses the
default theme colour.

Copy `internal/modules/bundled/minecraft/module.yaml` (log-based) or `source` (RCON-based) into
`<modules_dir>/<id>/module.yaml`, change the regexes, and add the game to `config.yaml`. Unknown keys are an
error, so a typo cannot silently disable a setting. Add a fixture of real log lines and test it the way
`internal/modules/minecraft_test.go` does.

## Memory admission

Besides `max_active_games`, a start is refused when the host does not have the memory for the game.

- A module declares what the game typically uses in `runtime.ram` (for example `ram: 8g`). Without it, `runtime.memory` (the container limit) is used; with neither, the game is never refused for memory.
- An instance can override the figure with the reserved option `ram` (in `options:` of a `config.yaml` game, or under *More settings* when adding a game from the dashboard).
- Once a game has run, its measured peak (sampled every 30 seconds, kept in `memory-peaks.json` next to `settings.json`) replaces the declared figure.
- A start is admitted when the host's available memory, less `server.memory_reserve_mb` (default 1024) and less what other starting games are still to take, covers the figure. A switch counts the memory the stopping game gives back, and is refused before anything is stopped.
- Set `server.memory_reserve_mb: -1` to turn the check off. If host memory can't be read, the check is skipped.

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
  backups_root: /mnt/usb/backups  # optional: each game's backups go to <backups_root>/<game id> (see the README)
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
# policy.yaml: only games_root is required. Everything else has a safe default.
games_root: /srv/games                 # managed binds must be exact paths inside this folder
# names: [valheim, "gs-*"]            # optional: leave it out and any name works, because the guard only manages
                                       # containers the dashboard made (label crowsnest.managed=true)
# images: ["@modules"]                 # optional. Left out, it is the images the bundled modules declare. Add your own
                                       # beside it: ["@modules", "ghcr.io/you/mygame"]. A list without "@modules" is
                                       # exactly that list. "*" alone = any image; prefixes are fully qualified
# networks: [crowsnest-games-net]      # optional. Left out, it is platform.games_network from config.yaml
# ports: ["27000-28999/udp"]          # optional: extra host ports, beyond the games you switch on (see below)
host_ips: [10.0.0.2]                   # optional: limits the address ports are published on
exec: false                            # may managed scopes use docker exec (save-on-stop hooks need it)
labels: []                             # extra labels they may require (the watchtower opt-out is always fine)
pin_digests: true                      # managed creates must name the image by digest (see "Image pinning" below)
max_scopes: 32
```

- **Ports come from the games you allow.** On the Games page each bundled game has a switch. Turning it on asks
  for your password, is written to the history, and adds that game's published ports (shown under the card with
  the module's reason for each) to what the guard accepts. It is stored in `allowed.json` beside the managed
  scopes file; the guard only adds ports a *bundled* module declares, so the file cannot open anything else. A
  game can't be switched off while one of its servers still exists, since the guard would drop it. A second
  server of the same game gets the next free host port on its own (a second Palworld is 8212, a third 8213), but only
  if the policy admits that port, so add a range to `ports` for the games you plan to run more than one of, such
  as `["8200-8299/udp", "25560-25599/tcp"]`. A port you type that another dashboard game holds is refused, naming
  that game. `ports` in `policy.yaml` is only for ports beyond those: a game installed from a URL, or a different host port. An admin with no
  stored password (Google sign-in only) sees a banner on every page and is refused until they set one in Settings,
  Users: the password is only used to confirm this, so a hijacked session alone cannot widen the guard.
- **A module installed from a URL has a switch too, but a weaker one.** The panel can write module files and the
  lock file, so the guard never takes a port or an image from them. The switch only makes the dashboard offer the
  game; the card shows the `images:` and `ports:` lines to paste into `policy.yaml`, and until they are there the
  plan says the game falls outside the policy. Install as many as you like and switch them on when you want them.
- Point `games_root` at a folder that holds only game data, such as `<your data mount>/crowsnest/games`, not at a
  mount shared with other services: every dashboard-added game's folder is `<games_root>/<id>`, and the policy
  lets the panel bind anything inside `games_root`. Create it once, owned by you, before the first game.
  `platform.games_root` in config.yaml must be the same path. Servers you set up by hand keep their own paths.
- Managed binds never nest: a managed scope whose bind is inside another bind in force (its own, another managed
  game's, or one of your `GUARD_SCOPES`), or holds one, is not loaded. A container that can write a folder could
  turn a path below it into a symlink, and Docker follows that symlink when it binds the path, so a nested bind
  would reach the whole host. Sibling folders such as `<id>/config` and `<id>/data` are fine.
- Ownership, not a list of names, is what keeps the panel off your other containers. A game the dashboard creates
  carries the label `crowsnest.managed=true`, and with no `names` in the policy the guard only acts on a container
  that has it: a scope called `caddy` finds nothing, because your proxy has no such label. Name your games
  anything you like. If you do set `names`, it is the old behaviour: only those names, and the label is not
  required.
- A managed scope can never carry volumes, capabilities, aliases, host networking, or exec unless the policy allows
  it. Security options, extra networks and fixed addresses are only for a game the policy names in an
  [exception](#exceptions-one-game-beyond-the-envelope).
- Images and the games network need no entry. The guard allows the images the bundled modules were built for, and
  only the games network, so you don't keep a list in step with the modules. A module installed from a URL is not
  bundled: add its image to `images` (with `"@modules"` if you also want the bundled ones). The guard and the
  dashboard's preview resolve these the same way. The dashboard's policy editor cannot empty `images`, `networks`
  or `names`, because an empty list means the defaults.
- Official Docker Hub images are fully qualified in a scope (`itzg/minecraft-server` is `docker.io/itzg/minecraft-server`),
  so policy prefixes are written that way.
- `Policy.Admit` is the same check the dashboard will use to preview "does this fit?" before enabling a game.

### Exceptions: one game beyond the envelope

Some games need what the envelope never grants. Windrose is the case: its invite-code relay needs a real LAN
address (a macvlan network, with a pinned IPv4 so a firewall rule can find it) and its Wine runtime needs
`seccomp=unconfined`. An `exceptions` entry grants exactly that to one container and nothing else:

```yaml
exceptions:
  - name: windrose                       # exact container name, never a wildcard
    image: indifferentbroccoli/windrose-server-docker   # the one image it may run
    networks:                            # extra networks, with the only addresses it may be pinned to
      dockervlan: [10.0.1.16]
      crowsnest-games-net: [192.168.0.50]
    secopts: [seccomp=unconfined]        # the only security options it may ask for
```

- Only the file on the host can add or change one. The dashboard's Game policy page lists them but cannot edit
  them, and saving the rest of the policy from the dashboard keeps them as they are.
- A game whose module asks for more than the envelope grants (`runtime.secopts`, `runtime.networks`) shows as
  *needs a policy exception* in Settings → Game modules until the policy has an entry for its name.
- The guard checks the exception itself, on the create request: another address, another network or another
  security option is refused.
- The module takes the operator's network and addresses from options (`lan_network`, `lan_ipv4`, `games_ipv4`),
  so they are typed in the form, not written into the module. The host firewall script
  (`windrose-firewall.sh`) that keeps the macvlan address away from the host stays a manual step.
- Moving a hand-written Windrose to the dashboard: remove its entry from `GUARD_SCOPES` and `config.yaml`
  (the dashboard refuses an id config.yaml already uses), add the exception above, then enable `windrose`
  on the Games page with the data folder set to `Windrose` so it keeps its world.

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
| `POST /api/managed/games/{id}/refresh` | pull the image tag again; only if it now points to another image, recreate the container on that digest (the game must be stopped) |
| `POST /api/managed/games/{id}/rollback` | recreate a **stopped** game on its previous digest and swap the two; 409 when there is none, or while it is running, starting or stopping |
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
- Edits, rollbacks and updates that bring a new image recreate the container (the data folder is a bind mount, so nothing is lost). An unreachable
  registry is tolerated on an edit or rollback if the image is already local, but not on a refresh. Pull-on-start for managed
  games is not wired: use refresh.

### Image pinning and rollback

A module names its image by tag (`runtime.tag`, default `latest`), and a tag moves whenever upstream pushes. So a
dashboard game is pulled by tag once, and its container is created from the exact image that tag resolved to:
`image: repo@sha256:...`. Nothing changes until an admin presses **Update image**.

- **Where the digest comes from.** After pulling `repo:tag`, the panel inspects the image (the guard already lets it
  read scope images) and takes the `RepoDigests` entry for that repository. It is kept in `games.json` as `image`
  (the `repo:tag` it was resolved from), `digest`, and `previous_digest` (what the digest was before the last change).
  `GET /api/managed/games` lists the three, plus `refresh` (`updated` or `up_to_date`) once an Update image finishes.
- **Update image** pulls the tag again. Same digest: the container is left alone and the page says it is already up to
  date. New digest: the container is recreated on it and the old digest becomes `previous_digest`. A failed pull
  leaves the old container untouched.
- **Roll back** (shown when there is a previous digest) recreates the container on `previous_digest` and swaps the two,
  so rolling back again returns to the newer image. The game must be stopped. A world saved by a newer server version
  may not load in an older one: back up first. Rolling back needs the old image: it is pulled by digest if it was pruned.
- **Edits** (Settings) recreate on the pinned digest; they only follow the tag when you change `image` or `tag`.
- **Games installed before pinning** keep running as they are, by tag. Their first Update image (or an edit) resolves
  and stores a digest; the image they ran until then becomes the rollback target if the update brings a new one.
- An image with no registry digest (built locally) cannot be pinned: it keeps running by tag, which `pin_digests`
  refuses.

`pin_digests: true` in `policy.yaml` makes the guard enforce it: a create from a **managed** scope must name its image as
`repo@sha256:<64 hex>` (no tag), otherwise it is refused with `image ... must be pinned by digest ... the policy sets
pin_digests`. Pulls by tag stay allowed (that is how a new digest is found). The operator's own `GUARD_SCOPES` are not
affected, and a scope cannot switch it off for itself (it is not a scope key). Scopes name repositories only, so
`Policy.Admit` and the catalogue's verdicts do not change. Settings shows the setting; a dashboard save that does not
send it keeps what the file has.

### Options that fill themselves in

A module option can say `derive: "http://{id}:8212"`. For a game enabled from the dashboard, an option left empty
is filled from the game itself, so nobody types wiring such as the REST API address. `{id}` is the game's id (also its
container name on the games network) and `{env:KEY}` is the name of the variable that holds secret option `KEY`.
`managed_required: true` makes an option required for dashboard games only. The Games page tucks derived options
under "More settings" with an "automatic" placeholder; typing a value there overrides it.

### The Games page

Admins get a **Games** link in the header, opening `/games`. It lists the games enabled from the dashboard (installing, ready or
failed, with the error), and has a form to add one: pick a module, an id, the module's options (secret options are
password fields), then **Preview** to see whether it fits the policy before **Enable**. Each game shows the tag it
follows and the first 12 characters of the digest it runs. Per game: **Edit** (recreates the container; leaving a
secret empty keeps it), **Update image** (says whether there was anything new), **Roll back** (when there is a
previous image), and **Disable** (the data folder is kept). When an
install finishes the page reloads so the game's card appears. It talks to `/api/managed/*`; without `managed.dir` the
dialog says the feature is off.

### Policy on the Games page

The page shows the policy in force. It is read-only by default: the panel mounts the policy directory read-only, so a
compromised panel cannot widen its own limits. To edit it from the dashboard, mount the policy **directory**
writable into the panel and set `managed.policy_editable: true`. Saves are validated with the same parser as the
guard, written atomically, and applied by the guard within seconds (a managed game that no longer fits is dropped).
Keep the guard's own mount read-only.

Even then the dashboard can only **tighten** the policy: every list entry must already be in the file (compared
exactly), `max_scopes` can only fall, and `exec` and `pin_digests` can only turn toward the stricter setting. Widening,
including exceptions, is done in `policy.yaml` on the host. Enabling the option logs a warning at startup, because a
compromised panel could still remove limits (for example every entry of a list but one).

### Deploying it (tested shape)

Verified end to end on a real Docker daemon with the production chain (panel → execguard → guard → docker.sock), the
panel and execguard read-only with all capabilities dropped, and the guard as uid 1000 plus the docker group:

```yaml
dockerproxy-crowsnest:                    # the guard
  environment:
    - GUARD_SCOPES=[...]                  # your hand-written scopes stay exactly as they are
    - GUARD_SCOPES_FILE=/etc/crowsnest/managed/scopes.json
    - GUARD_POLICY=/etc/crowsnest/policy/policy.yaml
  volumes:
    - ${USERDIR}/crowsnest/config/managed:/etc/crowsnest/managed:ro   # the panel's managed dir, read-only here
    - ./policy:/etc/crowsnest/policy:ro                                # a directory holding policy.yaml
crowsnest-execguard:
  volumes:
    - ./config.yaml:/app/config.yaml:ro                                 # already there
    - ${USERDIR}/crowsnest/config/managed:/app/data/managed:ro          # same path as managed.dir in config.yaml
    - ./policy:/etc/crowsnest/policy:ro                                 # same path as managed.policy_file: limits which containers get a rule
crowsnest:                                # the panel
  volumes:
    - ${USERDIR}/crowsnest/config:/app/data                            # already there: managed/ lives inside it
    - ./policy:/etc/crowsnest/policy:ro
```

```yaml
# config.yaml
platform: {games_root: /srv/games, host_ip: 10.0.0.2}
managed: {dir: /app/data/managed, policy_file: /etc/crowsnest/policy/policy.yaml}
```

- **Mount directories, not single files.** A bind-mounted file is pinned to its inode: an editor that saves by
  replacing the file (`sed -i`, most editors) leaves the container reading the old policy until it restarts. The
  managed directory and the policy directory both avoid this.
- `mkdir -p ${USERDIR}/crowsnest/config/managed` and make it writable by the panel's uid (1000).
- `policy.yaml` is parsed at every reload, so tightening it takes effect within seconds and drops any managed scope
  that no longer fits. The panel reads the same file for its preview.
- **exec and backups.** (`crowsnest guard --exec` runs this allowlist inside the guard container, in front of the
  guard; the quickstart does. `crowsnest execguard` runs it as a separate container.) Everything the panel does goes through execguard, whose allowlist for `config.yaml` games is
  read at start. For dashboard-enabled games it is built from each module's `backup:` block (command, `list_dir`,
  `before_stop`) and **reloaded every 2 seconds** from the managed dir, so enabling a game adds its backup command
  and disabling removes it, with no restart. The command always comes from the installed module, never from the
  saved state, so a panel that rewrote `games.json` could pick a game but not a command. A game also gets a rule only
  if its id is a container name the policy's `names` allows, so a rewritten `games.json` cannot aim a module's
  backup command at an unrelated container either. Execguard therefore needs `config.yaml` (for `managed.dir` and
  `managed.policy_file`), the managed dir and the policy directory mounted read-only; with the policy unreadable it
  issues no dashboard-game rules. `valheim`, `palworld` and `minecraft`
  ship a backup; a module without one has none.

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
5. Remote module sources: hash-pinned install is done (below); signed catalogs are not built.

## Several servers from one module

You can enable the same module more than once (for example two Valheim worlds) as long as each game has its own id and title. Every game gets its own data folder, named after its id (`<games_root>/<id>`), unless you set **Data folder name** under *More settings*. Host ports must differ: a clash with another managed game is refused with a message naming it, and you set different ones in **Published ports** (`host:container/proto`, comma-separated). The operator's policy must allow the names and ports, and memory limits still apply.

## Showing join details on the card

A module can list `connect:` entries (a `label` and the `option` whose value to show), such as the Palworld and Valheim server passwords. They appear on the game's card for admins and are never part of the list API.

## Installing a module from a URL

```
crowsnest module install https://example.com/mygame/module.yaml [--sha256 HASH] [--yes]
crowsnest module update mygame
crowsnest module remove mygame
crowsnest module list
```

Needs `modules_dir` in `config.yaml`. Install downloads the manifest (https only, 256 KiB cap, nothing is run),
validates it, and prints what it would let the module do: the image, ports, env, security options, the backup
command, admin actions, RCON and API addresses and host commands it asks you to run. You approve by typing the
module's id. Give `--sha256` when the author published a hash and the download must match it exactly.

What is recorded: `<modules_dir>/modules.lock.json` holds each installed module's source, SHA-256 and date.
At startup a locked module is loaded only if its `module.yaml` still has that hash. If the file was edited or
swapped, it is left out with a log line, and its games fall back to the baseline until you re-approve it.
`update` re-downloads from the recorded source and shows what changed in that summary (new image, new port,
newly loosened security option) before you approve; if the source is byte-identical to what you approved it just
restores that copy. Update refuses if the source now serves a different module id.

Limits: a module cannot replace a bundled one or a hand-placed one, and the policy envelope still applies
(a module only runs what `policy.yaml` allows). This pins what you approved; it does not prove who wrote it.
A signed catalog would, and is deferred until someone needs it.
