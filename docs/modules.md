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
