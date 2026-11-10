# Writing a module

A **module** teaches CrowsNest about one game: how to run its container, when it counts as online, who is
connected, what the settings form asks. It is one YAML file, `module.yaml`, and **no code**. If a game prints
its state in its log, a module is usually 30 lines.

This guide builds one from scratch. The finished example is
[`examples/mygame/module.yaml`](examples/mygame/module.yaml); the bundled modules in
`internal/modules/bundled/` are bigger, real ones (`minecraft` reads the log, `source` and `valheim` use RCON and
REST).

## What a module can and cannot do

A module is a *description*, not a program. It can name an image, ports, data folders, environment, log patterns and
(optionally) one backup command. It cannot run anything on the host, ask for host networking, capabilities or extra
privileges, or reach outside the limits in the operator's `policy.yaml`: the guard checks every container against
that policy, whatever the module says. A module that wants something unusual (a LAN address, a relaxed seccomp
profile) only works if the operator has written an exception for that game. So installing someone else's module
is a smaller decision than installing someone else's program; still, **read it first**, especially its `image`,
`env` and `backup.exec`.

## Step 1: identity and container

```yaml
api_version: 1          # always 1 for now
id: mygame              # lowercase letters, digits, dashes; also the folder name
name: My Game
description: "One or two sentences for the Games page."

runtime:
  ram: 2g               # typical memory use; see "Memory" below
  image: example/mygame-server   # repository, no tag. Leave it out to make the operator choose the image.
  stop_grace: 30s       # time Docker waits for the server to save before it is killed
  data_dir: MyGame      # folder under games_root for this game's data
  ports:
    - {port: 7777, proto: udp}
  data:
    - {path: /data}     # <games_root>/MyGame is mounted at /data
  env:
    - SERVER_NAME=${server_name}   # ${key} is replaced by the option below
```

`ports` are what players connect to; keep admin ports (RCON, REST) off this list, since CrowsNest reaches them on
the private games network. `data` lines are bind mounts of the game's folder (`sub:` mounts a subfolder).

## Step 2: options (the settings form)

```yaml
options:
  - {key: server_name, label: Server name, default: My CrowsNest server}
  - {key: admin_password, label: Admin password, secret: true}
  - {key: rcon_addr, label: RCON address, derive: "{id}:25575"}
```

- `default` pre-fills the field. `required: true` forces a value.
- `secret: true` keeps the value out of every rendered file: it is stored separately and handed to the container as
  a variable. Use it for passwords.
- `derive` fills a value in from the game's own id when the operator leaves it empty (`{id}` is the game's id, also
  its container name on the games network), so wiring that follows from the game is never typed in.
- Every game also gets five reserved options without you declaring them: `image`, `tag`, `ports`
  (`host:container/proto,...`), `data_dir` and `ram` (see below).

## Step 3: tell CrowsNest when it is online, and who is on

Most servers print both to their log. You give regular expressions, and CrowsNest follows the log.

```yaml
status:
  ready_log: 'Server is listening on port'      # this line = online; until then the game is "starting"
players:
  type: log_markers
  join:  '\[INFO\] (\S+) connected'              # group 1 = a player id
  leave: '\[INFO\] (\S+) disconnected'
  world: 'Loading world "([^"]+)"'               # optional, group 1 = world name

startup:                                         # optional progress bar while it boots
  - {match: 'Loading config', pct: 30, label: Reading config}
  - {match: 'Server is listening on port', pct: 100, label: Server ready}
```

Tips: match something that only appears once the server is truly ready (not "starting" lines); anchor the
join/leave patterns so chat lines can't match; keep the ready line out of the join/leave patterns.

Games without a useful log can use `players.type: source_rcon` (Source engine RCON `status`) or `http_json` (a
REST API, see `palworld` and `valheim`). With `players.type: none` the game is shown online whenever its container
is running, and idle auto-stop will never stop it.

## Step 4: check it against a real log

Start the game once with any setup, capture its output, and replay it:

```sh
docker logs mygame-container > sample.log
crowsnest module check docs/examples/mygame --log sample.log
```

```
ok    My Game (mygame) is a valid module, api_version 1
      line 1     startup  30%  Reading config
      line 3     READY: [10:00:09] [INFO] Server is listening on port 7777
      line 4     players 0 -> 1 [Alex]
      ...
info  peak players 2
```

It validates the file (unknown keys are errors, so a typo can't silently switch something off), warns about common
omissions, and shows exactly when the game would have counted as ready, which startup steps fired and each join or
leave. Nothing touches Docker. If the READY line never shows, the ready pattern is wrong. Do this before anything
else: a pattern that does not match real output is the usual bug.

For a bundled module, also commit a trimmed real log under `internal/modules/testdata/` and a test like
`internal/modules/minecraft_test.go`.

## Step 5: optional extras

- **Backup:** `backup: {exec: [...], list_dir: /data/backups, before_stop: true}`. The command runs with `docker
  exec` in the container and is the only exec the guard allows for this game. The operator must have set
  `exec: true` in the policy.
- **Join details on the card:** `connect: [{label: Password, option: server_password}]` shows option values players
  need.
- **Host steps:** `host_setup:` lists things only the operator can do (a firewall rule, a network), shown beside
  the form.
- **Admin console, REST actions, pre-stop save:** see `palworld` (REST) and `minecraft` (RCON).
- **Card colour:** `accent: "#rrggbb"`.

## Memory

`runtime.ram` is the typical memory use. CrowsNest refuses a start when the host's free memory (less a reserve)
is below it, and once the game has run it uses the measured peak instead. A game with neither `ram` nor
`memory` is never checked. An operator can override per game with the `ram` option.

## Using and sharing it

1. Put it at `<modules_dir>/mygame/module.yaml` (set `modules_dir` in `config.yaml`) and restart. It then shows
   up on the Games page if the operator's policy allows its image, ports and names; the page says why if not.
2. To share it, publish the folder (the `module.yaml` and a trimmed `sample.log`) and say which image and tag you
   tested it with. Whoever installs it should run `crowsnest module check` on it and read it.
3. Someone else can install it from a URL: `crowsnest module install https://…/module.yaml`. See
   [modules.md](modules.md#installing-a-module-from-a-url).
4. To add it to CrowsNest itself, open a pull request adding the folder under `internal/modules/bundled/` with a
   real-log test.

The full list of keys is in `internal/modules/manifest.go`; the policy and guard are explained in
[modules.md](modules.md).
