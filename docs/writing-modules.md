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

## Installing and using a module

A module does nothing until it is installed, the operator's policy allows what it asks for, and a game is added from
it. Four steps.

### 1. Install it

`modules_dir` must be set in `config.yaml` (the quickstart sets it to `/app/data/modules`). Then either:

- **From a URL**, which shows you what it does first:
  ```sh
  docker compose exec crowsnest crowsnest module install https://example.com/mygame/module.yaml
  ```
  Read the list it prints (image, ports, env, backup command, anything that loosens isolation) and type the module
  id to approve. If the author published a hash, add `--sha256 <hash>` and the download must match it exactly.
  The module is recorded with its hash in `modules.lock.json`; if the file is edited later it stops loading until
  you approve it again. Details: [modules.md](modules.md#installing-a-module-from-a-url).
- **By hand**, for a module you wrote or were handed as a file: copy the folder to `<modules_dir>/mygame/` so the
  file is `<modules_dir>/mygame/module.yaml`. Run `crowsnest module check <modules_dir>/mygame` first. Hand-placed
  modules are not hash-pinned, so only do this with a file you have read.

Then **restart CrowsNest** (`docker compose restart crowsnest`); modules load at start. The log says
`modules: "mygame" not loaded: ...` if it was left out, with the reason.

### 2. Let the policy allow it

The dashboard only creates what `policy.yaml` permits, and the module can't change that. For `mygame` the policy
needs, at least, its ports in `ports`. The games network and container names need no entry, and a bundled
module's image is already allowed. A module you installed from a URL also needs its switch turned on under **Games** (your password is asked), and
its image and ports listed here, beside `@modules` so the bundled ones stay allowed; the card shows the lines:

```yaml
images: ["@modules", "docker.io/example/mygame-server"]   # Docker Hub images are written fully qualified
ports:  ["7777/udp"]
```

If the module has a `backup:` block the policy needs `exec: true`. If it asks for `runtime.secopts` or
`runtime.networks`, it needs an [exception](modules.md#exceptions-one-game-beyond-the-envelope) naming that one
container. Edit the file on the host (the guard reloads it within seconds). Not sure what is missing? Step 3's
**Preview** says exactly which rule it fails.

### 3. Add a game from it

Sign in as an admin and open **Games**. Pick the module, choose an id (it becomes the container name), fill in the
options (passwords are stored separately, never in a rendered file), press **Preview**, then **Enable**. CrowsNest
pulls the image, creates the container and the card appears. Use **Edit** to change options (it recreates the
container), **Update image** and **Roll back** for versions, **Disable** to remove it (the data folder is kept).

Prefer files over the page? A game in `config.yaml` with `id: mygame` (or `module: mygame`) uses the module the same
way; see [modules.md](modules.md#using-a-module).

### 4. Check it works

Start it from its card. It should read *starting*, then *online* when the ready line appears in the log, and the
player count should follow joins and leaves. If not, run `docker logs <container>` into a file and
`crowsnest module check` it with `--log`.

### Updating and removing

`crowsnest module update mygame` re-downloads from the recorded source and lists what changed (new image, new port,
loosened isolation) before you approve. `crowsnest module remove mygame` deletes it. Games already made from it stay on the Games page as *failed*
("module is not installed") and leave the dashboard; their containers and data are untouched. You can still
**Disable** them (stop the game first), but you can't edit or re-create them until a module with that id is installed
again. `crowsnest module list` shows what is installed and flags any file that no longer matches its pinned hash.

## Sharing your module

There is no central catalogue: you publish the file and people install it from your URL.

1. **Host the file over https** at a stable address. A raw file in a git repo works (use a tag or commit in the URL
   so it does not change under people): `https://raw.githubusercontent.com/you/crowsnest-mygame/v1.0/module.yaml`.
2. **Publish its hash** in your README so installers can pin it: `sha256sum module.yaml`. Publish a new hash with each
   version.
3. **Say what you tested**: the exact image and tag, the game version, and which parts are verified (ready line,
   joins and leaves, backup). Include a trimmed `sample.log` from a real run so others can `module check` it.
4. **Keep it small and honest.** Pin the image you trust, don't ask for isolation exceptions unless the game needs
   them, and explain any you do ask for. People read the approval list; surprises cost trust.
5. **Version it.** Changing the image, ports or env is a change installers must re-approve (they will see it in
   `update`), so note it in your changelog.

You don't need anyone's permission and nothing has to be added to CrowsNest itself. CrowsNest does not take outside
contributions; if you want something built in, fork it. A fork can keep its own `internal/modules/bundled/` folder
and test fixtures; the rest of this guide is all a module author needs.

## When it doesn't work

| What you see | Likely cause |
|---|---|
| `module check` fails with an unknown key | a typo in the YAML; unknown keys are errors on purpose |
| `modules: "x" not loaded: ... changed` | the file differs from its pinned hash; `crowsnest module update x` |
| Module is not on the Games page | not installed in `modules_dir`, or CrowsNest was not restarted |
| Preview says it falls outside the policy | add its name, image, port or network to `policy.yaml` (or an exception) |
| Stuck on *starting* | the `ready_log` pattern never matches; replay a real log with `module check --log` |
| Stays *online* with 0 players | `join`/`leave` patterns do not match, or group 1 is not the player id |
| Start refused for memory | `runtime.ram` is larger than the host's free memory; see Memory above |

The full list of keys is in `internal/modules/manifest.go`; the policy and guard are explained in
[modules.md](modules.md).
