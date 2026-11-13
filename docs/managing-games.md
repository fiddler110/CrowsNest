# Managing games from the dashboard

Making a copy of a game, installing modules from a source, disabling and deleting a game, and cleaning up its folder. Adding a game is covered in [writing-modules.md](writing-modules.md) and [modules.md](modules.md).

Back to the [README](../README.md).

## Making a copy of a game (profiles)

**Games, Make a copy** on a game's card opens the add form filled in from that game's settings: a second Valheim
world, a friends' Palworld with another password. The copy is a game of its own (its own id, data folder, backups
folder, ports and start/stop), so it is edited, backed up, restored and disabled like any other. Its data folder is
left empty so it follows the new id, and its ports move to the next free ones the policy allows. **Secrets are
copied by the server and never shown**: leave a password field empty to keep the original's, or type a new one.
Games still start one at a time unless you raised "Servers allowed at once" and the memory budget allows it.

## Installing a module from a source

If `managed.trusted_keys` lists at least one publisher key in `config.yaml` (and `modules_dir` is set and writable by
the panel), the Games page has **Game modules from a source**, which also lists your trusted keys and, if `managed.catalogue_url` is set, a catalogue to pick from: give it the https address of a `module.yaml`. The
panel fetches the module and the signature beside it (`<address>.sig`), checks that a key you trust signed those exact
bytes, and shows what the module would let it do. You confirm with your password and the install is of exactly the
file you were shown (a changed file is refused). Only signed modules can be installed this way. **Check for update**
beside an installed module fetches its recorded source again (never an address from the browser), shows what the new
file adds and removes, and replaces it after your password. The new file must be signed by a trusted key and declare
the same id. Games already using the module keep their current wiring until you save their settings or restart them.
Installing grants nothing: a game from the
module still has to fit `policy.yaml`. The panel only fetches https from public addresses (a private, loopback,
link-local or Tailscale address is refused, even through a redirect). See docs/modules.md, "Signed modules". Modules to try this with: [fiddler110/crowsnest-modules](https://github.com/fiddler110/crowsnest-modules).

### Pulling in a module, step by step

Example: the 7 Days to Die module from [fiddler110/crowsnest-modules](https://github.com/fiddler110/crowsnest-modules).

1. **Trust the publisher** (once). Add the key to `config.yaml`, then restart CrowsNest. The key for that repository is
   in its README; check it there, not in the same place you got the module from.
   ```yaml
   modules_dir: /app/data/modules          # must be set, and writable by the panel
   managed:
     trusted_keys:
       - {name: publisher, public_key: OzuKyYzMpWBZrFtKy9MMumlEY5isVbJI/MVrL4sJCyk=}
   ```
2. **Install it.** On the Games page, under **Game modules from a source**, paste the address and press **Look at
   it**:
   `https://raw.githubusercontent.com/fiddler110/crowsnest-modules/main/sevendtd/module.yaml`
   Read the list of what the module would run (image, ports, environment, backup command), type your password and press
   **Install this exact file**. Use the `main` address (or a branch or tag you follow) if you want updates later; an
   address with a commit hash in it is pinned for good and **Check for update** will never find anything new.
   The same from a terminal: `docker compose exec crowsnest crowsnest module install <address>` (restart CrowsNest to
   load it).
3. **Let the policy allow it.** Add the module's image and ports to `policy.yaml` on the host (the module's own README
   lists them; for 7 Days to Die: image `docker.io/didstopia/7dtd-server`, ports `26900/tcp` and `26900-26903/udp`).
   Keep `@modules` in `images:` so the bundled games stay allowed, and set `exec: true` if the module has a backup.
4. **Switch it on.** A module from a source is off until you turn it on under **Games** (your password is asked).
5. **Add a game from it.** Games, pick the module, give it an id, fill in the options, **Preview** (it says which policy
   rule a game fails, if any), then **Enable**.

Prefer files? Clone the repository and copy the folder: `scripts/install.sh <modules_dir> sevendtd` (or copy
`sevendtd/module.yaml` to `<modules_dir>/sevendtd/module.yaml`), then restart. That copy is not pinned or
signature-checked, so only do it for a file you have read.

## Editing config files

When a game's module declares `files:` (Minecraft's `server.properties` and operators, Valheim's admin, allowed and
banned lists), admins get a **Files** tab on its card. Pick a file, edit it and press Save.

- **Running or stopped.** While the game runs, files are read and written inside its container with `docker exec`;
  nothing is mounted into the panel. For a game enabled from the dashboard that is stopped, a short-lived helper
  container (`<id>-files`, the game's image and data folders only) does it, for files inside the game's data folders.
  A game set up in `config.yaml`, or a file elsewhere in the image, needs the game running. A file that does not
  exist yet reads as empty and Save creates it.
- **Saving asks for your password** and shows how many lines changed. Each save is recorded in the activity feed and
  the audit file (who, which file, the hash before and after, never the content).
- **Nothing is overwritten blindly.** The editor remembers the hash of what it loaded. If the file changed since (the
  game rewrote it, or another admin saved), the save is refused with a 409; Reload and make the change again.
- **The last 10 versions are kept** in `file-history/` next to `settings.json` (mode 0600, as these files can hold
  passwords). Pick one from the list, Load that version, then Save to put it back.
- **Secrets stay hidden.** A module can mark lines such as `rcon.password=` as redacted; the editor shows
  `••••••••` and keeps the real value on save unless you type a new one. A hidden value is also hidden in the kept
  versions you load, so loading an old version and saving keeps the *current* secret, not the old one.
- **A change usually needs a restart.** The note under the editor says what the module says. Some games rewrite
  their files when they stop (marked `stop_first`); the editor then says to edit while the game is stopped, which
  the helper container allows.
- Only text files up to the file's limit (64 KiB by default) are editable. The file keeps its owner and mode.

Operators: the exec guard learns the two fixed commands per file from the module, so installing a module with
`files:` shows each path in the approval summary. See docs/modules.md, `files:`.

## Disabling a game and deleting its data

**Games, Disable** removes the container and takes the game off the dashboard; its data folders and backups stay,
so it can be enabled again. **Disable and delete…** (admin only, the game must be stopped) can also delete:

- **its data folders:** the world, configs and everything else the game saved. The panel never gets write access to
  game folders for this. It runs a one-shot `<game id>-clean` container from the game's own pinned image, with only
  that game's data folders mounted, running one fixed command (`find <folder> -mindepth 1 -delete` on each) and then
  removed. The empty folder itself stays, because the panel cannot remove a folder it has no access to.
- **its backups:** the game's `<backups_root>/<id>` folder, removed by the panel itself, and only after the backups
  folder passes the same drive check as a backup does (an unmounted drive deletes nothing).

The two are separate ticks, both off by default. Deleting needs the game's id typed out and your password, like
widening the guard, and is recorded in the activity log. Delete the data without the backups and you can still bring
the world back with Restore after enabling the game again. If emptying the folders fails, nothing else is changed and
the game stays listed. Each game now uses up to four guard scopes (the game, its restore helper, its files helper and its clean
helper), which count towards `max_scopes` in `policy.yaml` (default 64, so about 20 games with all three).

Only dashboard-enabled games can do this; a game set up by hand in `config.yaml` has to be cleaned up by hand.

## Cleaning up empty game folders

"Disable and delete…" leaves the game's own folder behind, empty, and the panel cannot remove it (it has no access
to `games_root` itself, on purpose). `quickstart/sweep-empty-games.sh` does that from the host:

```
quickstart/sweep-empty-games.sh -n /srv/games      # dry run: lists what it would remove
quickstart/sweep-empty-games.sh /srv/games         # removes them
```

It runs `rmdir` on folders directly under `games_root` that are empty, so it cannot delete anything with a file in
it, and it never follows links. It skips folders changed in the last hour (`-a MINUTES`), and any folder a Docker
container mounts, so a game that is set up but has not run yet keeps its folder. If Docker cannot be asked, it
removes nothing. To run it daily, edit the paths and user in `quickstart/crowsnest-sweep.service`, then:

```
sudo cp quickstart/crowsnest-sweep.{service,timer} /etc/systemd/system/
sudo systemctl enable --now crowsnest-sweep.timer
```

This stays outside the panel on purpose: giving it write access to `games_root` would let it change every game's world.
