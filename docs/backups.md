# Backups and restore

Backing up a game, a shared backups folder, an offsite copy, restoring, and what CrowsNest checks for you.

Back to the [README](../README.md).

## Backups

A game with a `backup:` block in `config.yaml` (or in its module) gets a Backups panel for admins, with a "Back up
now" button and the list of backup files. Backups run inside the game's container with `docker exec`, so they use
whatever the image provides (the Palworld example in `config.yaml.example` shows one).

`exec` needs the Docker proxy to allow it, and a generic proxy can't limit which commands run. That's what the
bundled exec guard is for. It runs inside the guard container with `crowsnest guard --exec` (the quickstart does
this), or on its own as `crowsnest execguard` (the `execguard` service in `compose.yaml.example`). It allows
exactly the commands your config implies (each `backup.exec`, the `list_dir` listing, Windrose's readiness check),
refuses exec options such as `Privileged`, `User` and `Env`, and only lets `exec/<id>/start` through for ids it
approved itself. Restart it after changing `backup:` settings.

For the Docker API itself, `crowsnest guard` replaces the generic socket proxy. It's a scoped filter that lets
CrowsNest see and control only the containers named in `GUARD_SCOPES` (or the policy, for games added from the
dashboard).

With `before_stop: true` CrowsNest also takes a backup each time it stops that game on purpose, after the world is
saved, so an "update on start" pull always has a fresh backup behind it. A failed backup is logged and never stops
the game from stopping.

With `keep: N` (and `list_dir`) CrowsNest deletes all but the newest N files in `list_dir` after each successful
backup, using one more exec command the guard allows. It counts files, and the container needs `sh`, GNU `find`,
`sort`, `tail` and `cut`.

### A shared backups folder

Set `platform.backups_root` (a host path, for example an external drive) and every dashboard-enabled game whose
module declares `backup.dir` backs up into its own folder, `<backups_root>/<game id>`. The panel mounts the folder
read-write at `platform.backups_mount` (default `/game-backups`), each game container gets only its own sub-folder,
and the panel lists and prunes it directly, with no `docker exec` for either. Add `backups_root` to `policy.yaml`
(the same path, separate from `games_root`) so the guard allows the bind. In the quickstart it is three commented
lines: the volume in `compose.yaml`, `backups_root` in `config.yaml`, and `backups_root` in `policy/policy.yaml`.

### Offsite copy

The panel can delete everything in `backups_root`, so a copy that lives somewhere else is the real safety net.
`quickstart/offsite/` is a sidecar for that: the `rclone/rclone` image running `offsite.sh`, which copies
`backups_root` to any rclone remote (SFTP, S3, B2, Google Drive, another disk) every few hours.
CrowsNest does not run it, talk to it or hold its credentials; the remote's secrets live only in the sidecar's
own `rclone.conf`.

```sh
cd quickstart/offsite
cp rclone.conf.example rclone.conf && chmod 600 rclone.conf      # fill it in; see the comments in it
BACKUPS_ROOT=/mnt/usb/backups docker compose up -d                # the same path as platform.backups_root
docker compose exec crowsnest-offsite sh /offsite.sh check           # dry run: what would be copied
docker compose exec crowsnest-offsite sh /offsite.sh once            # one real copy; non-zero exit if it failed
```

What it does, and why:

- **Copy, never sync.** A backup the panel prunes (or you delete with a game) stays offsite. Set
  `OFFSITE_KEEP_DAYS` to age offsite files out on their own schedule; the default keeps everything.
- **`--immutable`.** A backup that changes after it was copied is an error, not an overwrite, so a damaged or
  tampered local file cannot replace a good offsite one. That run reports FAILED and the sidecar tries again next time.
- **It skips files younger than `OFFSITE_MIN_AGE`** (default 2 minutes), so a backup still being written is not copied half-done.
- **It refuses a folder without the `.crowsnest-backups` marker,** which is what an unmounted drive looks like,
  so it never reports success after copying nothing.
- **It runs read-only, with no capabilities, as uid 1000,** and mounts the backups folder `:ro`. The user must be
  able to read the backups (see Permissions above); change `user:` in `compose.yaml` if your games write them as someone else.
- **The dashboard shows the result.** The sidecar writes `status/offsite.json` after every run. Mount that folder
  read-only into the panel and set `platform.offsite_status_file` to the file's path there: admins then see a banner
  when the last copy failed or none has succeeded in over twice the interval, the health endpoint reports it, and
  Discord is told once when it breaks and once when it works again.
- For encrypted backups, wrap the remote in rclone's `crypt` remote (see the comments in `rclone.conf.example`).

Tested against a local folder and an SFTP server: new files copied on the next pass, a changed file refused, local
deletions leaving the offsite copy alone, `OFFSITE_KEEP_DAYS` removing only old files and empty folders, and the
unmounted-drive refusal. **Restoring from offsite** is a copy back: `rclone copy offsite:crowsnest/<game id>
<backups_root>/<game id>`, then use the Restore button as usual.

## What CrowsNest checks for you

- **Every minute** the panel re-checks the folder: it is the one used before (the marker), it has at least 1 GiB
  free, and the panel can write to each game's folder. A problem is recorded in the activity log, sent to Discord
  once (and again when it clears), shown as a banner on the dashboard, and exported as `crowsnest_backups_ok` and
  `crowsnest_backups_free_bytes` on `/metrics`. While it lasts, backups are refused rather than written somewhere
  wrong. `GET /api/backups/health` (admin) returns the details, including folders no game uses (left behind by
  disabled or renamed games).
- **A refused backup is never silent.** A scheduled or before-stop backup that cannot run is recorded and
  notified. Stopping a game still goes ahead.
- **Exit status 0 is not trusted.** After a backup the panel checks that a new, non-empty file appeared in the
  game's folder; otherwise the backup is recorded as failed and old backups are not pruned.
- **Permission errors say what to do.** A failure containing "permission denied" names the folder and the fix.
- **First use needs your confirmation.** A folder with no marker that CrowsNest has never seen is refused, since
  a missing drive looks exactly like that. After checking that the right drive is mounted at `backups_root`, set
  `platform.backups_confirm_new: true` and restart; CrowsNest then marks the folder, and from then on a missing
  drive is caught. A drive that already carries a marker (a reinstall, or a second panel) is adopted without the
  flag. `crowsnest doctor` says which case you are in.

## Things to watch with a shared backups folder

- **A missing external drive looks like an empty folder.** If the host path does not exist when Docker starts the
  panel, Docker creates an empty directory there, and backups would quietly land on the system disk. CrowsNest
  puts a marker file (`.crowsnest-backups`, a random token) in the folder and remembers the same token in
  `backups-root` next to `settings.json`. A folder that no longer carries the remembered token is refused: no
  game's backup folder is created in it, and backing up, listing and pruning stop, with a message saying why.
  To accept a different drive on purpose, delete `backups-root` and restart. `crowsnest doctor` reports it. Bind
  the drive's mount point rather than a folder on it, and start Docker after the drive is mounted
  (`RequiresMountsFor=` in the Docker unit, or an fstab `x-systemd.before=docker.service` style ordering).
- **Permissions.** The panel (uid 1000) creates each game's folder with `backups_dir_mode` (default `0775`). A
  game whose own user is someone else gets "permission denied" from its backup command. Either chown the folder to
  that user on the host, run the game as the panel's uid, or set `backups_dir_mode: "0777"`. `doctor` says which mode
  is in use. Many images take `PUID`/`PGID`; matching the panel's uid is the cleanest fix.
- **The panel can delete backups.** The folder is mounted read-write into the panel so it can list and prune. A
  compromised panel could therefore delete every backup. The guard still limits what it can do to containers, but
  not to this folder. For protection against that, copy the folder offsite or to a snapshotting filesystem
  (immutable or append-only), which CrowsNest never has to touch. Pruning only deletes regular files directly inside
  a game's folder and never follows a link, so a game cannot aim it elsewhere.
- **Games can see only their own folder.** Each game binds `<backups_root>/<id>` and nothing else, so three Palworld
  servers (`palworld`, `palworld-2`, `palworld-friends`) keep three separate sets, and one game cannot read or
  overwrite another's. The folder is named after the game's **id**, which cannot be changed later: renaming means
  moving the folder yourself.
- **Disabling a game keeps its backups unless you say otherwise.** The folder stays in `backups_root`. To remove
  it with the game, use **Disable and delete…** ([managing-games.md](managing-games.md)), or delete it by hand when you are sure.
- **`backups_root` and `games_root` must be separate** folders, neither inside the other (the policy refuses
  otherwise), and `backups_root` must be the same host path in `config.yaml`, `policy.yaml` and the compose volume.
- **Retention counts files.** `keep: N` keeps the N newest files in a game's folder, so a backup that writes two
  files per run keeps N/2 runs. Files the game wrote by hand count too.
- **Only dashboard-enabled games get a folder.** Games in `config.yaml` with their own compose file keep backing up
  where they do today (inside their own data, listed over `docker exec`); give them a bind to a folder under
  `backups_root` yourself if you want them in the same place.
- **A big backup volume needs space checks.** `doctor` warns under 5 GiB free. Backups of several worlds add up
  quickly, so set `keep`.
- **Restore is by button** for the modules that have a restore command (see "Restoring a backup"). For any other,
  stop the game and unpack the file from `<backups_root>/<id>` into its data folder by hand.

## Restoring a backup

On a dashboard-enabled game whose module has a `restore:` command (Minecraft, Valheim, Windrose and Palworld), each file in the **Backups** tab has a **Restore** button.
It asks first, then:

1. stops the game (when it keeps a backup before stopping, that backup is taken first, so the world as it was a
   moment ago is the newest file in the list and is your way back);
2. runs a one-shot container, `<game id>-restore`, from the game's own pinned image, with the game's data folders and
   its backups folder (read-only), whose entrypoint is the module's `restore` command and which finds the chosen file in
   `$CROWSNEST_RESTORE_FILE`; the container is removed afterwards;
3. starts the game again if it was running.

The result is in the activity log (kind `restore`) and in Discord. Things to watch:

- **It replaces the current world.** The bundled commands delete the world folder and unpack the archive. If the
  command fails half way, the game is left **stopped** with partly restored data and nothing is started; restore the
  newest backup (the safety copy) or the file again.
- **No safety copy when the game was stopped,** or when the module does not back up before stopping: there is nothing
  to take one from. Back up first if the current world matters.
- **A restore that would delete its own file is refused.** With `keep: N`, the safety backup pushes the oldest file
  out; asking for that one is refused with a message, before anything is stopped.
- **Only plain file names** inside the game's own folder are accepted, and only files that are listed there.
- **The game may not restart by itself.** If the restart is refused (the active-game limit, or the restart cooldown),
  the game stays stopped and you are told to start it.
- **A new guard scope per game.** `<id>-restore` has the game's image and folders and nothing else (no ports, no
  exec). The policy admits it by the game's own name, so no `names:` change is needed, and the id `<anything>-restore`
  can no longer be used for a game. The panel rewrites the scopes at start, and the guard reloads them without a restart.
- **File ownership.** The helper runs as root. The bundled commands chown the restored folder to the owner of the
  data folder (Windrose: uid 1000), as the game expects.
- **Older archives.** A restore command expects the layout its module's backup command writes (`world/`,
  `worlds_local/`, `SaveProfiles/`). Archives made some other way are not understood.
- **Config-file games** (a hand-written compose service) cannot restore from the dashboard; their backups stay where they are.
