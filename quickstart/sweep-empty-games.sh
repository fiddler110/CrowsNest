#!/usr/bin/env bash
# Remove empty folders directly under games_root, for example what is left after
# "Disable and delete" (the panel empties a game's data folders but has no access
# to the folder that holds them).
#
#   sweep-empty-games.sh [-n] [-a MINUTES] /path/to/games_root
#
#   -n          dry run: list what would be removed, remove nothing
#   -a MINUTES  leave folders changed in the last MINUTES alone (default 60), so a
#               game being installed right now is not caught
#
# It only ever runs rmdir on a folder that is empty, one level below games_root,
# and never follows links. It also skips any folder an existing container mounts
# (a game that is set up but has not run yet has an empty folder that Docker would
# otherwise recreate root-owned). If it cannot ask Docker what is mounted it
# removes nothing.
set -euo pipefail

dry=0 age=60
while getopts "na:" opt; do
  case $opt in
    n) dry=1 ;;
    a) age=$OPTARG ;;
    *) echo "usage: $0 [-n] [-a MINUTES] GAMES_ROOT" >&2; exit 2 ;;
  esac
done
shift $((OPTIND - 1))
[[ $# -eq 1 ]] || { echo "usage: $0 [-n] [-a MINUTES] GAMES_ROOT" >&2; exit 2; }
[[ $age =~ ^[0-9]+$ ]] || { echo "-a needs a number of minutes" >&2; exit 2; }

root=$(realpath -e -- "$1") || { echo "$1 does not exist" >&2; exit 1; }
[[ -d $root ]] || { echo "$root is not a folder" >&2; exit 1; }
# Refuse a root that is clearly not a games folder: "/", a top-level folder, or a home folder.
if [[ $(awk -F/ '{print NF-1}' <<<"$root") -lt 2 || $root == "${HOME:-/nonexistent}" ]]; then
  echo "refusing $root: that does not look like a games folder" >&2; exit 1
fi

# Everything an existing container (running or not) mounts from the host.
if ! mounts=$(docker ps -aq | xargs -r docker inspect --format '{{range .Mounts}}{{println .Source}}{{end}}' 2>/dev/null); then
  echo "cannot ask Docker what is mounted: removing nothing" >&2; exit 1
fi

removed=0
while IFS= read -r -d '' dir; do
  skip=0
  while IFS= read -r src; do
    [[ -z $src ]] && continue
    if [[ $src == "$dir" || $src == "$dir"/* ]]; then skip=1; break; fi
  done <<<"$mounts"
  if ((skip)); then echo "keep   $dir (a container mounts it)"; continue; fi
  if ((dry)); then echo "would remove $dir"; else rmdir -- "$dir" 2>/dev/null && echo "removed $dir" || continue; fi
  removed=$((removed + 1))
done < <(find "$root" -mindepth 1 -maxdepth 1 -type d -empty -mmin "+$age" -print0)

echo "$removed empty folder(s) $([[ $dry == 1 ]] && echo "found" || echo "removed") under $root"
