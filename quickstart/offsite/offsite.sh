#!/bin/sh
# Copies CrowsNest's shared backups folder to an rclone remote, on a timer. Runs inside the rclone/rclone image
# (see compose.yaml next to this file); CrowsNest itself never holds the remote's credentials.
#
#   OFFSITE_REMOTE          where to copy to, e.g. "offsite:crowsnest" or "/mnt/other-disk/crowsnest" (required)
#   OFFSITE_INTERVAL        seconds between copies (default 21600, six hours)
#   OFFSITE_KEEP_DAYS       delete offsite files older than this many days (default: keep everything)
#   OFFSITE_SOURCE          the folder to copy (default /backups)
#   OFFSITE_MIN_AGE         skip files newer than this, so a backup still being written is not copied (default 2m)
#   OFFSITE_EXTRA_ARGS      extra rclone flags, e.g. "--bwlimit 2M"
#   OFFSITE_STATUS_FILE     where to report each result for the CrowsNest dashboard (default /status/offsite.json;
#                           skipped when its folder is not writable)
#
# `offsite.sh once` makes one copy and exits non-zero if it failed (for cron, or to test the setup).
# `offsite.sh check` only lists what would be copied (rclone --dry-run).
#
# It uses `rclone copy`, never `sync`: a backup the panel prunes or deletes locally stays offsite until
# OFFSITE_KEEP_DAYS passes. And --immutable: a backup that changes after it was copied is an error, not an overwrite.
set -u

SRC="${OFFSITE_SOURCE:-/backups}"
DEST="${OFFSITE_REMOTE:-}"
INTERVAL="${OFFSITE_INTERVAL:-21600}"
KEEP_DAYS="${OFFSITE_KEEP_DAYS:-}"
MIN_AGE="${OFFSITE_MIN_AGE:-2m}"
MODE="${1:-loop}"

log() { echo "offsite: $(date -u +%Y-%m-%dT%H:%M:%SZ) $*"; }

if [ -z "$DEST" ]; then log "OFFSITE_REMOTE is not set"; exit 2; fi
if [ ! -d "$SRC" ]; then log "$SRC is not a folder: is the backups folder mounted?"; exit 2; fi
case "$INTERVAL" in ''|*[!0-9]*) log "OFFSITE_INTERVAL must be a number of seconds"; exit 2;; esac
if [ -n "$KEEP_DAYS" ]; then
  case "$KEEP_DAYS" in *[!0-9]*|0) log "OFFSITE_KEEP_DAYS must be a whole number of days"; exit 2;; esac
fi

STATUS="${OFFSITE_STATUS_FILE:-/status/offsite.json}"
LAST_OK="0001-01-01T00:00:00Z"
# Keep the last good time across runs (and restarts) when a status file is already there.
prev=$(sed -n 's/.*"last_ok":"\([^"]*\)".*/\1/p' "$STATUS" 2>/dev/null | head -n 1)
[ -n "$prev" ] && LAST_OK="$prev"

# write_status ok|fail: a small JSON file the panel reads (read-only) to warn when copies fail or stop. Written
# atomically so the panel never reads half of it.
write_status() {
  [ -d "$(dirname "$STATUS")" ] && [ -w "$(dirname "$STATUS")" ] || return 0
  now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  if [ "$1" = ok ]; then LAST_OK="$now"; ok=true; err=""; else ok=false; err="${2:-the last copy failed: see the offsite container's log}"; fi
  remote=$(printf '%s' "$DEST" | sed 's/[\\"]/_/g')
  printf '{"ok":%s,"at":"%s","last_ok":"%s","interval_seconds":%s,"remote":"%s","error":"%s"}\n' \
    "$ok" "$now" "$LAST_OK" "$INTERVAL" "$remote" "$err" > "$STATUS.tmp" && mv "$STATUS.tmp" "$STATUS"
}

# The panel's marker file says which drive this is; it means nothing offsite.
# Without it the folder is not the backups folder (an unmounted drive leaves an empty directory): refuse to
# copy nothing and call it a success.
if [ ! -f "$SRC/.crowsnest-backups" ] && [ -z "${OFFSITE_NO_MARKER_CHECK:-}" ]; then
  log "$SRC has no .crowsnest-backups marker: not the CrowsNest backups folder, or the drive is not mounted (set OFFSITE_NO_MARKER_CHECK=1 to copy anyway)"
  write_status fail "the backups folder is not mounted or is not CrowsNest's (no .crowsnest-backups marker): nothing was copied"
  exit 3
fi

copy_once() {
  rc=0
  # shellcheck disable=SC2086 # OFFSITE_EXTRA_ARGS is meant to split
  rclone copy "$SRC" "$DEST" --exclude "/.crowsnest-backups" --min-age "$MIN_AGE" --immutable \
    --create-empty-src-dirs=false --stats-one-line --stats 0 -v ${OFFSITE_EXTRA_ARGS:-} "$@" || rc=1
  # Retention runs even when a copy failed: one bad file must not stop old backups being cleaned up.
  if [ -n "$KEEP_DAYS" ] && [ -z "${DRY:-}" ]; then
    # shellcheck disable=SC2086
    rclone delete "$DEST" --min-age "${KEEP_DAYS}d" -v ${OFFSITE_EXTRA_ARGS:-} || rc=1
    # shellcheck disable=SC2086
    rclone rmdirs "$DEST" --leave-root ${OFFSITE_EXTRA_ARGS:-} || rc=1   # only the empty ones
  fi
  return $rc
}

case "$MODE" in
  check) DRY=1; log "dry run: $SRC -> $DEST"; copy_once --dry-run; exit $? ;;
  once)  log "copying $SRC -> $DEST"; if copy_once; then write_status ok; log "done"; exit 0; fi; write_status fail; log "FAILED"; exit 1 ;;
  loop)  ;;
  *)     log "unknown mode '$MODE' (once, check or loop)"; exit 2 ;;
esac

log "copying $SRC -> $DEST every ${INTERVAL}s${KEEP_DAYS:+, keeping ${KEEP_DAYS} days offsite}"
while :; do
  if copy_once; then write_status ok; log "done"; else write_status fail; log "FAILED (will try again in ${INTERVAL}s)"; fi
  sleep "$INTERVAL" &
  wait $!
done
