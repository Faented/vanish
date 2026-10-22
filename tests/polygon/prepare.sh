#!/usr/bin/env bash
# sudo bash tests/polygon/prepare.sh
# Never replaces an existing run; use teardown first. No package installation.
set -euo pipefail
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
source "$HERE/common.sh"
init
for cmd in mktemp truncate mkfs.ext4 mount; do need "$cmd"; done
[[ ! -e "$BASE/current" && ! -L "$BASE/current" ]] || die 'a run already exists; finalize/teardown it first'
WITH_JOURNAL=0
[[ $# -le 1 ]] || die 'usage: prepare.sh [--with-journal]'
if [[ ${1:-} == '--with-journal' ]]; then WITH_JOURNAL=1; fi

RUN=$(mktemp -d "$BASE/run.XXXXXXXXXXXX")
IMG="$RUN/disk.img"
MNT="$RUN/mnt"
# A failure anywhere below must not orphan loop devices, the run directory or
# the current-run pointer: clean up only resources whose identity we verified.
# An EXIT trap (not ERR) is required because die() exits explicitly.
PREPARE_OK=0
cleanup_err() {
  local rc=$? loop
  trap - EXIT
  if [[ -f "$BASE/current" && $(cat -- "$BASE/current" 2>/dev/null) == "${RUN##*/}" ]]; then
    rm -f -- "$BASE/current"
  fi
  if [[ -f "$RUN/loop" ]]; then
    loop=$(cat -- "$RUN/loop" 2>/dev/null || true)
    if [[ $loop =~ ^/dev/loop[0-9]+$ && -b $loop && ! -L $loop ]] \
      && [[ $(losetup --noheadings --raw --output BACK-FILE "$loop" 2>/dev/null) == "$IMG" ]]; then
      umount -- "$MNT" 2>/dev/null || true
      losetup -d -- "$loop" 2>/dev/null || true
    fi
  fi
  rm -rf -- "$RUN" 2>/dev/null || true
  exit "$rc"
}
trap 'if (( ! PREPARE_OK )); then cleanup_err; fi' EXIT

mkdir -m 700 -- "$MNT"
truncate -s 256M -- "$IMG"
stat -c %d:%i -- "$IMG" > "$RUN/image.identity"
if (( WITH_JOURNAL )); then printf 'with-journal\n' > "$RUN/mode"; else printf 'no-journal\n' > "$RUN/mode"; fi
set_status allocated
printf '%s\n' "${RUN##*/}" > "$BASE/current"
printf 'Run: %s (on failure, inspect it and run teardown; no automatic destructive cleanup)\n' "$RUN"

# This file records only the newly allocated device, never a global loop list.
losetup --find --show --nooverlap "$IMG" > "$RUN/loop"
load_run
check_loop
check_unmounted
set_status attached
if (( WITH_JOURNAL )); then
  mkfs.ext4 -F -q "$LOOP"
else
  mkfs.ext4 -F -q -O ^has_journal "$LOOP"
fi
check_loop
check_unmounted
mount -o nodev,nosuid,noexec -- "$LOOP" "$MNT"
check_mounted
set_status mounted
PREPARE_OK=1
trap - EXIT
printf 'Prepared private ext4 run (%s). Next:\n  sudo bash %q/run_sweep.sh [trusted-vanish-binary]\n' "$(cat -- "$RUN/mode")" "$HERE"
printf 'State and logs: %s\n' "$RUN"
