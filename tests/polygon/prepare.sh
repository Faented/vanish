#!/usr/bin/env bash
# sudo bash tests/polygon/prepare.sh
# Never replaces an existing run; use teardown first. No package installation.
set -euo pipefail
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
source "$HERE/common.sh"
init
for cmd in mktemp truncate mkfs.ext4 mount; do need "$cmd"; done
[[ ! -e "$BASE/current" && ! -L "$BASE/current" ]] || die 'a run already exists; finalize/teardown it first'

RUN=$(mktemp -d "$BASE/run.XXXXXXXXXXXX")
IMG="$RUN/disk.img"
MNT="$RUN/mnt"
mkdir -m 700 -- "$MNT"
truncate -s 256M -- "$IMG"
stat -c %d:%i -- "$IMG" > "$RUN/image.identity"
set_status allocated
printf '%s\n' "${RUN##*/}" > "$BASE/current"
printf 'Run: %s (on failure, inspect it and run teardown; no automatic destructive cleanup)\n' "$RUN"

# This file records only the newly allocated device, never a global loop list.
losetup --find --show --nooverlap "$IMG" > "$RUN/loop"
load_run
check_loop
check_unmounted
set_status attached
mkfs.ext4 -F -q -O ^has_journal "$LOOP"
check_loop
check_unmounted
mount -o nodev,nosuid,noexec -- "$LOOP" "$MNT"
check_mounted
set_status mounted
printf 'Prepared private ext4 run. Next:\n  sudo bash %q/run_sweep.sh [trusted-vanish-binary]\n' "$HERE"
printf 'State and logs: %s\n' "$RUN"
