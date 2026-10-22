#!/usr/bin/env bash
# sudo bash tests/polygon/teardown.sh
# Only this run's loop and image are removed. Audit/PhotoRec output is retained.
set -euo pipefail
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
source "$HERE/common.sh"
init
if [[ ! -e "$BASE/current" && ! -L "$BASE/current" ]]; then
  printf 'No active polygon run. Legacy /tmp state and unrelated mounts are never touched.\n'
  exit 0
fi
load_run
if [[ -s "$RUN/loop" ]]; then
  check_loop
  # finalize normally unmounts $MNT, but udisks may have auto-mounted our loop
  # elsewhere. Unmount only mounts whose backing device is this exact loop.
  unmount_all_owned
  losetup --detach "$LOOP" || die 'detach failed; image retained'
fi
# Never unlink an image still associated with any loop, even after detach.
associations=$(losetup --associated "$IMG" --noheadings --output NAME)
[[ -z $associations ]] || die 'image still associated with a loop; refusing cleanup'
if findmnt --mountpoint "$MNT" >/dev/null; then die 'mountpoint still occupied'; else
  [[ $? == 1 ]] || die 'cannot inspect mountpoint'
fi
private_file "$IMG"
[[ $(stat -c %d:%i -- "$IMG") == "$(cat -- "$RUN/image.identity")" ]] || die 'image identity changed'
rmdir -- "$MNT" || die 'mountpoint not empty; image retained'
rm -- "$IMG"
set_status torn-down
rm -- "$BASE/current"
printf 'Owned loop/image removed. Audit state and any manual PhotoRec results retained in %s\n' "$RUN"
