#!/usr/bin/env bash
# Shared safety checks. Only source this file from the polygon scripts.
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077
BASE=/var/lib/vanish-polygon

die() { printf 'polygon: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null || die "missing dependency: $1 (install manually)"; }
private_dir() {
  [[ -d "$1" && ! -L "$1" ]] || die "not a real directory: $1"
  [[ $(stat -c %u -- "$1") == 0 ]] || die "not root-owned: $1"
  local mode
  mode=$(stat -c %a -- "$1")
  (( (8#$mode & 0022) == 0 )) || die "group/other-writable directory: $1"
}
private_file() {
  [[ -f "$1" && ! -L "$1" ]] || die "not a regular file: $1"
  [[ $(stat -c %u:%h -- "$1") == 0:1 ]] || die "unsafe owner/link count: $1"
  local mode
  mode=$(stat -c %a -- "$1")
  (( (8#$mode & 0077) == 0 )) || die "file is not private: $1"
}
init() {
  [[ $EUID == 0 ]] || die 'run with sudo bash tests/polygon/<phase>.sh'
  for cmd in stat flock findmnt losetup realpath grep dd wc blockdev; do need "$cmd"; done
  for dir in / /var /var/lib; do private_dir "$dir"; done
  if [[ ! -e "$BASE" && ! -L "$BASE" ]]; then mkdir -m 700 -- "$BASE"; fi
  private_dir "$BASE"
  [[ $(stat -c %a -- "$BASE") == 700 ]] || die "expected mode 700: $BASE"
  if [[ ! -e "$BASE/lock" && ! -L "$BASE/lock" ]]; then
    (set -o noclobber; : > "$BASE/lock")
  fi
  private_file "$BASE/lock"
  exec 9<>"$BASE/lock"
  flock -n 9 || die 'another polygon phase is running'
}
load_run() {
  private_file "$BASE/current"
  local name
  name=$(cat -- "$BASE/current")
  [[ $name =~ ^run\.[[:alnum:]]+$ ]] || die 'invalid run identifier'
  RUN="$BASE/$name"
  private_dir "$RUN"
  [[ $(stat -c %a -- "$RUN") == 700 ]] || die 'run directory is not private'
  IMG="$RUN/disk.img"
  MNT="$RUN/mnt"
  private_dir "$MNT"
  private_file "$RUN/image.identity"
  private_file "$IMG"
  [[ $(stat -c %d:%i -- "$IMG") == "$(cat -- "$RUN/image.identity")" ]] || die 'image identity changed'
  private_file "$RUN/status"
}
status_is() { [[ $(cat -- "$RUN/status") == "$1" ]] || die "expected phase '$1'; see $RUN/status"; }
set_status() { printf '%s\n' "$1" > "$RUN/status"; }
check_loop() {
  private_file "$IMG"
  private_file "$RUN/image.identity"
  [[ $(stat -c %d:%i -- "$IMG") == "$(cat -- "$RUN/image.identity")" ]] || die 'image identity changed'
  private_file "$RUN/loop"
  LOOP=$(cat -- "$RUN/loop")
  [[ $LOOP =~ ^/dev/loop[0-9]+$ && -b "$LOOP" && ! -L "$LOOP" ]] || die 'invalid loop device'
  [[ $(losetup --noheadings --raw --output BACK-FILE "$LOOP") == "$IMG" ]] || die 'loop backing path changed'
  [[ $(losetup --noheadings --raw --output BACK-INO "$LOOP") == "$(stat -c %i -- "$IMG")" ]] || die 'loop backing inode changed'
  # Do not compare BACK-MAJ:MIN with findmnt: util-linux may report it empty and
  # btrfs st_dev can differ from mountinfo MAJ:MIN. Path + inode + size above
  # already pin the exact backing file object.
  [[ $(losetup --noheadings --raw --output OFFSET "$LOOP") == 0 ]] || die 'unexpected loop offset'
  [[ $(losetup --noheadings --raw --output SIZELIMIT "$LOOP") == 0 ]] || die 'unexpected loop size limit'
  [[ $(blockdev --getsize64 "$LOOP") == "$(stat -c %s -- "$IMG")" ]] || die 'loop size differs from image size'
  # findmnt prints decimal major:minor; stat %t/%T give st_rdev in hex.
  local maj_hex min_hex
  maj_hex=$(stat -c %t -- "$LOOP")
  min_hex=$(stat -c %T -- "$LOOP")
  [[ $maj_hex =~ ^[0-9a-fA-F]+$ && $min_hex =~ ^[0-9a-fA-F]+$ ]] || die 'cannot read loop device numbers'
  DEVNUM=$(printf '%d:%d' "0x$maj_hex" "0x$min_hex")
}
check_unmounted() {
  local mounts
  # Enumerate first: command errors must never be mistaken for "not mounted".
  mounts=$(findmnt --raw --noheadings --output MAJ:MIN) || die 'cannot enumerate mounts'
  if grep -Fxq -- "$DEVNUM" <<< "$mounts"; then die 'owned loop is still mounted'; fi
  if findmnt --mountpoint "$MNT" >/dev/null; then die 'mountpoint is occupied'; else
    [[ $? == 1 ]] || die 'cannot inspect mountpoint'
  fi
}
check_mounted() {
  check_loop
  [[ $(findmnt --raw --noheadings --mountpoint "$MNT" --output SOURCE) == "$LOOP" ]] || die 'mount source changed'
  [[ $(findmnt --raw --noheadings --mountpoint "$MNT" --output MAJ:MIN) == "$DEVNUM" ]] || die 'mounted device identity changed'
  [[ $(findmnt --raw --noheadings --mountpoint "$MNT" --output FSTYPE) == ext4 ]] || die 'not ext4'
  [[ $(findmnt --raw --noheadings --mountpoint "$MNT" --output FSROOT) == / ]] || die 'not the filesystem root'
  [[ $(findmnt --raw --noheadings --submounts --mountpoint "$MNT" --output TARGET) == "$MNT" ]] || die 'nested/stacked mounts present'
  local devices expected
  devices=$(findmnt --raw --noheadings --output MAJ:MIN,TARGET) || die 'cannot enumerate mounts'
  expected="$DEVNUM $MNT"
  [[ $(awk -v dev="$DEVNUM" '$1 == dev { print $1 " " $2 }' <<< "$devices") == "$expected" ]] || die 'loop mounted at another location'
  private_dir "$MNT"
}
check_cases() {
  check_mounted
  private_dir "$MNT/cases"
  [[ $(stat -c %d -- "$MNT/cases") == "$(stat -c %d -- "$MNT")" ]] || die 'cases left the owned filesystem'
}
unmount_owned() {
  check_mounted
  sync
  umount -- "$MNT" || die 'unmount failed; refusing further operations'
  check_loop
  check_unmounted
}
# Unmount every mount whose source is exactly this run's loop. The desktop
# automounter may mount the disposable image at /run/media/<user>/<uuid> after
# finalize; that is still our loop, never an unrelated filesystem. Verify the
# device number before each unmount and never touch /.
unmount_all_owned() {
  check_loop
  local all maj target
  # Enumerate mounts independently of --source: findmnt exits 1 when the loop
  # is not mounted at all, which is a normal post-M5 state, not an error.
  all=$(findmnt --raw --noheadings --output MAJ:MIN,TARGET) || die 'cannot enumerate mounts'
  while read -r maj target; do
    [[ -n ${maj:-} ]] || continue
    [[ $maj == "$DEVNUM" ]] || continue
    [[ $target == / ]] && die 'refusing to unmount root'
    printf 'unmounting owned loop from %s\n' "$target" >&2
    umount -- "$target" || die "unmount failed: $target"
  done <<< "$all"
  check_loop
  check_unmounted
}
# Copy the loop device through O_DIRECT so the scan cannot be served from the
# page cache. Any read error is fatal, never "not found". The default requires
# an unmounted device; pass 'mounted' for the positive control that runs while
# the freshly synced filesystem is still mounted.
raw_copy() {
  local out=$1 mounted=${2:-no}
  [[ ! -e "$out" && ! -L "$out" ]] || die "refusing to overwrite raw copy: $out"
  check_loop
  if [[ $mounted == yes ]]; then
    check_mounted
  else
    check_unmounted
  fi
  dd if="$LOOP" of="$out" bs=1M iflag=direct status=none || die 'raw read failed'
}
# Count marker occurrences (not lines: binary data may contain no newlines).
raw_absent() {
  local pattern=$1 copy="$RUN/raw.scan" count rc=0
  raw_copy "$copy"
  count=$(LC_ALL=C grep -a -o -F -- "$pattern" "$copy" | wc -l) || rc=$?
  rm -f -- "$copy"
  [[ $rc == 0 || $rc == 1 ]] || die "raw scan failed: $pattern (rc=$rc)"
  printf 'raw matching occurrences for %s: %s\n' "$pattern" "$count"
  [[ $count == 0 ]]
}
