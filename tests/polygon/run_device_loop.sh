#!/usr/bin/env bash
# sudo bash tests/polygon/run_device_loop.sh [trusted-vanish-binary] [--passes N] [--verify] [--auto-photorec]
#
# M5 loop-only device-wipe evidence. Creates a private 256 MiB image and its own
# loop device, writes 64 distributed markers directly to the block device, runs
# `vanish device <loop> --device-wipe-loop --confirm-device <loop> --passes N`,
# then scans the raw device through O_DIRECT. This script NEVER targets a real
# disk: it refuses anything that is not its freshly created loop device.
#
# Exit codes: 0 full PASS (raw + PhotoRec 0), 1 FAIL, 2 INCOMPLETE.
set -euo pipefail
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
source "$HERE/common.sh"

usage() {
  printf 'usage: run_device_loop.sh [binary] [--passes N|--passes=N] [--verify] [--auto-photorec]\n' >&2
  exit "$1"
}
V=""
PASSES=1
VERIFY=0
AUTO=0
set_passes() {
  PASSES=$1
  [[ $PASSES =~ ^[1-9][0-9]*$ ]] && ((PASSES <= 35)) || die 'passes must be 1..35'
}
while (($#)); do
  case "$1" in
    -h|--help) usage 0 ;;
    --verify) VERIFY=1 ;;
    --auto-photorec) AUTO=1 ;;
    --passes)
      shift
      [[ $# -gt 0 ]] || die '--passes requires a value'
      set_passes "$1"
      ;;
    --passes=*) set_passes "${1#--passes=}" ;;
    --*) die "unknown option: $1 (arguments: $*)" ;;
    *) [[ -z $V ]] || die "binary already set to $V"; V=$1 ;;
  esac
  shift
done
V=$(realpath -e -- "${V:-$HERE/../../target/release/vanish}")
[[ -f $V && -x $V ]] || die "not an executable binary: $V"
init
if (( AUTO )); then need photorec; fi
[[ ! -e "$BASE/current" && ! -L "$BASE/current" ]] || die 'a run already exists; finalize/teardown it first'
for cmd in truncate mkfs.ext4 dd blockdev; do need "$cmd"; done

RUN=$(mktemp -d "$BASE/run.XXXXXXXXXXXX")
IMG="$RUN/disk.img"
MNT="$RUN/mnt"
LOOP=""
cleanup_failed() {
  local rc=$?
  if ((rc != 0)); then
    if [[ -n $LOOP && -b $LOOP ]]; then
      if [[ $(losetup --noheadings --raw --output BACK-FILE "$LOOP" 2>/dev/null) == "$IMG" ]]; then
        losetup --detach "$LOOP" || true
      fi
    fi
    if [[ -f "$BASE/current" && $(cat -- "$BASE/current") == $(basename -- "$RUN") ]]; then
      rm -f -- "$BASE/current"
    fi
    printf 'device-loop run failed; own loop detached, logs retained: %s\n' "$RUN" >&2
  fi
}
trap cleanup_failed EXIT

mkdir -m 700 -- "$MNT"
truncate -s 256M -- "$IMG"
stat -c %d:%i -- "$IMG" > "$RUN/image.identity"
printf 'device-loop\n' > "$RUN/mode"
printf 'allocated\n' > "$RUN/status"
printf '%s\n' "$(basename -- "$RUN")" > "$BASE/current"

LOOP=$(losetup --find --show --nooverlap "$IMG")
[[ -b $LOOP ]] || die 'losetup did not return a block device'
printf '%s\n' "$LOOP" > "$RUN/loop"
load_run
check_loop
check_unmounted

SIZE=$(blockdev --getsize64 "$LOOP")
[[ $SIZE == 268435456 ]] || die "unexpected device size: $SIZE"
STRIDE=$((SIZE / 64))
for ((i = 0; i < 64; i++)); do
  off=$((i * STRIDE))
  printf 'VANISH_ORACLE@%08x' "$off" | dd of="$LOOP" bs=1 seek="$off" conv=notrunc status=none
done
sync
blockdev --flushbufs "$LOOP"

# Positive O_DIRECT control: exactly 64 marker occurrences before the wipe.
raw_copy "$RUN/pre.scan"
if ! pre_count=$(LC_ALL=C grep -a -o -F -- 'VANISH_ORACLE@' "$RUN/pre.scan" | wc -l); then
  rm -f -- "$RUN/pre.scan"
  die 'positive raw control scan failed'
fi
rm -f -- "$RUN/pre.scan"
[[ $pre_count == 64 ]] || die "expected 64 markers before wipe, got $pre_count"

ARGS=(device "$LOOP" --device-wipe-loop --confirm-device "$LOOP" --passes "$PASSES" --json)
((VERIFY)) && ARGS+=(--verify)
rc=0
"$V" "${ARGS[@]}" > "$RUN/device.out" 2> "$RUN/device.err" || rc=$?
[[ $rc == 0 ]] || die "device-wipe returned rc=$rc; see $RUN/device.err"
grep -q '"status": "ok"' "$RUN/device.out" || die 'device-wipe did not report an ok event'
grep -q '"strategy": "loop_overwrite"' "$RUN/device.out" || die 'unexpected device strategy'
grep -q '"guarantee_level": "content-only"' "$RUN/device.out" || die 'unexpected guarantee level'
EXPECTED_BYTES=$((SIZE * PASSES))
grep -q "\"bytes\": $EXPECTED_BYTES" "$RUN/device.out" || die 'device-wipe did not report full-size bytes'

check_loop
check_unmounted
raw_copy "$RUN/post.scan"
post_count=$(LC_ALL=C grep -a -o -F -- 'VANISH_ORACLE@' "$RUN/post.scan" | wc -l) || true
rm -f -- "$RUN/post.scan"
[[ $post_count == 0 ]] || die "raw markers remain after device wipe: $post_count"

if ! ((AUTO)); then
  set_status device-loop-raw-clean
  printf 'INCOMPLETE: raw device scan is clean. Manual PhotoRec phase:\n' >&2
  printf '  sudo bash -c %q\n' "cd '$RUN' && photorec /log /debug /d '$RUN/recup' '$LOOP'" >&2
  printf 'Then clean up: sudo bash %q/teardown.sh\n' "$HERE" >&2
  exit 2
fi

mkdir -m 700 -- "$RUN/recup"
OUT="$RUN/photorec.stdout"
rc=0
(cd -- "$RUN" && photorec /log /debug /d "$RUN/recup" /cmd "$LOOP" partition_none,search > "$OUT" 2>&1) || rc=$?
if ((rc != 0)); then
  set_status device-loop-photorec-failed
  die "scripted photorec failed (rc=$rc); inspect $OUT"
fi
total=$(cat -- "$OUT" "$RUN/photorec.log" 2>/dev/null | grep -a -o -E 'Total: [0-9]+ files? found' | tail -n 1 || true)
if [[ -z $total ]]; then
  set_status device-loop-incomplete
  die "photorec log has no Total line; scan completeness unproven: $OUT"
fi
restored=$(find "$RUN/recup" -type f ! -name report.xml -print -quit)
if [[ $total != 'Total: 0 files found' || -n $restored ]]; then
  set_status device-loop-dirty
  die "FAIL: $total, restored: ${restored:-none-listed}"
fi

set_status device-loop-clean
printf 'PASS (full, loop-only): device raw markers 0, PhotoRec Total 0. Evidence: %s\n' "$RUN"
printf 'Clean up: sudo bash %q/teardown.sh\n' "$HERE"