#!/usr/bin/env bash
# sudo bash tests/polygon/run_sweep.sh [trusted-vanish-binary]
# File/directory CLI tests only: block-device CLI wiping is deliberately excluded.
set -euo pipefail
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
source "$HERE/common.sh"
init
[[ $# -le 1 ]] || die 'usage: run_sweep.sh [trusted-vanish-binary]'
V=$(realpath -e -- "${1:-$HERE/../../target/release/vanish}")
[[ -f "$V" && -x "$V" ]] || die "not an executable binary: $V"
load_run
status_is mounted
check_mounted
WORK="$MNT/cases"
[[ ! -e "$WORK" && ! -L "$WORK" ]] || die 'cases already exist; start a fresh run'
mkdir -m 700 -- "$WORK"
LOG="$RUN/sweep.log"
(set -o noclobber; : > "$LOG")
set_status sweep-running
fail=0
step() { printf '[%s] %s\n' "$1" "$2" | tee -a "$LOG"; }
expect() {
  local want=$1 desc=$2 got=0
  shift 2
  check_cases
  "$@" >> "$LOG" 2>&1 || got=$?
  check_cases
  if [[ $got == "$want" ]]; then step OK "$desc (rc=$got)"; else
    step FAIL "$desc (rc=$got, expected $want)"; fail=1
  fi
}
gone() {
  if [[ ! -e "$1" && ! -L "$1" ]]; then step OK "$2 removed"; else
    step FAIL "$2 remains"; fail=1
  fi
}

head -c 1048576 /dev/urandom > "$WORK/m1.bin"
expect 0 '1: 1MiB file' "$V" "$WORK/m1.bin"
gone "$WORK/m1.bin" '1: file'

head -c 4096 /dev/urandom > "$WORK/.vanish-v1-crashsimdeadbeef"
expect 0 '2: synthetic recovery tail' "$V" --recovery-scan "$WORK"
gone "$WORK/.vanish-v1-crashsimdeadbeef" '2: synthetic tail'

head -c 262144 /dev/urandom > "$WORK/p3.bin"
expect 0 '3: 3-pass verify' "$V" --passes 3 --verify --pattern zero "$WORK/p3.bin"
gone "$WORK/p3.bin" '3: file'

mkdir -p -- "$WORK/tree/sub"
head -c 65536 /dev/urandom > "$WORK/tree/a.bin"
head -c 65536 /dev/urandom > "$WORK/tree/sub/b.bin"
expect 0 '4: tree' "$V" "$WORK/tree"
gone "$WORK/tree" '4: tree'

head -c 65536 /dev/urandom > "$WORK/nr.bin"
expect 0 '5: no-rename' "$V" --no-rename "$WORK/nr.bin"
gone "$WORK/nr.bin" '5: file'

head -c 1048576 /dev/urandom > "$WORK/marker.bin"
for ((off=0; off<1048576; off+=16384)); do
  printf 'VANISH_ORACLE@%08x' "$off" | dd of="$WORK/marker.bin" bs=1 seek="$off" conv=notrunc status=none
done
sync
check_mounted
# Establish a positive raw control before deleting the file: exactly 64
# distinct marker offsets must be readable through O_DIRECT. Read errors fail.
check_mounted
if ! raw_copy "$RUN/marker.scan"; then die 'cannot read raw device for marker control'; fi
if ! marker_count=$(LC_ALL=C grep -a -o -F -- 'VANISH_ORACLE@' "$RUN/marker.scan" | wc -l); then
  rm -f -- "$RUN/marker.scan"
  die 'marker control scan failed'
fi
rm -f -- "$RUN/marker.scan"
[[ $marker_count == 64 ]] || die "expected 64 marker occurrences, got $marker_count"
printf 'verified: %s markers\n' "$marker_count" > "$RUN/marker.control"
expect 0 '6: marker file' "$V" "$WORK/marker.bin"
gone "$WORK/marker.bin" '6: file'
check_cases
remaining=$(find "$WORK" -mindepth 1 -print -quit)
if [[ -n $remaining ]]; then step FAIL 'unexpected entries/tails remain in cases'; fail=1; fi
sync
step INFO 'Block-device CLI test excluded: the CLI must reject device targets.'
if (( fail == 0 )); then set_status swept; else set_status sweep-failed; fi
step INFO "SWEEP ONLY: fail=$fail; raw and manual PhotoRec checks are still pending"
exit "$fail"
