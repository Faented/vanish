#!/usr/bin/env bash
# sudo bash tests/polygon/run_all.sh [trusted-vanish-binary] [--with-journal] [--auto-photorec]
#
# Orchestrates the full disposable-loop protocol:
#   prepare -> run_sweep -> finalize (raw scans) -> optional scripted PhotoRec.
# Never installs packages, never touches anything outside the private run state
# in /var/lib/vanish-polygon. Exit codes:
#   0  full PASS (raw checks + PhotoRec: 0 recovered files)
#   1  FAIL (a check failed; see the run logs)
#   2  INCOMPLETE (raw checks passed, PhotoRec still pending or unproven)
set -euo pipefail
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
source "$HERE/common.sh"

# The orchestrator deliberately does NOT hold the phase lock: init() would
# flock fd 9 and child phase scripts inherit it, deadlocking themselves with
# "another polygon phase is running". Each phase script takes and releases the
# lock itself. We only verify preconditions here.
[[ $EUID == 0 ]] || die 'run with sudo bash tests/polygon/run_all.sh ...'
for cmd in stat flock findmnt losetup realpath grep dd wc blockdev awk mktemp; do need "$cmd"; done

V=""
PREPARE_ARGS=()
AUTO_PHOTOREC=0
usage() {
  printf 'usage: run_all.sh [trusted-vanish-binary] [--with-journal] [--auto-photorec]\n' >&2
  exit 2
}
while (($#)); do
  case "$1" in
    --with-journal) PREPARE_ARGS+=(--with-journal) ;;
    --auto-photorec) AUTO_PHOTOREC=1 ;;
    -h|--help) usage ;;
    --*) die "unknown option: $1" ;;
    *) [[ -z $V ]] || die "binary already set to $V"; V=$1 ;;
  esac
  shift
done
if [[ -n $V ]]; then
  V=$(realpath -e -- "$V")
  [[ -f $V && -x $V ]] || die "not an executable binary: $V"
fi
[[ ! -e "$BASE/current" && ! -L "$BASE/current" ]] || die 'a run already exists; finalize/teardown it first'
if (( AUTO_PHOTOREC )); then
  need photorec
elif ! command -v photorec >/dev/null; then
  printf 'note: photorec not installed; the forensic phase will stay manual (install package testdisk yourself)\n'
fi

bash "$HERE/prepare.sh" "${PREPARE_ARGS[@]}"
load_run
check_loop
printf 'run: %s\n' "$RUN"

if ! bash "$HERE/run_sweep.sh" ${V:+"$V"}; then
  die "sweep failed; inspect $RUN/sweep.log, then run: sudo bash $HERE/teardown.sh"
fi

frc=0
bash "$HERE/finalize.sh" || frc=$?
[[ $frc == 2 ]] || die "finalize returned $frc (expected 2=INCOMPLETE); inspect $RUN/finalize.log"

load_run
check_loop
status_is raw-checked

if ! (( AUTO_PHOTOREC )); then
  printf 'INCOMPLETE: raw checks passed. Run the manual PhotoRec phase, then teardown:\n' >&2
  printf '  sudo bash -c %q\n' "cd '$RUN' && photorec /log /debug /d '$RUN/recup' '$LOOP'" >&2
  printf '  sudo bash %q/teardown.sh\n' "$HERE" >&2
  exit 2
fi

# Scripted PhotoRec phase (experimental): any ambiguity means INCOMPLETE, never PASS.
mkdir -m 700 -- "$RUN/recup"
OUT="$RUN/photorec.stdout"
if ! (cd -- "$RUN" && photorec /log /debug /d "$RUN/recup" /cmd "$LOOP" partition_none,search > "$OUT" 2>&1); then
  printf 'INCOMPLETE: scripted photorec failed (rc); run it manually, see %s\n' "$OUT" >&2
  exit 2
fi
total=$(cat -- "$OUT" "$RUN/photorec.log" 2>/dev/null | grep -a -o -E 'Total: [0-9]+ files? found' | tail -n 1 || true)
if [[ -z $total ]]; then
  printf 'INCOMPLETE: photorec log has no Total line; scan completeness unproven, verify manually: %s\n' "$OUT" >&2
  exit 2
fi
restored=$(find "$RUN/recup" -type f ! -name report.xml -print -quit)
if [[ $total != 'Total: 0 files found' || -n $restored ]]; then
  set_status photorec-dirty
  printf 'FAIL: %s, restored files: %s\n' "$total" "${restored:-none-listed}" >&2
  exit 1
fi
set_status photorec-clean
MODE=$(cat -- "$RUN/mode" 2>/dev/null || printf 'no-journal')
if [[ $MODE == with-journal ]]; then
  printf 'PASS (content only, with-journal): raw content markers and PhotoRec are clean, but journal-name residue is expected and documented; this is NOT a clean G2 result. Evidence: %s\n' "$RUN"
else
  printf 'PASS (full): raw checks + PhotoRec 0 recovered files. Evidence: %s\n' "$RUN"
fi
printf 'Then clean up: sudo bash %q/teardown.sh\n' "$HERE"
