#!/usr/bin/env bash
# sudo bash tests/polygon/finalize.sh
# Exit 2 means raw checks passed, but manual PhotoRec verification is pending.
# No overall PASS is issued by this script.
set -euo pipefail
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
source "$HERE/common.sh"
init
load_run
status_is swept
private_file "$RUN/marker.control"
[[ $(cat -- "$RUN/marker.control") == verified:* ]] || die 'missing positive raw control'
check_cases
remaining=$(find "$MNT/cases" -mindepth 1 -print -quit)
[[ -z $remaining ]] || die 'files/tails remain; refusing a success report'
REPORT="$RUN/finalize.log"
(set -o noclobber; : > "$REPORT")
MODE=$(cat -- "$RUN/mode" 2>/dev/null || printf 'no-journal')
unmount_owned
set_status unmounted
fail=0
if raw_absent VANISH_ORACLE >> "$REPORT"; then
  printf 'PASS: raw content-marker check only\n' | tee -a "$REPORT"
else
  printf 'FAIL: content markers remain on raw device\n' | tee -a "$REPORT"
  fail=1
fi
if raw_absent .vanish-v1- >> "$REPORT"; then
  printf 'PASS: raw plaintext-tail check only\n' | tee -a "$REPORT"
elif [[ $MODE == with-journal ]]; then
  # In the journal variant the metadata scan is an expected failure: ext4 may
  # keep copies of names in the journal. It is reported as a documented limit,
  # never as a content-clean pass.
  printf 'EXPECTED-FAIL (with-journal): tail names remain in journal copies\n' | tee -a "$REPORT"
else
  printf 'FAIL: plaintext tail names remain (including possible ext4 metadata remnants)\n' | tee -a "$REPORT"
  fail=1
fi
if (( fail != 0 )); then set_status raw-failed; exit 1; fi
set_status raw-checked
printf 'INCOMPLETE: deterministic raw checks passed; PhotoRec has NOT been run or verified.\n' | tee -a "$REPORT"
printf 'Optional manual scan (install photorec yourself; use Whole and wait for completion):\n' | tee -a "$REPORT"
printf '  sudo flock -n %q bash -c %q\n' "$BASE/lock" "cd '$RUN' && photorec /log /debug /d '$RUN/recup_whole' '$LOOP'" | tee -a "$REPORT"
printf 'Review the complete PhotoRec scan and recovered files manually; no files alone is not proof of a completed scan.\n' | tee -a "$REPORT"
printf 'Do not teardown until the manual scan finishes. Logs/results stay in %s, never in HOME.\n' "$RUN" | tee -a "$REPORT"
exit 2
