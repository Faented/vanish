#!/usr/bin/env bash
# M3-оракул (без root): прогнать wipe-кейсы на loop-ext4-полигоне.
# Условие: tests/polygon/prepare.sh уже выполнен с sudo.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
MNT=/mnt/vanish-poly
V="$HOME/afpp/vanish/target/release/vanish"
[ -x "$V" ] || V=/home/qurumnie/afpp/vanish/target/release/vanish
LOG="$HERE/sweep.log"
: > "$LOG"

fail=0
step() { echo "[$1] $2" | tee -a "$LOG"; }
expect() { # expect <код> <описание> <cmd…>
  local want="$1" desc="$2"; shift 2
  set +e; "$@" >/dev/null 2>>"$LOG"; local got=$?; set -e
  if [ "$got" = "$want" ]; then step OK "$desc (rc=$got)"; else step FAIL "$desc (rc=$got, ожидали $want)"; fail=1; fi
}

# --- кейсы ---
rm -rf "$MNT"/* 2>/dev/null || true
sync

# 1) простой файл 1МБ
head -c 1048576 /dev/urandom > "$MNT/m1.bin"
step RUN  "1: wipe файла 1МБ"
expect 0 "1: wipe rc" "$V" "$MNT/m1.bin"
[ ! -e "$MNT/m1.bin" ] && step OK "1: файл удалён" || { step FAIL "1: файл остался"; fail=1; }

# 2) хвост после обрыва: имитируем crash — создаём файл-хвост сами и не доводим
head -c 4096 /dev/urandom > "$MNT/.vanish-v1-crashsimdeadbeef"
step RUN "2: recovery хвоста"
expect 0 "2: recovery rc" "$V" --recovery-scan "$MNT"
[ ! -e "$MNT/.vanish-v1-crashsimdeadbeef" ] && step OK "2: хвост дожат" || { step FAIL "2: хвост остался"; fail=1; }

# 3) многократный 3-pass + verify
head -c 262144 /dev/urandom > "$MNT/p3.bin"
expect 0 "3: 3-pass verify rc" "$V" --passes 3 --verify --pattern zero "$MNT/p3.bin"

# 4) дерево с подкаталогом
mkdir -p "$MNT/tree/sub"
head -c 65536 /dev/urandom > "$MNT/tree/a.bin"
head -c 65536 /dev/urandom > "$MNT/tree/sub/b.bin"
expect 0 "4: дерево rc" "$V" "$MNT/tree"
[ ! -e "$MNT/tree" ] && step OK "4: дерево удалено" || { step FAIL "4: дерево осталось"; fail=1; }

# 5) rename=false
head -c 65536 /dev/urandom > "$MNT/nr.bin"
expect 0 "5: no-rename rc" "$V" --no-rename "$MNT/nr.bin"

# 6) маркер-кейс: делает raw-оракул в finalize ОСМЫСЛЕННЫМ.
#    Каждые 16КБ-офсет файла содержат строку-маркер поверх случайных данных;
#    после wipe маркеров не должно остаться на сыром устройстве:
#    если хоть один блок не перезатёрт — finalize обязан выдать FAIL.
head -c 1048576 /dev/urandom > "$MNT/marker.bin"
for off in $(seq 0 16384 1048575); do
  printf "VANISH_ORACLE@%08x" "$off" | dd of="$MNT/marker.bin" bs=1 seek="$off" conv=notrunc status=none 2>/dev/null
done
sync
# Пока файл жив, проверяем, что маркер реально записался (оракул не пустышка):
if ! grep -qa "VANISH_ORACLE@00010000" "$MNT/marker.bin"; then
  step FAIL "6: маркер не записан в файл (оракул был бы пустышкой)"; fail=1
fi
expect 0 "6: маркер-файл rc" "$V" "$MNT/marker.bin"

sync

echo "=== SWEEP DONE: fail=$fail ===" | tee -a "$LOG"
exit $fail
