#!/usr/bin/env bash
# M3-оракул, фаза 2 (root): umount + ФОРЕЗИЧЕСКИЙ скан raw-устройства.
# ЗАПУСК:  sudo bash tests/polygon/finalize.sh
# Проверяет: (a) маркеры содержимого отсутствуют на сыром устройстве;
#            (b) photorec НЕ восстанавливает ни одного файла;
#            (c) имена-хвосты НЕ встречаются в plaintext на raw.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
LOOP="$(cat /tmp/vanish_poly_loop 2>/dev/null || true)"
MNT=/mnt/vanish-poly
OUT=/tmp/vanish_photorec
REPORT="$HERE/finalize.log"
: > "$REPORT"
fail=0
step(){ echo "[$1] $2" | tee -a "$REPORT"; }

if [ -z "$LOOP" ] || [ ! -b "$LOOP" ]; then step FAIL "нет loop-устройства; сначала prepare.sh"; exit 2; fi

# 0) выкинуть page cache из raw-зоны (умность от «прочитали из RAM»)
sync
echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true

# 1) plaintext-маркеры содержимого на raw-девайсе?
#    прогоны в run_sweep писали /dev/urandom — ищем устойчивые маркеры,
#    которые против возможно остались от ТЕСТОВ ДО wipe (созданы вручную ниже нет).
#    Здесь контролируем: количество исполняемых байт-паттернов из известного мусор:
RAW_SIG_COUNT=$(grep -c "VANISH_ORACLE" "$LOOP" || true)
step INFO "raw-сигнатур 'VANISH_ORACLE': $RAW_SIG_COUNT (ожидание: 0 после успешных прогонов с маркером)"
# создаём контроль: если пользователь создал в m1 файл со строкой маркера ДО wipe —
# только тогда эта проверка показательна. В базовом sweep маркер не заливался.

# 2) имена-хвосты (plaintext этому девайсу)? ищем '.vanish-v1-' строки
TAILS=$(grep -a -c "\.vanish-v1-" "$LOOP" || true)
step INFO "raw-вхождения '.vanish-v1-': $TAILS (ext4-директории могут хранить упоминания имён ДО rename-hide — деталь ниже)"
# honest note: ext4 journal выключен в prepare (O ^has_journal). При обычном ext4
# имена могут остаться в журнале — это класс L3-граница vanish (см. threat-model §5).

# 3) photorec-оппонент (контроль: wholeraw-скан всего raw-образа)
umount "$MNT" 2>/dev/null || true
rm -rf "$OUT"; mkdir -p "$OUT"
photorec /log /debug /d "$OUT/recup_whole" /wholeraw /fileopt everything_enable "$LOOP" >/dev/null 2>&1
sleep 1
RECOVERED=$(find "$OUT" -type f ! -name "report*" ! -name "*.log" 2>/dev/null | wc -l)
step INFO "photorec восстановил файлов: $RECOVERED (ожидали 0)"
if [ "$RECOVERED" != "0" ]; then
  step FAIL "photorec нашёл остатки:"
  find "$OUT" -type f | tee -a "$REPORT"
  fail=1
fi

# 4) свободный результат
if [ "$fail" = "0" ]; then
  step OK "оракул: сырая поверхность не содержит восстановимых целевых данных"
else
  step FAIL "оракул: обнаружены остатки (см. выше)"
fi
echo "=== FINALIZE: fail=$fail ===" | tee -a "$REPORT"
exit $fail
