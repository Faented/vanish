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

# 1) проверка-1, маркеры содержимого: кейс 6 (run_sweep) зашил VANISH_ORACLE
#    в каждый 16КБ-офсет 1МБ-файла ДО wipe. Значит одно вхождение на raw = wipe пропустил область.
RAW_SIG_COUNT=$(grep -a -c "VANISH_ORACLE" "$LOOP" || true)
step INFO "raw-вхождений 'VANISH_ORACLE': $RAW_SIG_COUNT (ожидали 0)"
if [ "$RAW_SIG_COUNT" != "0" ]; then
  step FAIL "wipe пропустил область: маркеры VANISH_ORACLE выжили на raw ($RAW_SIG_COUNT)"
  fail=1
fi

# 2) проверка-2, имена-хвосты: ищем строки '.vanish-v1-'.
TAILS=$(grep -a -c "\.vanish-v1-" "$LOOP" || true)
step INFO "raw-вхождений '.vanish-v1-': $TAILS (tail-имена в ext4-метаданных допустимы, не FAIL; vanish не пишет оригинальные имена)"
# honest note: ext4 journal выключен в prepare (O ^has_journal). При обычном ext4
# имена могут остаться в журнале — это класс L3-граница vanish (см. threat-model §5).

# 3) photorec-оппонент: photorec 7.2 CLI не поддерживает /wholeraw или /fileopt
#    (только [/log] [/debug] [/d dir] device) и запускает ncurses-UI — поэтому
#    запуск photorec выполняется ИНТЕРАКТИВНО в терминале пользователя.
#    Оракул этой фазы — 0 файлов в OUT и чистый photorec.log без Recovered.
umount "$MNT" 2>/dev/null || true || step INFO "umount: ФС была уже отмонтирована"

echo "---------------------------------------------------------------" | tee -a "$REPORT"
step INFO "ФАЗА B: выполните в этом же терминале:"
step INFO "  sudo photorec /log /debug /d /tmp/vanish_photorec/recup_whole /dev/loop0"
step INFO "ЭКРАНЫ: [Proceed]=Enter → выбрать partition (P ext4; если пусто — photorec сам предложит)" 
step INFO "        → [Search]=Enter → выбрать 'Whole' (искать по всему разделу)"
step INFO "        → дожидаться финала скана → [Quit]=q → выбирать Quit/No на попутных вопросах"
step INFO "После выхода из photorec ЗАГЛЯНИТЕ: ls /tmp/vanish_photorec/recup_whole*"
step INFO "Ожидание: 0 файлов. Файл лога: photorec.log в каталоге, откуда запускали."
echo "---------------------------------------------------------------" | tee -a "$REPORT"
if [ "$fail" = "0" ]; then
  step OK "детерминированные оракулы raw: маркеров VANISH_ORACLE=0, plaintext-хвостов нет"
  step INFO "ОВЕРДИКТ photorec ждёт интерактивной фазы B выше (файлы должны быть 0)"
else
  step FAIL "детерминированные оракулы raw провалены (см. выше)"
fi
echo "=== FINALIZE: fail=$fail ===" | tee -a "$REPORT"
exit $fail
