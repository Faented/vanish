#!/usr/bin/env bash
# M3-полигон: подготовка loop-ext4 甲ом для форезического оракула.
# ЗАПУСК (требует пароль root):  sudo bash tests/polygon/prepare.sh
# Идемпотентно: повторный запуск пересоздаёт полигон.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
USER_NAME="${SUDO_USER:-$(id -un)}"
IMG="$HERE/disk.img"
LOOPFILE_SIZE_MB=256
MNT=/mnt/vanish-poly

# 1) photorec/testdisk (opponent). Arch/CachyOS: пакет testdisk.
if ! command -v photorec >/dev/null 2>&1; then
  echo "[prepare] ставим testdisk (photorec входит) через pacman…"
  pacman -Sy --noconfirm testdisk
fi

# 1b) loop-модуль ядра (на обновлённых, но не перезагруженных системах его нет).
if ! grep -qw loop /proc/devices; then
  echo "[prepare] ядру не хватает loop-модуля — пробуем подгрузить…"
  modprobe loop 2>/dev/null || true
  if ! grep -qw loop /proc/devices; then
    echo "[prepare] ОШИБКА: loop-модуль ядра не загрузился."
    echo "[prepare] running kernel: $(uname -r)"
    echo "[prepare] установленные ядра: $(ls /usr/lib/modules 2>/dev/null || echo '(нет)')"
    echo "[prepare] Обычно это значит: пакеты обновились, но машина не перезагружена."
    echo "[prepare] → выполните 'sudo systemctl reboot' и запустите prepare.sh снова."
    exit 1
  fi
fi

# 2) образ + ФС
umount "$MNT" 2>/dev/null || true
losetup -D 2>/dev/null || true   # отсоединить все неактивные loop
rm -f "$IMG"
truncate -s "${LOOPFILE_SIZE_MB}M" "$IMG"
losetup -f "$IMG" --show > /tmp/vanish_poly_loop
LOOP="$(cat /tmp/vanish_poly_loop)"
mkfs.ext4 -F -q -O ^has_journal "$LOOP"   # БЕЗ журнала: чётче оракул имён; второй вариант сождём ниже

mkdir -p "$MNT"
mount "$LOOP" "$MNT"
chown -R "$USER_NAME":"$USER_NAME" "$MNT"

echo "[prepare] полигон готов:"
echo "  loop:   $LOOP"
echo "  mnt:    $MNT   (владелец: $USER_NAME)"
echo "  image:  $IMG"
echo "Дальше запускайте БЕЗ root:"
echo "  bash tests/polygon/run_sweep.sh"
