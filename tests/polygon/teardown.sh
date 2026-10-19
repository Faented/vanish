#!/usr/bin/env bash
# M3-полигон: разборка.  ЗАПУСК:  sudo bash tests/polygon/teardown.sh
# Идемпотентно: безопасно запускать повторно; снимает ТОЛЬКО наш loop
# (по backing-файлу disk.img) — чужие loop-устройства не трогает.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
IMG="$HERE/disk.img"
MNT=/mnt/vanish-poly

# 1) отмонтировать точку, убрать пустой каталог
umount "$MNT" 2>/dev/null || true
rmdir "$MNT" 2>/dev/null || true

# 2) отсоединить ровно наш loop (найден по backing-файлу)
LO="$(losetup -j "$IMG" 2>/dev/null | cut -d: -f1 | head -1)"
if [ -n "${LO:-}" ]; then
  umount "$LO" 2>/dev/null || true
  if losetup -d "$LO" 2>/dev/null; then
    echo "[teardown] loop отсоединён: $LO"
  fi
fi

# 3) образ и временные артефакты
rm -f "$IMG"
rm -f /tmp/vanish_poly_loop
rm -rf /tmp/vanish_photorec /tmp/vanish_photorec_u
rm -f "$HOME/photorec.log" 2>/dev/null || true

# 4) отчистит ли дисковое пространство spot-check: образ не должен существовать
if [ -e "$IMG" ]; then echo "[teardown] ВНИМАНИЕ: не удалось удалить $IMG"; exit 1; fi

echo "[teardown] полигон разобран (loop/mnt/образ/артефакты)."
