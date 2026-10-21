#!/usr/bin/env bash
# build-release: продуктовая сборка vanish + (опц.) упаковщик UPX + манифест SHA256SUMS.
# Использование:   bash scripts/build-release.sh
# Результат:       dist/vanish + dist/SHA256SUMS
#
# Порядок (важен):
#   1) cargo test --workspace --release --locked; cargo build --release --locked
#   2) upx --best --lzma  (если установлен; иначе шаг пропускается с примечанием)
#   3) SHA-256 финального (уже упакованного) бинаря -> dist/SHA256SUMS
#      Манифест считается ПОСЛЕ упаковки, иначе --selfcheck упадёт.
# Проверка целостности:  dist/vanish --selfcheck   (коды 0/1/2/4)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DIST="$ROOT/dist"
BIN_SRC="$ROOT/target/release/vanish"

echo "[build] cargo test --workspace --release --locked…"
cargo test --workspace --release --locked
echo "[build] cargo build --release --locked…"
cargo build --release --locked

[ -x "$BIN_SRC" ] || { echo "[build] ОШИБКА: не найден $BIN_SRC"; exit 4; }

mkdir -p "$DIST"
cp -f "$BIN_SRC" "$DIST/vanish"
chmod +x "$DIST/vanish"

# 2) UPX только сжимает бинарь: это не шифрование и не подпись поставки.
#    Не обязателен: без него манифест честно описывает обычный бинарь.
if command -v upx >/dev/null 2>&1; then
  echo "[build] упаковка upx --best --lzma…"
  upx --best --lzma -q "$DIST/vanish"
else
  echo "[build] ПРИМЕЧАНИЕ: upx не установлен — бинарь остаётся неупакованным."
  echo "[build]   поставить: sudo pacman -S upx"
fi

# 3) манифест по ФАЙЛУ (в т.ч. если он упакован).
HASH="$(sha256sum "$DIST/vanish" | awk '{print $1}')"
printf '%s  vanish\n' "$HASH" > "$DIST/SHA256SUMS"

echo "[build] SHA-256 бинаря: $HASH"
echo "[build] артефакты в dist/:"
ls -la "$DIST"
echo "[build] проверьте целостность:  $DIST/vanish --selfcheck   (ожидаю rc=0)"
