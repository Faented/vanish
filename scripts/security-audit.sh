#!/usr/bin/env bash
# security-audit: разовый (по желанию — в CI) аудит репозитория на утечки.
#   1) рабочее дерево — секретоподобные строки
#   2) вся история коммитов — то же (с исключением файлов-держателей паттернов)
#   3) крипо-крупняк: блобы > 5 МиБ в объектах
#   4) tracked-but-ignored: файлы, добавленные в git вопреки .gitignore
#   5) .gitignore покрывает критичные классы
# Выход: 0 = PASS, 1 = FAIL (печатает, где).

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

SECRET_RE='(-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|ghu_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|ghr_[A-Za-z0-9]{36}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|sk-[A-Za-z0-9]{32,})'
bad=0

echo "== 1) рабочее дерево: секретоподобные строки =="
scan_rc=0
HITS=$(grep -rIlE "$SECRET_RE" --exclude-dir=.git --exclude-dir=target \
       --exclude=security-audit.sh --exclude=pre-commit --exclude=.gitignore --exclude=.gitattributes .) || scan_rc=$?
if [ "$scan_rc" -gt 1 ]; then echo "FAIL: ошибка сканирования рабочего дерева"; bad=1; fi
if [ -n "$HITS" ]; then echo "FAIL — найдено в файле(ах):"; echo "$HITS"; bad=1; else echo "OK: 0 совпадений"; fi

echo "== 2) история коммитов: секретоподобные строки =="
b2=0
commits=$(git rev-list --all)
for sha in $commits; do
  scan_rc=0
  HITS=$(git grep -l -I -E "$SECRET_RE" "$sha" -- . \
    ':!.githooks/**' ':!scripts/security-audit.sh' ':!.gitignore' ':!.gitattributes') || scan_rc=$?
  if [ "$scan_rc" = 0 ]; then
    # Never print matching secret contents into CI logs.
    echo "FAIL: секретоподобные строки в истории:"; echo "$HITS"; b2=1
  elif [ "$scan_rc" -gt 1 ]; then
    echo "FAIL: ошибка чтения истории $sha"; b2=1
  fi
done
[ "$b2" = 0 ] && echo "OK: история чиста" || bad=1

echo "== 3) блобы > 5 МиБ в объектной базе =="
b3=0
objects=$(git rev-list --objects --all --no-object-names)
for o in $objects; do
  if ! s=$(git cat-file -s "$o"); then
    echo "FAIL: не удалось прочитать размер объекта $o"; b3=1; continue
  fi
  if [ "$s" -gt 5242880 ]; then echo "FAIL: объект $o = $s байт"; b3=1; fi
done
[ "$b3" = 0 ] && echo "OK: крупных объектов нет" || bad=1

echo "== 4) tracked-but-ignored (утечка мимо .gitignore) =="
TBI=$(git ls-files --cached --ignored --exclude-standard)
if [ -n "$TBI" ]; then echo "FAIL — в git, но должен был быть игнорирован:"; echo "$TBI"; bad=1; else echo "OK: таких нет"; fi

echo "== 5) .gitignore критичные классы =="
classes_ok=1
for pat in 'target' '.env' '\*.pem' '\*.key' '\*.img' '\*.log' '\.vanish-v1-'; do
  grep -q -- "$pat" .gitignore || { echo "ВНИМАНИЕ: в .gitignore нет класса '$pat'"; bad=1; classes_ok=0; }
done
[ "$classes_ok" = 0 ] || echo "OK: классы покрыты"

if [ "$bad" = 0 ]; then
  echo "=== SECURITY-AUDIT: PASS ==="
else
  echo "=== SECURITY-AUDIT: FAIL ==="; exit 1
fi
