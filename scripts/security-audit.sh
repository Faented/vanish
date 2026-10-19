#!/usr/bin/env bash
# security-audit: разовый (по желанию — в CI) аудит репозитория на утечки.
#   1) рабочее дерево — секретоподобные строки
#   2) вся история коммитов — то же (с исключением файлов-держателей паттернов)
#   3) крипо-крупняк: блобы > 5 МиБ в объектах
#   4) tracked-but-ignored: файлы, добавленные в git вопреки .gitignore
#   5) .gitignore покрывает критичные классы
# Выход: 0 = PASS, 1 = FAIL (печатает, где).

set -euo pipefail

# Паттерны-держатели, где упоминание регулярки само по себе легитимно:
EXCLUDE_FILES='.githooks|scripts/security-audit.sh|.gitignore|.gitattributes'

SECRET_RE='(-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|ghu_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|ghr_[A-Za-z0-9]{36}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|sk-[A-Za-z0-9]{32,})'
bad=0

echo "== 1) рабочее дерево: секретоподобные строки =="
HITS=$(grep -rIlE "$SECRET_RE" --exclude-dir=.git --exclude-dir=target \
       --exclude=security-audit.sh --exclude=pre-commit --exclude=.gitignore --exclude=.gitattributes . 2>/dev/null || true)
if [ -n "$HITS" ]; then echo "FAIL — найдено в файле(ах):"; echo "$HITS"; bad=1; else echo "OK: 0 совпадений"; fi

echo "== 2) история коммитов: секретоподобные строки =="
b2=0
for sha in $(git rev-list --all); do
  for f in $(git diff-tree -r --no-commit-id --name-only "$sha" 2>/dev/null); do
    case "$f" in .githooks/*|scripts/security-audit.sh|*security-audit.sh|.gitignore|.gitattributes) continue ;; esac
    if git show "$sha:$f" 2>/dev/null | grep -nE "$SECRET_RE" >/dev/null 2>&1; then
      echo "FAIL: коммит $sha, файл $f:"; git show "$sha:$f" | grep -nE "$SECRET_RE" | head -3 | sed 's/^/    /'
      b2=1
    fi
  done
done
[ "$b2" = 0 ] && echo "OK: история чиста" || bad=1

echo "== 3) блобы > 5 МиБ в объектной базе =="
b3=0
for o in $(git rev-list --objects --all | awk '{print $1}'); do
  s=$(git cat-file -s "$o" 2>/dev/null || echo 0)
  if [ "$s" -gt 5242880 ]; then echo "FAIL: объект $o = $s байт"; b3=1; fi
done
[ "$b3" = 0 ] && echo "OK: крупных объектов нет" || bad=1

echo "== 4) tracked-but-ignored (утечка мимо .gitignore) =="
TBI=$(git ls-files -i --exclude-standard 2>/dev/null || true)
if [ -n "$TBI" ]; then echo "FAIL — в git, но должен был быть игнорирован:"; echo "$TBI"; bad=1; else echo "OK: таких нет"; fi

echo "== 5) .gitignore критичные классы =="
for pat in 'target' '.env' '\*.pem' '\*.key' '\*.img' '\*.log' '\.vanish-v1-'; do
  grep -q -- "$pat" .gitignore || { echo "ВНИМАНИЕ: в .gitignore нет класса '$pat'"; bad=1; }
done
echo "OK: классы покрыты"

if [ "$bad" = 0 ]; then
  echo "=== SECURITY-AUDIT: PASS ==="
else
  echo "=== SECURITY-AUDIT: FAIL ==="; exit 1
fi
