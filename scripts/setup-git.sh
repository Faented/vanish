#!/usr/bin/env bash
# setup-git.sh — локальная настройка git для репозитория (vanish или любой другой).
#
# Использование:
#   bash scripts/setup-git.sh                             # интерактивно: спросит name/email
#   bash scripts/setup-git.sh --name "Имя" --email "mail@host"
#   GIT_USER_NAME="Имя" GIT_USER_EMAIL="mail@host" bash scripts/setup-git.sh
#   bash scripts/setup-git.sh --help
#
# Что делает:
#   - задаёт user.name/user.email В ЛОКАЛЬНЫЙ конфиг этого репозитория
#     (глобальный ~/.gitconfig не затрагивается),
#   - прописывает безопасные базовые привычки (main, pull.rebase, colors,
#     autocrlf, diff.renames, whitespace),
#   - печатает итоговую локальную конфигурацию.
#
# Чего НЕ делает: не переписывает историю; старые коммиты со служебной
# идентичностью (vanish-orchestrator) остаются как есть. Новые коммиты
# пойдут уже с настроенной идентичностью.

set -euo pipefail

fatal() { echo "setup-git: ОШИБКА: $*" >&2; exit 2; }
info()  { echo "setup-git: $*"; }
usage() {
  cat <<'EOF'
Использование:
  bash scripts/setup-git.sh [--name "Имя"] [--email "mail@host"]
Прочее:
  - можно задать через env: GIT_USER_NAME / GIT_USER_EMAIL
  - без аргументов — интерактивный режим
  - настройки затрагивают ТОЛЬКО локальный конфиг репозитория
EOF
}

# --- определить корень репозитория (из текущего каталога или из расположения скрипта)
ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [ -z "$ROOT" ]; then
  ROOT="$(cd "$(dirname "$0")/.." 2>/dev/null && pwd || true)"
  git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1 || fatal "запуск вне git-репозитория"
fi
cd "$ROOT"

# --- разбор аргументов
NAME="${GIT_USER_NAME:-}"
EMAIL="${GIT_USER_EMAIL:-}"
while [ $# -gt 0 ]; do
  case "$1" in
    --name)  [ $# -ge 2 ] || fatal "--name требует значение";  NAME="${2}";  shift 2 ;;
    --email) [ $# -ge 2 ] || fatal "--email требует значение"; EMAIL="${2}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) fatal "неизвестный аргумент: $1" ;;
  esac
done

# --- интерактивный режим, если ничего не задано
if [ -z "$NAME" ] || [ -z "$EMAIL" ]; then
  if [ ! -t 0 ]; then
    fatal "stdin не терминал и имя/email не заданы (используйте --name/--email или env)"
  fi
  cur_name="$(git config user.name  2>/dev/null || true)"
  cur_mail="$(git config user.email 2>/dev/null || true)"
  [ -n "$NAME" ]  || { read -rp "Git user.name  [${cur_name:-нет}]: " v; NAME="${v:-$cur_name}"; }
  [ -n "$EMAIL" ] || { read -rp "Git user.email [${cur_mail:-нет}]: " v; EMAIL="${v:-$cur_mail}"; }
fi

# --- валидация
[ -n "$NAME" ]  || fatal "user.name не задан"
[ -n "$EMAIL" ] || fatal "user.email не задан"
case "$EMAIL" in *@*) ;; *) fatal "user.email без '@': '$EMAIL'" ;; esac

# --- применяем ТОЛЬКО локальный конфиг репо
git config user.name    "$NAME"
git config user.email   "$EMAIL"
git config init.defaultBranch main
git config pull.rebase  true
git config color.ui     auto
git config core.autocrlf input
git config diff.renames true
git config core.whitespace trailing-space,space-before-tab

# pre-commit-барьер утечек (если в репо есть .githooks)
if [ -d "$ROOT/.githooks" ]; then
  git config core.hooksPath .githooks
  info "подключены локальные хуки: .githooks"
fi

info "локальный конфиг настроен: $ROOT"
git config --local --list | sed 's/^/  /'
