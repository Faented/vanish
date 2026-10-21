# Проверки исправлений аудита

Это протокол регрессионных проверок исходников, **не вердикт о физической
невосстановимости** и не замена испытаниям на отдельном носителе.

Локальный результат 2026-10-22: **95 Rust-тестов** проходят на Rust 1.85.0:
34 Linux backend, 10 core unit, 32 core integration, 4 CLI unit и 15 CLI
integration. **8 тестов Git-защит** также проходят. Release-прогон повторяет
набор (см. команды ниже); это не вердикт о физической невосстановимости.

## Воспроизводимые команды

```bash
cargo +1.85.0 test --workspace --locked
cargo test --workspace --release --locked
cargo build --release --locked
cargo fmt --all -- --check
python3 scripts/test-security.py
bash scripts/security-audit.sh
git diff --check
for script in scripts/*.sh .githooks/pre-commit tests/polygon/*.sh; do
    bash -n "$script" || exit
done
```

CI запускает Rust-проверки на 1.85.0 и stable и `cargo fmt --all -- --check`.
Локальные проверки не означают, что удалённый CI уже отработал.
`cargo clippy --workspace --all-targets --locked` также запускается при ручном
ревью, но пока выдаёт предупреждения; lint-clean статус не заявляется.
`cargo fmt --all -- --check` проходит после нормализации форматирования
workspace; это не заменяет проверку корректности.

## Что проверяют тесты

- CLI: сохранность целей при dry-run, совместный JSON/report, закрытый stdout,
  запрет существующего/вложенного/symlink report, приватные права отчёта,
  отказ missing/symlink/overlapping-целям, отсутствие scratch в freespace dry-run
  и после ошибки wipe, блокировка device без доступа к устройству, отказ
  subcommand-имени после цели вместо удаления, hex>16 и `--size` вне freespace.
- Fake Platform в `crates/vanish-core/tests/pipeline_fake.rs`: ошибки обязательных
  операций, отказ verify и sync до финального удаления, все экстенты и проходы
  текущего файла после сигнала, непродолжение следующих целей, recovery-ошибки,
  приватность сообщений, отказ относительных целей до rename, план dry-run для
  каталогов, per-entry диагностика `check` и учёт пользовательских Options.
- Linux backend: независимая проверка direct/buffered fd, подмена inode и типа,
  освобождение fd при ошибках, симлинки в компонентах пути, короткий/прерванный IO,
  EOF и нулевой прогресс, ошибки sync, переполнение диапазона, проход через
  search-only предков без требования read-доступа, отключённый
  destructive device API, консервативные диагностические отказы, FIEMAP
  flags/overflow, RENAME_NOREPLACE, NUL в путях, non-UTF8 xattr и errno-политика
  punch/trim.
- Core unit tests: allowlist ФС, невозможность обойти swap-политику фиктивным
  флагом, ошибки обхода дерева, повреждённый UTF-8 в манифесте selfcheck и
  отсутствие скрытого fallback для явно заданного манифеста.
- `scripts/test-security.py`: временные Git-репозитории, содержимое индекса при
  partial staging, вложенные секретные имена, rename, tracked-but-ignored,
  секрет в начальном коммите и отсутствие значений секретов в выводе.

Файловые фикстуры создаются в собственных временных каталогах. Тесты не
используют реальные блочные устройства и не требуют root. Для скриптов
полигона выполняются только синтаксические/изолированные проверки, а не
настоящие mount, mkfs, discard или forensic recovery.

## Что этим не доказано

Полная защита от конкурентной подмены namespace, корректность при любом
power-loss, отсутствие mmap/новых держателей, очистка shared extents и старых
журнальных/SSD-копий, реальные HDD/SSD, Windows/macOS и аутентичность поставки.
См. `docs/security-hardening.md` и `crates/backend-linux/SAFETY.md`.
