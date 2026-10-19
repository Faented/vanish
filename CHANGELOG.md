# CHANGELOG

Формат Keep-a-Changelog, версии по плану M-фаз. Гарантии — из утверждённого `docs/PLAN.md`.

## v1.0-linux (2026-10-20)

Первый релиз vanish: кросс-платформенное защищённое удаление; Linux-бэкенд готов к бою.

### Возможности
- Конвейер wipe по PLAN §6: детект стратегии по ФС (`ext4/xfs` → overwrite; `btrfs` → отказ `cow_fs` без `--accept-cow`; tmpfs → `ram_unlink`, честные `bytes=0`; busy → отказ rc=3). По умолчанию 1 проход (`pattern zero/random`) — в ногу с NIST 800-88; опционально `--passes 3` + `--verify`, Gutmann/35 — по флагам.
- Переименование → tail (`.vanish-v1-<12hex>` от SHA-256 имени) перед unlink; отчёт `vanish.report.v1` без plaintext-имён (только `name_hash` либо tails).
- Режимы: `wipe/check/freespace/device/recovery/--recovery-scan`; флаги `--dry-run`, `--json`; коды выхода 0/1/2/3/4 (успех / partial / ошибка аргументов / отказ по reject-политике / внутренняя ошибка).
- Linux-специфика: O_DIRECT с падением в обычный fd, FIEMAP-экстенты, PUNCH_HOLE+FITRIM после wipe, BLKSECDISCARD→BLKDISCARD для device, детект busy по /proc, детект swap-подключения, dm-crypt/rotational-сообщения.
- Recovery-скан хвостов `.vanish-v1-*` (включая пустые tail-каталоги, рекурсивно).

### QA
- Юнит-батарея: 9/9 (FakePlatform, pipeline-инварианты: Gutmann-35, детерминированный ChaCha20-replay, отчёт без plaintext).
- M1 smoke-вердикт: PASS-с-замечаниями; замечание F-1 закрыто в этом же релизе (`--recovery-scan <путь>` честно пробрасывает цели).
- M3 root-полигон: loop-ext4 256 МиБ без журнала; свип 6/6 кейсов; детерминированный raw-оракул (0 маркеров `VANISH_ORACLE`, 0 plaintext-хвостов на устройстве); photorec 7.2 whole-скан: `Total: 0 files found`, на диске только служебный `report.xml`. Вердикт: PASS → релиз v1.0-linux.

### Известные ограничения v1.0
- Только Linux-бэкенд; Windows (M4) и macOS (M5) — планы v1.1/v1.2.
- ext4 С журналом: имена могут осесть в журнале; vanish v1.0 журнал не трогает (L3-граница, threat-model §5; полигон QA — ext4 без журнала).
- device-wipe проверен на loop-носители BLKDISCARD-путём; на физическом SSD прогонов не было.
- photorec 7.2 CLI не поддерживает `/wholeraw` — фаза B форезики запускается интерактивно.

### Технические фиксы этой версии
- F-3: `struct fiemap` приведена к ядерной раскладке (добавлено `fm_mapped_extents`); закрыт критический CPU-спин/рост RSS на реальном overwrite (ext4/loop); добавлен guard против непрогрессирующего `start`.
- F-4: в `verify()` чтение в отдельный выровненный O_DIRECT-буфер (устранён EINVAL на 4К-куске).
- F-1 (из M1): `--recovery-scan <путь>` честно пробрасывает цели.
