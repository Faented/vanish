# CHANGELOG

Формат Keep-a-Changelog, версии по плану M-фаз. Гарантии — из утверждённого `docs/PLAN.md`.

## Unreleased — исправления аудита

- Временно заблокировано исполнение `device`; dry-run остаётся read-only планом.
- SIGINT заканчивает текущий файл; исправляются обязательные sync/unlink,
  классификация verify-ошибок и учёт recovery/CLI failures.
- Устранены изменения целей при dry-run freespace и небезопасная перезапись
  существующего файла через `--report`; отчёт теперь должен быть новым файлом.
- Проверяется идентичность обоих Linux fd; исправлены short-read verification,
  обработка нулевой записи и fallback syncfs.
- Непроверенные ФС требуют override; неработающий swap-disable обход запрещён.
- Добавлены негативные тесты, CI и проверки git-барьеров. MSRV — Rust 1.85.
- Контракт кодов выхода ужесточён: `skipped` вне dry-run — partial (`1`);
  ошибка вывода/отчёта не может дать `code=0`; прерванный freespace удаляет
  скретч; ошибка `wipe_target` больше не оставляет временный файл.
- `--pattern hex` с `--passes > 16` отклоняется (`2`); `--size` допустим только
  для freespace; `--force-fs` больше не отключает защиту `/proc,/sys,/dev,/run`;
  удалён мёртвый `--yes`.
- Ядро требует абсолютные пути до rename; dry-run каталогов даёт план, а не
  ложное «каталог не пуст»; `bytes` — сумма перезаписанных extents; при
  `nlink > 1` выводится предупреждение, что другие имена не сняты (каскада нет).
- `check` стал per-entry диагностическим: ошибки FS/`/proc` дают предупреждение
  и «диагностика неполна», учитываются пользовательские `Options`, отказ
  политики не маскируется.
- Linux-бэкенд: FIEMAP с `FLAG_SYNC`, выровненный `repr(C)`-буфер, отказ на
  `SHARED/ENCODED/UNKNOWN/DATA_ENCRYPTED`, clamp `fm_length`; `RENAME_NOREPLACE`
  и валидация одного компонента; bounds перед overwrite/verify; punch/trim не
  маскируют EIO; `/proc/mounts` fail-closed с unescape и всеми bind-строками;
  не-UTF8 xattr отвергаются; XFS journal консервативно считается Active; нет
  паник на NUL в путях.
- Зависимости бэкендов стали target-specific; неиспользуемый `thiserror` удалён.
- Уточнение к исторической записи v1.0: recovery-tail — 16 случайных hex,
  не 12 hex от SHA-256 имени.
- Уточнены ограничения и отозваны универсальные обещания невосстановимости:
  см. `docs/security-hardening.md`. Нижеследующие записи — история, не текущая
  гарантия безопасности.

## v1.0-linux (2026-10-20)

Первый релиз vanish: кросс-платформенное защищённое удаление; Linux-бэкенд готов к бою.

### Возможности
- Конвейер wipe по PLAN §6: детект стратегии по ФС (`ext4/xfs` → overwrite; `btrfs` → отказ `cow_fs` без `--accept-cow`; tmpfs → `ram_unlink`, честные `bytes=0`; busy → отказ rc=3). По умолчанию 1 проход (`pattern zero/random`) — в ногу с NIST 800-88; опционально `--passes 3` + `--verify`, Gutmann/35 — по флагам.
- Переименование → tail (`.vanish-v1-<12hex>` от SHA-256 имени) перед unlink; отчёт `vanish.report.v1` без plaintext-имён (только `name_hash` либо tails).
- Режимы: `wipe/check/freespace/device/recovery/--recovery-scan`; флаги `--dry-run`, `--json`; коды выхода 0/1/2/3/4 (успех / partial / ошибка аргументов / отказ по reject-политике / внутренняя ошибка).
- Linux-специфика: O_DIRECT с падением в обычный fd, FIEMAP-экстенты, PUNCH_HOLE+FITRIM после wipe, BLKSECDISCARD→BLKDISCARD для device, детект busy по /proc, детект swap-подключения, dm-crypt/rotational-сообщения.
- Recovery-скан хвостов `.vanish-v1-*` (включая пустые tail-каталоги, рекурсивно).

### QA
- Юнит-батарея: 11/11 (FakePlatform: конвейер/инварианты Gutmann-35, детерминированный ChaCha20-replay, отчёт без plaintext; + selfcheck SHA-256-вектор и матрица ok/tamper/absent).
- M1 smoke-вердикт: PASS-с-замечаниями; замечание F-1 закрыто в этом же релизе (`--recovery-scan <путь>` честно пробрасывает цели).
- M3 root-полигон: loop-ext4 256 МиБ без журнала; свип 6/6 кейсов; детерминированный raw-оракул (0 маркеров `VANISH_ORACLE`, 0 plaintext-хвостов на устройстве); photorec 7.2 whole-скан: `Total: 0 files found`, на диске только служебный `report.xml`. Вердикт: PASS → релиз v1.0-linux.

### Сборка и крипто-целостность
- **Крипто-интегрити сборки**: `scripts/build-release.sh` — release-сборка + (опционально) упаковщик UPX (`--best --lzma`) + манифест `SHA256SUMS`, считаемый по финальному (уже упакованному) бинарю. Рантайм-проверка: `vanish --selfcheck [MANIFEST]` — пересчитывает SHA-256 живого exe и сверяет с манифестом. Коды: 0=verified, 1=tampered, 2=манифест не найден, 4=ошибка. Манифест ищется: аргумент → `VANISH_SHA256SUMS` → рядом с exe.

### Документация
- `README.md`: полный цикл сборки/упаковки + руководство пользователя (режимы wipe/check/freespace/device/recovery/selfcheck, флаги, коды выхода, политики отказа, приватность отчёта).

### Известные ограничения v1.0
- Только Linux-бэкенд; Windows (M4) и macOS (M5) — планы v1.1/v1.2.
- ext4 С журналом: имена могут осесть в журнале; vanish v1.0 журнал не трогает (L3-граница, threat-model §5; полигон QA — ext4 без журнала).
- device-wipe проверен на loop-носителе BLKDISCARD-путём; на физическом SSD прогонов не было.
- photorec 7.2 CLI не поддерживает `/wholeraw` — фаза B форезики запускается интерактивно.

### Технические фиксы этой версии
- F-3: `struct fiemap` приведена к ядерной раскладке (добавлено `fm_mapped_extents`); закрыт критический CPU-спин/рост RSS на реальном overwrite (ext4/loop); добавлен guard против непрогрессирующего `start`.
- F-4: в `verify()` чтение в отдельный выровненный O_DIRECT-буфер (устранён EINVAL на 4К-куске).
- F-1 (из M1): `--recovery-scan <путь>` честно пробрасывает цели.
