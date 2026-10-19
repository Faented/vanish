# QA-вердикт vanish v0.1 smoke (M1)

- **Дата:** 2026-10-20
- **QA-агент:** независимый (свежий контекст, subagent); проверялось поведение бинарника; исходный код просматривался только для диагноза находки F-1 и для матрицы инвариантов §14.
- **Бинарник:** `/home/qurumnie/afpp/vanish/target/release/vanish` (build 2026-10-20 01:06, не пересобирался).
- **Env:** `/tmp/opencode` — tmpfs (RAM-ФС: стратегия `ram_unlink`, honest `bytes=0`); `/home/qurumnie/afpp/vanish/tests/_scratch` — Btrfs/NVMe (подтверждено детектором ФС продукта: `cow_fs: COW-ФС Btrfs`); root-доступа нет (raw-device wipe, strace-сценарии, swap-off — недоступны).
- **Полигоны строго ограничены:** `/tmp/opencode/qa1*`, `/tmp/opencode/qa2*`, `tests/_scratch/cowtest`, `docs/qa/qa-verdict-m1-smoke.md`, `/tmp/opencode/qa1-out.json`.

---

## 1. Протокол батареи

| # | Команда | Ожидание | Факт | Статус |
|---|---------|----------|------|--------|
| 1 | `mkdir -p /tmp/opencode/qa1/sub`; 5 файлов 84К random `f{1..5}.bin`; `sub/g.bin` 8К random; `os.setxattr(f1.bin,'user.notes',b'abv')`; `ln -f f2.bin link2.bin` | корпус создан | создано; `f2.bin nlink=2`, `link2.bin nlink=2`; xattr записан | **OK** |
| 2 | `vanish --dry-run /tmp/opencode/qa1` | код 0; файлы на месте | rc=0; все 9 целей `skipped (dry-run)`; `ls` = 7 записей, ничего не удалено | **OK** |
| 3 | `vanish --json /tmp/opencode/qa1 > /tmp/opencode/qa1-out.json; echo $?` | код выхода; `schema=="vanish.report.v1"`; plaintext имён = 0; link2 → rejected(reason=hard_links) | rc=**1** (ok=6, rejected=2, skipped=1; по полу выхода: rejected>0∧ok>0 → 1 «partial»); `schema="vanish.report.v1"`; grep имён f1..f5/link2/sub/g.bin и абсолютных путей по JSON = **0 совпадений**; **два** события rejected с `reason: "hard_links: файл имеет 2 жёстких ссылок; без --wipe-all-hardlinks отказ"` — по одному на каждое имя (f2.bin, link2.bin) связки с nlink=2 | **OK** |
| 4 | остатки после (3) | f1, f3, f4, f5, sub/g.bin отсутствуют; f2.bin+link2.bin живут (nlink=2); хвостов нет | `ls /tmp/opencode/qa1` = только `f2.bin`, `link2.bin` (оба nlink=2); f1/f3/f4/f5/g.bin отсутствуют; `find -name '.vanish-v1-*'` → пусто | **OK** |
| 5 | `head -c 1000 /dev/urandom > busy.bin`; python3 держит fd открытым (`time.sleep(40)`, background); сразу `vanish /tmp/opencode/qa1/busy.bin`; затем `pkill -f "qa1/busy.bin"` | код 3; текст содержит «busy» и pid | rc=**3**; `[rejected] … Some("busy: файл занят другим процессом (pid [152587])")`; busy.bin не тронут (size=1000 сохранён после); python убит по pid | **OK** |
| 6а | `mkdir -p /tmp/opencode/qa2/d1`; `d1/data.bin` 4096 random; `vanish /tmp/opencode/qa2` | код 0 | rc=0, ok=3 (файл + 2 каталога); qa2 удалён целиком (`find: No such file or directory`) | **OK** |
| 6б | хвост-артефакт: `mkdir -p /tmp/opencode/qa2/rescue && head -c 3000 /dev/urandom > /tmp/opencode/qa2/rescue/.vanish-v1-deadbeefdeadbeef`; `vanish --recovery-scan /tmp/opencode/qa2` | код 0 и хвост исчез (find) | rc=0, но «найдено хвостов-файлов: **0**»; хвост **остался** (find подтверждает). Дополнительные замеры: скан не находит хвост даже на верхнем уровне корня и при прямом скане каталога-родителя. Контроль той же механики через субкоманду: `vanish recovery /tmp/opencode/qa2` → «найдено хвостов-файлов: 1», `[ok] db61f0ae2dc0`, хвост удалён, rc=0 | **FAIL → F-1** |
| 7 | `vanish /home/qurumnie/afpp/vanish/tests/_scratch/cowtest` (Btrfs, 1 МБ файл) → затем `vanish --accept-cow …` | код 3 и «cow_fs»; затем код 0, каталог удалён | rc=**3**, `reason: "cow_fs: COW-ФС Btrfs может иметь снапшоты; без --accept-cow отказ"`; `--accept-cow` → rc=0, ok=2, каталог удалён (в `_scratch` нет `cowtest`) | **OK** |
| 8 | `vanish check /tmp/opencode/qa1`; `vanish freespace /tmp/opencode/qa1 --size 2000000`; find qa1 | батарея ожидала exists=false; код 0; «find → пусто» | `check`: rc=0, `exists=true kind=dir verdict=RAM-ФС: unlink достаточно`, swap: /dev/zram0 32010 МБ; `freespace`: rc=0, «бюджет 1 МБ (из доступных 15953)», ok=1; хвостов после freespace нет. Факт `exists=true` и наличие f2.bin/link2.bin/busy.bin несовместимы с буквой ожидания пункта, но согласованы с п.4 (связку сохранить) и п.5 (busy.bin оставить) — ожидание батареи внутренне противоречиво → **F-2** (к батарее, не к продукту) | **OK (замечание F-2)** |
| 9 | `command -v photorec testdisk` | отсутствуют: not_available_in_env | оба rc=1, не найдены — зафиксировано | **OK** (информативно) |
| 10 | `cd /home/qurumnie/afpp/vanish && cargo test --release 2>&1 \| grep "test result"` | n passed | итого по 10 крейтам: **9 passed; 0 failed** (все 9 — suite pipeline, например `pipeline_gutmann_35_passes_distinct`); остальные крейты — 0 тестов в release-прогоне | **OK** |

**Счёт батареи: 9 OK / 1 FAIL (пункт 6б).**

---

## 2. Гигиена артефактов

- **plaintext-check отчёта:** `/tmp/opencode/qa1-out.json` — нет ни одного исходного имени (`f1.bin`…`f5.bin`, `link2.bin`, `sub`, `g.bin`, `busy.bin`, `rescue`) и ни одного абсолютного пути (`/tmp/opencode`, `/home/`): grep = 0. Имена только SHA-256 (`name_hash`) либо `.vanish-v1-*` (tails). stderr боевого прогона пуст. ✔
- **Структура JSON:** все обязательные поля схемы v1 присутствуют (`schema, started_ms, finished_ms, code, ok, skipped, rejected, failed, bytes, targets, notes`); в targets — kind/name_hash/status/bytes/warnings/elapsed_ms; `guarantees` заполнен для стратегий ≠ null (`ssd_chipoff_protected=false`, `swap_pages_possible=true` — честно для tmpfs). ✔
- **Хвост-чек:** после всех прогонов `find /tmp/opencode/qa1 /tmp/opencode/qa2 /home/qurumnie/afpp/vanish/tests/_scratch -name '.vanish-v1-*'` → **0 хвостов** (dry-run, wipe, busy-отказ, freespace, cowtest). Тестовый хвост из п.6 был удалён только субкомандой `recovery` (см. F-1). ✔
- **Отказ без частичного стирания:** busy.bin и cowtest/f1.bin после отказов не модифицированы (размер сохранён). ✔
- `bytes: 0` для `ram_unlink`/`cow_accept` — честный (в схеме описано: «0 если стратегия не пишет»).

## 3. Инвариант-матрица §14 (PLAN.md)

| Инвариант | Как проверен здесь | Вердикт |
|-----------|--------------------|---------|
| 1. Никаких временных файлов вне `.vanish-v1-*` (и recovery-скан их находит) | Прогонами (dry-run/wipe/cow/freespace): чужих временных имён не появлялось; после каждого прогона хвостов 0. НО скан по флагу `--recovery-scan <путь>` молча игнорирует путь (F-1) — «находит» не гарантирован | **ЧАСТИЧНО** (гигиена OK; флаг recovery дефектен — F-1) |
| 2. Нет содержимого целевого файла в логах/stdout/stderr/отчёте | grep plaintext (имена, пути) по JSON и stderr → 0 | **OK** |
| 3. Нет `mmap` целевого; только `open_direct` + `pwrite`/`pread` | Напрямую не проверено (нет root/strace-сценария); в данной среде все успешные прогоны — `ram_unlink`/`cow_accept`, записи не было (bytes=0) | **НЕ ПРОВЕРЕН → M3** |
| 4. `unlink` только после полного fsync+verify всех проходов | Косвенно: отказные сценарии ничего не стирали; удаления на tmpfs — по ram_unlink-дизайну (данные исчезают с инодой). Реальной записи с verify не было (bytes=0 всюду) | **ЧАСТИЧНО → M3** |
| 5. `nlink>1` → отказ с кодом 3; каскад только `--wipe-all-hardlinks` | Напрямую: 2 события `reason hard_links`, оба имени живут с nlink=2, каскада не было | **OK** |
| 6. Файл открыт другим процессом / mmap'лен → отказ rc=3, предупреждение | Напрямую: rc=3, `busy: …(pid [152587])`, файл цел | **OK** |
| 7. Отчёт без plaintext имён (только хэш или `.vanish-v1-*`) | Напрямую (см. §2) | **OK** |
| 8. rc=4 при неполной записи/неудачном fsync | Не воспроизводимо в среде (нет root, нет блочных устройств, fsync не падает штатно) | **НЕ ПРОВЕРЕН → M3** |
| 9. QA-вердикт PASS обязателен перед релизом | Настоящий файл | **OK** (процесс выполнен) |

## 4. Ограничения и не-проверенное

- **Forensics-оракул (photorec/testdisk) отсутствует в env** (`not_available_in_env`) → маркерный-оракул форезики на raw-device НЕ выполнен. Требуется root-полигон (loop-ext4/img) в **M3**: device-wipe и rc=4-путь, честность перезаписи при GC/SSR, verify-проходы, strace-проверка инварианта 3 (нет mmap).
- Все успешные удаления в этой батарее — `ram_unlink` (tmpfs) или `cow_accept` (Btrfs): реальный overwrite-конвейер (`--passes/--pattern/--verify`) в этой батарее не проверен (в отчётах `bytes=0` — не «успех без работы», а честная стратегия ФС).
- Каскадное удаление связки `--wipe-all-hardlinks` не проверялось (вне объёма батареи M1).

## 5. Итог

## ИТОГОВЫЙ ВЕРДИКТ: **PASS-с-замечаниями**

M1-smoke в целом проходит: честные отказы (hard_links / cow_fs / busy), отсутствие plaintext в отчёте, гигиена хвостов, recovery-механизм через субкоманду, тесты 9/9 passed. Одна существенная находка (F-1) делает флаг `--recovery-scan` бесполезным и потенциально опасным (тихий ложный успех) — обязательна к устранению до приёмки recovery в M3.

### Находки

| ID | Приоритет | Описание |
|----|-----------|----------|
| **F-1** | **HIGH** | `vanish --recovery-scan <путь>` молча игнорирует переданный путь и сканирует CWD процесса. Диагноз (исключительно read-only): main.rs, ветка `recovery_scan` вызывает `recovery_mode(Vec::new(), …)`, внутри которого пустые roots заменяются текущим каталогом. Замер: при живом хвосте `/tmp/opencode/qa2/rescue/.vanish-v1-deadbeefdeadbeef` (3000 Б) и даже при хвосте на верхнем уровне сканируемого корня — rc=**0**, «найдено хвостов-файлов: 0», хвост остаётся. Ожидание: rc=0 и хвост удалён. Опасность: false-confidence — тихий успех без работы (нарушение духа инварианта 1 «recovery-скан их находит»). Обход, проверенный в батарее: субкоманда `vanish recovery <путь>` работает корректно («найдено хвостов-файлов: 1», `[ok] db61f0ae2dc0`, хвост удалён). Требуется проброс целей в ветке флага; фикс до приёмки recovery в M3. |
| **F-2** | INFO (к батарее M1, не к продукту) | Пункт 8 ожидает `check /tmp/opencode/qa1 → exists=false` и «find qa1 → пусто», но пункты 4 и 5 этой же батареи легитимно сохраняют в qa1 `f2.bin`+`link2.bin` (nlink=2) и `busy.bin`. Продукт отвечает `exists=true` и эти файлы не трогает — противоречие внутри самой батареи; поведение продукта согласовано с инвариантами 5/6. Для будущих батарей: check выполнять по отдельному пути. |
| **F-3** | INFO | photorec/testdisk отсутствуют в среде → форезика-оракул на raw-device не выполнен; закрывается root-полигоном loop-ext4 в M3 (см. §4). |

## Пост-вердиктная обработка (оркестратор, та же сессия)
- **F-1 (HIGH) — ИСПРАВЛЕН:** ветка флага `--recovery-scan` в `crates/vanish-cli/src/main.rs`
  теперь пробрасывает `cli.targets` в `recovery_mode`. Регресс-тест оркестратора:
  `vanish --recovery-scan /tmp/opencode/qa2` → «найдено хвостов-файлов: 1», хвост удалён,
  `find … -name '.vanish-v1-*' | wc -l` == 0, rc=0. Свежий бинарник пересобран.
- **F-3 отложен** на MW-M3-полигон (root + loop-ext4 + photorec/testdisk) — вопрос вынесен
  пользователю.
