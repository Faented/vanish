# Контракт vanish-core v1 (заморожен после M0/M1)

## Трейты (ядро ↔ бэкенды)

Ядро (`vanish-core`) не содержит платформенных вызовов. Бэкенды реализуют:

```rust
pub trait Platform: Send + Sync {
    fn name(&self) -> &'static str;
    fn fsinfo(&self, path: &Path) -> Result<VolumeInfo>;
    fn openers(&self, dev: u64, ino: u64) -> Result<Vec<Opener>>;
    fn open_handle(&self, t: &Target) -> Result<Box<dyn WipeHandle>>;
    fn stream_names(&self, t: &Target) -> Result<Vec<(String, u64)>>;
    fn erase_stream(&self, t: &Target, name: &str) -> Result<()>;
    fn rename_to_tail(&self, t: &Target) -> Result<String>;
    fn fsync_dir(&self, dir: &Path) -> Result<()>;
    fn unlink(&self, t: &Target, tail: &str) -> Result<()>;
    fn rmdir(&self, t: &Target, tail: &str) -> Result<()>;
    fn trim_mount(&self, mount: &Path) -> Result<bool>;
    fn swap_active(&self) -> Result<Vec<SwapEntry>>;
    fn find_tails(&self, root: &Path) -> Result<Vec<PathBuf>>;
}

pub trait WipeHandle: Send {
    fn dev_ino(&self) -> (u64, u64);
    fn len(&self) -> Result<u64>;
    fn extents(&self) -> Result<Option<Vec<Extent>>>;   // None → не поддержан
    fn overwrite(&mut self, off: u64, len: u64, gen: &mut PatternStream) -> Result<()>;
    fn verify(&mut self, off: u64, len: u64, gen: &mut PatternStream) -> Result<()>;
    fn sync(&self) -> Result<()>;
    fn punch(&mut self) -> Result<bool>;                 // false = не поддержан
    fn truncate0(&mut self) -> Result<()>;
    fn dontneed(&self) -> Result<()>;
}
```

Ключевые семантики:
- `Target.orig_abs` — путь на момент подачи; после `rename_to_tail` меняется только
  `abs`/`name`. Хэши в отчёте считаются от `orig_abs` (инвариант 7).
- `PatternStream` — детерминированный replay: содержимое чанка №k зависит только
  от (seed, kind, pass, k); verify обязан восстановить ту же последовательность.
- `WipeHandle.overwrite/verify` вызываются поочерёдно по диапазонам экстентов;
  проход = `{ overwrite(range)…; sync(); verify? }` для каждого диапазона.
- `extents() = None` → пишем весь файл (0..len).
- Отказы: `Busy`, `HardLinks{n}`, `CowFs`, `UnsupportedFs`, `ReadOnlyMount`,
  `SwapActive`, `UnsafePath`, `IdentityMismatch`, `VerifyMismatch`, `Io`, `NotPermitted`.

## Порядок конвейера (§6 плана)

1. probe: `fsinfo` → `decide` (отказы этой фазы — до каких-либо изменений).
2. `openers` → занятость.
3. nlink>1 → отказ (без `--wipe-all-hardlinks`).
4. `rename_to_tail` (если `--rename`) + `fsync_dir`.
5. `open_handle` → сверка `dev_ino` == target (`IdentityMismatch` иначе).
6. потоков затирание (`erase_stream`) кроме `--keep-streams`.
7. Проходы записи: per pass, per extent — overwrite; `sync()`; verify (если `--verify`).
8. `punch()` при SSD/шифрованном (стратегия `overwrite_dealloc`).
9. `dontneed()`.
10. `truncate0()` → `sync()` → drop handle → `unlink/rmdir` → `fsync_dir`.
11. `trim_mount` только при `--trim`.

## Коды выхода

0 ok · 1 partial (ok>0 и rejected>0) · 2 usage · 3 все отклонены (busy/hardlink/COW/…) ·
4 любой IO/verify-fail.

## Отчёт `vanish.report.v1`

Схема: см. `docs/contract/report.v1.schema.json`. Запрещены plaintext исходные
имён — только `name_hash` (SHA-256 `%s` от orig-пути) и `tail` (имя-хвост).

## Real-полигон, зафиксированный при заморозке

- Текущая машина: Btrfs (/home, NVMe SSD) + tmpfs → покрываются
  `cow_accept`/`ram_unlink` + все ветки отказов; overwrite-ветки (HDD/SSD на ext4/xfs)
  проверены юнит-тестами FakePlatform, реально — до MCC2 root-полигона (loop-ext4).
