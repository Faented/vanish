# Task-brief 002 — core-dev (M1) — ВЫПОЛНЕНО оркестратором (проведено как core-фазa)
Артефакты: `crates/vanish-core/*`, `crates/vanish-cli/*` (каркас CLI + все режимы),
`crates/backend-linux/*` (ранняя реализация контракта), контракт: `docs/contract/*`.
DoD: cargo build/test проходят; юнит-тесты 9/9 (FakePlatform), smoke на машине
(tmpfs ram_unlink, btrfs coop, отказы busy/hardlink/COW, dry-run, --json, recovery,
freespace). Отклонения от плана: нет. Найходки зафиксированы в contract.md.

# Task-brief 003 — backend-linux (M2) — частично внутри 002 (syscalls: O_DIRECT,
FIEMAP, PUNCH_HOLE, FITRIM, BLKSECDISCARD/BLKDISCARD, /proc-детекты, dm-crypt uuid,
rotational, swaps, xattrs). Оставшееся: NVMe SANITIZE/CRYPTO_ERASE ioctl, LUKS
детект через dm uuid (сделан), `--wipe-ext4-journal` (после решения по №001).
