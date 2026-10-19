//! КОНТРАКТ (заморожен после M0 — см. docs/contract/):
//! платформенные бэкенды реализуют ТОЛЬКО эти трейты.
//! Ядро не знает ни одной платформенной детали (syscall/WinAPI).

use serde::Serialize;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use crate::error::Result;
use crate::fsinfo::VolumeInfo;
use crate::pattern::PatternStream;

/// Экстент файла: [logical, logical+len) внутри файла.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Extent {
    /// смещение в файле, байт
    pub logical: u64,
    /// длина, байт
    pub len: u64,
}

/// Процесс, держащий открытый дескриптор цели.
#[derive(Debug, Clone, Serialize)]
pub struct Opener {
    pub pid: u32,
    pub exe: String,
}

/// Своп-объект в системе.
#[derive(Debug, Clone, Serialize)]
pub struct SwapEntry {
    pub path: String,
    /// байтов
    pub size: u64,
}

/// Контекст одного целевого пути (переresolve'енный, без symlink).
#[derive(Debug, Clone)]
pub struct Target {
    /// абсолютный путь без ссылок
    pub abs: PathBuf,
    /// путь цели КАК ЗАДАН (не меняется после rename; для хэша отчёта)
    pub orig_abs: PathBuf,
    pub parent: PathBuf,
    pub name: OsString,
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    pub nlink: u32,
}

impl Target {
    pub fn from_parts(abs: PathBuf, dev: u64, ino: u64, size: u64, nlink: u32) -> Self {
        let parent = abs
            .parent()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/"));
        let name = abs
            .file_name()
            .map(OsStr::to_owned)
            .unwrap_or_else(|| OsString::from("/"));
        Target {
            orig_abs: abs.clone(),
            abs,
            parent,
            name,
            dev,
            ino,
            size,
            nlink,
        }
    }
}

/// Ручка открытого файла для wipe-движка (платформенно-непрозрачная).
pub trait WipeHandle: Send {
    /// (dev, ino) — сверка с Target.
    fn dev_ino(&self) -> (u64, u64);
    fn len(&self) -> Result<u64>;
    /// None = экстенты не поддержаны — пишем весь файл.
    fn extents(&self) -> Result<Option<Vec<Extent>>>;
    /// Генератор отвечает за содержимое буферов; ручка — за доставку [off, off+len).
    fn overwrite(&mut self, off: u64, len: u64, gen: &mut PatternStream) -> Result<()>;
    /// Прочитать [off, off+len) и сверить с тем же паттерном (детерминированный replay).
    fn verify(&mut self, off: u64, len: u64, gen: &mut PatternStream) -> Result<()>;
    fn sync(&self) -> Result<()>;
    /// Deallocate (пер-p TRIM на SSD); false = платформа не умеет (не фатально).
    fn punch(&mut self) -> Result<bool>;
    fn truncate0(&mut self) -> Result<()>;
    /// Выкинуть данные из кеша страниц (если писали без bypass-IO).
    fn dontneed(&self) -> Result<()>;
}

/// Платформенный API: всё, что ядро может попросить у ОС.
pub trait Platform: Send + Sync {
    fn name(&self) -> &'static str;

    /// Диагностика тома (probe/decision).
    fn fsinfo(&self, path: &Path) -> Result<VolumeInfo>;

    /// Процессы, держащие fd на (dev, ino); сам vanish исключается.
    fn openers(&self, dev: u64, ino: u64) -> Result<Vec<Opener>>;

    /// Открыть файловое handle (bypass-IO, когда возможно; O_RDWR с --verify).
    fn open_handle(&self, t: &Target) -> Result<Box<dyn WipeHandle>>;

    /// Расширенные хвостов-потоки (ADS на NTFS / xattr linux/mac): [(имя, байтов)].
    fn stream_names(&self, t: &Target) -> Result<Vec<(String, u64)>>;
    fn erase_stream(&self, t: &Target, name: &str) -> Result<()>;

    /// rename внутри того же каталога (сокрытие имени) → вернёт имя-хвост.
    fn rename_to_tail(&self, t: &Target) -> Result<String>;
    fn fsync_dir(&self, dir: &Path) -> Result<()>;
    /// Снять файл по имени в родителе `t`.
    fn unlink(&self, t: &Target, tail: &str) -> Result<()>;
    /// Снять пустой каталог по имени (после rename-hide).
    fn rmdir(&self, t: &Target, tail: &str) -> Result<()>;

    /// FITRIM точки монтирования; false = не выполнено (не root / не fs).
    fn trim_mount(&self, mount: &Path) -> Result<bool>;

    fn swap_active(&self) -> Result<Vec<SwapEntry>>;

    /// Найти хвостов recovery: файлы `.vanish-v1-*` под root (рекурсивно).
    fn find_tails(&self, root: &Path) -> Result<Vec<PathBuf>>;
}
