//! Единый тип ошибок vanish. Коды выхода CLI формируются из него.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum VanishError {
    #[error("несоответствие объекта после открытия (race/symlink): {0}")]
    IdentityMismatch(String),

    #[error("файл занят другим процессом (pid {pids:?})")]
    Busy { pids: Vec<u32> },

    #[error("файл имеет {nlink} жёстких ссылок; без --wipe-all-hardlinks отказ")]
    HardLinks { nlink: u32 },

    #[error("COW-ФС {fs} может иметь снапшоты; без --accept-cow отказ")]
    CowFs { fs: String },

    #[error("неподдерживаемая ФС/среда: {0}")]
    UnsupportedFs(String),

    #[error("небезопасный путь: {0}")]
    UnsafePath(String),

    #[error("перемонтированная read-only ФС")]
    ReadOnlyMount,

    #[error("своп активен на той же ФС/устройстве")]
    SwapActive,

    #[error("ввод-вывод: {0}")]
    Io(#[from] std::io::Error),

    #[error("верификация не прошла на смещении {offset}")]
    VerifyMismatch { offset: u64 },

    #[error("локальная ошибка: {0}")]
    Local(String),

    #[error("отказано пользователем/средой: {0}")]
    NotPermitted(String),
}

pub type Result<T> = std::result::Result<T, VanishError>;

/// Размер единицы ошибки идёт прямо в отчёт.
impl VanishError {
    /// Серверное имя для отчёта (строкой, без plaintext содержимого).
    pub fn kind(&self) -> &'static str {
        match self {
            VanishError::IdentityMismatch(_) => "identity_mismatch",
            VanishError::Busy { .. } => "busy",
            VanishError::HardLinks { .. } => "hard_links",
            VanishError::CowFs { .. } => "cow_fs",
            VanishError::UnsupportedFs(_) => "unsupported_fs",
            VanishError::UnsafePath(_) => "unsafe_path",
            VanishError::ReadOnlyMount => "read_only_mount",
            VanishError::SwapActive => "swap_active",
            VanishError::Io(_) => "io",
            VanishError::VerifyMismatch { .. } => "verify_mismatch",
            VanishError::Local(_) => "local",
            VanishError::NotPermitted(_) => "not_permitted",
        }
    }
}
