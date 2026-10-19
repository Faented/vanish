//! vanish-core: платформо-независимое ядро защищённого удаления.
//!
//! Держит контракт (трейты `Platform`/`WipeHandle`), конвейеры, стратегию
//! решения, отчёты и инварианты. Не содержит ни одного syscall.

pub mod aligned;
pub mod check;
pub mod config;
pub mod error;
pub mod fsinfo;
pub mod pattern;
pub mod pipeline;
pub mod platform;
pub mod recovery;
pub mod report;
pub mod signal;
pub mod strategy;
pub mod util;
pub mod walk;

pub use error::{Result, VanishError};

/// Версия формата хвостов/отчёта.
pub const FORMAT_VERSION: &str = "v1";
/// Префикс имён-хвостов (recovery ищет это).
pub const TAIL_PREFIX: &str = ".vanish-v1-";
