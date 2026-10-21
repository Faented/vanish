//! Настройки прогона. Единственный источник параметров конвейера.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternChoice {
    /// случайный поток (ChaCha20) — по умолчанию и достаточно
    Random,
    /// нули — быстрее, половина полезности
    Zero,
    /// hex-байт 0x00..=0xFF
    Hex(u8),
    /// Гутман 35-проходный — только явно (legacy-носители)
    Gutmann,
}

impl Default for PatternChoice {
    fn default() -> Self {
        PatternChoice::Random
    }
}

#[derive(Debug, Clone)]
pub struct Options {
    /// всего проходов записи (при Gutmann игнорируется: там 35)
    pub passes: u8,
    pub pattern: PatternChoice,
    pub verify: bool,
    pub dry_run: bool,
    /// переименование в `.vanish-v1-*` перед wipe (по умолчанию true)
    pub rename: bool,
    /// per-file deallocate на SSD (punch-hole/SET_ZERO_DATA); `--no-trim` = false
    pub punch: bool,
    /// FITRIM на точке монтирования после прогона (root); `--trim`
    pub trim_mount: bool,
    pub accept_cow: bool,
    pub force_fs: bool,
    /// `--keep-streams`: не затирать ADS/xattr (по умолчанию затираем)
    pub keep_streams: bool,
    pub wipe_all_hardlinks: bool,
    /// Reserved: rejected until verified swap disabling/restoration is implemented.
    pub disable_swap_for_wipe: bool,
    pub no_preserve_root: bool,
    /// не спускаться в другие ФС при рекурсии
    pub xdev: bool,
    pub json: bool,
    pub report_file: Option<std::path::PathBuf>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            passes: 1,
            pattern: PatternChoice::Random,
            verify: false,
            dry_run: false,
            rename: true,
            punch: true,
            trim_mount: false,
            accept_cow: false,
            force_fs: false,
            keep_streams: false,
            wipe_all_hardlinks: false,
            no_preserve_root: false,
            xdev: false,
            json: false,
            report_file: None,
            disable_swap_for_wipe: false,
        }
    }
}

impl Options {
    /// Всего фактик проходов с учётом Gutmann.
    pub fn effective_passes(&self) -> u8 {
        match self.pattern {
            PatternChoice::Gutmann => 35,
            _ => self.passes.max(1),
        }
    }
}
