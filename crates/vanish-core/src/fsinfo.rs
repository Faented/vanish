//! Описание носителя/ФС для диагностики.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FsKind {
    Ext4,
    Xfs,
    F2fs,
    Btrfs,
    Zfs,
    Tmpfs,
    Ramfs,
    Overlayfs,
    Nfs,
    Cifs,
    Fuse,
    Vfat,
    Exfat,
    Ntfs,
    Apfs,
    Hfs,
    Proc,
    Sysfs,
    Devfs,
    Other,
}

impl FsKind {
    /// («Поддержанная» ФС: конвейер wipe физически корректен.)
    pub fn is_supported_pipeline(self) -> bool {
        !matches!(self, FsKind::Nfs | FsKind::Cifs | FsKind::Fuse | FsKind::Overlayfs)
    }

    pub fn is_pseudo(self) -> bool {
        matches!(self, FsKind::Proc | FsKind::Sysfs | FsKind::Devfs)
    }

    pub fn is_ram(self) -> bool {
        matches!(self, FsKind::Tmpfs | FsKind::Ramfs)
    }

    pub fn is_cow(self) -> bool {
        matches!(self, FsKind::Btrfs | FsKind::Zfs)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceKind {
    Rotational,
    Ssd,
    Ram,
    Net,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptionState {
    Encrypted,
    NotEncrypted,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalState {
    Active,
    None,
    Unknown,
}

impl JournalState {
    pub fn to_str(self) -> &'static str {
        match self {
            JournalState::Active => "active",
            JournalState::None => "none",
            JournalState::Unknown => "unknown",
        }
    }
}

/// Что диагностировано на носителе для одного целевого пути.
#[derive(Debug, Clone, Serialize)]
pub struct VolumeInfo {
    pub fs: FsKind,
    pub fs_name: String,
    pub mount: String,
    pub device: Option<String>,
    pub device_kind: DeviceKind,
    pub encrypted: EncryptionState,
    pub journal: JournalState,
    pub cow: bool,
    pub ro_mount: bool,
    pub swap_sharing_fs: bool,
    pub swap_pages_possible: bool,
    pub ssd_chipoff_protected: bool,
}

impl VolumeInfo {
    /// Короткая человеческая формулировка гарантий на этом томе.
    pub fn protective_summary(&self) -> String {
        if self.encrypted == EncryptionState::Encrypted {
            "шифрованный том: на носителе шифротекст; ключевая рекомендация — уничтожение ключа".into()
        } else if self.cow {
            "COW-ФС: старые блоки могут оставаться в снапшотах; перезапись на месте бессмысленна".into()
        } else if self.fs.is_ram() {
            "RAM-ФС: unlink достаточно".into()
        } else if self.device_kind == DeviceKind::Ssd {
            "SSD без шифрования: лучшее достижимое; против chip-off гарантии нет".into()
        } else if self.device_kind == DeviceKind::Rotational {
            "HDD: однопроходная перезапись достаточна (NIST 800-88)".into()
        } else {
            "носитель не классифицирован; стратегия — лучшее достижимое".into()
        }
    }
}
