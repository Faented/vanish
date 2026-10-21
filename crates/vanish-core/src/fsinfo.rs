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
    /// Explicitly supported logical-deletion pipelines, not physical-erasure guarantees.
    /// COW filesystems still require explicit acceptance in `strategy::decide`.
    pub fn is_supported_pipeline(self) -> bool {
        matches!(
            self,
            FsKind::Ext4
                | FsKind::Xfs
                | FsKind::Vfat
                | FsKind::Exfat
                | FsKind::Btrfs
                | FsKind::Zfs
                | FsKind::Tmpfs
                | FsKind::Ramfs
        )
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
    /// Диагностическая сводка, не сертификат физического санитирования.
    pub fn protective_summary(&self) -> String {
        if self.encrypted == EncryptionState::Encrypted {
            "шифрованный том: на носителе шифротекст; ключевая рекомендация — уничтожение ключа"
                .into()
        } else if self.cow {
            "COW-ФС: старые блоки могут оставаться в снапшотах; перезапись на месте бессмысленна"
                .into()
        } else if self.fs.is_ram() {
            "RAM-ФС: логическое удаление; прежние копии в swap не исключены".into()
        } else if self.device_kind == DeviceKind::Ssd {
            "SSD: логическое удаление/deallocation; физическое санитирование не доказано".into()
        } else if self.device_kind == DeviceKind::Rotational {
            "HDD: логическая перезапись; журналы, копии и remapped-блоки не покрываются".into()
        } else {
            "носитель не классифицирован; физических гарантий нет".into()
        }
    }
}
