//! Стратегия удаления: решение из VolumeInfo + Options.
//! Честный отказ лучше иллюзии защищённости.

use crate::config::Options;
use crate::error::{Result, VanishError};
use crate::fsinfo::{EncryptionState, VolumeInfo};

/// Человекочитаемое имя стратегии для отчёта.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// HDD-объём: перезапись N проходов
    HddOverwrite,
    /// SSD/шифрованный: перезапись + dealloc (punch-hole)
    OverwriteDealloc,
    /// RAM-ФС
    RamUnlink,
    /// COW-ФС (--accept-cow): truncate+unlink, перезапись бессмысленна
    CowAccept,
}

impl Strategy {
    pub fn to_str(self) -> &'static str {
        match self {
            Strategy::HddOverwrite => "hdd_overwrite",
            Strategy::OverwriteDealloc => "overwrite_dealloc",
            Strategy::RamUnlink => "ram_unlink",
            Strategy::CowAccept => "cow_accept",
        }
    }

    pub fn do_overwrite(self) -> bool {
        !matches!(self, Strategy::RamUnlink | Strategy::CowAccept)
    }

    pub fn do_punch(self) -> bool {
        self == Strategy::OverwriteDealloc
    }
}

/// Валидация цели против стратегии/опций. Отказ формируется здесь.
pub fn decide(_kind_is_file: bool, v: &VolumeInfo, o: &Options) -> Result<Strategy> {
    if v.fs.is_pseudo() {
        return Err(VanishError::UnsupportedFs(format!("{:?}", v.fs)));
    }
    if !v.fs.is_supported_pipeline() && !o.force_fs {
        return Err(VanishError::UnsupportedFs(format!("{:?}", v.fs)));
    }
    if v.ro_mount {
        return Err(VanishError::ReadOnlyMount);
    }
    // This option used to bypass the policy without actually disabling swap.
    // Until a verified swap lifecycle exists, never treat it as protection.
    if o.disable_swap_for_wipe {
        return Err(VanishError::NotPermitted(
            "--disable-swap-for-wipe is unavailable; disable swap externally and retry".into(),
        ));
    }
    if v.swap_sharing_fs {
        return Err(VanishError::SwapActive);
    }
    if v.fs.is_ram() {
        return Ok(Strategy::RamUnlink);
    }
    if v.cow || v.fs.is_cow() {
        if !o.accept_cow {
            return Err(VanishError::CowFs {
                fs: v.fs_name.clone(),
            });
        }
        return Ok(Strategy::CowAccept);
    }
    let ssd_like = matches!(v.device_kind, crate::fsinfo::DeviceKind::Ssd)
        || v.encrypted == EncryptionState::Encrypted;
    if ssd_like {
        Ok(Strategy::OverwriteDealloc)
    } else if v.device_kind == crate::fsinfo::DeviceKind::Rotational {
        Ok(Strategy::HddOverwrite)
    } else {
        // неизвестный носитель: лучшее достижимое — перезапись + dealloc
        Ok(Strategy::OverwriteDealloc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsinfo::{DeviceKind, FsKind, JournalState};

    fn volume(fs: FsKind) -> VolumeInfo {
        VolumeInfo {
            fs,
            fs_name: format!("{fs:?}"),
            mount: "/fixture".into(),
            device: None,
            device_kind: DeviceKind::Rotational,
            encrypted: EncryptionState::NotEncrypted,
            journal: JournalState::None,
            cow: fs.is_cow(),
            ro_mount: false,
            swap_sharing_fs: false,
            swap_pages_possible: false,
            ssd_chipoff_protected: false,
        }
    }

    #[test]
    fn unknown_and_unvalidated_filesystems_require_override() {
        let mut opts = Options::default();
        for fs in [FsKind::Other, FsKind::F2fs, FsKind::Apfs, FsKind::Overlayfs] {
            let v = volume(fs);
            assert!(matches!(
                decide(true, &v, &opts),
                Err(VanishError::UnsupportedFs(_))
            ));
            opts.force_fs = true;
            assert!(decide(true, &v, &opts).is_ok());
            opts.force_fs = false;
        }
    }

    #[test]
    fn swap_policy_applies_before_ram_or_cow_shortcuts() {
        let mut opts = Options {
            accept_cow: true,
            ..Options::default()
        };
        for fs in [FsKind::Ext4, FsKind::Tmpfs, FsKind::Btrfs] {
            let mut v = volume(fs);
            v.swap_sharing_fs = true;
            assert!(matches!(
                decide(true, &v, &opts),
                Err(VanishError::SwapActive)
            ));
            opts.disable_swap_for_wipe = true;
            assert!(matches!(
                decide(true, &v, &opts),
                Err(VanishError::NotPermitted(_))
            ));
            opts.disable_swap_for_wipe = false;
        }
    }

    #[test]
    fn overrides_do_not_allow_pseudo_or_read_only_filesystems() {
        let opts = Options {
            force_fs: true,
            ..Options::default()
        };
        assert!(matches!(
            decide(true, &volume(FsKind::Proc), &opts),
            Err(VanishError::UnsupportedFs(_))
        ));
        let mut v = volume(FsKind::Ext4);
        v.ro_mount = true;
        assert!(matches!(
            decide(true, &v, &opts),
            Err(VanishError::ReadOnlyMount)
        ));
    }
}
