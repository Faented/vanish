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
    if v.fs.is_ram() {
        return Ok(Strategy::RamUnlink);
    }
    if v.cow || v.fs.is_cow() {
        if !o.accept_cow {
            return Err(VanishError::CowFs { fs: v.fs_name.clone() });
        }
        return Ok(Strategy::CowAccept);
    }
    if v.swap_sharing_fs && !o.disable_swap_for_wipe {
        return Err(VanishError::SwapActive);
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
