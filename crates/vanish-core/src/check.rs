//! `vanish check`: диагностика пути БЕЗ записи. Всё read-only.
//! Diagnostic reports intentionally include volume/device paths and opener
//! details; they do not share the wipe report's hashed-name privacy contract.

use serde::Serialize;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use crate::config::Options;
use crate::error::Result;
use crate::fsinfo::{DeviceKind, EncryptionState, JournalState, VolumeInfo};
use crate::platform::{Opener, Platform, SwapEntry};
use crate::strategy::{decide, Strategy};

#[derive(Debug, Serialize)]
pub struct CheckEntry {
    pub name_hash: String,
    pub exists: bool,
    pub kind: String,
    pub size: Option<u64>,
    pub nlink: Option<u32>,
    pub volume: Option<VolumeInfo>,
    pub openers: Vec<Opener>,
    pub hardlink_refusal: bool,
    /// Highest sanitization level this path could reach with the given Options.
    pub guarantee_ceiling: String,
    pub guarantee_notes: Vec<String>,
    pub verdict: String,
}

#[derive(Debug, Serialize)]
pub struct CheckReport {
    pub backend: &'static str,
    pub swap: Vec<SwapEntry>,
    pub entries: Vec<CheckEntry>,
}

/// Собрать диагностику по списку путей.
///
/// Per-path failures are reported inside the entry instead of aborting the whole
/// report: `check` is diagnostic and must stay usable when, for example, another
/// user's `/proc/<pid>/fd` is unreadable. A global swap query failure still
/// fails the report (there is no entry to attach it to).
pub fn run(
    plat: &dyn Platform,
    paths: &[std::path::PathBuf],
    opts: &Options,
) -> Result<CheckReport> {
    let mut entries = Vec::new();
    for p in paths {
        match check_one(plat, p, opts) {
            Ok(entry) => entries.push(entry),
            Err(error) => entries.push(CheckEntry {
                name_hash: crate::util::name_sha256(p),
                exists: false,
                kind: "error".into(),
                size: None,
                nlink: None,
                volume: None,
                openers: Vec::new(),
                hardlink_refusal: false,
                guarantee_ceiling: "none".into(),
                guarantee_notes: Vec::new(),
                verdict: format!("проверка не удалась: {}: {}", error.kind(), error),
            }),
        }
    }
    let swap = plat.swap_active()?;
    Ok(CheckReport {
        backend: plat.name(),
        swap,
        entries,
    })
}

fn check_one(plat: &dyn Platform, p: &Path, opts: &Options) -> Result<CheckEntry> {
    let mut e = CheckEntry {
        name_hash: crate::util::name_sha256(p),
        exists: false,
        kind: "missing".into(),
        size: None,
        nlink: None,
        volume: None,
        openers: Vec::new(),
        hardlink_refusal: false,
        guarantee_ceiling: "none".into(),
        guarantee_notes: Vec::new(),
        verdict: String::new(),
    };
    let md = match std::fs::symlink_metadata(p) {
        Ok(m) => m,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            e.verdict = "нет такой цели; удалять нечего".into();
            return Ok(e);
        }
        Err(error) => return Err(error.into()),
    };
    e.exists = true;
    if md.is_symlink() {
        e.kind = "symlink".into();
        e.verdict = "symlink; not followed".into();
        return Ok(e);
    }
    if !md.is_dir() && !md.is_file() {
        e.kind = "special".into();
        e.verdict = "отказ: не обычный файл или каталог; не затираем".into();
        return Ok(e);
    }
    let mut refusals = Vec::new();
    let mut warnings = Vec::new();
    let (dev, ino, nlink) = (md.dev(), md.ino(), md.nlink());
    if md.is_dir() {
        e.kind = "dir".into();
        e.guarantee_ceiling = "G0".into();
        e.guarantee_notes
            .push("каталог: удаляется только имя; содержимое обрабатывается отдельно".into());
    } else {
        e.kind = "file".into();
        e.size = Some(md.len());
        e.nlink = Some(nlink as u32);
        if nlink > 1 {
            e.hardlink_refusal = true;
            refusals.push(format!(
                "nlink={}; откажется без --wipe-all-hardlinks",
                nlink
            ));
        }
    }
    let volume = match plat.fsinfo(p) {
        Ok(volume) => Some(volume),
        Err(error) => {
            warnings.push(format!("fsinfo недоступен: {}", error.kind()));
            None
        }
    };
    let mut plan: Option<Strategy> = None;
    if let Some(volume) = &volume {
        match decide(md.is_file(), volume, opts) {
            Ok(strategy) => plan = Some(strategy),
            Err(error) => refusals.push(format!("{}: {}", error.kind(), error)),
        }
        if md.is_file() {
            e.guarantee_ceiling = ceiling_for(plan, volume).into();
            if matches!(volume.journal, JournalState::Active) {
                e.guarantee_notes
                    .push("журнал ФС может сохранять имена и метаданные".into());
            }
            if matches!(plan, Some(Strategy::CowAccept)) {
                e.guarantee_notes
                    .push("COW/снапшоты: старые блоки не гарантированно уничтожены".into());
            }
            if matches!(plan, Some(Strategy::RamUnlink)) {
                e.guarantee_notes
                    .push("RAM-ФС: физическая чистка носителя этим режимом не доказана".into());
            }
            if matches!(volume.device_kind, DeviceKind::Ssd) {
                e.guarantee_notes
                    .push("SSD/FTL: физическое санирование чипом не доказано".into());
            }
            if matches!(volume.encrypted, EncryptionState::Encrypted) {
                e.guarantee_notes
                    .push("шифрование тома не равнозначно crypto-erase ключей".into());
            }
        }
    }
    match plat.openers(dev, ino) {
        Ok(openers) => {
            if !openers.is_empty() {
                refusals.push(format!(
                    "открыт процессами {:?}; откажется",
                    openers.iter().map(|o| o.pid).collect::<Vec<_>>()
                ));
            }
            e.openers = openers;
        }
        Err(error) => warnings.push(format!(
            "не удалось проверить открытые дескрипторы: {}",
            error.kind()
        )),
    }
    e.verdict = if !refusals.is_empty() {
        let mut verdict = format!("отказ: {}", refusals.join("; "));
        if !warnings.is_empty() {
            verdict.push_str(&format!("; предупреждения: {}", warnings.join("; ")));
        }
        verdict
    } else if !warnings.is_empty() {
        format!("диагностика неполна: {}", warnings.join("; "))
    } else {
        match &volume {
            Some(volume) => volume.protective_summary(),
            None => "диагностика неполна: нет данных о файловой системе".into(),
        }
    };
    e.volume = volume;
    Ok(e)
}

/// Ceiling for a file given the planned strategy and volume caveats. G2/G4/G5
/// are never claimed: journal, COW and device-wide sanitization remain outside
/// this project's proven scope.
fn ceiling_for(plan: Option<Strategy>, v: &VolumeInfo) -> &'static str {
    match plan {
        None => "none",
        Some(Strategy::RamUnlink | Strategy::CowAccept) => "content-only",
        Some(Strategy::HddOverwrite | Strategy::OverwriteDealloc) => {
            if matches!(v.journal, JournalState::Active | JournalState::Unknown) {
                "content-only"
            } else {
                "G1"
            }
        }
    }
}
