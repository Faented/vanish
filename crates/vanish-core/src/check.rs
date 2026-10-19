//! `vanish check`: диагностика пути БЕЗ записи. Всё read-only.

use serde::Serialize;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use crate::error::Result;
use crate::fsinfo::{JournalState, VolumeInfo};
use crate::platform::{Opener, Platform, SwapEntry};

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
    pub verdict: String,
}

#[derive(Debug, Serialize)]
pub struct CheckReport {
    pub backend: &'static str,
    pub swap: Vec<SwapEntry>,
    pub entries: Vec<CheckEntry>,
}

/// Собрать диагностику по списку путей.
pub fn run(plat: &dyn Platform, paths: &[std::path::PathBuf]) -> Result<CheckReport> {
    let mut entries = Vec::new();
    for p in paths {
        let e = check_one(plat, p)?;
        entries.push(e);
    }
    let swap = plat.swap_active().unwrap_or_else(|_| Vec::new());
    Ok(CheckReport {
        backend: plat.name(),
        swap,
        entries,
    })
}

fn check_one(plat: &dyn Platform, p: &Path) -> Result<CheckEntry> {
    let mut e = CheckEntry {
        name_hash: crate::util::name_sha256(p),
        exists: false,
        kind: "missing".into(),
        size: None,
        nlink: None,
        volume: None,
        openers: Vec::new(),
        hardlink_refusal: false,
        verdict: String::new(),
    };
    let md = match std::fs::symlink_metadata(p) {
        Ok(m) => m,
        Err(_) => {
            e.verdict = "нет такой цели; удалять нечего".into();
            return Ok(e);
        }
    };
    e.exists = true;
    if md.is_symlink() {
        e.verdict = "symlink-target is wiped elsewhere; vanish не следует ссылкам".into();
        return Ok(e);
    }
    let mut reason: Option<String> = None;
    let (dev, ino, nlink) = (
        md.dev(),
        md.ino(),
        md.nlink(),
    );
    if md.is_dir() {
        e.kind = "dir".into();
        let v = Some(plat.fsinfo(p).unwrap_or_else(|er| fallback_info(&er.to_string())));
        e.volume = v;
        reason = match refusal_from(&e.volume, &crate::fsinfo::JournalState::Unknown) {
            Some(r) => Some(r),
            None => None,
        };
    } else {
        e.kind = "file".into();
        e.size = Some(md.len());
        e.nlink = Some(nlink as u32);
        let v = Some(plat.fsinfo(p).unwrap_or_else(|er| fallback_info(&er.to_string())));
        e.volume = v;
        if nlink > 1 {
            e.hardlink_refusal = true;
            reason = Some(format!("nlink={}; откажется без --wipe-all-hardlinks", nlink));
        }
    }
    e.openers = plat.openers(dev, ino).unwrap_or_default();
    if !e.openers.is_empty() {
        reason = Some(format!(
            "открыт процессами {:?}; откажется",
            e.openers.iter().map(|o| o.pid).collect::<Vec<_>>()
        ));
    }
    let vol = e.volume.clone().unwrap();
    let j = vol.journal;
    let _ = j.to_str();
    e.verdict = reason
        .map(|r| format!("отказ: {}", r))
        .unwrap_or_else(|| vol.protective_summary());
    Ok(e)
}

fn refusal_from(_v: &Option<VolumeInfo>, _j: &JournalState) -> Option<String> {
    None // уточнено в check_one
}

fn fallback_info(msg: &str) -> VolumeInfo {
    VolumeInfo {
        fs: crate::fsinfo::FsKind::Other,
        fs_name: format!("unknown ({})", msg),
        mount: "?".into(),
        device: None,
        device_kind: crate::fsinfo::DeviceKind::Unknown,
        encrypted: crate::fsinfo::EncryptionState::Unknown,
        journal: JournalState::Unknown,
        cow: false,
        ro_mount: false,
        swap_sharing_fs: false,
        swap_pages_possible: false,
        ssd_chipoff_protected: false,
    }
}
