//! Recovery: дожимаем хвосты `.vanish-v1-*`, оставшиеся после сбоя.
//! Хвосты затираются КАК ФАЙЛЫ с rename=false (они уже хвосты).

use std::path::{Path, PathBuf};

use crate::config::Options;
use crate::error::Result;
use crate::platform::{Platform, Target};
use crate::report::RunReport;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

pub fn run(
    plat: &dyn Platform,
    roots: &[PathBuf],
    opts: &Options,
    report: &mut RunReport,
) -> Result<usize> {
    let mut found = 0usize;
    for root in roots {
        for path in plat.find_tails(root)? {
            found += 1;
            let tag = crate::util::name_sha256(&path);
            let md = match std::fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if md.is_dir() || md.is_symlink() {
                continue;
            }
            let target = Target::from_parts(
                path,
                md.dev(),
                md.ino(),
                md.len(),
                md.nlink() as u32,
            );
            let mut pipe = super::pipeline::Pipeline::new(plat, opts, report);
            if let Err(e) = pipe.wipe_target(target, false) {
                report.note(format!("tail-hash {}: отложено ({})", &tag[0..12], e));
            }
        }
    }
    Ok(found)
}

pub fn run_dirs(
    plat: &dyn Platform,
    roots: &[PathBuf],
    opts: &Options,
    report: &mut RunReport,
) -> Result<usize> {
    let mut n = 0usize;
    for root in roots {
        for path in plat.find_tails(root)? {
            if let Ok(md) = std::fs::symlink_metadata(&path) {
                if !md.is_dir() {
                    continue;
                }
                let empty = std::fs::read_dir(&path)
                    .map(|mut rd| rd.next().is_none())
                    .unwrap_or(false);
                if !empty {
                    continue;
                }
                let t = Target::from_parts(
                    path,
                    md.dev(),
                    md.ino(),
                    md.len(),
                    md.nlink() as u32,
                );
                let mut pipe = super::pipeline::Pipeline::new(plat, opts, report);
                if pipe.wipe_dir(t).is_ok() {
                    n += 1;
                }
            }
        }
    }
    Ok(n)
}

#[allow(dead_code)]
#[allow(dead_code)]
fn tail_tag(_p: &Path) -> &'static str {
    "tail_hashed_in_events"
}
