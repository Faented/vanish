//! Recovery: complete `.vanish-v1-*` tails left after a failure.
//! Every failure is recorded and returned; no failed tail is reported as success.

use std::path::PathBuf;

use crate::config::Options;
use crate::error::{Result, VanishError};
use crate::pipeline::Pipeline;
use crate::platform::{Platform, Target};
use crate::report::RunReport;
use crate::signal::shutdown_requested;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

pub fn run(
    plat: &dyn Platform,
    roots: &[PathBuf],
    opts: &Options,
    report: &mut RunReport,
) -> Result<usize> {
    recover(plat, roots, opts, report, false)
}

pub fn run_dirs(
    plat: &dyn Platform,
    roots: &[PathBuf],
    opts: &Options,
    report: &mut RunReport,
) -> Result<usize> {
    recover(plat, roots, opts, report, true)
}

fn recover(
    plat: &dyn Platform,
    roots: &[PathBuf],
    opts: &Options,
    report: &mut RunReport,
    dirs: bool,
) -> Result<usize> {
    let mut count = 0;
    let mut first_error = None;
    // Both file and directory tails already have a recovery name.
    let mut recovery_opts = opts.clone();
    recovery_opts.rename = false;
    let mut pipe = Pipeline::new(plat, &recovery_opts, report);
    for root in roots {
        if shutdown_requested() {
            pipe.skipped_event("tail", root, "SIGINT/SIGTERM: recovery не начато");
            continue;
        }
        let mut paths = match plat.find_tails(root) {
            Ok(paths) => paths,
            Err(e) => {
                pipe.record_error("tail", root, &e);
                first_error.get_or_insert(e);
                continue;
            }
        };
        if dirs {
            paths.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
        }
        for path in paths {
            if shutdown_requested() {
                pipe.skipped_event("tail", &path, "SIGINT/SIGTERM: цель не начата");
                continue;
            }
            let result = (|| -> Result<bool> {
                let md = std::fs::symlink_metadata(&path)?;
                if md.is_symlink() || (!md.is_dir() && !md.is_file()) {
                    // The file pass owns rejection of special/symlink tails.
                    if dirs {
                        return Ok(false);
                    }
                    return Err(VanishError::UnsafePath(
                        "не обычный файл или каталог".into(),
                    ));
                }
                if md.is_dir() != dirs {
                    return Ok(false);
                }
                if dirs && std::fs::read_dir(&path)?.next().transpose()?.is_some() {
                    pipe.skipped_event("dir", &path, "каталог не пуст");
                    return Ok(false);
                }
                let target = Target::from_parts(
                    path.clone(),
                    md.dev(),
                    md.ino(),
                    md.len(),
                    md.nlink() as u32,
                );
                if dirs {
                    pipe.wipe_dir(target)?;
                } else {
                    pipe.wipe_target(target, false)?;
                }
                Ok(true)
            })();
            match result {
                Ok(true) => count += 1,
                Ok(false) => {}
                Err(e) => {
                    pipe.record_error(if dirs { "dir" } else { "tail" }, &path, &e);
                    first_error.get_or_insert(e);
                }
            }
        }
    }
    match first_error {
        Some(e) => Err(e),
        None => Ok(count),
    }
}
