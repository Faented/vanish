//! Walker: собираем файлы (без symlink) и папки; постсоветский порядок,
//! отказ на пересечение других ФС (без `--xdev`).

use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use crate::config::Options;
use crate::error::Result;

#[derive(Debug, Default)]
pub struct TreePlan {
    /// Вся файловая глубина (порядок не критичен: после wipe всё равно unlink).
    pub files: Vec<PathBuf>,
    /// Папки от глубочайшей ко корню (rmdir снизу вверх).
    pub dirs: Vec<PathBuf>,
    /// Пропущенные (symlink) иные причины.
    pub skipped: Vec<(PathBuf, String)>,
}

fn gather(dir: &Path, base_dev: u64, o: &Options, plan: &mut TreePlan) -> std::result::Result<(), std::io::Error> {
    let rd = std::fs::read_dir(dir)?;
    for entry in rd {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue, // гонка прав: пропуск, зафиксируем при wipe
        };
        let path = entry.path();
        let md = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => {
                plan.skipped.push((path, "vanished mid-walk".into()));
                continue;
            }
        };
        if md.file_type().is_symlink() {
            plan.skipped.push((path, "symlink: не затираем".into()));
            continue;
        }
        if md.is_dir() {
            let dev = md.dev();
            if dev != base_dev && !o.xdev {
                plan.skipped.push((path.clone(), "другая ФС; без --xdev".into()));
                continue;
            }
            gather(&path, base_dev, o, plan)?;
            plan.dirs.push(path);
        } else {
            plan.files.push(path);
        }
    }
    Ok(())
}

/// Построить план для корня-папки. Сам root включается в dirs последним.
pub fn build(root: &Path, o: &Options) -> Result<TreePlan> {
    let md = std::fs::symlink_metadata(root)?;
    let mut plan = TreePlan::default();
    if md.is_dir() {
        let base_dev = md.dev();
        gather(root, base_dev, o, &mut plan)?;
        plan.dirs.push(root.to_path_buf());
        // deepest-first: сортируем по количеству компонентов
        plan.dirs.sort_by(|a, b| {
            b.components().count().cmp(&a.components().count())
        });
    } else {
        plan.files.push(root.to_path_buf());
    }
    Ok(plan)
}
