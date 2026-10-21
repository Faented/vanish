//! Walker: собираем файлы (без symlink) и папки; порядок снизу вверх,
//! `--xdev` запрещает пересечение границ файловой системы.

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

fn gather(
    dir: &Path,
    base_dev: u64,
    o: &Options,
    plan: &mut TreePlan,
) -> std::result::Result<(), std::io::Error> {
    let rd = std::fs::read_dir(dir)?;
    for entry in rd {
        let entry = entry?;
        let path = entry.path();
        let md = std::fs::symlink_metadata(&path)?;
        if md.file_type().is_symlink() {
            plan.skipped.push((path, "symlink: не затираем".into()));
            continue;
        }
        if crosses_boundary(base_dev, md.dev(), o.xdev) {
            plan.skipped.push((path, "другая ФС; --xdev".into()));
            continue;
        }
        if md.is_dir() {
            gather(&path, base_dev, o, plan)?;
            plan.dirs.push(path);
        } else if md.is_file() {
            plan.files.push(path);
        } else {
            plan.skipped
                .push((path, "не обычный файл или каталог".into()));
        }
    }
    Ok(())
}

fn crosses_boundary(base_dev: u64, target_dev: u64, xdev: bool) -> bool {
    xdev && base_dev != target_dev
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
        plan.dirs
            .sort_by(|a, b| b.components().count().cmp(&a.components().count()));
    } else {
        plan.files.push(root.to_path_buf());
    }
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::{crosses_boundary, gather, TreePlan};
    use crate::config::Options;

    fn fixture_dir() -> std::path::PathBuf {
        let preferred = std::path::Path::new("/tmp/opencode");
        let base = if preferred.is_dir() {
            preferred.to_path_buf()
        } else {
            std::env::temp_dir()
        };
        let path = base.join(format!("vanish-walk-{}", crate::util::random_tail()));
        // Exclusive creation: never reuse or overwrite another test's fixture.
        std::fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn xdev_means_stay_on_the_original_filesystem() {
        assert!(crosses_boundary(1, 2, true));
        assert!(!crosses_boundary(1, 2, false));
        assert!(!crosses_boundary(1, 1, true));
    }

    #[test]
    fn read_dir_error_is_not_silently_ignored() {
        let root = fixture_dir();
        let path = root.join("not-a-directory");
        std::fs::write(&path, b"disposable fixture, not a directory").unwrap();
        let result = gather(&path, 0, &Options::default(), &mut TreePlan::default());
        std::fs::remove_dir_all(root).unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn xdev_applies_to_both_files_and_directories() {
        use std::os::unix::fs::MetadataExt;

        let root = fixture_dir();
        let file = root.join("file");
        let dir = root.join("dir");
        std::fs::write(&file, b"disposable fixture").unwrap();
        std::fs::create_dir(&dir).unwrap();
        // Inject a different root-device identity; no mounts/devices involved.
        let base_dev = std::fs::metadata(&root).unwrap().dev().wrapping_add(1);
        let mut plan = TreePlan::default();
        let opts = Options {
            xdev: true,
            ..Options::default()
        };
        gather(&root, base_dev, &opts, &mut plan).unwrap();
        assert!(plan.files.is_empty());
        assert!(plan.dirs.is_empty());
        assert_eq!(plan.skipped.len(), 2);
        let mut plan = TreePlan::default();
        gather(&root, base_dev, &Options::default(), &mut plan).unwrap();
        assert_eq!(plan.files, vec![file]);
        assert_eq!(plan.dirs, vec![dir]);
        assert!(plan.skipped.is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }
}
