//! Конвейер: один целевой путь → решить → wipe → отчёт-событие.
//! Порядок шагов (контракт §6): probe-проверки → занятость → хардлинки
//! → rename-hide+fsync(dir) → open+bypass-IO → потоки → запись+sync+verify → punch →
//! fadvise → truncate0+sync → unlink → fsync(dir).

use crate::config::Options;
use crate::error::{Result, VanishError};
use crate::fsinfo::{JournalState, VolumeInfo};
use crate::pattern::PatternStream;
use crate::platform::{Platform, Target};
use crate::report::{Guarantees, RunReport, TargetEvent, Timer};
use crate::signal::shutdown_requested;
use crate::strategy::{decide, Strategy};
use crate::util;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

/// Achieved wipe level for a successfully overwritten file. Journal names are a
/// separate caveat: with an active journal the level is downgraded to
/// `content-only` even though the data extents were overwritten.
fn file_guarantee_level(strategy: Strategy, v: &VolumeInfo) -> &'static str {
    match strategy {
        Strategy::RamUnlink | Strategy::CowAccept => "content-only",
        Strategy::HddOverwrite | Strategy::OverwriteDealloc => {
            if matches!(v.journal, JournalState::Active | JournalState::Unknown) {
                "content-only"
            } else {
                "G1"
            }
        }
    }
}

pub struct Pipeline<'a> {
    pub platform: &'a dyn Platform,
    pub opts: &'a Options,
    pub report: &'a mut RunReport,
}

impl<'a> Pipeline<'a> {
    pub fn new(platform: &'a dyn Platform, opts: &'a Options, report: &'a mut RunReport) -> Self {
        Pipeline {
            platform,
            opts,
            report,
        }
    }

    /// Полный проход одного PATH (файл или папка).
    pub fn wipe_any(&mut self, root: &std::path::Path) {
        let timer = Timer::start();
        if self.skip_if_cancelled("file", root) {
            return;
        }
        let md = match std::fs::symlink_metadata(root) {
            Ok(m) => m,
            Err(e) => {
                self.bad_event("file", root, &e.into(), timer);
                return;
            }
        };
        if md.is_symlink() {
            self.reject_event("file", root, "symlink", "не затираем".into(), timer);
            return;
        }
        if !root.is_absolute() {
            // The backend pins parent components and requires an absolute,
            // consistent target; checking that only after rename would hide the
            // original name first and then reject an already renamed target.
            self.reject_event(
                if md.is_dir() { "dir" } else { "file" },
                root,
                "unsafe_path",
                "нужен абсолютный путь".into(),
                timer,
            );
            return;
        }
        if md.is_dir() {
            self.wipe_tree(root, timer);
            return;
        } else if !md.is_file() {
            self.reject_event("file", root, "unsafe_path", "не обычный файл".into(), timer);
            return;
        } else {
            let target = Target::from_parts(
                root.to_path_buf(),
                md.dev(),
                md.ino(),
                md.len(),
                md.nlink() as u32,
            );
            match self.wipe_target(target, true) {
                Ok(()) => {}
                Err(e) => self.bad_event("file", root, &e, timer),
            }
        }
    }

    fn wipe_tree(&mut self, root: &std::path::Path, timer: Timer) {
        let plan = match crate::walk::build(root, self.opts) {
            Ok(p) => p,
            Err(e) => {
                self.bad_event("dir", root, &e, timer);
                return;
            }
        };
        for note in &plan.skipped {
            self.skipped_event("file", &note.0, &note.1);
        }
        let n_files = plan.files.len();
        let n_dirs = plan.dirs.len();
        for f in &plan.files {
            if self.skip_if_cancelled("file", f) {
                continue;
            }
            match std::fs::symlink_metadata(f) {
                Ok(md) if md.is_file() && !md.is_symlink() => {
                    let t = Target::from_parts(
                        f.clone(),
                        md.dev(),
                        md.ino(),
                        md.len(),
                        md.nlink() as u32,
                    );
                    if let Err(e) = self.wipe_target(t, true) {
                        self.bad_event("file", f, &e, Timer::start());
                    }
                }
                Ok(_) => self.record_error(
                    "file",
                    f,
                    &VanishError::UnsafePath("тип цели изменился".into()),
                ),
                Err(e) => self.record_error("file", f, &e.into()),
            }
        }
        for d in &plan.dirs {
            if self.skip_if_cancelled("dir", d) {
                continue;
            }
            if self.opts.dry_run {
                // In a dry-run nothing was unlinked, so every parent directory
                // is still non-empty. Report the plan instead of a misleading
                // "directory is not empty" skip.
                if let Err(error) = self.dry_run_event(d, false, Timer::start()) {
                    self.record_error("dir", d, &error);
                }
                continue;
            }
            match std::fs::symlink_metadata(d) {
                Ok(md) if md.is_dir() => {
                    // Не трогаем непустой каталог: в нём остались
                    // отклонённые/пропущенные цели — «failed» тут был бы ложью.
                    let empty = match std::fs::read_dir(d).and_then(|mut rd| rd.next().transpose())
                    {
                        Ok(entry) => entry.is_none(),
                        Err(e) => {
                            self.record_error("dir", d, &e.into());
                            continue;
                        }
                    };
                    if !empty {
                        let ev = TargetEvent {
                            kind: "dir".into(),
                            name_hash: util::name_sha256(d),
                            tail: None,
                            strategy: None,
                            status: "skipped".into(),
                            reason: Some(
                                "каталог не пуст: остались отклонённые или пропущенные цели".into(),
                            ),
                            bytes: 0,
                            warnings: vec![],
                            guarantee_level: "none".into(),
                            guarantees: None,
                            elapsed_ms: 0,
                        };
                        self.report.push(ev);
                        continue;
                    }
                    let t = Target::from_parts(
                        d.clone(),
                        md.dev(),
                        md.ino(),
                        md.len(),
                        md.nlink() as u32,
                    );
                    // каталоги: rename-hide от исходного имени, затем rmdir;
                    let res = self.wipe_dir(t);
                    if let Err(e) = res {
                        self.bad_event("dir", d, &e, Timer::start());
                    }
                }
                Ok(_) => self.record_error(
                    "dir",
                    d,
                    &VanishError::UnsafePath("тип цели изменился".into()),
                ),
                Err(e) => self.record_error("dir", d, &e.into()),
            }
        }
        self.report.note(format!(
            "дерево {}: файлов {}, папок {}",
            util::name_sha256(root),
            n_files,
            n_dirs
        ));
    }

    /// Папка: действия — verify-nlink=1? Для каталогов nlink>1 нормально
    /// (родитель + младенцы); не отказываем. rename → fsync(dir) → rmdir → fsync(dir).
    pub fn wipe_dir(&mut self, mut t: Target) -> Result<()> {
        let timer = Timer::start();
        if self.skip_if_cancelled("dir", &t.orig_abs) {
            return Ok(());
        }
        if !t.abs.is_absolute() || !t.parent.is_absolute() {
            return Err(VanishError::UnsafePath(
                "target directory path must be absolute".into(),
            ));
        }
        if !self.opts.rename && t.name.to_str().is_none() {
            return Err(VanishError::UnsafePath(
                "non-UTF8 basename requires rename before string-based removal".into(),
            ));
        }
        if self.opts.dry_run {
            self.dry_run_event(&t.abs, false, timer)?;
            return Ok(());
        }
        let vinfo = self.platform.fsinfo(&t.abs)?;
        let strategy = decide(false, &vinfo, self.opts)?;
        let tail: Option<String> = if self.opts.rename {
            let tl = self.platform.rename_to_tail(&t)?;
            t.abs = t.parent.join(&tl);
            t.name = tl.clone().into();
            // Persist the recovery name before performing irreversible work.
            self.platform.fsync_dir(&t.parent)?;
            Some(tl)
        } else {
            None
        };
        if let Err(e) = self.platform.rmdir(&t, &t.name.to_string_lossy()) {
            return Err(e);
        }
        self.platform.fsync_dir(&t.parent)?;
        let ev = TargetEvent {
            kind: "dir".into(),
            name_hash: util::name_sha256(&t.orig_abs),
            tail,
            strategy: Some(strategy.to_str().into()),
            status: "ok".into(),
            reason: None,
            bytes: 0,
            warnings: vec![],
            guarantee_level: "G0".into(),
            guarantees: Some(self.guarantees(&vinfo)),
            elapsed_ms: timer.ms(),
        };
        self.report.push(ev);
        Ok(())
    }

    /// Универсальная обработка одного целевого inode (файл).
    pub fn wipe_target(&mut self, mut target: Target, allow_rename: bool) -> Result<()> {
        let timer = Timer::start();
        if self.skip_if_cancelled("file", &target.orig_abs) {
            return Ok(());
        }
        if !target.abs.is_absolute() || !target.parent.is_absolute() {
            return Err(VanishError::UnsafePath(
                "target file path must be absolute".into(),
            ));
        }
        if !(allow_rename && self.opts.rename) && target.name.to_str().is_none() {
            return Err(VanishError::UnsafePath(
                "non-UTF8 basename requires rename before string-based removal".into(),
            ));
        }
        if self.opts.dry_run {
            self.dry_run_event(&target.abs, true, timer)?;
            return Ok(());
        }
        // Инвариант 5: nlink>1 — отказ.
        if target.nlink > 1 && !self.opts.wipe_all_hardlinks {
            return Err(VanishError::HardLinks {
                nlink: target.nlink,
            });
        }
        let vinfo = self.platform.fsinfo(&target.abs)?;
        let strategy = decide(true, &vinfo, self.opts)?;
        // Инвариант 6: открытые дескрипторы других процессов — отказ.
        let openers = self.platform.openers(target.dev, target.ino)?;
        if !openers.is_empty() {
            return Err(VanishError::Busy {
                pids: openers.iter().map(|o| o.pid).collect(),
            });
        }
        // rename-hide.
        let tail: Option<String> = if allow_rename && self.opts.rename {
            let tl = self.platform.rename_to_tail(&target)?;
            target.abs = target.parent.join(&tl);
            target.name = tl.clone().into();
            self.platform.fsync_dir(&target.parent)?;
            Some(tl)
        } else {
            None
        };
        let seed = util::random_seed32();
        let wipe_handle = self.platform.open_handle(&target)?;
        if wipe_handle.dev_ino() != (target.dev, target.ino) {
            drop(wipe_handle);
            return Err(VanishError::IdentityMismatch(format!(
                "dev/ino изменились после rename: {}",
                util::name_sha256(&target.abs)
            )));
        }
        let mut wipe_handle = wipe_handle;
        let mut warnings: Vec<String> = vec![];
        if target.nlink > 1 {
            // --wipe-all-hardlinks only permits the operation; it does not
            // enumerate other names. State that plainly instead of implying a
            // cascade that never happened.
            warnings.push("hardlinks: другие имена этого inode не удалены".into());
        }
        let mut bytes_wiped: u64 = 0;
        // Потоки: затираем по умолчанию.
        if !self.opts.keep_streams {
            for (name, _sz) in self.platform.stream_names(&target)? {
                if let Err(e) = self.platform.erase_stream(&target, &name) {
                    warnings.push(format!(
                        "stream-hash {}: не удалён ({})",
                        util::name_sha256(std::path::Path::new(&name)),
                        e.kind()
                    ));
                }
            }
        }
        // Проходы записи (extent-aware).
        if strategy.do_overwrite() {
            let len = wipe_handle.len()?;
            let ranges: Vec<(u64, u64)> = match wipe_handle.extents()? {
                Some(exs) if !exs.is_empty() => exs.iter().map(|e| (e.logical, e.len)).collect(),
                _ => vec![(0, len)],
            };
            // `bytes` in the report means bytes actually overwritten (sum of
            // extents), not the logical file size (which overstates sparse files).
            bytes_wiped = ranges.iter().map(|(_, len)| *len).sum();
            for p in 0..self.opts.effective_passes() {
                for (off, rlen) in &ranges {
                    let mut gen = PatternStream::new(self.opts.pattern, p, seed);
                    wipe_handle.overwrite(*off, *rlen, &mut gen)?;
                }
                // Verification must observe a completed, durable pass, not just
                // dirty cache pages. SIGINT never shortens an extent or pass.
                wipe_handle.sync()?;
                if self.opts.verify {
                    for (off, rlen) in &ranges {
                        let mut vgen = PatternStream::new(self.opts.pattern, p, seed);
                        wipe_handle.verify(*off, *rlen, &mut vgen)?;
                    }
                }
            }
        }
        // Dealloc (SSD).
        if strategy.do_punch() && self.opts.punch {
            match wipe_handle.punch() {
                Ok(true) => {}
                Ok(false) => warnings.push("punch-hole: не поддержан ФС".into()),
                Err(e) => warnings.push(format!("punch-hole: {}", e.kind())),
            }
        }
        if let Err(e) = wipe_handle.dontneed() {
            warnings.push(format!("fadvise: {}", e.kind()));
        }
        // Финальный ход: truncate0 → sync → unlink (инвариант 4).
        wipe_handle.truncate0()?;
        wipe_handle.sync()?;
        drop(wipe_handle);
        self.platform
            .unlink(&target, &target.name.to_string_lossy())?;
        self.platform.fsync_dir(&target.parent)?;
        if self.opts.trim_mount {
            let mount: std::path::PathBuf = vinfo.mount.clone().into();
            if !self.platform.trim_mount(&mount)? {
                warnings.push("FITRIM не выполнен (нужен root?)".into());
            }
        }
        let ev = TargetEvent {
            kind: "file".into(),
            name_hash: util::name_sha256(&target.orig_abs),
            tail,
            strategy: Some(strategy.to_str().into()),
            status: "ok".into(),
            reason: None,
            bytes: bytes_wiped,
            warnings,
            guarantee_level: file_guarantee_level(strategy, &vinfo).into(),
            guarantees: Some(self.guarantees(&vinfo)),
            elapsed_ms: timer.ms(),
        };
        self.report.push(ev);
        Ok(())
    }

    fn guarantees(&self, v: &VolumeInfo) -> Guarantees {
        Guarantees {
            ssd_chipoff_protected: v.ssd_chipoff_protected,
            journal_contains_old_names: matches!(v.journal, crate::fsinfo::JournalState::Active),
            swap_pages_possible: v.swap_pages_possible,
            encrypted_at_rest: v.encrypted == crate::fsinfo::EncryptionState::Encrypted,
        }
    }

    fn dry_run_event(&mut self, path: &std::path::Path, is_file: bool, timer: Timer) -> Result<()> {
        // fd-цель может исчезнуть к моменту dry-run; это не ошибка, а «пустая цель».
        let vinfo = self.platform.fsinfo(path)?;
        let plan = match decide(is_file, &vinfo, self.opts) {
            Ok(s) => s.to_str().to_string(),
            Err(e) => {
                self.bad_event(if is_file { "file" } else { "dir" }, path, &e, timer);
                return Ok(());
            }
        };
        let ev = TargetEvent {
            kind: if is_file { "file" } else { "dir" }.into(),
            name_hash: util::name_sha256(path),
            tail: None,
            strategy: Some(plan),
            status: "skipped".into(),
            reason: Some("dry-run".into()),
            // Nothing was written: planned size is not "bytes overwritten".
            bytes: 0,
            warnings: vec![],
            guarantee_level: "none".into(),
            guarantees: Some(self.guarantees(&vinfo)),
            elapsed_ms: timer.ms(),
        };
        self.report.push(ev);
        Ok(())
    }

    fn reject_event(
        &mut self,
        kind: &str,
        path: &std::path::Path,
        reason_kind: &str,
        detail: String,
        timer: Timer,
    ) {
        let ev = TargetEvent {
            kind: kind.into(),
            name_hash: util::name_sha256(path),
            tail: None,
            strategy: None,
            status: "rejected".into(),
            reason: Some(format!("{}: {}", reason_kind, detail)),
            bytes: 0,
            warnings: vec![],
            guarantee_level: "none".into(),
            guarantees: None,
            elapsed_ms: timer.ms(),
        };
        self.report.push(ev);
    }

    fn fail_event(
        &mut self,
        kind: &str,
        path: &std::path::Path,
        reason_kind: &str,
        detail: String,
        timer: Timer,
    ) {
        let ev = TargetEvent {
            kind: kind.into(),
            name_hash: util::name_sha256(path),
            tail: None,
            strategy: None,
            status: "failed".into(),
            reason: Some(format!("{}: {}", reason_kind, detail)),
            bytes: 0,
            warnings: vec![],
            guarantee_level: "none".into(),
            guarantees: None,
            elapsed_ms: timer.ms(),
        };
        self.report.push(ev);
    }

    fn bad_event(&mut self, kind: &str, path: &std::path::Path, e: &VanishError, timer: Timer) {
        // Backend errors may embed original paths, stream names or mount names.
        // Never serialize their free-form Display text into the report.
        let detail = match e {
            VanishError::VerifyMismatch { offset } => format!("offset={offset}"),
            VanishError::HardLinks { nlink } => format!("nlink={nlink}"),
            VanishError::Io(e) => format!("{:?}", e.kind()),
            _ => "детали скрыты".into(),
        };
        match e {
            VanishError::Io(_) | VanishError::VerifyMismatch { .. } | VanishError::Local(_) => {
                self.fail_event(kind, path, e.kind(), detail, timer)
            }
            _ => self.reject_event(kind, path, e.kind(), detail, timer),
        }
    }

    /// Record an error returned by a Result-based entry point, without leaking
    /// backend-provided paths or other free-form details into the report.
    pub fn record_error(&mut self, kind: &str, path: &std::path::Path, error: &VanishError) {
        self.bad_event(kind, path, error, Timer::start());
    }

    pub(crate) fn skipped_event(&mut self, kind: &str, path: &std::path::Path, reason: &str) {
        self.report.push(TargetEvent {
            kind: kind.into(),
            name_hash: util::name_sha256(path),
            tail: None,
            strategy: None,
            status: "skipped".into(),
            reason: Some(reason.into()),
            bytes: 0,
            warnings: vec![],
            guarantee_level: "none".into(),
            guarantees: None,
            elapsed_ms: 0,
        });
    }

    fn skip_if_cancelled(&mut self, kind: &str, path: &std::path::Path) -> bool {
        if shutdown_requested() {
            self.skipped_event(kind, path, "SIGINT/SIGTERM: цель не начата");
            true
        } else {
            false
        }
    }
}
