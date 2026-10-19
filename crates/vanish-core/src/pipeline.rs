//! Конвейер: один целевой путь → решить → wipe → отчёт-событие.
//! Порядок шагов (контракт §6): probe-проверки → занятость → хардлинки
//! → rename-hide → open+bypass-IO → потоки → проходы записи → punch →
//! fadvise → truncate0+sync → unlink → fsync(dir).

use crate::config::Options;
use crate::error::{Result, VanishError};
use crate::fsinfo::VolumeInfo;
use crate::pattern::PatternStream;
use crate::platform::{Platform, Target};
use crate::report::{Guarantees, RunReport, TargetEvent, Timer};use crate::signal::shutdown_requested;
use crate::strategy::decide;
use crate::util;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

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
        let md = match std::fs::symlink_metadata(root) {
            Ok(m) => m,
            Err(e) => {
                self.fail_event("file", root, "io", e.to_string(), timer);
                return;
            }
        };
        if md.is_symlink() {
            self.reject_event("file", root, "symlink", "не затираем".into(), timer);
            return;
        }
        if md.is_dir() {
            self.wipe_tree(root, timer);
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
            self.report.note(format!("skip ({}): {}", note.0.display(), note.1));
        }
        let n_files = plan.files.len();
        let n_dirs = plan.dirs.len();
        for f in &plan.files {
            match std::fs::symlink_metadata(f) {
                Ok(md) if !md.is_dir() => {
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
                _ => {}
            }
            if shutdown_requested() {
                self.report
                    .note("SIGINT: оставшиеся цели не тронуты");
                break;
            }
        }
        for d in &plan.dirs {
            match std::fs::symlink_metadata(d) {
                Ok(md) if md.is_dir() => {
                    // Не трогаем непустой каталог: в нём остались
                    // отклонённые/пропущенные цели — «failed» тут был бы ложью.
                    let empty = std::fs::read_dir(d)
                        .map(|mut rd| rd.next().is_none())
                        .unwrap_or(false);
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
                _ => {}
            }
            if shutdown_requested() {
                break;
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
    /// (родитель + младенцы); не отказываем. rename → rmdir → fsync(dir).
    pub fn wipe_dir(&mut self, mut t: Target) -> Result<()> {
        let timer = Timer::start();
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
            guarantees: Some(self.guarantees(&vinfo)),
            elapsed_ms: timer.ms(),
        };
        self.report.push(ev);
        Ok(())
    }

    /// Универсальная обработка одного целевого inode (файл).
    pub fn wipe_target(&mut self, mut target: Target, allow_rename: bool) -> Result<()> {
        let timer = Timer::start();
        if self.opts.dry_run {
            self.dry_run_event(&target.abs, true, timer)?;
            return Ok(());
        }
        // Инвариант 5: nlink>1 — отказ.
        if target.nlink > 1 && !self.opts.wipe_all_hardlinks {
            return Err(VanishError::HardLinks { nlink: target.nlink });
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
            Some(tl)
        } else {
            None
        };
        let seed = util::random_seed32();
        let wipe_handle = match self.platform.open_handle(&target) {
            Ok(h) => h,
            Err(e) => {
                self.platform.fsync_dir(&target.parent).ok();
                return Err(e);
            }
        };
        if wipe_handle.dev_ino() != (target.dev, target.ino) {
            drop(wipe_handle);
            return Err(VanishError::IdentityMismatch(format!(
                "dev/ino изменились после rename: {}",
                util::name_sha256(&target.abs)
            )));
        }
        let mut wipe_handle = wipe_handle;
        let mut warnings: Vec<String> = vec![];
        let mut bytes_wiped: u64 = 0;
        // Потоки: затираем по умолчанию.
        if !self.opts.keep_streams {
            for (name, _sz) in self.platform.stream_names(&target)? {
                if let Err(e) = self.platform.erase_stream(&target, &name) {
                    warnings.push(format!("поток {}: не удалён ({})", name, e));
                }
            }
        }
        // Проходы записи (extent-aware).
        if strategy.do_overwrite() {
            let len = wipe_handle.len().unwrap_or(target.size);
            bytes_wiped = len;
            let ranges: Vec<(u64, u64)> = match wipe_handle.extents()? {
                Some(exs) if !exs.is_empty() => {
                    exs.iter().map(|e| (e.logical, e.len)).collect()
                }
                _ => vec![(0, len)],
            };
            for p in 0..self.opts.effective_passes() {
                for (off, rlen) in &ranges {
                    let mut gen = PatternStream::new(self.opts.pattern, p, seed);
                    wipe_handle.overwrite(*off, *rlen, &mut gen)?;
                    if self.opts.verify {
                        let mut vgen = PatternStream::new(self.opts.pattern, p, seed);
                        wipe_handle.verify(*off, *rlen, &mut vgen)?;
                    }
                    if shutdown_requested() {
                        break;
                    }
                }
                wipe_handle.sync()?;
                if shutdown_requested() {
                    self.report
                        .note("SIGINT: текущий файл доводится до конца, остальные отменены");
                    break;
                }
            }
        }
        // Dealloc (SSD).
        if strategy.do_punch() && self.opts.punch {
            match wipe_handle.punch() {
                Ok(true) => {}
                Ok(false) => warnings.push("punch-hole: не поддержан ФС".into()),
                Err(e) => warnings.push(format!("punch-hole: {}", e)),
            }
        }
        if let Err(e) = wipe_handle.dontneed() {
            warnings.push(format!("fadvise: {}", e));
        }
        // Финальный ход: truncate0 → sync → unlink (инвариант 4).
        wipe_handle.truncate0()?;
        wipe_handle.sync()?;
        drop(wipe_handle);
        if let Err(e) = self
            .platform
            .unlink(&target, &target.name.to_string_lossy())
        {
            warnings.push(format!("unlink: {} (хвост остался для recovery)", e));
        }
        if let Err(e) = self.platform.fsync_dir(&target.parent) {
            warnings.push(format!("fsync(dir): {}", e));
        }
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
            guarantees: Some(self.guarantees(&vinfo)),
            elapsed_ms: timer.ms(),
        };
        self.report.push(ev);
        Ok(())
    }

    fn seed_of(&self, _t: &Target) -> [u8; 32] {
        util::random_seed32()
    }

    fn guarantees(&self, v: &VolumeInfo) -> Guarantees {
        Guarantees {
            ssd_chipoff_protected: v.ssd_chipoff_protected,
            journal_contains_old_names: matches!(
                v.journal,
                crate::fsinfo::JournalState::Active
            ),
            swap_pages_possible: v.swap_pages_possible,
            encrypted_at_rest: v.encrypted == crate::fsinfo::EncryptionState::Encrypted,
        }
    }

    fn dry_run_event(
        &mut self,
        path: &std::path::Path,
        is_file: bool,
        timer: Timer,
    ) -> Result<()> {
        // fd-цель может исчезнуть к моменту dry-run; это не ошибка, а «пустая цель».
        let md = std::fs::symlink_metadata(path).ok();
        let vinfo = self.platform.fsinfo(path)?;
        let plan = match decide(is_file, &vinfo, self.opts) {
            Ok(s) => s.to_str().to_string(),
            Err(e) => {
                self.reject_event("file", path, e.kind(), e.to_string(), timer);
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
            bytes: md.as_ref().map(|m| m.len()).unwrap_or(0),
            warnings: vec![],
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
        _timer: Timer,
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
            guarantees: None,
            elapsed_ms: 0,
        };
        self.report.push(ev);
    }

    fn bad_event(&mut self, kind: &str, path: &std::path::Path, e: &VanishError, timer: Timer) {
        match e {
            VanishError::Io(_) => self.fail_event(kind, path, e.kind(), e.to_string(), timer),
            _ => self.reject_event(kind, path, e.kind(), e.to_string(), timer),
        }
    }
}
