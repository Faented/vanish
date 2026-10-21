//! Интеграционные тесты конвейера vanish-core на FakePlatform.
//! Проверяют инварианты: 9 Security Invariants (см. docs/PLAN.md §14).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use vanish_core::config::{Options, PatternChoice};
use vanish_core::error::{Result, VanishError};
use vanish_core::fsinfo::{DeviceKind, EncryptionState, FsKind, JournalState, VolumeInfo};
use vanish_core::pattern::PatternStream;
use vanish_core::platform::{Extent, Opener, Platform, SwapEntry, Target, WipeHandle};
use vanish_core::report::RunReport;

/// Хранилище уровня «inode»: key = имя, value = байты.
#[derive(Default)]
struct Store {
    files: HashMap<String, Vec<u8>>,
    pass_fingerprints: Vec<Vec<u8>>, // первый чанк каждого прохода
    punch_called: bool,
    truncate_called: bool,
    unlink_names: Vec<String>,
    renamed: Vec<(String, String)>,
    streams_names: Vec<String>,
    events: Vec<String>,
    extents: Option<Vec<Extent>>,
    fault: Option<&'static str>,
    fsync_fail_at: Option<usize>,
    fsync_count: usize,
    sync_fail_at: Option<usize>,
    sync_count: usize,
    signal_on_write: bool,
    signal_on_discovery: bool,
    tails: Vec<PathBuf>,
    volume: Option<VolumeInfo>,
}

fn injected() -> VanishError {
    std::io::Error::other("secret-original-file secret-stream-name /secret/mount").into()
}

type Shared = Arc<Mutex<Store>>;

fn store() -> Shared {
    Arc::new(Mutex::new(Store::default()))
}

#[test]
fn check_reports_platform_faults_without_mutating() {
    let fixture = Fixture::new();
    let path = fixture.file("check-input");
    for fault in ["swap_active", "fsinfo", "openers"] {
        let shared = store();
        shared.lock().unwrap().fault = Some(fault);
        let plat = FakePlatform {
            store: shared.clone(),
            openers_list: vec![],
        };
        let result =
            vanish_core::check::run(&plat, std::slice::from_ref(&path), &Options::default());
        if fault == "swap_active" {
            // A global swap query has no entry to attach the failure to.
            assert!(matches!(result, Err(VanishError::Io(_))), "fault {fault}");
        } else {
            // `check` is diagnostic: an unreadable /proc or filesystem probe
            // must not hide the rest of the report.
            let report = result.expect("diagnostic check must still return a report");
            assert_eq!(report.entries.len(), 1);
            assert!(
                report.entries[0].verdict.contains("диагностика неполна"),
                "fault {fault}: {}",
                report.entries[0].verdict
            );
        }
        let st = shared.lock().unwrap();
        assert!(st.renamed.is_empty());
        assert!(!st.truncate_called);
        assert!(st.unlink_names.is_empty());
    }
}

#[test]
fn check_only_not_found_means_missing() {
    let fixture = Fixture::new();
    let missing = fixture.0.join("missing");
    let file = fixture.file("not-a-directory");
    let invalid = file.join("child");
    let plat = FakePlatform {
        store: store(),
        openers_list: vec![],
    };
    let report = vanish_core::check::run(&plat, &[missing], &Options::default()).unwrap();
    assert!(!report.entries[0].exists);
    assert_eq!(report.entries[0].kind, "missing");
    // ENOTDIR is a metadata read failure, not evidence that the target is absent.
    let report = vanish_core::check::run(&plat, &[invalid], &Options::default()).unwrap();
    assert!(report.entries[0].verdict.contains("проверка не удалась"));
    assert_eq!(report.entries[0].kind, "error");
}

#[test]
fn check_classifies_symlinks_and_special_files_without_following_or_opening() {
    let fixture = Fixture::new();
    let link = fixture.0.join("link");
    std::os::unix::fs::symlink("absent-target", &link).unwrap();
    let socket = fixture.0.join("socket");
    let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let shared = store();
    // Even a broken fsinfo implementation must not be called for these objects.
    shared.lock().unwrap().fault = Some("fsinfo");
    let plat = FakePlatform {
        store: shared.clone(),
        openers_list: vec![],
    };
    let report = vanish_core::check::run(&plat, &[link, socket], &Options::default()).unwrap();
    assert_eq!(report.entries[0].kind, "symlink");
    assert_eq!(report.entries[0].verdict, "symlink; not followed");
    assert_eq!(report.entries[1].kind, "special");
    assert!(report.entries[1].verdict.starts_with("отказ:"));
    assert!(report
        .entries
        .iter()
        .all(|e| e.exists && e.volume.is_none()));
    assert!(shared.lock().unwrap().events.is_empty());
}

#[test]
fn check_verdict_uses_default_strategy_refusals_for_files_and_directories() {
    let fixture = Fixture::new();
    let file = fixture.file("file");
    let shared = store();
    let plat = FakePlatform {
        store: shared.clone(),
        openers_list: vec![],
    };
    for (fs, swap, ro, expected) in [
        (FsKind::Btrfs, false, false, "cow_fs"),
        (FsKind::Other, false, false, "unsupported_fs"),
        (FsKind::Ext4, true, false, "swap_active"),
        (FsKind::Tmpfs, true, false, "swap_active"),
        (FsKind::Ext4, false, true, "read_only_mount"),
    ] {
        let mut volume = plat.info();
        volume.fs = fs;
        volume.cow = fs.is_cow();
        volume.swap_sharing_fs = swap;
        volume.ro_mount = ro;
        shared.lock().unwrap().volume = Some(volume);
        let report = vanish_core::check::run(
            &plat,
            &[file.clone(), fixture.0.clone()],
            &Options::default(),
        )
        .unwrap();
        for entry in report.entries {
            assert!(
                entry.verdict.starts_with("отказ:"),
                "{fs:?}: {}",
                entry.verdict
            );
            assert!(
                entry.verdict.contains(expected),
                "{fs:?}: {}",
                entry.verdict
            );
        }
    }
}

#[test]
fn check_uses_supplied_options_for_strategy_verdict() {
    let fixture = Fixture::new();
    let file = fixture.file("file");
    let shared = store();
    let plat = FakePlatform {
        store: shared.clone(),
        openers_list: vec![],
    };
    let mut volume = plat.info();
    volume.fs = FsKind::Btrfs;
    volume.cow = true;
    shared.lock().unwrap().volume = Some(volume);
    let refused =
        vanish_core::check::run(&plat, std::slice::from_ref(&file), &Options::default()).unwrap();
    assert!(refused.entries[0].verdict.contains("cow_fs"));
    let accepted = vanish_core::check::run(
        &plat,
        std::slice::from_ref(&file),
        &Options {
            accept_cow: true,
            ..Options::default()
        },
    )
    .unwrap();
    assert!(!accepted.entries[0].verdict.starts_with("отказ:"));
}

#[test]
fn check_preserves_hardlink_and_busy_refusals_alongside_strategy_refusal() {
    let fixture = Fixture::new();
    let file = fixture.file("file");
    std::fs::hard_link(&file, fixture.0.join("second-link")).unwrap();
    let shared = store();
    let plat = FakePlatform {
        store: shared.clone(),
        openers_list: vec![Opener {
            pid: 4242,
            exe: "/diagnostic/process".into(),
        }],
    };
    let mut volume = plat.info();
    volume.swap_sharing_fs = true;
    shared.lock().unwrap().volume = Some(volume);
    let report = vanish_core::check::run(&plat, &[file], &Options::default()).unwrap();
    let entry = &report.entries[0];
    assert!(entry.hardlink_refusal);
    assert!(entry.verdict.contains("nlink=2"));
    assert!(entry.verdict.contains("swap_active"));
    assert!(entry.verdict.contains("4242"));
    // CheckReport is intentionally diagnostic, unlike the wipe RunReport.
    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains("/dev/fake0"));
    assert!(json.contains("/diagnostic/process"));
}

struct FakeHandle {
    key: String,
    store: Shared,
    len: u64,
    dev: u64,
    ino: u64,
}

impl FakeHandle {
    fn send_pass_start(&self) {
        let mut st = self.store.lock().unwrap();
        st.pass_fingerprints.push(Vec::new());
    }
    fn record_first_chunk(&self, buf: &[u8]) {
        let mut st = self.store.lock().unwrap();
        if let Some(last) = st.pass_fingerprints.last_mut() {
            if last.is_empty() {
                *last = buf.to_vec();
            }
        }
    }
}

impl WipeHandle for FakeHandle {
    fn dev_ino(&self) -> (u64, u64) {
        (self.dev, self.ino)
    }
    fn len(&self) -> Result<u64> {
        Ok(self.len)
    }
    fn extents(&self) -> Result<Option<Vec<Extent>>> {
        Ok(self.store.lock().unwrap().extents.clone())
    }
    fn overwrite(&mut self, off: u64, len: u64, gen: &mut PatternStream) -> Result<()> {
        let signal = {
            let mut st = self.store.lock().unwrap();
            st.events.push(format!("write:{off}:{len}"));
            if st.fault == Some("write") {
                return Err(injected());
            }
            std::mem::take(&mut st.signal_on_write)
        };
        if signal {
            unsafe {
                libc::raise(libc::SIGINT);
            }
        }
        self.send_pass_start();
        let chunk = 4096u64;
        let mut pos = 0u64;
        while pos < len {
            let n = chunk.min(len - pos) as usize;
            let mut buf = vec![0u8; n];
            gen.fill(&mut buf);
            self.record_first_chunk(&buf);
            let mut st = self.store.lock().unwrap();
            let data = st.files.get_mut(&self.key).expect("data");
            let start = (off + pos) as usize;
            data[start..start + n].copy_from_slice(&buf);
            pos += n as u64;
        }
        Ok(())
    }
    fn verify(&mut self, off: u64, len: u64, gen: &mut PatternStream) -> Result<()> {
        {
            let mut st = self.store.lock().unwrap();
            st.events.push(format!("verify:{off}:{len}"));
            if st.fault == Some("verify") {
                return Err(VanishError::VerifyMismatch { offset: off });
            }
        }
        let chunk = 4096u64;
        let mut pos = 0u64;
        while pos < len {
            let n = chunk.min(len - pos) as usize;
            let mut buf = vec![0u8; n];
            gen.fill(&mut buf);
            let st = self.store.lock().unwrap();
            let data = st.files.get(&self.key).expect("data");
            let start = (off + pos) as usize;
            if data[start..start + n] != buf[..] {
                return Err(VanishError::VerifyMismatch { offset: off + pos });
            }
            pos += n as u64;
        }
        Ok(())
    }
    fn sync(&self) -> Result<()> {
        let mut st = self.store.lock().unwrap();
        st.events.push("sync".into());
        st.sync_count += 1;
        if st.fault == Some("sync") || st.sync_fail_at == Some(st.sync_count) {
            return Err(injected());
        }
        Ok(())
    }
    fn punch(&mut self) -> Result<bool> {
        self.store.lock().unwrap().punch_called = true;
        Ok(true)
    }
    fn truncate0(&mut self) -> Result<()> {
        let mut st = self.store.lock().unwrap();
        st.events.push("truncate".into());
        st.truncate_called = true;
        if let Some(d) = st.files.get_mut(&self.key) {
            d.clear();
        }
        self.len = 0;
        Ok(())
    }
    fn dontneed(&self) -> Result<()> {
        if self.store.lock().unwrap().fault == Some("dontneed") {
            return Err(injected());
        }
        Ok(())
    }
}

struct FakePlatform {
    store: Shared,
    openers_list: Vec<Opener>,
}

impl FakePlatform {
    fn info(&self) -> VolumeInfo {
        VolumeInfo {
            fs: FsKind::Ext4,
            fs_name: "fake-ext4".into(),
            mount: "/fake".into(),
            device: Some("/dev/fake0".into()),
            device_kind: DeviceKind::Ssd,
            encrypted: EncryptionState::NotEncrypted,
            journal: JournalState::None,
            cow: false,
            ro_mount: false,
            swap_sharing_fs: false,
            swap_pages_possible: false,
            ssd_chipoff_protected: false,
        }
    }
}

impl Platform for FakePlatform {
    fn name(&self) -> &'static str {
        "fake"
    }
    fn fsinfo(&self, _p: &Path) -> Result<VolumeInfo> {
        let mut st = self.store.lock().unwrap();
        st.events.push("fsinfo".into());
        if st.fault == Some("fsinfo") {
            return Err(injected());
        }
        Ok(st.volume.clone().unwrap_or_else(|| self.info()))
    }
    fn openers(&self, _dev: u64, _ino: u64) -> Result<Vec<Opener>> {
        if self.store.lock().unwrap().fault == Some("openers") {
            return Err(injected());
        }
        Ok(self.openers_list.clone())
    }
    fn open_handle(&self, t: &Target) -> Result<Box<dyn WipeHandle>> {
        let mut st = self.store.lock().unwrap();
        st.events.push("open".into());
        let key = t.abs.to_string_lossy().into_owned();
        let data = st
            .files
            .get(&key)
            .ok_or_else(|| VanishError::Local(format!("no such fake file {}", key)))?;
        Ok(Box::new(FakeHandle {
            key,
            store: self.store.clone(),
            len: data.len() as u64,
            dev: t.dev,
            ino: t.ino,
        }))
    }
    fn stream_names(&self, _t: &Target) -> Result<Vec<(String, u64)>> {
        let st = self.store.lock().unwrap();
        Ok(st.streams_names.iter().map(|n| (n.clone(), 4u64)).collect())
    }
    fn erase_stream(&self, _t: &Target, name: &str) -> Result<()> {
        if self.store.lock().unwrap().fault == Some("stream") {
            return Err(injected());
        }
        self.store
            .lock()
            .unwrap()
            .streams_names
            .retain(|n| n != name);
        Ok(())
    }
    fn rename_to_tail(&self, t: &Target) -> Result<String> {
        let tail = format!(".{}", vanish_core::util::random_tail());
        let old_key = t.abs.to_string_lossy().into_owned();
        let new_key = t.parent.join(&tail).to_string_lossy().into_owned();
        let mut st = self.store.lock().unwrap();
        st.events.push("rename".into());
        let data = st
            .files
            .remove(&old_key)
            .ok_or_else(|| VanishError::Local(format!("rename: нет ключа {}", old_key)))?;
        st.files.insert(new_key.clone(), data);
        st.renamed.push((old_key.clone(), new_key.clone()));
        drop(st);
        Ok(tail)
    }
    fn fsync_dir(&self, _d: &Path) -> Result<()> {
        let mut st = self.store.lock().unwrap();
        st.events.push("fsync_dir".into());
        st.fsync_count += 1;
        if st.fsync_fail_at == Some(st.fsync_count) {
            return Err(injected());
        }
        Ok(())
    }
    fn unlink(&self, t: &Target, tail: &str) -> Result<()> {
        let key = t.parent.join(tail).to_string_lossy().into_owned();
        let mut st = self.store.lock().unwrap();
        st.events.push("unlink".into());
        if st.fault == Some("unlink") {
            return Err(injected());
        }
        st.files
            .remove(&key)
            .ok_or_else(|| VanishError::Local(format!("unlink: нет {}", key)))?;
        st.unlink_names.push(key);
        Ok(())
    }
    fn rmdir(&self, _t: &Target, _tail: &str) -> Result<()> {
        let mut st = self.store.lock().unwrap();
        st.events.push("rmdir".into());
        if st.fault == Some("rmdir") {
            return Err(injected());
        }
        Ok(())
    }
    fn trim_mount(&self, _m: &Path) -> Result<bool> {
        Ok(true)
    }
    fn swap_active(&self) -> Result<Vec<SwapEntry>> {
        if self.store.lock().unwrap().fault == Some("swap_active") {
            return Err(injected());
        }
        Ok(vec![])
    }
    fn find_tails(&self, _root: &Path) -> Result<Vec<PathBuf>> {
        let mut st = self.store.lock().unwrap();
        st.events.push("find_tails".into());
        if st.fault == Some("find_tails") {
            return Err(injected());
        }
        if st.signal_on_discovery {
            unsafe {
                libc::raise(libc::SIGINT);
            }
        }
        Ok(st.tails.clone())
    }
}

fn wipe_one(
    store: Shared,
    name: &str,
    size: u64,
    opts: &Options,
    openers: Vec<Opener>,
) -> (RunReport, Result<()>) {
    // кладём файл под именем "/fake/<name>"
    {
        let mut st = store.lock().unwrap();
        let key = format!("/fake/{}", name);
        st.files.insert(
            key.clone(),
            (0..size).map(|i| (i * 31 % 251) as u8).collect(),
        );
    }
    let plat = FakePlatform {
        store: store.clone(),
        openers_list: openers,
    };
    let mut report = RunReport::new();
    let t = Target::from_parts(
        PathBuf::from(format!("/fake/{}", name)),
        0x999,
        size + 1,
        size,
        1,
    );
    let mut pipe = vanish_core::pipeline::Pipeline::new(&plat, opts, &mut report);
    let res = pipe.wipe_target(t, true);
    (report, res)
}

fn base_opts() -> Options {
    Options {
        verify: true,
        ..Options::default()
    }
}

#[test]
fn pipeline_overwrite_unlink_and_reports() {
    let store = store();
    let opts = base_opts();
    let (report, res) = wipe_one(store.clone(), "doc.bin", 40960, &opts, vec![]);
    res.expect("wipe должен пройти");
    let st = store.lock().unwrap();
    // rename сделан и файл снят
    assert_eq!(st.renamed.len(), 1);
    assert_eq!(st.unlink_names.len(), 1);
    // truncate-0 после проходов
    assert!(st.truncate_called);
    // punch (SSD-стратегия)
    assert!(st.punch_called);
    // файл удалён из хранилища
    assert!(st.files.is_empty());
    // событие ok со стратегией overwrite_dealloc и байтами
    let ev = &report.targets[0];
    assert_eq!(ev.status, "ok");
    assert_eq!(ev.strategy.as_deref(), Some("overwrite_dealloc"));
    assert_eq!(ev.bytes, 40960);
    assert!(ev.tail.is_some());
    // инвариант 7: имя исходного файла не попадает в отчёт
    assert!(!serde_json::to_string(&report).unwrap().contains("doc.bin"));
    // инвариант 8: перезаписанное содержимое НЕ осталось (truncate-0 после записей)
    // (данные удалены из fake-storeunlink'ом)
}

#[test]
fn pipeline_verify_detects_pattern() {
    // verify=true; FakeHandlet verify сверяет контент с паттерном.
    // Ничего не подменяем — должен пройти без VerifyMismatch.
    let store = store();
    let mut opts = base_opts();
    opts.passes = 3;
    let (report, res) = wipe_one(store, "d3.bin", 8192, &opts, vec![]);
    res.expect("3 pass + verify должны пройти");
    assert_eq!(report.ok, 1);
    assert_eq!(report.failed, 0);
}

#[test]
fn pipeline_gutmann_35_passes_distinct() {
    let store = store();
    let mut opts = base_opts();
    opts.pattern = PatternChoice::Gutmann;
    let size = 8192u64;
    let (report, res) = wipe_one(store.clone(), "gut.bin", size, &opts, vec![]);
    res.expect("gutmann должен пройти");
    let st = store.lock().unwrap();
    let fp = &st.pass_fingerprints;
    assert_eq!(fp.len(), 35, "должно быть 35 проходов");
    // Содержимое по таблице Гутманна:
    //(row1=0x55, row7=0x00, row2/17=0xAA, rand1=рандом-строка)
    assert!(fp[1].iter().all(|b| *b == 0x55));
    assert!(fp[7].iter().all(|b| *b == 0x00));
    assert!(fp[17].iter().all(|b| *b == 0xAA));
    assert!(!fp[0].iter().all(|b| *b == fp[0][0]), "строка 0 — random");
    assert!(!fp[3].iter().all(|b| *b == fp[3][0]), "строка 3 — random");
    assert_eq!(report.ok, 1);
}

#[test]
fn pipeline_refuses_hardlinks() {
    // Настоящий отказ через прямой Target с nlink=2:
    let store2 = store();
    let plat = FakePlatform {
        store: store2.clone(),
        openers_list: vec![],
    };
    let mut report = RunReport::new();
    let mut opts = base_opts();
    opts.wipe_all_hardlinks = false;
    let t = Target::from_parts("/fake/x.bin".into(), 1, 2, 10, 2);
    {
        let mut st = store2.lock().unwrap();
        st.files.insert("/fake/x.bin".into(), vec![7u8; 10]);
    }
    let mut pipe = vanish_core::pipeline::Pipeline::new(&plat, &opts, &mut report);
    let res = pipe.wipe_target(t, true);
    assert!(matches!(res, Err(VanishError::HardLinks { nlink: 2 })));
    // данные НЕ тронуты
    assert_eq!(
        store2
            .lock()
            .unwrap()
            .files
            .get("/fake/x.bin")
            .unwrap()
            .len(),
        10
    );
}

#[test]
fn pipeline_refuses_busy() {
    let store = store();
    let opts = base_opts();
    let openers = vec![Opener {
        pid: 4242,
        exe: "/bin/sleeper".into(),
    }];
    let (report, res) = wipe_one(store, "busy.bin", 2048, &opts, openers);
    match res {
        Err(VanishError::Busy { pids }) => assert!(pids.contains(&4242)),
        other => panic!("ожидался Busy, получено ok={}", other.is_ok()),
    }
    assert_eq!(report.rejected, 0); // ошибка возвращена CLI как reject — event не пушится ядром при Err
}

#[test]
fn pipeline_dry_run_touches_nothing() {
    let store = store();
    let mut opts = base_opts();
    opts.dry_run = true;
    let (report, res) = wipe_one(store.clone(), "dry.bin", 4096, &opts, vec![]);
    res.expect("dry-run проходит");
    let st = store.lock().unwrap();
    assert!(st.files.contains_key("/fake/dry.bin"));
    assert!(st.renamed.is_empty());
    assert!(st.unlink_names.is_empty());
    assert_eq!(report.ok, 0);
    assert_eq!(report.skipped, 1);
    assert_eq!(report.targets[0].status, "skipped");
}

#[test]
fn relative_target_is_rejected_before_any_rename_or_write() {
    let shared = store();
    let plat = FakePlatform {
        store: shared.clone(),
        openers_list: vec![],
    };
    let mut report = RunReport::new();
    let t = Target::from_parts(PathBuf::from("relative.bin"), 0x999, 2, 1, 1);
    let opts = base_opts();
    let mut pipe = vanish_core::pipeline::Pipeline::new(&plat, &opts, &mut report);
    let error = pipe
        .wipe_target(t, true)
        .expect_err("a relative target must be rejected");
    assert!(matches!(error, VanishError::UnsafePath(_)));
    let st = shared.lock().unwrap();
    assert!(st.renamed.is_empty());
    assert!(st.events.is_empty());
    assert!(!st.truncate_called);
}

#[test]
fn dry_run_tree_reports_planned_directories_not_non_empty_skips() {
    let fixture = Fixture::new();
    let root = fixture.0.clone();
    std::fs::create_dir(root.join("sub")).unwrap();
    std::fs::write(root.join("sub/child.bin"), [1u8; 32]).unwrap();
    let shared = store();
    let plat = FakePlatform {
        store: shared.clone(),
        openers_list: vec![],
    };
    let mut opts = base_opts();
    opts.dry_run = true;
    let mut report = RunReport::new();
    let mut pipe = vanish_core::pipeline::Pipeline::new(&plat, &opts, &mut report);
    pipe.wipe_any(&root);
    assert!(report.targets.iter().any(|event| event.kind == "dir"));
    assert!(report
        .targets
        .iter()
        .filter(|event| event.kind == "dir")
        .all(|event| event.reason.as_deref() == Some("dry-run")));
    assert!(!report.targets.iter().any(|event| event
        .reason
        .as_deref()
        .is_some_and(|r| r.contains("не пуст"))));
    assert!(root.join("sub/child.bin").exists());
}

#[test]
fn pipeline_streams_removed() {
    let store = store();
    {
        let mut st = store.lock().unwrap();
        st.streams_names.push("user.mark".into());
        st.streams_names.push("user.sidelink".into());
    }
    let opts = base_opts();
    let (report, res) = wipe_one(store.clone(), "xs.bin", 4096, &opts, vec![]);
    res.expect("wipe прошёл");
    assert!(store.lock().unwrap().streams_names.is_empty());
    let ev = &report.targets[0];
    assert_eq!(ev.status, "ok");
}

#[test]
fn pipeline_zero_pattern_pass_email() {
    let store = store();
    let mut opts = base_opts();
    opts.pattern = PatternChoice::Zero;
    opts.verify = true;
    let (report, res) = wipe_one(store.clone(), "zz.bin", 512, &opts, vec![]);
    res.expect("zero паттерн тоже должен пройти");
    // после первой записи данные — нули; содержимое до truncate недоступно в fake.
    assert_eq!(report.ok, 1);
}

#[test]
fn chunks_iteration_works() {
    let c: Vec<(u64, u64)> = vanish_core::util::iterate_chunks(4096, 10000, 4096)
        .map(|x| (x.offset, x.len))
        .collect();
    assert_eq!(c.len(), 3);
    assert_eq!(c[2], (12288, 1808));
}

#[test]
fn multi_extent_pass_is_synced_before_any_verification() {
    let shared = store();
    shared.lock().unwrap().extents = Some(vec![
        Extent {
            logical: 0,
            len: 16,
        },
        Extent {
            logical: 32,
            len: 16,
        },
    ]);
    let mut opts = base_opts();
    opts.passes = 3;
    let (report, result) = wipe_one(shared.clone(), "extent.bin", 64, &opts, vec![]);
    result.unwrap();
    let st = shared.lock().unwrap();
    let mut expected = vec!["fsinfo", "rename", "fsync_dir", "open"];
    for _ in 0..3 {
        expected.extend([
            "write:0:16",
            "write:32:16",
            "sync",
            "verify:0:16",
            "verify:32:16",
        ]);
    }
    expected.extend(["truncate", "sync", "unlink", "fsync_dir"]);
    assert_eq!(st.events, expected);
    assert_eq!(report.ok, 1);
}

#[test]
fn required_operation_failures_never_report_success() {
    for fault in ["write", "sync", "verify", "unlink"] {
        let shared = store();
        shared.lock().unwrap().fault = Some(fault);
        let (report, result) = wipe_one(
            shared.clone(),
            "secret-original-file",
            64,
            &base_opts(),
            vec![],
        );
        assert!(result.is_err(), "fault {fault}");
        assert_eq!(report.ok, 0, "fault {fault}");
        if fault != "unlink" {
            assert!(!shared.lock().unwrap().truncate_called, "fault {fault}");
        }
    }
    for fail_at in [1, 2] {
        let shared = store();
        shared.lock().unwrap().fsync_fail_at = Some(fail_at);
        let (report, result) = wipe_one(shared.clone(), "fsync.bin", 64, &base_opts(), vec![]);
        assert!(matches!(result, Err(VanishError::Io(_))));
        assert_eq!(report.ok, 0);
        if fail_at == 1 {
            assert_eq!(
                shared.lock().unwrap().events,
                ["fsinfo", "rename", "fsync_dir"]
            );
        }
    }
    let shared = store();
    shared.lock().unwrap().sync_fail_at = Some(2); // final truncate sync
    let (report, result) = wipe_one(shared.clone(), "final-sync.bin", 64, &base_opts(), vec![]);
    assert!(result.is_err());
    assert_eq!(report.ok, 0);
    let st = shared.lock().unwrap();
    assert!(st.truncate_called);
    assert!(!st.events.contains(&"unlink".into()));
}

#[test]
fn arbitrary_backend_errors_are_redacted_and_verify_mismatch_is_failed() {
    let shared = store();
    let plat = FakePlatform {
        store: shared,
        openers_list: vec![],
    };
    let opts = base_opts();
    let path = Path::new("/secret/secret-original-file");
    let mut report = RunReport::new();
    {
        let mut pipe = vanish_core::pipeline::Pipeline::new(&plat, &opts, &mut report);
        for error in [
            injected(),
            VanishError::Local("secret-original-file secret-stream-name".into()),
            VanishError::UnsafePath("secret-original-file".into()),
            VanishError::IdentityMismatch("secret-original-file".into()),
            VanishError::CowFs {
                fs: "secret-original-file".into(),
            },
            VanishError::VerifyMismatch { offset: 42 },
        ] {
            pipe.record_error("file", path, &error);
        }
    }
    assert_eq!(report.failed, 3);
    assert_eq!(report.rejected, 3);
    assert_eq!(
        report.targets.last().unwrap().reason.as_deref(),
        Some("verify_mismatch: offset=42")
    );
    assert_private(&report);
}

fn assert_private(report: &RunReport) {
    let json = serde_json::to_string(report).unwrap();
    for secret in [
        "secret-original-file",
        "secret-stream-name",
        "/secret/mount",
    ] {
        assert!(!json.contains(secret), "report exposed {secret}: {json}");
    }
}

#[test]
fn warning_details_and_stream_names_are_private() {
    for fault in ["stream", "dontneed"] {
        let shared = store();
        {
            let mut st = shared.lock().unwrap();
            st.fault = Some(fault);
            st.streams_names.push("secret-stream-name".into());
        }
        let (report, result) = wipe_one(shared, "secret-original-file", 64, &base_opts(), vec![]);
        result.unwrap();
        assert!(!report.targets[0].warnings.is_empty());
        assert_private(&report);
    }
}

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        Self::with_preferred_base(Path::new("/tmp/opencode"))
    }

    fn with_preferred_base(preferred: &Path) -> Self {
        let base = if preferred.is_dir() {
            preferred.to_path_buf()
        } else {
            std::env::temp_dir()
        };
        let path = base.join(format!("vanish-core-{}", vanish_core::util::random_tail()));
        // Exclusive creation: never reuse an existing fixture directory.
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn file(&self, name: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, [7u8; 64]).unwrap();
        path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Only this test's unique disposable fixture is removed.
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn add_fake(shared: &Shared, path: &Path) {
    shared
        .lock()
        .unwrap()
        .files
        .insert(path.to_string_lossy().into_owned(), vec![7u8; 64]);
}

#[test]
fn fixture_falls_back_when_preferred_directory_is_absent() {
    let owner = Fixture::new();
    let missing = owner.0.join("not-created");
    let fixture = Fixture::with_preferred_base(&missing);
    assert_eq!(fixture.0.parent(), Some(std::env::temp_dir().as_path()));
    assert!(!missing.exists());
}

#[test]
fn no_rename_non_utf8_basename_is_rejected_before_any_backend_operation() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let fixture = Fixture::new();
    let name = OsString::from_vec(b"own-disposable-\xff".to_vec());
    let path = fixture.0.join(name);
    let original = b"disposable original bytes";
    std::fs::write(&path, original).unwrap();
    let shared = store();
    let plat = FakePlatform {
        store: shared.clone(),
        openers_list: vec![],
    };
    let mut report = RunReport::new();
    for (rename, allow_rename) in [(false, true), (false, false), (true, false)] {
        let mut opts = base_opts();
        opts.rename = rename;
        let mut pipe = vanish_core::pipeline::Pipeline::new(&plat, &opts, &mut report);
        let target = Target::from_parts(path.clone(), 1, 2, 64, 1);
        assert!(matches!(
            pipe.wipe_target(target, allow_rename),
            Err(VanishError::UnsafePath(_))
        ));
        if !rename {
            let target = Target::from_parts(path.clone(), 1, 3, 0, 2);
            assert!(matches!(
                pipe.wipe_dir(target),
                Err(VanishError::UnsafePath(_))
            ));
        }
    }
    // The fake store's string keys cannot represent this basename. Any backend
    // call would either be recorded or fail for a different reason; none occurs.
    let st = shared.lock().unwrap();
    assert!(st.events.is_empty());
    assert!(st.files.is_empty());
    assert!(st.renamed.is_empty());
    assert!(st.unlink_names.is_empty());
    assert_eq!(report.ok, 0);
    assert_eq!(std::fs::read(&path).unwrap(), original);
}

#[test]
fn walk_symlink_skip_is_structured_and_private() {
    let fixture = Fixture::new();
    let link = fixture.0.join("secret-original-file");
    std::os::unix::fs::symlink("secret-stream-name", &link).unwrap();
    let shared = store();
    let plat = FakePlatform {
        store: shared,
        openers_list: vec![],
    };
    let mut report = RunReport::new();
    vanish_core::pipeline::Pipeline::new(&plat, &base_opts(), &mut report).wipe_any(&fixture.0);
    assert_eq!(report.skipped, 2); // symlink and its nonempty parent
    assert!(report
        .targets
        .iter()
        .any(|ev| ev.name_hash == vanish_core::util::name_sha256(&link) && ev.status == "skipped"));
    assert_private(&report);
}

#[test]
fn missing_walk_root_is_an_error() {
    let fixture = Fixture::new();
    let missing = fixture.0.join("secret-original-file");
    assert!(vanish_core::walk::build(&missing, &base_opts()).is_err());
    let plat = FakePlatform {
        store: store(),
        openers_list: vec![],
    };
    let mut report = RunReport::new();
    vanish_core::pipeline::Pipeline::new(&plat, &base_opts(), &mut report).wipe_any(&missing);
    assert_eq!(report.failed, 1);
    assert_private(&report);
}

#[test]
fn wipe_any_records_verify_failure_without_truncating() {
    let fixture = Fixture::new();
    let path = fixture.file("secret-original-file");
    let shared = store();
    add_fake(&shared, &path);
    shared.lock().unwrap().fault = Some("verify");
    let plat = FakePlatform {
        store: shared.clone(),
        openers_list: vec![],
    };
    let mut report = RunReport::new();
    vanish_core::pipeline::Pipeline::new(&plat, &base_opts(), &mut report).wipe_any(&path);
    assert_eq!(report.failed, 1);
    assert_eq!(report.rejected, 0);
    assert_eq!(report.ok, 0);
    assert!(!shared.lock().unwrap().truncate_called);
    assert_private(&report);
}

#[test]
fn directory_rename_is_durable_before_rmdir() {
    for fail_at in [None, Some(1), Some(2)] {
        let shared = store();
        {
            let mut st = shared.lock().unwrap();
            st.files.insert("/fake/dir".into(), vec![]);
            st.fsync_fail_at = fail_at;
        }
        let plat = FakePlatform {
            store: shared.clone(),
            openers_list: vec![],
        };
        let mut report = RunReport::new();
        let result = vanish_core::pipeline::Pipeline::new(&plat, &base_opts(), &mut report)
            .wipe_dir(Target::from_parts("/fake/dir".into(), 1, 2, 0, 2));
        assert_eq!(result.is_err(), fail_at.is_some());
        assert_eq!(report.ok, usize::from(fail_at.is_none()));
        let events = shared.lock().unwrap().events.clone();
        if fail_at == Some(1) {
            assert_eq!(events, ["fsinfo", "rename", "fsync_dir"]);
        } else {
            assert_eq!(
                events,
                ["fsinfo", "rename", "fsync_dir", "rmdir", "fsync_dir"]
            );
        }
    }
}

#[test]
fn recovery_records_and_returns_discovery_metadata_and_wipe_errors() {
    let fixture = Fixture::new();
    for fault in ["find_tails", "missing", "verify", "unlink"] {
        let shared = store();
        let path = fixture.0.join("secret-original-file");
        if fault != "missing" {
            std::fs::write(&path, [7u8; 64]).unwrap();
        }
        add_fake(&shared, &path);
        {
            let mut st = shared.lock().unwrap();
            st.tails.push(path.clone());
            st.fault = Some(fault);
        }
        let plat = FakePlatform {
            store: shared,
            openers_list: vec![],
        };
        let mut report = RunReport::new();
        let result =
            vanish_core::recovery::run(&plat, &[fixture.0.clone()], &base_opts(), &mut report);
        assert!(result.is_err(), "fault {fault}");
        assert_eq!(report.failed, 1, "fault {fault}");
        assert_eq!(report.ok, 0);
        assert_private(&report);
        if path.exists() {
            std::fs::remove_file(path).unwrap();
        }
    }
}

#[test]
fn recovery_rejects_symlink_and_continues_after_failed_tail() {
    let fixture = Fixture::new();
    let link = fixture.0.join("secret-original-file");
    std::os::unix::fs::symlink("secret-stream-name", &link).unwrap();
    let file = fixture.file("good-tail");
    let shared = store();
    add_fake(&shared, &file);
    shared.lock().unwrap().tails = vec![link, file];
    let plat = FakePlatform {
        store: shared.clone(),
        openers_list: vec![],
    };
    let mut report = RunReport::new();
    assert!(
        vanish_core::recovery::run(&plat, &[fixture.0.clone()], &base_opts(), &mut report).is_err()
    );
    assert_eq!(report.rejected, 1);
    assert_eq!(report.ok, 1);
    assert!(shared.lock().unwrap().renamed.is_empty());
    assert_private(&report);
}

#[test]
fn directory_recovery_propagates_required_errors_and_skips_nonempty() {
    let fixture = Fixture::new();
    let dir = fixture.0.join("secret-original-file");
    std::fs::create_dir(&dir).unwrap();
    for fault in ["rmdir", "fsync_dir", "none"] {
        let shared = store();
        {
            let mut st = shared.lock().unwrap();
            st.tails.push(dir.clone());
            st.fault = Some(fault);
            if fault == "fsync_dir" {
                st.fsync_fail_at = Some(1);
            }
        }
        let plat = FakePlatform {
            store: shared.clone(),
            openers_list: vec![],
        };
        let mut report = RunReport::new();
        if fault == "none" {
            std::fs::write(dir.join("child"), b"fixture").unwrap();
        }
        let result =
            vanish_core::recovery::run_dirs(&plat, &[fixture.0.clone()], &base_opts(), &mut report);
        if fault == "none" {
            assert_eq!(result.unwrap(), 0);
            assert_eq!(report.skipped, 1);
            assert!(!shared.lock().unwrap().events.contains(&"rmdir".into()));
        } else {
            assert!(result.is_err());
            assert_eq!(report.failed, 1);
        }
        assert_eq!(report.ok, 0);
        assert_private(&report);
    }
}

#[test]
fn cancellation_finishes_all_extents_and_passes_but_starts_no_next_target() {
    const CHILD: &str = "VANISH_CORE_CANCELLATION_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "cancellation_finishes_all_extents_and_passes_but_starts_no_next_target",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    // This process runs only this test: no global signal/reset races with other tests.
    vanish_core::signal::install();
    let fixture = Fixture::new();
    let a = fixture.file("a");
    let b = fixture.file("b");
    let shared = store();
    add_fake(&shared, &a);
    add_fake(&shared, &b);
    {
        let mut st = shared.lock().unwrap();
        st.extents = Some(vec![
            Extent {
                logical: 0,
                len: 16,
            },
            Extent {
                logical: 32,
                len: 16,
            },
        ]);
        st.signal_on_write = true;
    }
    let plat = FakePlatform {
        store: shared.clone(),
        openers_list: vec![],
    };
    let mut opts = base_opts();
    opts.passes = 3;
    let mut report = RunReport::new();
    vanish_core::pipeline::Pipeline::new(&plat, &opts, &mut report).wipe_any(&fixture.0);
    assert!(vanish_core::signal::shutdown_requested());
    assert_eq!(report.ok, 1);
    assert_eq!(report.skipped, 2); // remaining file AND root directory
    {
        let st = shared.lock().unwrap();
        assert_eq!(
            st.events.iter().filter(|e| e.starts_with("write:")).count(),
            6
        );
        assert_eq!(
            st.events
                .iter()
                .filter(|e| e.starts_with("verify:"))
                .count(),
            6
        );
        assert_eq!(st.unlink_names.len(), 1);
        assert_eq!(st.renamed.len(), 1);
        assert!(!st.events.contains(&"rmdir".into()));
    }
    let events = shared.lock().unwrap().events.clone();
    let mut pipe = vanish_core::pipeline::Pipeline::new(&plat, &opts, &mut report);
    pipe.wipe_target(Target::from_parts(a, 1, 1, 64, 1), true)
        .unwrap();
    pipe.wipe_dir(Target::from_parts(fixture.0.clone(), 1, 2, 0, 1))
        .unwrap();
    pipe.wipe_any(&b);
    vanish_core::recovery::run(&plat, &[fixture.0.clone()], &opts, &mut report).unwrap();
    vanish_core::recovery::run_dirs(&plat, &[fixture.0.clone()], &opts, &mut report).unwrap();
    assert_eq!(shared.lock().unwrap().events, events);
}

#[test]
fn recovery_cancellation_checks_each_discovered_tail_before_start() {
    const CHILD: &str = "VANISH_CORE_RECOVERY_CANCELLATION_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "recovery_cancellation_checks_each_discovered_tail_before_start",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    vanish_core::signal::install();
    let fixture = Fixture::new();
    let a = fixture.file("a");
    let b = fixture.file("b");
    let shared = store();
    add_fake(&shared, &a);
    add_fake(&shared, &b);
    {
        let mut st = shared.lock().unwrap();
        st.tails = vec![a, b];
        st.signal_on_discovery = true;
    }
    let plat = FakePlatform {
        store: shared.clone(),
        openers_list: vec![],
    };
    let mut report = RunReport::new();
    let count = vanish_core::recovery::run(
        &plat,
        &[fixture.0.clone(), fixture.0.clone()],
        &base_opts(),
        &mut report,
    )
    .unwrap();
    assert_eq!(count, 0);
    assert_eq!(report.ok, 0);
    assert_eq!(report.skipped, 3); // two discovered tails, then the next root
    assert_eq!(shared.lock().unwrap().events, ["find_tails"]);
}
