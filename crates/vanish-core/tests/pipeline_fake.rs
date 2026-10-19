//! Интеграционные тесты конвейера vanish-core на FakePlatform.
//! Проверяют инварианты: 9 Security Invariants (см. docs/PLAN.md §14).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use vanish_core::config::{Options, PatternChoice};
use vanish_core::error::{Result, VanishError};
use vanish_core::fsinfo::{
    DeviceKind, EncryptionState, FsKind, JournalState, VolumeInfo,
};
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
}

type Shared = Arc<Mutex<Store>>;

fn store() -> Shared {
    Arc::new(Mutex::new(Store::default()))
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
        Ok(None)
    }
    fn overwrite(&mut self, _off: u64, len: u64, gen: &mut PatternStream) -> Result<()> {
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
            let start = pos as usize;
            data[start..start + n].copy_from_slice(&buf);
            pos += n as u64;
        }
        Ok(())
    }
    fn verify(&mut self, _off: u64, len: u64, gen: &mut PatternStream) -> Result<()> {
        let chunk = 4096u64;
        let mut pos = 0u64;
        while pos < len {
            let n = chunk.min(len - pos) as usize;
            let mut buf = vec![0u8; n];
            gen.fill(&mut buf);
            let st = self.store.lock().unwrap();
            let data = st.files.get(&self.key).expect("data");
            if data[pos as usize..pos as usize + n] != buf[..] {
                return Err(VanishError::VerifyMismatch { offset: pos });
            }
            pos += n as u64;
        }
        Ok(())
    }
    fn sync(&self) -> Result<()> {
        Ok(())
    }
    fn punch(&mut self) -> Result<bool> {
        self.store.lock().unwrap().punch_called = true;
        Ok(true)
    }
    fn truncate0(&mut self) -> Result<()> {
        let mut st = self.store.lock().unwrap();
        st.truncate_called = true;
        if let Some(d) = st.files.get_mut(&self.key) {
            d.clear();
        }
        self.len = 0;
        Ok(())
    }
    fn dontneed(&self) -> Result<()> {
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
        Ok(self.info())
    }
    fn openers(&self, _dev: u64, _ino: u64) -> Result<Vec<Opener>> {
        Ok(self.openers_list.clone())
    }
    fn open_handle(&self, t: &Target) -> Result<Box<dyn WipeHandle>> {
        let st = self.store.lock().unwrap();
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
        Ok(st
            .streams_names
            .iter()
            .map(|n| (n.clone(), 4u64))
            .collect())
    }
    fn erase_stream(&self, _t: &Target, name: &str) -> Result<()> {
        self.store.lock().unwrap().streams_names.retain(|n| n != name);
        Ok(())
    }
    fn rename_to_tail(&self, t: &Target) -> Result<String> {
        let tail = format!(".{}", vanish_core::util::random_tail());
        let old_key = t.abs.to_string_lossy().into_owned();
        let new_key = t.parent.join(&tail).to_string_lossy().into_owned();
        let mut st = self.store.lock().unwrap();
        let data = st.files.remove(&old_key).ok_or_else(|| {
            VanishError::Local(format!("rename: нет ключа {}", old_key))
        })?;
        st.files.insert(new_key.clone(), data);
        st.renamed.push((old_key.clone(), new_key.clone()));
        drop(st);
        Ok(tail)
    }
    fn fsync_dir(&self, _d: &Path) -> Result<()> {
        Ok(())
    }
    fn unlink(&self, t: &Target, tail: &str) -> Result<()> {
        let key = t.parent.join(tail).to_string_lossy().into_owned();
        let mut st = self.store.lock().unwrap();
        st.files
            .remove(&key)
            .ok_or_else(|| VanishError::Local(format!("unlink: нет {}", key)))?;
        st.unlink_names.push(key);
        Ok(())
    }
    fn rmdir(&self, _t: &Target, _tail: &str) -> Result<()> {
        Ok(())
    }
    fn trim_mount(&self, _m: &Path) -> Result<bool> {
        Ok(true)
    }
    fn swap_active(&self) -> Result<Vec<SwapEntry>> {
        Ok(vec![])
    }
    fn find_tails(&self, _root: &Path) -> Result<Vec<PathBuf>> {
        Ok(vec![])
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
    let plat = FakePlatform { store: store.clone(), openers_list: openers };
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
    let plat = FakePlatform { store: store2.clone(), openers_list: vec![] };
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
    assert_eq!(store2.lock().unwrap().files.get("/fake/x.bin").unwrap().len(), 10);
}

#[test]
fn pipeline_refuses_busy() {
    let store = store();
    let opts = base_opts();
    let openers = vec![Opener { pid: 4242, exe: "/bin/sleeper".into() }];
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
