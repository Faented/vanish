//! vanish CLI: разбор аргументов, диспетчеризация, коды выхода.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use clap::{Parser, Subcommand};
use vanish_core::config::{Options, PatternChoice};
use vanish_core::platform::Platform;
use vanish_core::report::RunReport;

#[cfg(target_os = "linux")]
use backend_linux as be;

#[cfg(target_os = "macos")]
use backend_macos as be;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use backend_windows as be;

#[derive(Parser, Debug)]
#[command(
    name = "vanish",
    version,
    about = "vanish — честное защищённое удаление (файлы/папки). Отказ лучше иллюзии защищённости."
)]
struct Cli {
    /// цели (файлы или папки)
    #[arg(trailing_var_arg = true)]
    targets: Vec<PathBuf>,

    #[command(subcommand)]
    cmd: Option<Cmd>,

    /// число проходов записи (по умолчанию 1)
    #[arg(long, default_value_t = 1)]
    passes: u8,

    /// лекоторые рattern: random|zero|gutmann|hex:XX
    #[arg(long)]
    pattern: Option<String>,

    #[arg(long)]
    verify: bool,
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    no_rename: bool,
    #[arg(long)]
    no_trim: bool, // выключить per-file deallocate
    #[arg(long)] // FITRIM точки монтирования
    trim: bool,
    #[arg(long)]
    json: bool,
    #[arg(long)]
    report: Option<PathBuf>,
    #[arg(long)]
    accept_cow: bool,
    #[arg(long)]
    no_preserve_root: bool,
    #[arg(long)]
    keep_streams: bool,
    #[arg(long)]
    force_fs: bool,
    #[arg(long)]
    wipe_all_hardlinks: bool,
    #[arg(long)]
    disable_swap_for_wipe: bool,
    #[arg(long)]
    xdev: bool,
    #[arg(long)]
    yes: bool,                 // для device-режима: авто-yes
    #[arg(long)]
    recovery_scan: bool, // альтернатива subcommand
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// диагностика пути (read-only)
    Check {
        /// пути для анализа
        #[arg(trailing_var_arg = true)]
        paths: Vec<PathBuf>,
    },
    /// затирание свободного места в каталоге
    Freespace {
        dir: PathBuf,
        /// лимит байтов (иначе — вся доступность-0.5%)
        #[arg(long)]
        size: Option<u64>,
    },
    /// wipe блочного устройства (корень/Sanitize)
    Device {
        dev: PathBuf,
    },
    /// дожимание хвостов .vanish-v1-*
    Recovery {
        #[arg(trailing_var_arg = true)]
        roots: Vec<PathBuf>,
    },
}

impl Cli {
    fn opts(&self) -> Result<Options, String> {
        let pattern = match self.pattern.as_deref() {
            None => PatternChoice::Random,
            Some("random") => PatternChoice::Random,
            Some("zero") => PatternChoice::Zero,
            Some("gutmann") => PatternChoice::Gutmann,
            Some(s) if s.starts_with("hex:") => {
                let v = u8::from_str_radix(&s[4..], 16).map_err(|_| "hex:X — неверный байт")?;
                if self.passes > 1 || s.len() != 6 {
                    // hex:xx одна с 1 проходом
                }
                PatternChoice::Hex(v)
            }
            Some(other) => return Err(format!("неизвестный pattern: {}", other)),
        };
        let mut passes = self.passes;
        if passes == 0 {
            return Err("--passes должен быть >= 1".into());
        }
        if matches!(pattern, PatternChoice::Hex(_)) && passes > 16 {
            passes = 16; // sane cap
        }
        Ok(Options {
            passes,
            pattern,
            verify: self.verify,
            dry_run: self.dry_run,
            rename: !self.no_rename,
            punch: !self.no_trim,
            trim_mount: self.trim,
            accept_cow: self.accept_cow,
            force_fs: self.force_fs,
            keep_streams: self.keep_streams,
            wipe_all_hardlinks: self.wipe_all_hardlinks,
            disable_swap_for_wipe: self.disable_swap_for_wipe,
            no_preserve_root: self.no_preserve_root,
            xdev: self.xdev,
            json: self.json,
            report_file: self.report.clone(),
            yes: self.yes,
        })
    }
}

fn safety_refuse(path: &Path, o: &Options) -> Option<&'static str> {
    let canon = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let s = canon.to_string_lossy();
    if s == "/" && !o.no_preserve_root {
        return Some("/")
    }
    if !o.force_fs {
        for bad in ["/proc", "/sys", "/dev", "/run"] {
            if s.starts_with(bad) {
                return Some(bad);
            }
        }
    }
    None
}

fn make_platform() -> std::boxed::Box<dyn Platform> {
    be::platform()
}

fn compute_exit(report: &RunReport) -> u8 {
    if report.targets.is_empty() {
        return 0;
    }
    let failed = report.failed;
    let rejected = report.rejected;
    let ok = report.ok;
    if failed > 0 {
        4
    } else if rejected > 0 && ok > 0 {
        1
    } else if rejected > 0 && ok == 0 {
        3
    } else {
        0
    }
}

fn emit(report: &RunReport, cli: &Cli) {
    if cli.json {
        let mut out = std::io::stdout();
        let _ = serde_json::to_writer_pretty(&mut out, report);
        let _ = out.write_all(b"\n");
    } else {
        for t in &report.targets {
            println!(
                "[{}] {} kind={} {} bytes={} {:?}",
                t.status,
                t.kind.as_ref() as &str,
                t.kind,
                t.name_hash.get(0..12).unwrap_or("?"),
                t.bytes,
                t.reason
            );
        }
        if let Some(f) = &cli.report {
            if let Ok(text) = serde_json::to_string_pretty(report) {
                let _ = std::fs::write(f, text);
            }
        }
        eprintln!("{}", report.summary_text());
        for n in &report.notes {
            eprintln!("note: {}", n);
        }
    }
}

fn wipe_mode(cli: &Cli, opts: &Options, plat: Option<std::boxed::Box<dyn Platform>>) -> u8 {
    let plat = plat.unwrap_or_else(make_platform);
    let mut report = RunReport::new();
    vanish_core::signal::install();
    for p in &cli.targets {
        if let Some(bad) = safety_refuse(p, opts) {
            report.note(format!("refused: {} — {}", vanish_core::util::name_sha256(p), bad));
            continue;
        }
        let canon = std::fs::canonicalize(p);
        let target = match canon {
            Ok(c) => c,
            Err(e) => {
                report.note(format!(
                    "missing {} ({}): пропущен",
                    vanish_core::util::name_sha256(p),
                    e
                ));
                continue;
            }
        };
        {
            let mut pipe = vanish_core::pipeline::Pipeline::new(plat.as_ref(), opts, &mut report);
            pipe.wipe_any(&target);
        }
    }
    let code = compute_exit(&report);
    let fin = report.finish(code);
    emit(&fin, cli);
    code
}

fn check_mode(paths: &[PathBuf], cli: &Cli) -> u8 {
    let plat = make_platform();
    let rep = match vanish_core::check::run(plat.as_ref(), paths) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("check не удался: {}", e);
            return 4;
        }
    };
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default());
    } else {
        eprintln!("backend: {}", rep.backend);
        for e in &rep.entries {
            eprintln!(
                "hash={:012}… exists={} kind={} nlink={:?} verdict={}",
                e.name_hash,
                e.exists,
                e.kind,
                e.nlink,
                e.verdict
            );
            if !e.openers.is_empty() {
                eprintln!("  openers: {:?}", e.openers);
            }
        }
        for s in &rep.swap {
            eprintln!("swap: {} {} МБ", s.path, s.size / 1024 / 1024);
        }
    }
    0
}

fn freespace_mode(dir: PathBuf, size: Option<u64>, cli: &Cli, opts: &mut Options) -> u8 {
    #[cfg(target_os = "linux")]
    {
        use std::io::Write;
        let avail = match be::avail_bytes(&dir) {
            Ok(a) => a,
            Err(_) => {
                eprintln!("нет statvfs на dir");
                return 4;
            }
        };
        let budget = size.unwrap_or(avail * 95 / 100);
        eprintln!("freespace: бюджет {} МБ (из доступных {})", budget / 1024 / 1024, avail / 1024 / 1024);
        let tail = format!(".{}", vanish_core::util::random_tail());
        let path = dir.join(tail);
        let file = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(f) => f,
            Err(e) => {
                eprintln!("freespace file create: {}", e);
                return 4;
            }
        };
        let mut w = std::io::BufWriter::with_capacity(1024 * 1024, file);
        let zero = vec![0u8; 1024 * 1024];
        let mut written: u64 = 0;
        while written < budget {
            match w.write_all(&zero) {
                Ok(_) => {
                    written += zero.len() as u64;
                    if written % (256 * 1024 * 1024) == 0 {
                        let _ = w.flush();
                    }
                }
                Err(e) => {
                    // ENOSPC ожидаем на финале
                    if e.kind() != std::io::ErrorKind::StorageFull {
                        let raw = e.raw_os_error().unwrap_or(0);
                        if raw != ENOSPC {
                            eprintln!("freespace write: {} (после {} байт)", e, written);
                            // файл остаётся как хвост —демьз recovery
                            break;
                        }
                    }
                    break;
                }
            }
        }
        let _ = w.flush();
        if let Ok(f) = w.get_mut().sync_all() {
            let _ = f;
        }
        drop(w);
        // данные затёрты в файле — обрабатываем через общий конвейер (tail-name задан).
        let md = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => return 4,
        };
        let mut report = RunReport::new();
        let mut details = vanish_core::util::name_sha256(&path);
        let _ = &mut details;
        let target = vanish_core::platform::Target::from_parts(
            path,
            md.dev(),
            md.ino(),
            md.len(),
            md.nlink() as u32,
        );
        let plat = make_platform();
        {
            let mut pipe = vanish_core::pipeline::Pipeline::new(plat.as_ref(), opts, &mut report);
            if let Err(e) = pipe.wipe_target(target, false) {
                eprintln!("freespace pipeline: {}", e);
            }
        }
        let code = compute_exit(&report);
        let fin = report.finish(code);
        emit(&fin, cli);
        code
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (dir, size, cli, opts);
        eprintln!("freespace: только Linux в v0.1");
        3
    }
}

fn device_mode(dev: PathBuf, cli: &Cli) -> u8 {
    #[cfg(target_os = "linux")]
    {
        if !cli.yes {
            eprint!(
                "ВАРНИНГ: FORMAT/WIPE устройства {} — данные НЕ ВОССТАНОВИМЫ. Наберите yes для продолжения: ",
                dev.display()
            );
            let _ = std::io::stdout().flush();
            let mut line = String::new();
            let _ = std::io::stdin().read_line(&mut line);
            if line.trim() != "yes" {
                eprintln!("отказ; отменено пользователем");
                return 0;
            }
        }
        if be::is_mounted_device(&dev) {
            eprintln!("устройство смонтировано — откажусь; (размонтируйте)");
            return 3;
        }
        let plat = make_platform();
        for s in plat.swap_active().unwrap_or_default() {
            if s.path == dev.display().to_string() {
                eprintln!("устройство активно в swap — откажусь");
                return 3;
            }
        }
        match be::device_wipe(&dev) {
            Ok(r) => {
                eprintln!(
                    "device {}: {} МБ method={} physically_guaranteed={}",
                    r.path,
                    r.size / 1024 / 1024,
                    r.method,
                    r.physical_guaranteed
                );
                if !r.physical_guaranteed {
                    eprintln!(
                        "WARNING: BLKDISCARD — LOGICAL deallocation (TRIM); физическое стирание НЕ ГАРАНТИРОВАНО."
                    );
                    eprintln!("Рекомендация: сначала cryptsetup luksErase ключа, затем NVMe/ATA Secure Erase, затемшифровать заново.");
                }
                0
            }
            Err(e) => {
                eprintln!("device wipe: {} (нужен root?)", e);
                4
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (dev, cli);
        eprintln!("device: только Linux в v0.1");
        3
    }
}

fn recovery_mode(roots: Vec<PathBuf>, cli: &Cli, opts: &mut Options) -> u8 {
    let plat = make_platform();
    let roots: Vec<PathBuf> = if roots.is_empty() {
        vec![std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))]
    } else {
        roots
    };
    let mut report = RunReport::new();
    match vanish_core::recovery::run(plat.as_ref(), &roots, opts, &mut report) {
        Ok(n) => report.note(format!("найдено хвостов-файлов: {}", n)),
        Err(e) => {
            eprintln!("recovery: {}", e);
        }
    }
    match vanish_core::recovery::run_dirs(plat.as_ref(), &roots, opts, &mut report) {
        Ok(n) => report.note(format!("убрано пустых хвостов-каталогов: {}", n)),
        Err(e) => {
            eprintln!("recovery(директории): {}", e);
        }
    }
    let code = compute_exit(&report);
    let fin = report.finish(code);
    emit(&fin, cli);
    code
}

const ENOSPC: i32 = 28; // linux errno: no space left on device

fn main() -> ExitCode {
    let cli = Cli::parse();
    let opts = match cli.opts() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("usage: {}", e);
            return ExitCode::from(2);
        }
    };
    let mut opts = opts;
    let code = match &cli.cmd {
        Some(Cmd::Check { paths }) => check_mode(paths, &cli),
        Some(Cmd::Freespace { dir, size }) => freespace_mode(dir.clone(), *size, &cli, &mut opts),
        Some(Cmd::Device { dev }) => device_mode(dev.clone(), &cli),
        Some(Cmd::Recovery { roots }) => recovery_mode(roots.clone(), &cli, &mut opts),
        None => {
            if cli.recovery_scan {
                recovery_mode(cli.targets.clone(), &cli, &mut opts)
            } else if cli.targets.is_empty() {
                eprintln!("vanish: укажите цели (или используйте 'check'/'freespace'/'device'/'recovery-scan')");
                2
            } else {
                wipe_mode(&cli, &opts, None)
            }
        }
    };
    ExitCode::from(code)
}
