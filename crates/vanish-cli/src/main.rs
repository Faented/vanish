//! vanish CLI: разбор аргументов, диспетчеризация, коды выхода.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use clap::{Parser, Subcommand};
use serde::Serialize;
use vanish_core::config::{Options, PatternChoice};
use vanish_core::error::VanishError;
use vanish_core::platform::{Platform, Target};
use vanish_core::report::{RunReport, TargetEvent};

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
    #[arg(value_name = "TARGET", num_args = 0..)]
    targets: Vec<PathBuf>,

    #[command(subcommand)]
    cmd: Option<Cmd>,

    /// число проходов записи (по умолчанию 1)
    #[arg(long, global = true, default_value_t = 1)]
    passes: u8,
    /// pattern: random|zero|gutmann|hex:XX
    #[arg(long, global = true)]
    pattern: Option<String>,
    #[arg(long, global = true)]
    verify: bool,
    #[arg(long, global = true)]
    dry_run: bool,
    #[arg(long, global = true)]
    no_rename: bool,
    #[arg(long, global = true)]
    no_trim: bool,
    #[arg(long, global = true)]
    trim: bool,
    #[arg(long, global = true)]
    json: bool,
    #[arg(long, global = true)]
    report: Option<PathBuf>,
    #[arg(long, global = true)]
    accept_cow: bool,
    #[arg(long, global = true)]
    no_preserve_root: bool,
    #[arg(long, global = true)]
    keep_streams: bool,
    #[arg(long, global = true)]
    force_fs: bool,
    #[arg(long, global = true)]
    wipe_all_hardlinks: bool,
    #[arg(long, global = true)]
    disable_swap_for_wipe: bool,
    #[arg(long, global = true)]
    xdev: bool,
    #[arg(long, global = true)]
    yes: bool,
    #[arg(long, global = true)]
    recovery_scan: bool,
    /// freespace limit in bytes (default: 95% of available space)
    #[arg(long, global = true)]
    size: Option<u64>,
    /// самоверификация бинаря: SHA-256 текущего exe против манифеста SHA256SUMS
    #[arg(
        long,
        global = true,
        num_args = 0..=1,
        default_missing_value = "",
        value_name = "MANIFEST"
    )]
    selfcheck: Option<String>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// диагностика пути (read-only)
    Check {
        /// пути для анализа
        #[arg(value_name = "PATH", num_args = 0..)]
        paths: Vec<PathBuf>,
    },
    /// затирание свободного места в каталоге
    Freespace { dir: PathBuf },
    /// wipe блочного устройства (временно отключено; устройство не открывается)
    Device { dev: PathBuf },
    /// дожимание хвостов .vanish-v1-*
    Recovery {
        #[arg(value_name = "ROOT", num_args = 0..)]
        roots: Vec<PathBuf>,
    },
}

impl Cli {
    fn opts(&self) -> Result<Options, String> {
        let pattern = match self.pattern.as_deref() {
            None | Some("random") => PatternChoice::Random,
            Some("zero") => PatternChoice::Zero,
            Some("gutmann") => PatternChoice::Gutmann,
            Some(s) if s.starts_with("hex:") => {
                let v = u8::from_str_radix(&s[4..], 16).map_err(|_| "hex:X — неверный байт")?;
                PatternChoice::Hex(v)
            }
            Some(other) => return Err(format!("неизвестный pattern: {}", other)),
        };
        let mut passes = self.passes;
        if passes == 0 {
            return Err("--passes должен быть >= 1".into());
        }
        if matches!(pattern, PatternChoice::Hex(_)) && passes > 16 {
            passes = 16;
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

struct ReportSink {
    file: File,
}

struct PreparedTarget {
    path: PathBuf,
    canonical: PathBuf,
}

fn absolute_normalized(path: &Path) -> io::Result<PathBuf> {
    let raw = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut result = PathBuf::new();
    for component in raw.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                result.pop();
            }
            other => result.push(other.as_os_str()),
        }
    }
    Ok(result)
}

fn has_symlink_component(path: &Path) -> io::Result<bool> {
    let absolute = absolute_normalized(path)?;
    let mut current = PathBuf::new();
    for component in absolute.components() {
        current.push(component.as_os_str());
        if let Ok(md) = std::fs::symlink_metadata(&current) {
            if md.file_type().is_symlink() {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Open the report before anything that can remove or overwrite a user target.
/// `inside_targets` is used for modes which delete descendants of their roots.
fn prepare_report(
    path: Option<&Path>,
    targets: &[PathBuf],
    inside_targets: bool,
) -> Result<Option<ReportSink>, String> {
    let Some(path) = path else { return Ok(None) };
    let absolute = absolute_normalized(path).map_err(|_| "invalid report path")?;
    if has_symlink_component(&absolute).map_err(|_| "invalid report path")? {
        return Err("report path contains a symlink".into());
    }
    match std::fs::symlink_metadata(&absolute) {
        Ok(_) => return Err("report path must be a new file".into()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err("cannot inspect report path".into()),
    }
    let parent = absolute.parent().ok_or("invalid report path")?;
    if !parent.is_dir() {
        return Err("report parent is not a directory".into());
    }
    let parent = std::fs::canonicalize(parent).map_err(|_| "cannot resolve report parent")?;
    let report_canon = parent.join(absolute.file_name().ok_or("invalid report path")?);

    for target in targets {
        let target_abs = absolute_normalized(target).map_err(|_| "invalid target path")?;
        if target_abs == absolute {
            return Err("report path is also a target".into());
        }
        match std::fs::symlink_metadata(target) {
            Ok(_) => {}
            Err(_) => continue,
        }
        let target_canon = match std::fs::canonicalize(target) {
            Ok(path) => path,
            Err(_) => continue,
        };
        if inside_targets && report_canon.starts_with(&target_canon) {
            return Err("report path is inside a deleted target".into());
        }
    }

    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&absolute)
        .map_err(|_| "cannot create report file")?;
    #[cfg(unix)]
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|_| "cannot secure report file")?;
    Ok(Some(ReportSink { file }))
}

fn write_serialized<T: Serialize>(sink: &mut ReportSink, value: &T) -> io::Result<()> {
    let bytes = serde_json::to_vec_pretty(value).map_err(io::Error::other)?;
    sink.file.set_len(0)?;
    sink.file.write_all(&bytes)?;
    sink.file.write_all(b"\n")?;
    sink.file.flush()?;
    sink.file.sync_all()
}

fn safety_refuse(path: &Path, o: &Options) -> Option<&'static str> {
    let canon = std::fs::canonicalize(path).ok()?;
    let s = canon.to_string_lossy();
    if s == "/" && !o.no_preserve_root {
        return Some("preserve_root");
    }
    if !o.force_fs {
        for bad in ["/proc", "/sys", "/dev", "/run"] {
            if s == bad || s.starts_with(&format!("{bad}/")) {
                return Some("protected filesystem");
            }
        }
    }
    None
}

#[cfg(unix)]
fn hardlink_refused(md: &std::fs::Metadata, opts: &Options) -> bool {
    md.nlink() > 1 && !opts.wipe_all_hardlinks
}

#[cfg(not(unix))]
fn hardlink_refused(_md: &std::fs::Metadata, _opts: &Options) -> bool {
    false
}

fn make_platform() -> Box<dyn Platform> {
    be::platform()
}

fn compute_exit(report: &RunReport) -> u8 {
    let interrupted = report.targets.iter().any(|event| {
        event.status == "skipped"
            && event
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("SIGINT") || reason.contains("SIGTERM"))
    });
    if report.failed > 0 {
        4
    } else if report.rejected > 0 && report.ok == 0 && !interrupted {
        3
    } else if report.ok > 0 && report.rejected == 0 && !interrupted {
        0
    } else if report.rejected == 0 && !interrupted {
        // A dry-run is intentionally represented by skipped events. Planning
        // without touching anything is a successful operation, not partial.
        0
    } else if report.targets.is_empty() && !interrupted {
        0
    } else {
        1
    }
}

fn emit(report: &RunReport, cli: &Cli, mut sink: Option<ReportSink>) -> bool {
    let mut success = true;
    if cli.json {
        let mut out = io::stdout().lock();
        if serde_json::to_writer_pretty(&mut out, report).is_err() || out.write_all(b"\n").is_err()
        {
            success = false;
        }
    } else {
        let mut out = io::stdout().lock();
        for target in &report.targets {
            if writeln!(
                out,
                "[{}] {} {} bytes={} {:?}",
                target.status,
                target.kind,
                target.name_hash.get(0..12).unwrap_or("?"),
                target.bytes,
                target.reason
            )
            .is_err()
            {
                success = false;
                break;
            }
        }
        eprintln!("{}", report.summary_text());
        for note in &report.notes {
            eprintln!("note: {}", note);
        }
    }
    if let Some(ref mut sink) = sink {
        if write_serialized(sink, report).is_err() {
            eprintln!("report output failed");
            success = false;
        }
    }
    success
}

fn finish_run(report: RunReport, code: u8, cli: &Cli, sink: Option<ReportSink>) -> u8 {
    let finished = report.finish(code);
    if emit(&finished, cli, sink) {
        code
    } else {
        4
    }
}

fn record_rejection(report: &mut RunReport, kind: &str, path: &Path, detail: &'static str) {
    report.push(TargetEvent {
        kind: kind.into(),
        name_hash: vanish_core::util::name_sha256(path),
        tail: None,
        strategy: None,
        status: "rejected".into(),
        reason: Some(detail.into()),
        bytes: 0,
        warnings: vec![],
        guarantees: None,
        elapsed_ms: 0,
    });
}

fn wipe_mode(cli: &Cli, opts: &Options, plat: Option<Box<dyn Platform>>) -> u8 {
    let sink = match prepare_report(cli.report.as_deref(), &cli.targets, !opts.dry_run) {
        Ok(sink) => sink,
        Err(_) => {
            eprintln!("report setup failed");
            return 4;
        }
    };
    let plat = plat.unwrap_or_else(make_platform);
    let mut report = RunReport::new();
    vanish_core::signal::install();

    // Resolve and validate every top-level target before starting any deletion.
    // This prevents an input such as `dir child` from deleting `dir` and only
    // then discovering that `child` was an alias/nested target.
    let mut candidates = Vec::<Option<PreparedTarget>>::new();
    for path in &cli.targets {
        let md = match std::fs::symlink_metadata(path) {
            Ok(md) => md,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                record_rejection(&mut report, "file", path, "missing target");
                candidates.push(None);
                continue;
            }
            Err(error) => {
                let error: VanishError = error.into();
                let mut pipe =
                    vanish_core::pipeline::Pipeline::new(plat.as_ref(), opts, &mut report);
                pipe.record_error("file", path, &error);
                candidates.push(None);
                continue;
            }
        };
        if md.file_type().is_symlink() {
            record_rejection(&mut report, "file", path, "symlink target");
            candidates.push(None);
            continue;
        }
        if has_symlink_component(path).unwrap_or(true) {
            record_rejection(&mut report, "file", path, "symlink path component");
            candidates.push(None);
            continue;
        }
        if !md.is_file() && !md.is_dir() {
            record_rejection(&mut report, "file", path, "special target");
            candidates.push(None);
            continue;
        }
        if md.is_file() && hardlink_refused(&md, opts) {
            record_rejection(&mut report, "file", path, "hard-linked target");
            candidates.push(None);
            continue;
        }
        if let Some(reason) = safety_refuse(path, opts) {
            record_rejection(
                &mut report,
                if md.is_dir() { "dir" } else { "file" },
                path,
                reason,
            );
            candidates.push(None);
            continue;
        }
        let canonical = match std::fs::canonicalize(path) {
            Ok(canonical) => canonical,
            Err(_) => {
                record_rejection(&mut report, "file", path, "unresolvable target");
                candidates.push(None);
                continue;
            }
        };
        if candidates
            .iter()
            .flatten()
            .any(|candidate| candidate.canonical == canonical)
        {
            record_rejection(
                &mut report,
                if md.is_dir() { "dir" } else { "file" },
                path,
                "alias target",
            );
            candidates.push(None);
            continue;
        }
        candidates.push(Some(PreparedTarget {
            path: path.clone(),
            canonical,
        }));
    }

    // A parent target owns all descendants. Reject descendants rather than
    // allowing input order to decide which path is removed first.
    let overlapping: Vec<bool> = candidates
        .iter()
        .map(|candidate| {
            candidate.as_ref().is_some_and(|candidate| {
                candidates.iter().any(|other| {
                    other.as_ref().is_some_and(|other| {
                        candidate.canonical != other.canonical
                            && (other.canonical.starts_with(&candidate.canonical)
                                || candidate.canonical.starts_with(&other.canonical))
                    })
                })
            })
        })
        .collect();
    for index in 0..candidates.len() {
        let Some(candidate) = candidates[index].as_ref() else {
            continue;
        };
        if overlapping[index] {
            let path = candidate.path.clone();
            candidates[index] = None;
            record_rejection(&mut report, "dir", &path, "overlapping targets rejected");
        }
    }

    for candidate in candidates.into_iter().flatten() {
        if vanish_core::signal::shutdown_requested() {
            let mut pipe = vanish_core::pipeline::Pipeline::new(plat.as_ref(), opts, &mut report);
            pipe.wipe_any(&candidate.path);
            continue;
        }
        let mut pipe = vanish_core::pipeline::Pipeline::new(plat.as_ref(), opts, &mut report);
        pipe.wipe_any(&candidate.path);
    }
    let code = compute_exit(&report);
    finish_run(report, code, cli, sink)
}

fn check_mode(paths: &[PathBuf], cli: &Cli) -> u8 {
    let sink = match prepare_report(cli.report.as_deref(), paths, false) {
        Ok(sink) => sink,
        Err(_) => {
            eprintln!("report setup failed");
            return 4;
        }
    };
    let plat = make_platform();
    let rep = match vanish_core::check::run(plat.as_ref(), paths) {
        Ok(report) => report,
        Err(_) => {
            eprintln!("check failed");
            return 4;
        }
    };
    let mut success = true;
    if cli.json {
        let mut out = io::stdout().lock();
        success =
            serde_json::to_writer_pretty(&mut out, &rep).is_ok() && out.write_all(b"\n").is_ok();
    } else {
        eprintln!("backend: {}", rep.backend);
        for entry in &rep.entries {
            eprintln!(
                "hash={:012}… exists={} kind={} nlink={:?} verdict={}",
                entry.name_hash, entry.exists, entry.kind, entry.nlink, entry.verdict
            );
            if !entry.openers.is_empty() {
                eprintln!("  openers: {:?}", entry.openers);
            }
        }
        for swap in &rep.swap {
            eprintln!("swap: {} {} MiB", swap.path, swap.size / 1024 / 1024);
        }
    }
    if let Some(mut sink) = sink {
        if write_serialized(&mut sink, &rep).is_err() {
            eprintln!("report output failed");
            success = false;
        }
    }
    if success {
        0
    } else {
        4
    }
}

#[cfg(target_os = "linux")]
fn freespace_mode(dir: PathBuf, cli: &Cli, opts: &Options) -> u8 {
    vanish_core::signal::install();
    let sink = match prepare_report(cli.report.as_deref(), std::slice::from_ref(&dir), false) {
        Ok(sink) => sink,
        Err(_) => {
            eprintln!("report setup failed");
            return 4;
        }
    };
    let mut report = RunReport::new();
    let avail = match be::avail_bytes(&dir) {
        Ok(available) => available,
        Err(error) => {
            let error: VanishError = error.into();
            let platform = make_platform();
            let mut pipe =
                vanish_core::pipeline::Pipeline::new(platform.as_ref(), opts, &mut report);
            pipe.record_error("freespace", &dir, &error);
            let code = compute_exit(&report);
            return finish_run(report, code, cli, sink);
        }
    };
    let budget = cli.size.unwrap_or_else(|| avail.saturating_mul(95) / 100);
    if opts.dry_run {
        report.push(TargetEvent {
            kind: "freespace".into(),
            name_hash: vanish_core::util::name_sha256(&dir),
            tail: None,
            strategy: Some("planned".into()),
            status: "skipped".into(),
            reason: Some("dry-run: no file created or written".into()),
            bytes: 0,
            warnings: vec![],
            guarantees: None,
            elapsed_ms: 0,
        });
        return finish_run(report, 0, cli, sink);
    }

    eprintln!(
        "freespace: budget {} MiB (available {} MiB)",
        budget / 1024 / 1024,
        avail / 1024 / 1024
    );
    let path = dir.join(format!(".{}", vanish_core::util::random_tail()));
    let file = match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(file) => file,
        Err(error) => {
            let error: VanishError = error.into();
            let platform = make_platform();
            let mut pipe =
                vanish_core::pipeline::Pipeline::new(platform.as_ref(), opts, &mut report);
            pipe.record_error("freespace", &dir, &error);
            let code = compute_exit(&report);
            return finish_run(report, code, cli, sink);
        }
    };
    let zero = vec![0u8; 1024 * 1024];
    let mut written = 0u64;
    let mut write_error = None;
    let mut file = Some(file);
    {
        let mut writer = io::BufWriter::with_capacity(1024 * 1024, file.take().unwrap());
        while written < budget {
            let amount = std::cmp::min((budget - written) as usize, zero.len());
            if let Err(error) = writer.write_all(&zero[..amount]) {
                write_error = Some(error);
                break;
            }
            written += amount as u64;
        }
        if let Err(error) = writer.flush() {
            if write_error.is_none() {
                write_error = Some(error);
            }
        }
        match writer.into_inner() {
            Ok(inner) => file = Some(inner),
            Err(error) => {
                if write_error.is_none() {
                    write_error = Some(error.into_error());
                }
            }
        }
    }
    if let Some(file) = file {
        if let Err(error) = file.sync_all() {
            if write_error.is_none() {
                write_error = Some(error);
            }
        }
    }

    if let Some(error) = write_error {
        if let Ok(md) = std::fs::symlink_metadata(&path) {
            let target = Target::from_parts(
                path.clone(),
                md.dev(),
                md.ino(),
                md.len(),
                md.nlink() as u32,
            );
            let platform = make_platform();
            let mut pipe =
                vanish_core::pipeline::Pipeline::new(platform.as_ref(), opts, &mut report);
            if let Err(cleanup) = pipe.wipe_target(target, false) {
                pipe.record_error("file", &path, &cleanup);
            }
        }
        let error = VanishError::Io(error);
        let platform = make_platform();
        let mut pipe = vanish_core::pipeline::Pipeline::new(platform.as_ref(), opts, &mut report);
        pipe.record_error("freespace", &dir, &error);
    } else {
        match std::fs::symlink_metadata(&path) {
            Ok(md) => {
                let target = Target::from_parts(
                    path.clone(),
                    md.dev(),
                    md.ino(),
                    md.len(),
                    md.nlink() as u32,
                );
                let platform = make_platform();
                let mut pipe =
                    vanish_core::pipeline::Pipeline::new(platform.as_ref(), opts, &mut report);
                if let Err(error) = pipe.wipe_target(target, false) {
                    pipe.record_error("file", &path, &error);
                }
            }
            Err(error) => {
                let error: VanishError = error.into();
                let platform = make_platform();
                let mut pipe =
                    vanish_core::pipeline::Pipeline::new(platform.as_ref(), opts, &mut report);
                pipe.record_error("freespace", &dir, &error);
            }
        }
    }
    let code = compute_exit(&report);
    finish_run(report, code, cli, sink)
}

#[cfg(not(target_os = "linux"))]
fn freespace_mode(dir: PathBuf, cli: &Cli, opts: &Options) -> u8 {
    vanish_core::signal::install();
    let sink = match prepare_report(cli.report.as_deref(), std::slice::from_ref(&dir), false) {
        Ok(sink) => sink,
        Err(_) => {
            eprintln!("report setup failed");
            return 4;
        }
    };
    let mut report = RunReport::new();
    record_rejection(&mut report, "freespace", &dir, "unsupported platform");
    finish_run(report, 3, cli, sink)
}

fn device_mode(dev: PathBuf, cli: &Cli) -> u8 {
    // Device execution is deliberately disabled. In particular, this branch does
    // not stat, open, ioctl, mount-check, or prompt for the supplied device.
    if cli
        .report
        .as_deref()
        .is_some_and(|report| absolute_normalized(report).ok() == absolute_normalized(&dev).ok())
    {
        eprintln!("report setup failed");
        return 4;
    }
    let sink = match prepare_report(cli.report.as_deref(), &[], false) {
        Ok(sink) => sink,
        Err(_) => {
            eprintln!("report setup failed");
            return 4;
        }
    };
    let mut report = RunReport::new();
    report.push(TargetEvent {
        kind: "device".into(),
        name_hash: vanish_core::util::name_sha256(&dev),
        tail: None,
        strategy: Some("disabled".into()),
        status: "rejected".into(),
        reason: Some(if cli.dry_run {
            "dry-run: device execution disabled; no device access performed".into()
        } else {
            "device execution disabled; no device access performed".into()
        }),
        bytes: 0,
        warnings: vec![],
        guarantees: None,
        elapsed_ms: 0,
    });
    finish_run(report, 3, cli, sink)
}

fn recovery_mode(roots: Vec<PathBuf>, cli: &Cli, opts: &Options) -> u8 {
    vanish_core::signal::install();
    let roots = if roots.is_empty() {
        vec![std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))]
    } else {
        roots
    };
    let sink = match prepare_report(cli.report.as_deref(), &roots, !opts.dry_run) {
        Ok(sink) => sink,
        Err(_) => {
            eprintln!("report setup failed");
            return 4;
        }
    };
    let platform = make_platform();
    let mut report = RunReport::new();
    let mut valid_roots = Vec::new();
    for root in roots {
        match std::fs::symlink_metadata(&root) {
            Ok(md) if md.file_type().is_symlink() => {
                let error = VanishError::UnsafePath("symlink root".into());
                let mut pipe =
                    vanish_core::pipeline::Pipeline::new(platform.as_ref(), opts, &mut report);
                pipe.record_error("tail", &root, &error);
            }
            Ok(_) if safety_refuse(&root, opts).is_some() => {
                let error = VanishError::UnsafePath("protected root".into());
                let mut pipe =
                    vanish_core::pipeline::Pipeline::new(platform.as_ref(), opts, &mut report);
                pipe.record_error("tail", &root, &error);
            }
            Ok(_) | Err(_) => valid_roots.push(root),
        }
    }
    if !valid_roots.is_empty() {
        if vanish_core::recovery::run(platform.as_ref(), &valid_roots, opts, &mut report).is_err() {
            report.note("recovery file scan failed");
        }
        if vanish_core::recovery::run_dirs(platform.as_ref(), &valid_roots, opts, &mut report)
            .is_err()
        {
            report.note("recovery directory scan failed");
        }
    }
    let code = compute_exit(&report);
    finish_run(report, code, cli, sink)
}

/// Коды выхода selfcheck: 0=verified, 1=TAMPERED, 2=manifest missing, 4=error.
fn selfcheck_mode(manifest_arg: Option<&str>) -> u8 {
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(_) => {
            eprintln!("selfcheck: cannot determine executable");
            return 4;
        }
    };
    let explicit = match manifest_arg {
        Some("") | None => None,
        Some(path) => Some(Path::new(path)),
    };
    let manifest = match vanish_core::selfcheck::resolve_manifest(&exe, explicit) {
        Some(path) => path,
        None => {
            eprintln!("selfcheck: SHA256SUMS manifest not found");
            return 2;
        }
    };
    match vanish_core::selfcheck::check(&exe, &manifest) {
        Ok(true) => {
            println!("[ok] selfcheck: SHA-256 matches manifest");
            0
        }
        Ok(false) => {
            println!("[tampered] selfcheck: SHA-256 does not match manifest");
            1
        }
        Err(_) => {
            eprintln!("selfcheck failed");
            4
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if cli.selfcheck.is_some() {
        return ExitCode::from(selfcheck_mode(cli.selfcheck.as_deref()));
    }
    let opts = match cli.opts() {
        Ok(opts) => opts,
        Err(error) => {
            eprintln!("usage: {}", error);
            return ExitCode::from(2);
        }
    };
    let code = match &cli.cmd {
        Some(Cmd::Check { paths }) => check_mode(paths, &cli),
        Some(Cmd::Freespace { dir }) => freespace_mode(dir.clone(), &cli, &opts),
        Some(Cmd::Device { dev }) => device_mode(dev.clone(), &cli),
        Some(Cmd::Recovery { roots }) => recovery_mode(roots.clone(), &cli, &opts),
        None if cli.recovery_scan => recovery_mode(cli.targets.clone(), &cli, &opts),
        None if cli.targets.is_empty() => {
            eprintln!("vanish: specify targets or a subcommand");
            2
        }
        None => wipe_mode(&cli, &opts, None),
    };
    ExitCode::from(code)
}
