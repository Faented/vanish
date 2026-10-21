//! vanish CLI: разбор аргументов, диспетчеризация, коды выхода.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

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
    about = "vanish — честное защищённое удаление (файлы/папки). Отказ лучше иллюзии защищённости.",
    args_conflicts_with_subcommands = true
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
        let passes = self.passes;
        if passes == 0 {
            return Err("--passes должен быть >= 1".into());
        }
        if matches!(pattern, PatternChoice::Hex(_)) && passes > 16 {
            // A one-byte pattern has only 16 distinct values per pass; silently
            // capping would pretend more passes ran than the report shows.
            return Err("--pattern hex:XX: --passes не может быть больше 16".into());
        }
        if self.size.is_some() && !matches!(self.cmd, Some(Cmd::Freespace { .. })) {
            return Err("--size допустим только с подкомандой freespace".into());
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
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut current = PathBuf::new();
    for component in absolute.components() {
        // Do not lexically erase `link/..`: kernel resolution may reach a
        // different directory. The backend rejects parent traversal as well.
        if component == std::path::Component::ParentDir {
            return Ok(true);
        }
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

    let mut open = OpenOptions::new();
    open.write(true).create_new(true);
    #[cfg(unix)]
    open.mode(0o600);
    let file = open
        .open(&absolute)
        .map_err(|_| "cannot create report file")?;
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
    // System pseudo-filesystems are always refused. --force-fs is an explicit
    // override for an unsupported ordinary filesystem, not a permit to wipe
    // kernel interfaces.
    for bad in ["/proc", "/sys", "/dev", "/run"] {
        if s == bad || s.starts_with(&format!("{bad}/")) {
            return Some("protected filesystem");
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

fn compute_exit(report: &RunReport, dry_run: bool) -> u8 {
    let interrupted = report.targets.iter().any(|event| {
        event.status == "skipped"
            && event
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("SIGINT") || reason.contains("SIGTERM"))
    });
    if report.failed > 0 {
        return 4;
    }
    if interrupted {
        return 1;
    }
    if report.rejected > 0 {
        return if report.ok == 0 { 3 } else { 1 };
    }
    // Outside a dry-run a skipped target means the requested work was not done
    // (for example a directory that could not be emptied). That is a partial
    // result, never success. A dry-run is intentionally all-skipped.
    if !dry_run && report.skipped > 0 {
        return 1;
    }
    0
}

fn emit(report: &mut RunReport, cli: &Cli, mut sink: Option<ReportSink>) -> bool {
    let mut success = true;
    if cli.json {
        let mut out = io::stdout().lock();
        if serde_json::to_writer_pretty(&mut out, report).is_err()
            || out.write_all(b"\n").is_err()
            || out.flush().is_err()
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
            for warning in &target.warnings {
                eprintln!(
                    "  warning[{}]: {}",
                    target.name_hash.get(0..12).unwrap_or("?"),
                    warning
                );
            }
        }
        if out.flush().is_err() {
            success = false;
        }
        eprintln!("{}", report.summary_text());
        for note in &report.notes {
            eprintln!("note: {}", note);
        }
    }
    if let Some(ref mut sink) = sink {
        // The report file must agree with the process exit contract even when
        // stdout (or the JSON stream) failed after the report was finished.
        if !success {
            report.code = 4;
        }
        if write_serialized(sink, report).is_err() {
            eprintln!("report output failed");
            success = false;
        }
    }
    success
}

fn finish_run(report: RunReport, code: u8, cli: &Cli, sink: Option<ReportSink>) -> u8 {
    let mut finished = report.finish(code);
    if emit(&mut finished, cli, sink) {
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
    let sink = match prepare_report(cli.report.as_deref(), &cli.targets, true) {
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
        // Canonical paths are absolute and free of symlink components; the core
        // rejects relative targets before any rename. SIGINT is handled inside
        // wipe_any: it emits a skipped event and starts no further work.
        let mut pipe = vanish_core::pipeline::Pipeline::new(plat.as_ref(), opts, &mut report);
        pipe.wipe_any(&candidate.canonical);
    }
    let code = compute_exit(&report, opts.dry_run);
    finish_run(report, code, cli, sink)
}

fn check_mode(paths: &[PathBuf], cli: &Cli, opts: &Options) -> u8 {
    let sink = match prepare_report(cli.report.as_deref(), paths, false) {
        Ok(sink) => sink,
        Err(_) => {
            eprintln!("report setup failed");
            return 4;
        }
    };
    let plat = make_platform();
    let rep = match vanish_core::check::run(plat.as_ref(), paths, opts) {
        Ok(report) => report,
        Err(_) => {
            eprintln!("check failed");
            return 4;
        }
    };
    let mut success = true;
    if cli.json {
        let mut out = io::stdout().lock();
        success = serde_json::to_writer_pretty(&mut out, &rep).is_ok()
            && out.write_all(b"\n").is_ok()
            && out.flush().is_ok();
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
    // Check the same filesystem policy before filling space, not only when the
    // resulting scratch file reaches the wipe pipeline.
    let platform = make_platform();
    let preflight = (|| -> vanish_core::error::Result<()> {
        let md = std::fs::symlink_metadata(&dir)?;
        if !md.is_dir() || has_symlink_component(&dir)? || safety_refuse(&dir, opts).is_some() {
            return Err(VanishError::UnsafePath("unsafe freespace directory".into()));
        }
        let volume = platform.fsinfo(&dir)?;
        vanish_core::strategy::decide(true, &volume, opts)?;
        Ok(())
    })();
    if let Err(error) = preflight {
        let mut pipe = vanish_core::pipeline::Pipeline::new(platform.as_ref(), opts, &mut report);
        pipe.record_error("freespace", &dir, &error);
        let code = compute_exit(&report, opts.dry_run);
        return finish_run(report, code, cli, sink);
    }
    // The preflight above already rejected symlink components; the canonical
    // absolute path keeps the scratch file and the core pipeline consistent.
    let dir = std::fs::canonicalize(&dir).unwrap_or(dir);
    let avail = match be::avail_bytes(&dir) {
        Ok(available) => available,
        Err(error) => {
            let platform = make_platform();
            let mut pipe =
                vanish_core::pipeline::Pipeline::new(platform.as_ref(), opts, &mut report);
            pipe.record_error("freespace", &dir, &error);
            let code = compute_exit(&report, opts.dry_run);
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
            let code = compute_exit(&report, opts.dry_run);
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
            if vanish_core::signal::shutdown_requested() {
                break;
            }
            let amount = std::cmp::min(budget - written, zero.len() as u64) as usize;
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

    if write_error.is_none() && vanish_core::signal::shutdown_requested() {
        // The scratch file exists only to occupy free space. On SIGINT/SIGTERM
        // remove it directly instead of starting another (potentially long) wipe.
        match std::fs::remove_file(&path) {
            Ok(()) => {
                report.push(TargetEvent {
                    kind: "freespace".into(),
                    name_hash: vanish_core::util::name_sha256(&path),
                    tail: None,
                    strategy: Some("planned".into()),
                    status: "skipped".into(),
                    reason: Some("SIGINT/SIGTERM: freespace остановлен, скретч-файл удалён".into()),
                    bytes: 0,
                    warnings: vec![],
                    guarantees: None,
                    elapsed_ms: 0,
                });
            }
            Err(error) => {
                let platform = make_platform();
                let mut pipe =
                    vanish_core::pipeline::Pipeline::new(platform.as_ref(), opts, &mut report);
                pipe.record_error("freespace", &path, &VanishError::Io(error));
            }
        }
        let code = compute_exit(&report, opts.dry_run);
        return finish_run(report, code, cli, sink);
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
                // This is our own zero-filled scratch file; never leave it
                // behind, even when the wipe pipeline refused the target.
                if let Err(remove) = std::fs::remove_file(&path) {
                    pipe.record_error("file", &path, &VanishError::Io(remove));
                }
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
                    if let Err(remove) = std::fs::remove_file(&path) {
                        pipe.record_error("file", &path, &VanishError::Io(remove));
                    }
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
    let code = compute_exit(&report, opts.dry_run);
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
    let sink = match prepare_report(cli.report.as_deref(), &roots, true) {
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
            Ok(md)
                if md.file_type().is_symlink() || has_symlink_component(&root).unwrap_or(true) =>
            {
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
    let valid_roots: Vec<PathBuf> = valid_roots
        .into_iter()
        .filter_map(|root| match std::fs::canonicalize(&root) {
            Ok(canonical) => Some(canonical),
            Err(error) => {
                let mut pipe =
                    vanish_core::pipeline::Pipeline::new(platform.as_ref(), opts, &mut report);
                pipe.record_error("tail", &root, &error.into());
                None
            }
        })
        .collect();
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
    let code = compute_exit(&report, opts.dry_run);
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
    // clap only recognises a subcommand in the first non-option position; a bare
    // name like `check` after a target would silently become another positional
    // target. Refuse instead of guessing. `./check` addresses such a file.
    if cli.cmd.is_none() {
        const SUBCOMMANDS: [&str; 4] = ["check", "freespace", "device", "recovery"];
        if let Some(name) = cli.targets.iter().find_map(|target| {
            let mut components = target.components();
            match (components.next(), components.next()) {
                (Some(std::path::Component::Normal(name)), None) => name.to_str(),
                _ => None,
            }
        }) {
            if SUBCOMMANDS.contains(&name) {
                eprintln!(
                    "usage: '{name}' is a subcommand name; use './{name}' to address a file with this name"
                );
                return ExitCode::from(2);
            }
        }
    }
    let opts = match cli.opts() {
        Ok(opts) => opts,
        Err(error) => {
            eprintln!("usage: {}", error);
            return ExitCode::from(2);
        }
    };
    let code = match &cli.cmd {
        Some(Cmd::Check { paths }) => check_mode(paths, &cli, &opts),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn report(statuses: &[(&str, Option<&str>)]) -> RunReport {
        let mut report = RunReport::new();
        for (status, reason) in statuses {
            report.push(TargetEvent {
                kind: "file".into(),
                name_hash: "test".into(),
                tail: None,
                strategy: None,
                status: (*status).into(),
                reason: reason.map(str::to_string),
                bytes: 0,
                warnings: Vec::new(),
                guarantees: None,
                elapsed_ms: 0,
            });
        }
        report
    }

    #[test]
    fn exit_contract_distinguishes_failed_partial_and_dry_run() {
        assert_eq!(compute_exit(&report(&[]), false), 0);
        assert_eq!(compute_exit(&report(&[("ok", None)]), false), 0);
        assert_eq!(compute_exit(&report(&[("rejected", None)]), false), 3);
        assert_eq!(
            compute_exit(&report(&[("ok", None), ("rejected", None)]), false),
            1
        );
        assert_eq!(compute_exit(&report(&[("skipped", None)]), false), 1);
        assert_eq!(compute_exit(&report(&[("skipped", None)]), true), 0);
        assert_eq!(
            compute_exit(
                &report(&[("skipped", Some("SIGINT/SIGTERM: цель не начата"))]),
                false
            ),
            1
        );
        assert_eq!(compute_exit(&report(&[("failed", None)]), false), 4);
        assert_eq!(
            compute_exit(&report(&[("failed", None), ("ok", None)]), false),
            4
        );
    }

    #[test]
    fn hex_pattern_rejects_more_than_sixteen_passes() {
        let cli = Cli::try_parse_from([
            "vanish",
            "--pattern",
            "hex:aa",
            "--passes",
            "17",
            "/tmp/opencode/target",
        ])
        .expect("arguments parse");
        let error = cli.opts().expect_err("17 hex passes must be rejected");
        assert!(error.contains("16"), "unexpected error: {error}");
    }

    #[test]
    fn size_flag_is_only_valid_for_freespace() {
        let cli = Cli::try_parse_from(["vanish", "--size", "42", "/tmp/opencode/target"])
            .expect("arguments parse");
        let error = cli.opts().expect_err("--size outside freespace");
        assert!(error.contains("freespace"), "unexpected error: {error}");

        let cli = Cli::try_parse_from(["vanish", "freespace", "/tmp/opencode", "--size", "42"])
            .expect("arguments parse");
        assert_eq!(cli.opts().expect("freespace accepts --size").passes, 1);
    }

    #[test]
    fn force_fs_does_not_override_system_path_protection() {
        let cli = Cli::try_parse_from(["vanish", "--force-fs", "/proc"]).expect("arguments parse");
        let opts = cli.opts().expect("valid options");
        assert!(opts.force_fs);
        assert_eq!(
            safety_refuse(Path::new("/proc"), &opts),
            Some("protected filesystem")
        );
    }
}
