use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn fixture() -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let base = if Path::new("/tmp/opencode").is_dir() {
        PathBuf::from("/tmp/opencode")
    } else {
        // The CLI safety tests must not depend on the host root filesystem or
        // swap placement. A tmpfs is a supported pipeline and keeps the tests
        // deterministic on CI runners; fall back only if it is unavailable.
        #[cfg(target_os = "linux")]
        if Path::new("/dev/shm").is_dir() {
            return create_fixture(Path::new("/dev/shm"), stamp);
        }
        std::env::temp_dir()
    };
    create_fixture(&base, stamp)
}

fn create_fixture(base: &Path, stamp: u128) -> PathBuf {
    let path = base.join(format!("vanish-cli-test-{}-{}", std::process::id(), stamp));
    fs::create_dir(&path).expect("fixture directory");
    path
}

fn assert_exit(output: &std::process::Output, expected: i32) {
    assert_eq!(
        output.status.code(),
        Some(expected),
        "unexpected exit status\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_vanish"))
        .args(args)
        .output()
        .expect("run vanish")
}

#[test]
fn dry_run_preserves_target_and_honors_json_and_report() {
    let root = fixture();
    let target = root.join("secret");
    let report = root.join("report.json");
    fs::write(&target, b"secret").expect("target");

    let output = run(&[
        "--dry-run",
        "--json",
        "--report",
        report.to_str().unwrap(),
        target.to_str().unwrap(),
    ]);

    assert_exit(&output, 0);
    assert!(target.exists());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("vanish.report.v1"));
    assert!(stdout.contains("dry-run"));
    assert!(report.exists());
    assert!(fs::read_to_string(&report)
        .unwrap()
        .contains("vanish.report.v1"));
    fs::remove_dir_all(root).expect("cleanup");
}

#[cfg(unix)]
#[test]
fn missing_and_symlink_are_rejected_without_following_link() {
    let root = fixture();
    let target = root.join("real");
    let link = root.join("link");
    let missing = root.join("missing");
    fs::write(&target, b"keep").expect("target");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");

    let output = run(&["--json", missing.to_str().unwrap(), link.to_str().unwrap()]);

    assert_exit(&output, 3);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("missing target"));
    assert!(stdout.contains("symlink target"));
    assert!(!stdout.contains(target.to_str().unwrap()));
    assert_eq!(fs::read(&target).unwrap(), b"keep");
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn device_dry_run_preflights_without_touching_supplied_path() {
    let root = fixture();
    let supplied = root.join("not-a-device");
    fs::write(&supplied, b"keep").unwrap();
    let output = run(&["device", "--dry-run", "--json", supplied.to_str().unwrap()]);

    assert_exit(&output, 3);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("device execution disabled"));
    assert!(
        stdout.contains("not a block device"),
        "preflight rejection expected: {stdout}"
    );
    assert_eq!(fs::read(&supplied).unwrap(), b"keep");
    fs::remove_dir_all(root).expect("cleanup");
}

#[cfg(target_os = "linux")]
#[test]
fn freespace_dry_run_does_not_create_a_scratch_file() {
    let root = fixture();
    let output = run(&[
        "freespace",
        "--dry-run",
        "--size",
        "3",
        "--json",
        root.to_str().unwrap(),
    ]);

    assert_exit(&output, 0);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("no file created or written"));
    assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn report_cannot_overwrite_target_or_existing_file() {
    let root = fixture();
    let target = root.join("keep");
    let report = root.join("existing-report");
    fs::write(&target, b"keep target").unwrap();
    fs::write(&report, b"keep report").unwrap();
    for destination in [&target, &report] {
        let output = run(&[
            "--report",
            destination.to_str().unwrap(),
            target.to_str().unwrap(),
        ]);
        assert_exit(&output, 4);
        assert_eq!(fs::read(&target).unwrap(), b"keep target");
        assert_eq!(fs::read(&report).unwrap(), b"keep report");
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn report_inside_target_tree_is_rejected_even_in_dry_run() {
    let root = fixture();
    let tree = root.join("tree");
    fs::create_dir(&tree).unwrap();
    let target = tree.join("keep");
    let report = tree.join("new-report");
    fs::write(&target, b"keep").unwrap();
    let output = run(&[
        "--dry-run",
        "--report",
        report.to_str().unwrap(),
        tree.to_str().unwrap(),
    ]);
    assert_exit(&output, 4);
    assert!(!report.exists());
    assert_eq!(fs::read(&target).unwrap(), b"keep");
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn report_symlink_and_symlink_parent_are_rejected() {
    let root = fixture();
    let target = root.join("keep");
    fs::write(&target, b"keep").unwrap();
    let link = root.join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let parent = root.join("parent");
    let alias = root.join("alias");
    fs::create_dir(&parent).unwrap();
    std::os::unix::fs::symlink(&parent, &alias).unwrap();
    for destination in [link, alias.join("new-report")] {
        let output = run(&[
            "--report",
            destination.to_str().unwrap(),
            target.to_str().unwrap(),
        ]);
        assert_exit(&output, 4);
        assert_eq!(fs::read(&target).unwrap(), b"keep");
    }
    assert_eq!(fs::read_dir(parent).unwrap().count(), 0);
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn report_is_private_and_matches_stdout() {
    use std::os::unix::fs::PermissionsExt;
    let root = fixture();
    let target = root.join("keep");
    let report = root.join("report");
    fs::write(&target, b"keep").unwrap();
    let output = run(&[
        "--dry-run",
        "--json",
        "--report",
        report.to_str().unwrap(),
        target.to_str().unwrap(),
    ]);
    assert_exit(&output, 0);
    assert_eq!(fs::read(&report).unwrap(), output.stdout);
    assert_eq!(
        fs::metadata(report).unwrap().permissions().mode() & 0o077,
        0
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn device_execution_is_disabled_and_preserves_regular_file() {
    let root = fixture();
    let supplied = root.join("owned-file");
    fs::write(&supplied, b"keep").unwrap();
    let output = run(&["device", supplied.to_str().unwrap(), "--json"]);
    assert_exit(&output, 3);
    assert!(String::from_utf8_lossy(&output.stdout).contains("device execution disabled"));
    assert_eq!(fs::read(&supplied).unwrap(), b"keep");
    fs::remove_dir_all(root).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn device_loop_wipe_requires_matching_confirmation_before_any_access() {
    let root = fixture();
    let supplied = root.join("not-a-device");
    let other = root.join("other");
    fs::write(&supplied, b"keep").unwrap();
    fs::write(&other, b"other").unwrap();
    let output = run(&[
        "device",
        supplied.to_str().unwrap(),
        "--device-wipe-loop",
        "--confirm-device",
        other.to_str().unwrap(),
    ]);
    assert_exit(&output, 2);
    assert!(String::from_utf8_lossy(&output.stderr).contains("does not match"));
    assert_eq!(fs::read(&supplied).unwrap(), b"keep");
    fs::remove_dir_all(root).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn device_loop_wipe_rejects_regular_file_after_matching_confirmation() {
    let root = fixture();
    let supplied = root.join("not-a-device");
    fs::write(&supplied, b"keep").unwrap();
    let output = run(&[
        "device",
        supplied.to_str().unwrap(),
        "--device-wipe-loop",
        "--confirm-device",
        supplied.to_str().unwrap(),
        "--json",
    ]);
    assert_exit(&output, 4);
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("\"failed\": 1"),
        "expected a failed target report"
    );
    assert_eq!(fs::read(&supplied).unwrap(), b"keep");
    fs::remove_dir_all(root).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn device_loop_wipe_flags_stay_read_only_in_dry_run() {
    let root = fixture();
    let supplied = root.join("not-a-device");
    fs::write(&supplied, b"keep").unwrap();
    let output = run(&[
        "device",
        supplied.to_str().unwrap(),
        "--dry-run",
        "--device-wipe-loop",
        "--confirm-device",
        supplied.to_str().unwrap(),
        "--json",
    ]);
    assert_exit(&output, 3);
    assert_eq!(fs::read(&supplied).unwrap(), b"keep");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn overlapping_targets_are_rejected_before_deletion() {
    let root = fixture();
    let target = root.join("keep");
    fs::write(&target, b"keep").unwrap();
    let output = run(&["--json", root.to_str().unwrap(), target.to_str().unwrap()]);
    assert_exit(&output, 3);
    assert_eq!(fs::read(&target).unwrap(), b"keep");
    assert!(!String::from_utf8_lossy(&output.stdout).contains(root.to_str().unwrap()));
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn closed_stdout_returns_execution_error() {
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::process::Stdio;
    let root = fixture();
    let target = root.join("keep");
    fs::write(&target, b"keep").unwrap();
    for json in [false, true] {
        let (writer, reader) = UnixStream::pair().unwrap();
        drop(reader);
        let mut command = Command::new(env!("CARGO_BIN_EXE_vanish"));
        command.arg("--dry-run").arg(&target);
        if json {
            command.arg("--json");
        }
        let fd: OwnedFd = writer.into();
        let status = command
            .stdout(Stdio::from(fd))
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(4));
    }
    assert_eq!(fs::read(&target).unwrap(), b"keep");
    fs::remove_dir_all(root).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn freespace_checks_policy_before_creating_scratch_file() {
    let root = fixture();
    let output = run(&[
        "freespace",
        root.to_str().unwrap(),
        "--size",
        "3",
        "--force-fs",
        "--disable-swap-for-wipe",
        "--json",
    ]);
    assert_exit(&output, 3);
    assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn symlink_dotdot_path_is_rejected_without_touching_either_file() {
    let root = fixture();
    let destination = root.join("outside");
    fs::create_dir_all(destination.join("inner")).unwrap();
    fs::write(root.join("keep"), b"lexical").unwrap();
    fs::write(destination.join("keep"), b"resolved").unwrap();
    std::os::unix::fs::symlink(destination.join("inner"), root.join("link")).unwrap();
    let input = root.join("link/../keep");
    let output = run(&["--json", input.to_str().unwrap()]);
    assert_exit(&output, 3);
    assert_eq!(fs::read(root.join("keep")).unwrap(), b"lexical");
    assert_eq!(fs::read(destination.join("keep")).unwrap(), b"resolved");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn subcommand_name_after_target_is_rejected_not_treated_as_target() {
    let root = fixture();
    let target = root.join("check");
    fs::write(&target, b"keep").unwrap();
    let output = run(&["--dry-run", target.to_str().unwrap(), "check"]);
    assert_exit(&output, 2);
    assert_eq!(fs::read(&target).unwrap(), b"keep");
    fs::remove_dir_all(root).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn freespace_failure_removes_its_scratch_file() {
    let root = fixture();
    let output = run(&[
        "freespace",
        root.to_str().unwrap(),
        "--size",
        "4096",
        "--json",
    ]);
    // Whether the wipe is refused (unprivileged busy-probe) or succeeds, the
    // zero-filled scratch file must not stay in the user's directory.
    let _ = output.status.code();
    assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    fs::remove_dir_all(root).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn check_reports_guarantee_ceiling_without_mutating() {
    let root = fixture();
    let target = root.join("check-target");
    fs::write(&target, b"keep").unwrap();
    let output = run(&["check", target.to_str().unwrap()]);
    assert_exit(&output, 0);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("guarantee="), "stderr: {stderr}");
    assert!(stderr.contains("verdict="), "stderr: {stderr}");
    assert_eq!(fs::read(&target).unwrap(), b"keep");
    fs::remove_dir_all(root).unwrap();
}
