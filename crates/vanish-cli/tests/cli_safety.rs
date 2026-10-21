use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn fixture() -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("vanish-cli-test-{}-{}", std::process::id(), stamp));
    fs::create_dir(&path).expect("fixture directory");
    path
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

    assert_eq!(output.status.code(), Some(0));
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

    assert_eq!(output.status.code(), Some(3));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("missing target"));
    assert!(stdout.contains("symlink target"));
    assert!(!stdout.contains(target.to_str().unwrap()));
    assert_eq!(fs::read(&target).unwrap(), b"keep");
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn device_dry_run_is_disabled_without_touching_supplied_path() {
    let root = fixture();
    let supplied = root.join("not-a-device");
    let output = run(&["device", "--dry-run", "--json", supplied.to_str().unwrap()]);

    assert_eq!(output.status.code(), Some(3));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("device execution disabled"));
    assert!(!supplied.exists());
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

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("no file created or written"));
    assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    fs::remove_dir_all(root).expect("cleanup");
}
