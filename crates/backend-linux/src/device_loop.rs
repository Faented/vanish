//! M5: loop-only destructive device execution.
//!
//! This module is intentionally narrower than a general device wiper. It only
//! accepts a loop device whose backing file is visible in sysfs, and refuses if
//! preflight reports any mount, swap, holder, slave, boot relation or read-only
//! state. `device_wipe` itself remains permanently disabled.
//!
//! A successful return means every byte of the loop device was overwritten by
//! the requested pattern streams and, when `verify` is set, read back and
//! compared. It does not prove physical erasure of a real disk, a backing
//! filesystem's free blocks, a copy-on-write layer, or the loop backing file.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;

use vanish_core::config::PatternChoice;
use vanish_core::error::{Result, VanishError};
use vanish_core::pattern::PatternStream;
use vanish_core::util::random_seed32;

use crate::preflight::{preflight, DevicePreflight};
use crate::{sys as s, DeviceResult};

const BLKGETSIZE64: u64 = 0x8008_1272;
const BLKROGET: u64 = 0x125e;
const BLKFLSBUF: u64 = 0x1261;
const BUFFER_BYTES: usize = vanish_core::aligned::CHUNK;

/// Options for the narrow loop-only execution path.
#[derive(Debug, Clone, Copy)]
pub struct DeviceWipeOptions {
    pub passes: u8,
    pub pattern: PatternChoice,
    pub verify: bool,
}

fn effective_passes(pattern: PatternChoice, passes: u8) -> Result<u8> {
    if pattern == PatternChoice::Gutmann {
        return Ok(35);
    }
    if passes == 0 || passes > 35 {
        return Err(VanishError::NotPermitted(
            "device wipe passes must be between 1 and 35".into(),
        ));
    }
    Ok(passes)
}

/// Refuse unless preflight says this is an unattached-free loop device.
fn ensure_loop_safe(pf: &DevicePreflight) -> Result<()> {
    if !pf.is_loop || pf.loop_backing_file.is_none() {
        return Err(VanishError::NotPermitted(
            "device wipe is restricted to loop devices with a backing file".into(),
        ));
    }
    let mut blockers = Vec::new();
    if pf.read_only {
        blockers.push("read_only");
    }
    if pf.size_bytes == 0 {
        blockers.push("zero_size");
    }
    if !pf.mounts.is_empty() {
        blockers.push("mounted");
    }
    if pf.swap_active {
        blockers.push("swap_active");
    }
    if !pf.boot_related.is_empty() {
        blockers.push("boot_related");
    }
    if !pf.holders.is_empty() {
        blockers.push("holders");
    }
    if !pf.slaves.is_empty() {
        blockers.push("slaves");
    }
    if !blockers.is_empty() {
        return Err(VanishError::NotPermitted(format!(
            "device wipe refused: {}",
            blockers.join(", ")
        )));
    }
    Ok(())
}

fn ioctl_u64(fd: i32, request: u64, value: &mut u64) -> Result<()> {
    let rc = s::ioctl_raw(fd, request, value as *mut u64 as *mut libc::c_void);
    if rc < 0 {
        return Err(VanishError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

fn ioctl_int(fd: i32, request: u64, value: &mut libc::c_int) -> Result<()> {
    let rc = s::ioctl_raw(fd, request, value as *mut libc::c_int as *mut libc::c_void);
    if rc < 0 {
        return Err(VanishError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

fn flush(fd: i32) -> Result<()> {
    s::fsync_fd(fd)?;
    let rc = s::ioctl_raw(fd, BLKFLSBUF, std::ptr::null_mut());
    if rc < 0 {
        return Err(VanishError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

fn write_pass(
    fd: i32,
    size: u64,
    pass: u8,
    pattern: PatternChoice,
    seed: [u8; 32],
    verify: bool,
) -> Result<()> {
    let mut stream = PatternStream::new(pattern, pass, seed);
    let mut buffer = vec![0u8; BUFFER_BYTES];
    let mut offset = 0u64;
    while offset < size {
        let amount = std::cmp::min(BUFFER_BYTES as u64, size - offset) as usize;
        stream.fill(&mut buffer[..amount]);
        let wrote = s::pwrite_at(fd, &buffer[..amount], offset)?;
        if wrote != amount {
            return Err(VanishError::Io(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "short block-device write",
            )));
        }
        offset += amount as u64;
    }
    zeroize(&mut buffer);
    flush(fd)?;

    if verify {
        let mut replay = PatternStream::new(pattern, pass, seed);
        let mut expected = vec![0u8; BUFFER_BYTES];
        let mut readback = vec![0u8; BUFFER_BYTES];
        let mut offset = 0u64;
        while offset < size {
            let amount = std::cmp::min(BUFFER_BYTES as u64, size - offset) as usize;
            s::pread_exact_at(fd, &mut readback[..amount], offset)?;
            replay.fill(&mut expected[..amount]);
            if let Some(index) = readback[..amount]
                .iter()
                .zip(expected[..amount].iter())
                .position(|(got, want)| got != want)
            {
                return Err(VanishError::VerifyMismatch {
                    offset: offset + index as u64,
                });
            }
            offset += amount as u64;
        }
        zeroize(&mut expected);
        zeroize(&mut readback);
    }
    Ok(())
}

fn zeroize(buffer: &mut [u8]) {
    buffer.fill(0);
}

/// Overwrite a loop device. Generic block devices are still rejected.
pub fn device_wipe_loop(dev_path: &Path, options: &DeviceWipeOptions) -> Result<DeviceResult> {
    let passes = effective_passes(options.pattern, options.passes)?;
    let before = preflight(dev_path)?;
    ensure_loop_safe(&before)?;

    let raw =
        s::open_path(dev_path, libc::O_RDWR | libc::O_CLOEXEC | libc::O_EXCL).map_err(|error| {
            if error.raw_os_error() == Some(libc::EBUSY) {
                VanishError::NotPermitted("loop device is busy".into())
            } else {
                VanishError::Io(error)
            }
        })?;
    // SAFETY: open_path returned a fresh owned descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let fd_raw = fd.as_raw_fd();

    let stat = s::fstat(fd_raw)?;
    let mode = stat.st_mode & libc::S_IFMT;
    if mode != libc::S_IFBLK
        || libc::major(stat.st_rdev) != before.major
        || libc::minor(stat.st_rdev) != before.minor
    {
        return Err(VanishError::IdentityMismatch(
            "loop device identity changed during wipe setup".into(),
        ));
    }
    let mut size = 0u64;
    ioctl_u64(fd_raw, BLKGETSIZE64, &mut size)?;
    if size != before.size_bytes || size == 0 {
        return Err(VanishError::IdentityMismatch(
            "loop device identity changed during wipe setup".into(),
        ));
    }
    let mut read_only = 0 as libc::c_int;
    ioctl_int(fd_raw, BLKROGET, &mut read_only)?;
    if read_only != 0 {
        return Err(VanishError::ReadOnlyMount);
    }

    // Re-check after opening: loop devices can be detached/reassigned.
    let after = preflight(dev_path)?;
    ensure_loop_safe(&after)?;
    if after.major != before.major
        || after.minor != before.minor
        || after.canonical != before.canonical
        || after.size_bytes != size
    {
        return Err(VanishError::IdentityMismatch(
            "loop device identity changed during wipe setup".into(),
        ));
    }

    let seed = random_seed32();
    for pass in 1..=passes {
        write_pass(fd_raw, size, pass, options.pattern, seed, options.verify)?;
    }
    flush(fd_raw)?;

    Ok(DeviceResult {
        path: dev_path.display().to_string(),
        size,
        method: "loop_overwrite",
        physical_guaranteed: false,
        passes,
        bytes_written: size.saturating_mul(u64::from(passes)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn preflight_stub() -> DevicePreflight {
        DevicePreflight {
            path: PathBuf::from("/dev/loop-test"),
            canonical: PathBuf::from("/dev/loop-test"),
            major: 7,
            minor: 99,
            size_bytes: 1024,
            read_only: false,
            rotational: Some(false),
            model: None,
            mounts: vec![],
            swap_active: false,
            boot_related: vec![],
            holders: vec![],
            slaves: vec![],
            is_loop: true,
            loop_backing_file: Some(PathBuf::from("/tmp/backing.img")),
            execution_allowed: false,
            blockers: vec!["device execution disabled".into()],
        }
    }

    #[test]
    fn passes_are_bounded_and_gutmann_is_35() {
        assert_eq!(effective_passes(PatternChoice::Zero, 3).unwrap(), 3);
        assert_eq!(effective_passes(PatternChoice::Gutmann, 1).unwrap(), 35);
        assert!(effective_passes(PatternChoice::Zero, 0).is_err());
        assert!(effective_passes(PatternChoice::Zero, 36).is_err());
    }

    #[test]
    fn gate_rejects_non_loop_and_dangerous_loop_states() {
        assert!(ensure_loop_safe(&preflight_stub()).is_ok());

        let mut not_loop = preflight_stub();
        not_loop.is_loop = false;
        not_loop.loop_backing_file = None;
        assert!(ensure_loop_safe(&not_loop).is_err());

        for mutate in [
            |pf: &mut DevicePreflight| pf.mounts.push(PathBuf::from("/mnt")),
            |pf: &mut DevicePreflight| pf.swap_active = true,
            |pf: &mut DevicePreflight| pf.boot_related.push(PathBuf::from("/")),
            |pf: &mut DevicePreflight| pf.holders.push("dm-0".into()),
            |pf: &mut DevicePreflight| pf.slaves.push("sda".into()),
            |pf: &mut DevicePreflight| pf.read_only = true,
            |pf: &mut DevicePreflight| pf.size_bytes = 0,
        ] {
            let mut pf = preflight_stub();
            mutate(&mut pf);
            assert!(ensure_loop_safe(&pf).is_err());
        }
    }

    #[test]
    fn regular_file_is_rejected_before_device_open() {
        let dir = crate::test_support::TestDir::new();
        let file = dir.path().join("not-a-device");
        std::fs::write(&file, b"keep").unwrap();
        let options = DeviceWipeOptions {
            passes: 1,
            pattern: PatternChoice::Zero,
            verify: false,
        };
        assert!(device_wipe_loop(&file, &options).is_err());
        assert_eq!(std::fs::read(&file).unwrap(), b"keep");
    }
}
