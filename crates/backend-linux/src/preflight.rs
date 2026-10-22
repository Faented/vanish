//! Read-only preflight for a future device-wipe mode.
//!
//! This module deliberately never opens the target block device and never
//! issues a device ioctl. It only inspects metadata, procfs, and sysfs. Device
//! execution remains disabled regardless of the observations made here.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Component, Path, PathBuf};

const SECTOR_SIZE: u64 = 512;
const DEVICE_EXECUTION_DISABLED: &str = "device execution disabled";
const BOOT_RELATION_UNKNOWN: &str = "boot relation unknown";
const BOOT_MOUNTS: [&str; 3] = ["/", "/boot", "/boot/efi"];

/// Read-only observations about a block device.
///
/// The presence of a clean-looking value does not authorize any operation:
/// [`DevicePreflight::execution_allowed`] is always `false` in this iteration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevicePreflight {
    /// The path supplied by the caller.
    pub path: PathBuf,
    /// Fully resolved path of the block device.
    pub canonical: PathBuf,
    pub major: u32,
    pub minor: u32,
    /// Size from sysfs, in bytes.
    pub size_bytes: u64,
    /// Whether the device itself is marked read-only by sysfs.
    pub read_only: bool,
    /// `None` when the sysfs rotational attribute is unavailable.
    pub rotational: Option<bool>,
    /// `None` when the sysfs model attribute is unavailable or not UTF-8.
    pub model: Option<String>,
    /// Mount points whose mountinfo device number matches this device.
    pub mounts: Vec<PathBuf>,
    /// Exact canonical-path match in `/proc/swaps`.
    pub swap_active: bool,
    /// Present boot mount points served by this device or a sysfs parent.
    pub boot_related: Vec<PathBuf>,
    /// Entry names from `/sys/dev/block/M:m/holders`.
    pub holders: Vec<String>,
    /// Entry names from `/sys/dev/block/M:m/slaves`.
    pub slaves: Vec<String>,
    /// Whether this is a loop device with a readable backing file.
    pub is_loop: bool,
    /// Backing file reported by `/sys/dev/block/M:m/loop/backing_file`.
    pub loop_backing_file: Option<PathBuf>,
    /// Always `false`: destructive device execution is still disabled.
    pub execution_allowed: bool,
    /// Stable reasons why execution is blocked. Always contains
    /// `"device execution disabled"`.
    pub blockers: Vec<String>,
}

/// Inspect a block device without opening it or issuing ioctls.
///
/// Symlinks (for example `/dev/disk/by-id/...`) are resolved, but the final
/// object must be a block device. `/proc/self/mountinfo` and `/proc/swaps`
/// failures are propagated rather than treated as evidence of safety.
pub fn preflight(path: &Path) -> io::Result<DevicePreflight> {
    preflight_with(
        path,
        Path::new("/sys"),
        Path::new("/proc/self/mountinfo"),
        Path::new("/proc/swaps"),
    )
}

pub(crate) fn preflight_with(
    path: &Path,
    sysfs_root: &Path,
    mountinfo_path: &Path,
    swaps_path: &Path,
) -> io::Result<DevicePreflight> {
    let canonical = fs::canonicalize(path)?;
    let metadata = fs::metadata(&canonical)?;
    if !metadata.file_type().is_block_device() {
        return Err(invalid_input(format!(
            "not a block device: {}",
            path.display()
        )));
    }

    let rdev = metadata.rdev();
    let major = libc::major(rdev as libc::dev_t) as u32;
    let minor = libc::minor(rdev as libc::dev_t) as u32;

    let sysfs_root = fs::canonicalize(sysfs_root)?;
    let sysfs_link = sysfs_root
        .join("dev/block")
        .join(format!("{major}:{minor}"));
    let sysfs_device = fs::canonicalize(&sysfs_link)?;
    if !sysfs_device.starts_with(&sysfs_root) {
        return Err(invalid_data("sysfs block device path escapes sysfs root"));
    }

    let sectors = read_required_u64(&sysfs_device.join("size"))?;
    let size_bytes = size_sectors_to_bytes(sectors)?;
    let read_only = read_required_bool(&sysfs_device.join("ro"))?;
    let rotational = read_optional_bool(&sysfs_device.join("queue/rotational"))?;
    let model = read_optional_model(&sysfs_device.join("device/model"))?;

    let mountinfo = read_text_file(mountinfo_path)?;
    let rows = parse_mountinfo(&mountinfo)?;
    let mounts = mounts_for_device(&rows, major, minor, &canonical);
    let btrfs_fs_mounted = btrfs_membership_mounted(&sysfs_root, major, minor)?;

    let swaps = read_text_file(swaps_path)?;
    let swap_paths = parse_swaps(&swaps)?;
    let swap_active = is_active_swap(&swap_paths, &canonical);

    let holders = read_sysfs_names(&sysfs_device.join("holders"))?;
    let slaves = read_sysfs_names(&sysfs_device.join("slaves"))?;
    let loop_backing_file =
        read_optional_text(&sysfs_device.join("loop/backing_file"))?.map(PathBuf::from);
    let is_loop = loop_backing_file.is_some();

    let boot_related = boot_related_mounts(&rows, &sysfs_root, &sysfs_device, major, minor);
    let boot_relation_known = boot_related.is_some();
    let mut boot_related = boot_related.unwrap_or_default();
    // btrfs and other virtual-device filesystems report a different major:minor
    // in mountinfo; the source path still names the underlying block device.
    for mount in &mounts {
        if BOOT_MOUNTS.iter().any(|boot| Path::new(boot) == mount) && !boot_related.contains(mount)
        {
            boot_related.push(mount.clone());
        }
    }

    let blockers = blockers(
        read_only,
        size_bytes,
        &mounts,
        btrfs_fs_mounted,
        swap_active,
        &boot_related,
        boot_relation_known,
        &holders,
        &slaves,
    );

    Ok(DevicePreflight {
        path: path.to_path_buf(),
        canonical,
        major,
        minor,
        size_bytes,
        read_only,
        rotational,
        model,
        mounts,
        swap_active,
        boot_related,
        holders,
        slaves,
        is_loop,
        loop_backing_file,
        execution_allowed: false,
        blockers,
    })
}

/// One parsed `/proc/self/mountinfo` row.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MountInfoRow {
    major: u32,
    minor: u32,
    mount_point: PathBuf,
    source: PathBuf,
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn read_text_file(path: &Path) -> io::Result<String> {
    let bytes = fs::read(path)?;
    String::from_utf8(bytes)
        .map_err(|_| invalid_data(format!("non-UTF-8 file: {}", path.display())))
}

fn read_optional_text(path: &Path) -> io::Result<Option<String>> {
    match fs::read(path) {
        Ok(bytes) => String::from_utf8(bytes)
            .map(|text| Some(text.trim().to_string()))
            .map_err(|_| invalid_data(format!("non-UTF-8 file: {}", path.display()))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn read_required_u64(path: &Path) -> io::Result<u64> {
    let text = read_text_file(path)?;
    text.trim()
        .parse::<u64>()
        .map_err(|_| invalid_data(format!("invalid integer in {}", path.display())))
}

fn read_required_bool(path: &Path) -> io::Result<bool> {
    match read_text_file(path)?.trim() {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(invalid_data(format!(
            "invalid boolean in {}",
            path.display()
        ))),
    }
}

fn read_optional_bool(path: &Path) -> io::Result<Option<bool>> {
    match fs::read(path) {
        Ok(bytes) => {
            let text = String::from_utf8(bytes)
                .map_err(|_| invalid_data(format!("non-UTF-8 file: {}", path.display())))?;
            match text.trim() {
                "0" => Ok(Some(false)),
                "1" => Ok(Some(true)),
                _ => Err(invalid_data(format!(
                    "invalid boolean in {}",
                    path.display()
                ))),
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn read_optional_model(path: &Path) -> io::Result<Option<String>> {
    match fs::read(path) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(text) => {
                let text = text.trim();
                if text.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(text.to_owned()))
                }
            }
            Err(_) => Ok(None),
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// sysfs reports block sizes in 512-byte sectors.
fn size_sectors_to_bytes(sectors: u64) -> io::Result<u64> {
    sectors
        .checked_mul(SECTOR_SIZE)
        .ok_or_else(|| invalid_data("block device size overflows u64"))
}

fn parse_devnum(text: &str) -> io::Result<(u32, u32)> {
    let (major, minor) = text
        .trim()
        .split_once(':')
        .ok_or_else(|| invalid_data(format!("invalid device number: {text}")))?;
    let major = major
        .parse::<u32>()
        .map_err(|_| invalid_data(format!("invalid device number: {text}")))?;
    let minor = minor
        .parse::<u32>()
        .map_err(|_| invalid_data(format!("invalid device number: {text}")))?;
    Ok((major, minor))
}

/// Decode the octal escapes used by procfs paths.
fn unescape_proc_field(field: &str) -> io::Result<OsString> {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'\\' {
            out.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 4 > bytes.len() {
            return Err(invalid_data("truncated octal escape"));
        }
        let digits = &bytes[index + 1..index + 4];
        if !digits.iter().all(|byte| (b'0'..=b'7').contains(byte)) {
            return Err(invalid_data("invalid octal escape"));
        }
        let value = (u16::from(digits[0] - b'0') * 64)
            + (u16::from(digits[1] - b'0') * 8)
            + u16::from(digits[2] - b'0');
        if value == 0 || value > u16::from(u8::MAX) {
            return Err(invalid_data("octal escape is not a path byte"));
        }
        out.push(value as u8);
        index += 4;
    }
    Ok(OsString::from_vec(out))
}

/// Parse `/proc/self/mountinfo`, failing closed on malformed nonempty rows.
fn parse_mountinfo(data: &str) -> io::Result<Vec<MountInfoRow>> {
    let mut rows = Vec::new();
    for line in data.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            return Err(invalid_data("short mountinfo row"));
        }
        fields[0]
            .parse::<u64>()
            .map_err(|_| invalid_data("invalid mountinfo mount ID"))?;
        fields[1]
            .parse::<u64>()
            .map_err(|_| invalid_data("invalid mountinfo parent ID"))?;
        let (major, minor) = parse_devnum(fields[2])?;
        let _root = unescape_proc_field(fields[3])?;
        let mount_point = PathBuf::from(unescape_proc_field(fields[4])?);
        if mount_point.as_os_str().is_empty() || !mount_point.is_absolute() {
            return Err(invalid_data("invalid mountinfo mount point"));
        }
        if fields[5].is_empty() {
            return Err(invalid_data("empty mountinfo mount options"));
        }
        let separator = fields
            .iter()
            .enumerate()
            .skip(6)
            .find_map(|(index, field)| (*field == "-").then_some(index))
            .ok_or_else(|| invalid_data("mountinfo separator is missing"))?;
        if fields.len() != separator + 4 {
            return Err(invalid_data("invalid mountinfo trailing fields"));
        }
        if fields[separator + 1].is_empty() || fields[separator + 2].is_empty() {
            return Err(invalid_data("empty mountinfo filesystem or source"));
        }
        let source = PathBuf::from(unescape_proc_field(fields[separator + 2])?);
        rows.push(MountInfoRow {
            major,
            minor,
            mount_point,
            source,
        });
    }
    Ok(rows)
}

/// Parse paths from `/proc/swaps`, including octal-escaped spaces.
fn parse_swaps(data: &str) -> io::Result<Vec<PathBuf>> {
    let mut lines = data.lines();
    let header = lines
        .next()
        .ok_or_else(|| invalid_data("missing /proc/swaps header"))?;
    let header_fields: Vec<&str> = header.split_whitespace().collect();
    if header_fields != ["Filename", "Type", "Size", "Used", "Priority"] {
        return Err(invalid_data("invalid /proc/swaps header"));
    }

    let mut paths = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() != 5 {
            return Err(invalid_data("invalid /proc/swaps row"));
        }
        if !matches!(fields[1], "file" | "partition") {
            return Err(invalid_data("invalid /proc/swaps type"));
        }
        fields[2]
            .parse::<u64>()
            .ok()
            .and_then(|size| size.checked_mul(1024))
            .ok_or_else(|| invalid_data("invalid /proc/swaps size"))?;
        fields[3]
            .parse::<u64>()
            .map_err(|_| invalid_data("invalid /proc/swaps used size"))?;
        fields[4]
            .parse::<i32>()
            .map_err(|_| invalid_data("invalid /proc/swaps priority"))?;

        let path = PathBuf::from(unescape_proc_field(fields[0])?);
        if !path.is_absolute() {
            return Err(invalid_data("relative /proc/swaps path"));
        }
        paths.push(path);
    }
    Ok(paths)
}

fn mounts_for_device(
    rows: &[MountInfoRow],
    major: u32,
    minor: u32,
    canonical_device: &Path,
) -> Vec<PathBuf> {
    let mut mounts = Vec::new();
    for row in rows {
        let same_device = (row.major == major && row.minor == minor)
            || source_matches_device(&row.source, canonical_device);
        if same_device && !mounts.contains(&row.mount_point) {
            mounts.push(row.mount_point.clone());
        }
    }
    mounts
}

/// btrfs appends `[/subvolume]` to the source field; strip that suffix.
fn source_device_path(source: &Path) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;
    let bytes = source.as_os_str().as_bytes();
    let end = bytes
        .iter()
        .position(|byte| *byte == b'[')
        .unwrap_or(bytes.len());
    PathBuf::from(OsString::from_vec(bytes[..end].to_vec()))
}

fn source_matches_device(source: &Path, canonical_device: &Path) -> bool {
    if !source.is_absolute() {
        return false;
    }
    let source = source_device_path(source);
    source == canonical_device
        || fs::canonicalize(&source)
            .map(|resolved| resolved == canonical_device)
            .unwrap_or(false)
}

/// True when sysfs reports this block device as a member of a mounted btrfs
/// filesystem. btrfs mountinfo uses a synthetic device number, so a
/// multi-device filesystem could otherwise look unmounted.
fn btrfs_membership_mounted(sysfs_root: &Path, major: u32, minor: u32) -> io::Result<bool> {
    let root = sysfs_root.join("fs/btrfs");
    let entries = match fs::read_dir(&root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let devices = entry.path().join("devices");
        let devices = match fs::read_dir(&devices) {
            Ok(devices) => devices,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        for device in devices {
            let device = device?;
            let text = match fs::read_to_string(device.path().join("dev")) {
                Ok(text) => text,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            if parse_devnum(&text)? == (major, minor) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn is_active_swap(swap_paths: &[PathBuf], canonical_device: &Path) -> bool {
    swap_paths.iter().any(|path| {
        path == canonical_device
            || fs::canonicalize(path)
                .map(|resolved| resolved == canonical_device)
                .unwrap_or(false)
    })
}

fn read_sysfs_names(directory: &Path) -> io::Result<Vec<String>> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().into_string().map_err(|_| {
            invalid_data(format!(
                "non-UTF-8 name in sysfs directory {}",
                directory.display()
            ))
        })?;
        names.push(name);
    }
    names.sort();
    names.dedup();
    Ok(names)
}

/// Parse the relevant device-number fields from a sysfs `uevent` file.
///
/// Both `MAJ:MIN=...` and the `MAJOR=...`/`MINOR=...` pair are accepted.
fn parse_sysfs_maj_min(data: &str) -> io::Result<Option<(u32, u32)>> {
    let mut combined = None;
    let mut major = None;
    let mut minor = None;
    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| invalid_data("invalid sysfs uevent row"))?;
        let value = value.trim();
        match key {
            "MAJ:MIN" => combined = Some(parse_devnum(value)?),
            "MAJOR" => {
                major = Some(
                    value
                        .parse::<u32>()
                        .map_err(|_| invalid_data("invalid sysfs MAJOR"))?,
                );
            }
            "MINOR" => {
                minor = Some(
                    value
                        .parse::<u32>()
                        .map_err(|_| invalid_data("invalid sysfs MINOR"))?,
                );
            }
            _ => {}
        }
    }

    let paired = match (major, minor) {
        (Some(major), Some(minor)) => Some((major, minor)),
        (None, None) => None,
        _ => return Err(invalid_data("incomplete sysfs MAJOR/MINOR pair")),
    };
    match (combined, paired) {
        (Some(combined), Some(paired)) if combined != paired => {
            Err(invalid_data("conflicting sysfs device numbers"))
        }
        (Some(combined), _) => Ok(Some(combined)),
        (None, paired) => Ok(paired),
    }
}

fn is_block_sysfs_kobject(sysfs_root: &Path, directory: &Path) -> bool {
    let Ok(relative) = directory.strip_prefix(sysfs_root) else {
        return false;
    };
    let mut saw_block = false;
    for component in relative.components() {
        if let Component::Normal(name) = component {
            if saw_block {
                return true;
            }
            saw_block = name == OsStr::new("block");
        }
    }
    false
}

fn read_sysfs_devnum(sysfs_root: &Path, directory: &Path) -> io::Result<Option<(u32, u32)>> {
    let uevent = match read_optional_text_strict(&directory.join("uevent"))? {
        Some(uevent) => uevent,
        None => String::new(),
    };
    if let Some(devnum) = parse_sysfs_maj_min(&uevent)? {
        return Ok(Some(devnum));
    }

    if !is_block_sysfs_kobject(sysfs_root, directory) {
        return Ok(None);
    }
    let dev = read_optional_text_strict(&directory.join("dev"))?
        .ok_or_else(|| invalid_data("block sysfs entry lacks MAJOR/MINOR"))?;
    parse_devnum(dev.trim()).map(Some)
}

fn read_optional_text_strict(path: &Path) -> io::Result<Option<String>> {
    match fs::read(path) {
        Ok(bytes) => String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| invalid_data(format!("non-UTF-8 file: {}", path.display()))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Collect this device's number and the numbers of its sysfs block ancestors.
fn sysfs_device_numbers(
    sysfs_root: &Path,
    sysfs_device: &Path,
    major: u32,
    minor: u32,
) -> io::Result<Vec<(u32, u32)>> {
    if !sysfs_device.starts_with(sysfs_root) {
        return Err(invalid_data("sysfs device is outside sysfs root"));
    }
    let mut numbers = vec![(major, minor)];
    let mut current = sysfs_device.parent();
    while let Some(directory) = current {
        if directory == sysfs_root {
            break;
        }
        if !directory.starts_with(sysfs_root) {
            break;
        }
        if let Some(devnum) = read_sysfs_devnum(sysfs_root, directory)? {
            if !numbers.contains(&devnum) {
                numbers.push(devnum);
            }
        }
        current = directory.parent();
    }
    Ok(numbers)
}

/// Find boot mount points served by the device or one of its sysfs parents.
///
/// `None` means the relation could not be established; callers must add a
/// blocker instead of treating it as "not boot related".
fn boot_related_mounts(
    rows: &[MountInfoRow],
    sysfs_root: &Path,
    sysfs_device: &Path,
    major: u32,
    minor: u32,
) -> Option<Vec<PathBuf>> {
    if !rows
        .iter()
        .any(|row| row.mount_point == Path::new(BOOT_MOUNTS[0]))
    {
        return None;
    }
    let numbers = sysfs_device_numbers(sysfs_root, sysfs_device, major, minor).ok()?;
    let mut related = Vec::new();
    for mount in BOOT_MOUNTS {
        let mount = Path::new(mount);
        if rows
            .iter()
            .any(|row| row.mount_point == mount && numbers.contains(&(row.major, row.minor)))
        {
            related.push(mount.to_path_buf());
        }
    }
    Some(related)
}

#[allow(clippy::too_many_arguments)]
fn blockers(
    read_only: bool,
    size_bytes: u64,
    mounts: &[PathBuf],
    btrfs_fs_mounted: bool,
    swap_active: bool,
    boot_related: &[PathBuf],
    boot_relation_known: bool,
    holders: &[String],
    slaves: &[String],
) -> Vec<String> {
    let mut blockers = vec![DEVICE_EXECUTION_DISABLED.to_owned()];
    if read_only {
        blockers.push("read_only".to_owned());
    }
    if size_bytes == 0 {
        blockers.push("zero_size".to_owned());
    }
    if !mounts.is_empty() {
        blockers.push("mounted".to_owned());
    }
    if btrfs_fs_mounted {
        blockers.push("btrfs_fs_mounted".to_owned());
    }
    if swap_active {
        blockers.push("swap_active".to_owned());
    }
    if !boot_related.is_empty() {
        blockers.push("boot_related".to_owned());
    }
    if !holders.is_empty() {
        blockers.push("holders".to_owned());
    }
    if !slaves.is_empty() {
        blockers.push("slaves".to_owned());
    }
    if !boot_relation_known {
        blockers.push(BOOT_RELATION_UNKNOWN.to_owned());
    }
    blockers
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestDir;

    const SWAP_HEADER: &str = "Filename\tType\tSize\tUsed\tPriority\n";

    fn write_fake(root: &Path, relative: &str, contents: &[u8]) -> PathBuf {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn mountinfo_decodes_escaped_mount_points() {
        let rows = parse_mountinfo(
            "36 35 8:1 / /mnt/a\\040b rw shared:1 - ext4 /dev/sda1 rw\n\
             37 36 8:2 / /tab\\011and\\012line\\134x rw - ext4 /dev/sda2 rw\n",
        )
        .unwrap();
        assert_eq!(rows[0].major, 8);
        assert_eq!(rows[0].minor, 1);
        assert_eq!(rows[0].mount_point, PathBuf::from("/mnt/a b"));
        assert_eq!(rows[1].mount_point, PathBuf::from("/tab\tand\nline\\x"));
    }

    #[test]
    fn mount_source_path_matches_virtual_device_numbers() {
        let dir = TestDir::new();
        let device = dir.path().join("disk");
        fs::write(&device, []).unwrap();
        let canonical = fs::canonicalize(&device).unwrap();
        // btrfs reports a synthetic 0:34 device number while the underlying
        // block device is 259:2; the source path still identifies it.
        let rows = parse_mountinfo(&format!(
            "40 1 0:34 /@ / rw shared:1 - btrfs {} rw\n",
            device.display()
        ))
        .unwrap();
        assert_eq!(
            mounts_for_device(&rows, 259, 2, &canonical),
            vec![PathBuf::from("/")]
        );
    }

    #[test]
    fn mountinfo_accepts_multiple_rows_and_rejects_bad_rows() {
        let rows = parse_mountinfo(
            "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n\
             2 1 8:2 / /boot rw shared:2 - ext4 /dev/sda2 rw\n",
        )
        .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].mount_point, PathBuf::from("/boot"));
        assert!(parse_mountinfo("").unwrap().is_empty());

        for invalid in [
            "1 0 8:1 / / rw - ext4 /dev/sda1 rw extra\n",
            "1 0 8:1 / / rw ext4 /dev/sda1 rw\n",
            "x 0 8:1 / / rw - ext4 /dev/sda1 rw\n",
            "1 x 8:1 / / rw - ext4 /dev/sda1 rw\n",
            "1 0 nope / / rw - ext4 /dev/sda1 rw\n",
            "1 0 8:1 / bad\\04 / rw - ext4 /dev/sda1 rw\n",
            "1 0 8:1 / relative rw - ext4 /dev/sda1 rw\n",
        ] {
            assert!(parse_mountinfo(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn swaps_parser_handles_empty_files_and_escaped_spaces() {
        assert!(parse_swaps("").is_err());
        assert!(parse_swaps(SWAP_HEADER).unwrap().is_empty());

        let data = format!("{SWAP_HEADER}/swap\\040file file 4 0 -2\n");
        assert_eq!(
            parse_swaps(&data).unwrap(),
            vec![PathBuf::from("/swap file")]
        );

        for invalid in [
            format!("{SWAP_HEADER}relative file 4 0 -2\n"),
            format!("{SWAP_HEADER}/swap nope 4 0 -2\n"),
            format!("{SWAP_HEADER}/swap file x 0 -2\n"),
            format!("{SWAP_HEADER}/swap file 4 0\n"),
            format!("{SWAP_HEADER}/swap\\04 file 4 0 -2\n"),
        ] {
            assert!(parse_swaps(&invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn sysfs_uevent_accepts_both_device_number_forms() {
        assert_eq!(
            parse_sysfs_maj_min("MAJOR=8\nMINOR=1\nDEVNAME=sda1\n").unwrap(),
            Some((8, 1))
        );
        assert_eq!(
            parse_sysfs_maj_min("MAJ:MIN=259:2\nDEVNAME=nvme0n1p2\n").unwrap(),
            Some((259, 2))
        );
        assert_eq!(parse_sysfs_maj_min("DEVNAME=sda\n").unwrap(), None);
        for invalid in [
            "MAJOR=8\n",
            "MAJOR=x\nMINOR=1\n",
            "MAJ:MIN=259\n",
            "MAJ:MIN=259:2\nMAJOR=8\nMINOR=2\n",
            "not a key value row\n",
        ] {
            assert!(parse_sysfs_maj_min(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn size_conversion_is_checked() {
        assert_eq!(size_sectors_to_bytes(0).unwrap(), 0);
        assert_eq!(size_sectors_to_bytes(1).unwrap(), 512);
        let maximum = u64::MAX / SECTOR_SIZE;
        assert_eq!(size_sectors_to_bytes(maximum).unwrap(), maximum * 512);
        assert!(size_sectors_to_bytes(maximum + 1).is_err());
    }

    #[test]
    fn sysfs_names_are_sorted_and_missing_directories_are_empty() {
        let dir = TestDir::new();
        let holders = dir.path().join("devices/virtual/block/dm-0/holders");
        fs::create_dir_all(&holders).unwrap();
        fs::write(holders.join("dm-2"), []).unwrap();
        fs::write(holders.join("dm-1"), []).unwrap();
        assert_eq!(
            read_sysfs_names(&holders).unwrap(),
            vec!["dm-1".to_owned(), "dm-2".to_owned()]
        );
        assert!(read_sysfs_names(&dir.path().join("missing"))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn btrfs_membership_is_detected_from_sysfs() {
        let dir = TestDir::new();
        let root = fs::canonicalize(dir.path()).unwrap();
        write_fake(&root, "fs/btrfs/uuid/devices/nvme0n1p2/dev", b"259:2\n");
        assert!(btrfs_membership_mounted(&root, 259, 2).unwrap());
        assert!(!btrfs_membership_mounted(&root, 259, 3).unwrap());
    }

    #[test]
    fn blockers_include_every_conservative_reason() {
        assert_eq!(
            blockers(false, 512, &[], false, false, &[], true, &[], &[]),
            vec![DEVICE_EXECUTION_DISABLED.to_owned()]
        );
        let blockers = blockers(
            true,
            0,
            &[PathBuf::from("/")],
            true,
            true,
            &[PathBuf::from("/")],
            false,
            &["dm-0".to_owned()],
            &["sda".to_owned()],
        );
        for expected in [
            DEVICE_EXECUTION_DISABLED,
            "read_only",
            "zero_size",
            "mounted",
            "btrfs_fs_mounted",
            "swap_active",
            "boot_related",
            "holders",
            "slaves",
            BOOT_RELATION_UNKNOWN,
        ] {
            assert!(
                blockers.iter().any(|blocker| blocker == expected),
                "missing {expected:?} in {blockers:?}"
            );
        }
    }

    #[test]
    fn boot_relation_uses_sysfs_parent_device_numbers() {
        let dir = TestDir::new();
        let root = fs::canonicalize(dir.path()).unwrap();
        write_fake(
            &root,
            "devices/virtual/block/loop0/uevent",
            b"MAJOR=7\nMINOR=0\nDEVNAME=loop0\n",
        );
        write_fake(
            &root,
            "devices/virtual/block/loop0/loop0p1/uevent",
            b"MAJOR=7\nMINOR=1\nDEVNAME=loop0p1\n",
        );
        write_fake(
            &root,
            "devices/virtual/block/loop0/loop0p2/uevent",
            b"MAJOR=7\nMINOR=2\nDEVNAME=loop0p2\n",
        );
        let device = root.join("devices/virtual/block/loop0/loop0p1");
        let efi_device = root.join("devices/virtual/block/loop0/loop0p2");
        let rows = parse_mountinfo(
            "1 0 7:0 / / rw - ext4 /dev/loop0 rw\n\
             2 1 7:1 / /boot rw - ext4 /dev/loop0p1 rw\n\
             3 1 7:2 / /boot/efi rw - vfat /dev/loop0p2 rw\n",
        )
        .unwrap();

        assert_eq!(
            boot_related_mounts(&rows, &root, &device, 7, 1).unwrap(),
            vec![PathBuf::from("/"), PathBuf::from("/boot")]
        );
        assert_eq!(
            boot_related_mounts(&rows, &root, &efi_device, 7, 2).unwrap(),
            vec![PathBuf::from("/"), PathBuf::from("/boot/efi")]
        );
    }

    #[test]
    fn boot_relation_is_unknown_without_root_or_parent_metadata() {
        let dir = TestDir::new();
        let root = fs::canonicalize(dir.path()).unwrap();
        write_fake(
            &root,
            "devices/virtual/block/loop0/loop0p1/uevent",
            b"MAJOR=7\nMINOR=1\nDEVNAME=loop0p1\n",
        );
        let device = root.join("devices/virtual/block/loop0/loop0p1");
        let rows = parse_mountinfo("1 0 7:1 / / rw - ext4 /dev/loop0p1 rw\n").unwrap();
        assert!(boot_related_mounts(&rows, &root, &device, 7, 1).is_none());

        let rows = parse_mountinfo(
            "1 0 7:0 / / rw - ext4 /dev/loop0 rw\n\
             2 1 7:1 / /boot rw - ext4 /dev/loop0p1 rw\n",
        )
        .unwrap();
        assert!(boot_related_mounts(&rows, &root, &device, 7, 1).is_none());
    }

    #[test]
    fn preflight_rejects_missing_and_non_block_paths() {
        let dir = TestDir::new();
        assert!(matches!(
            preflight(&dir.path().join("missing")),
            Err(error) if error.kind() == io::ErrorKind::NotFound
        ));
        assert!(matches!(
            preflight(Path::new("/dev/null")),
            Err(error) if error.kind() == io::ErrorKind::InvalidInput
        ));

        let link = dir.path().join("null-link");
        std::os::unix::fs::symlink("/dev/null", &link).unwrap();
        assert!(matches!(
            preflight(&link),
            Err(error) if error.kind() == io::ErrorKind::InvalidInput
        ));
    }
}
