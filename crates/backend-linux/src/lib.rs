//! backend-linux: реализация контракта vanish-core поверх syscall.

mod sys;
#[cfg(test)]
mod test_support;

use std::ffi::OsStr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use sys as s;
use vanish_core::error::{Result, VanishError};
use vanish_core::fsinfo::{DeviceKind, EncryptionState, FsKind, JournalState, VolumeInfo};
use vanish_core::pattern::PatternStream;
use vanish_core::platform::{Extent, Opener, Platform, SwapEntry, Target, WipeHandle};

pub fn platform() -> Box<dyn Platform> {
    Box::new(LinuxPlatform)
}

/// RAII guard для RawFd.
pub struct Fd(i32);
impl Fd {
    pub fn raw(&self) -> i32 {
        self.0
    }
}
impl Drop for Fd {
    fn drop(&mut self) {
        s::close_fd(self.0);
    }
}

pub struct LinuxPlatform;

fn fs_of_magic(m: i64) -> FsKind {
    match m {
        s::MAGIC_EXT4 => FsKind::Ext4,
        s::MAGIC_XFS => FsKind::Xfs,
        s::MAGIC_F2FS => FsKind::F2fs,
        s::MAGIC_BTRFS => FsKind::Btrfs,
        s::MAGIC_ZFS => FsKind::Zfs,
        s::MAGIC_TMPFS => FsKind::Tmpfs,
        s::MAGIC_RAMFS => FsKind::Ramfs,
        s::MAGIC_OVERLAY => FsKind::Overlayfs,
        s::MAGIC_NFS => FsKind::Nfs,
        s::MAGIC_CIFS => FsKind::Cifs,
        s::MAGIC_FUSE => FsKind::Fuse,
        s::MAGIC_VFAT => FsKind::Vfat,
        s::MAGIC_EXFAT => FsKind::Exfat,
        s::MAGIC_NTFS3 | s::MAGIC_NTFS => FsKind::Ntfs,
        s::MAGIC_PROC => FsKind::Proc,
        s::MAGIC_SYSFS => FsKind::Sysfs,
        s::MAGIC_DEVPTS => FsKind::Devfs,
        _ => FsKind::Other,
    }
}

struct MountRow {
    dev: String,
    mount: String,
    opts: String,
}

fn proc_mounts() -> Result<Vec<MountRow>> {
    let data = std::fs::read_to_string("/proc/mounts")?;
    let mut out = Vec::new();
    for line in data.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 4 {
            out.push(MountRow {
                dev: f[0].into(),
                mount: unescape_mount(f[1]),
                opts: f[3].into(),
            });
        }
    }
    Ok(out)
}

/// /proc/mounts escapes space, tab, newline and backslash as \ooo.
fn unescape_mount(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let oct = &bytes[i + 1..i + 4];
            if oct.iter().all(|b| (b'0'..=b'7').contains(b)) {
                let value = u16::from(oct[0] - b'0') * 64
                    + u16::from(oct[1] - b'0') * 8
                    + u16::from(oct[2] - b'0');
                out.push(value as u8);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// All mount rows that currently expose this st_dev. Bind mounts of the same
/// filesystem can carry different options; callers must treat any `ro` row as
/// read-only rather than trusting the first match.
fn mount_rows_of(st_dev: u64) -> Result<Vec<MountRow>> {
    let mut out = Vec::new();
    for row in proc_mounts()? {
        if let Ok((dev, _, _, _)) = s::stat_dev_ino(Path::new(&row.mount)) {
            if dev == st_dev {
                out.push(row);
            }
        }
    }
    Ok(out)
}

fn sys_dev_dir(maj: u32, min: u32) -> Option<PathBuf> {
    let p = format!("/sys/dev/block/{}:{}", maj, min);
    let resolved = std::fs::read_link(Path::new(&p)).ok()?;
    Some(PathBuf::from("/sys/dev/block/").join(resolved))
}

fn rotational(dev: u64) -> DeviceKind {
    let (maj, min) = (libc::major(dev) as u32, libc::minor(dev) as u32);
    if let Some(dir) = sys_dev_dir(maj, min) {
        let parent = dir.parent().map(|p| p.to_path_buf()).unwrap_or(dir.clone());
        for cand in [
            dir.join("queue/rotational"),
            parent.join("queue/rotational"),
        ] {
            if let Ok(v) = std::fs::read_to_string(&cand) {
                return match v.trim() {
                    "0" => DeviceKind::Ssd,
                    "1" => DeviceKind::Rotational,
                    _ => DeviceKind::Unknown,
                };
            }
        }
    }
    DeviceKind::Unknown
}

fn is_dm_crypt(dev: u64) -> EncryptionState {
    let (maj, min) = (libc::major(dev) as u32, libc::minor(dev) as u32);
    if let Some(dir) = sys_dev_dir(maj, min) {
        let uuid_path = dir.join("dm/uuid");
        if let Ok(u) = std::fs::read_to_string(&uuid_path) {
            if u.trim().starts_with("CRYPT-") {
                return EncryptionState::Encrypted;
            }
            return EncryptionState::NotEncrypted;
        }
    }
    EncryptionState::Unknown
}

fn swap_entries() -> Result<Vec<SwapEntry>> {
    read_swap_entries(Path::new("/proc/swaps"))
}

fn read_swap_entries(path: &Path) -> Result<Vec<SwapEntry>> {
    let data = std::fs::read_to_string(path)?;
    parse_swap_entries(&data).map_err(VanishError::Io)
}

fn parse_swap_entries(data: &str) -> std::io::Result<Vec<SwapEntry>> {
    let invalid =
        || std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid /proc/swaps data");
    let mut lines = data.lines();
    if lines
        .next()
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        != Some(vec!["Filename", "Type", "Size", "Used", "Priority"])
    {
        return Err(invalid());
    }
    let mut out = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() != 5 || !matches!(f[1], "file" | "partition") {
            return Err(invalid());
        }
        let size = f[2]
            .parse::<u64>()
            .ok()
            .and_then(|n| n.checked_mul(1024))
            .ok_or_else(invalid)?;
        f[3].parse::<u64>().map_err(|_| invalid())?;
        f[4].parse::<i32>().map_err(|_| invalid())?;
        out.push(SwapEntry {
            path: f[0].into(),
            size,
        });
    }
    Ok(out)
}

fn basename_of(p: &str) -> String {
    p.rsplit('/').next().unwrap_or(p).to_string()
}

fn is_unsupported(error: &std::io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EOPNOTSUPP) | Some(libc::ENOTTY) | Some(libc::EINVAL) | Some(libc::ENOSYS)
    )
}

impl Platform for LinuxPlatform {
    fn name(&self) -> &'static str {
        "linux"
    }

    fn fsinfo(&self, path: &Path) -> Result<VolumeInfo> {
        let magic = s::statfs_magic(path)?;
        let fs = fs_of_magic(magic);
        let md = std::fs::symlink_metadata(path).map_err(VanishError::Io)?;
        let st_dev = md.dev() as u64;
        let rows = mount_rows_of(st_dev)?;
        let row = rows.first();
        let device_kind = if fs.is_ram() {
            DeviceKind::Ram
        } else {
            rotational(st_dev)
        };
        let encrypted = is_dm_crypt(st_dev);
        let journal = match fs {
            // XFS always carries a journal; conservative Active is the honest
            // answer because querying journal state would need xfs-specific code.
            FsKind::Ext4 | FsKind::Ntfs | FsKind::F2fs | FsKind::Xfs => JournalState::Active,
            FsKind::Vfat | FsKind::Exfat | FsKind::Tmpfs | FsKind::Ramfs => JournalState::None,
            _ => JournalState::Unknown,
        };
        let dev_name = row.as_ref().map(|r| basename_of(&r.dev));
        let entries = swap_entries()?;
        let mut swap_sharing = false;
        for sw in &entries {
            let sw_path = Path::new(&sw.path);
            // An inaccessible swap object is uncertainty, not evidence of safety.
            let swap_md = std::fs::metadata(sw_path)?;
            use std::os::unix::fs::FileTypeExt;
            let swap_dev = if swap_md.file_type().is_block_device() {
                swap_md.rdev()
            } else {
                swap_md.dev()
            };
            if swap_dev == st_dev {
                swap_sharing = true;
                break;
            }
            if let Some(dn) = &dev_name {
                if basename_of(&sw.path) == *dn {
                    swap_sharing = true;
                    break;
                }
            }
        }
        Ok(VolumeInfo {
            fs,
            fs_name: format!("{:?}", fs),
            mount: row.as_ref().map(|r| r.mount.clone()).unwrap_or_default(),
            device: row.as_ref().map(|r| r.dev.clone()),
            device_kind,
            encrypted,
            journal,
            cow: fs.is_cow(),
            ro_mount: rows.is_empty()
                || rows
                    .iter()
                    .any(|r| r.opts.split(',').any(|o| o.trim() == "ro")),
            swap_sharing_fs: swap_sharing,
            swap_pages_possible: !entries.is_empty(),
            // Detection alone is not cryptographic erasure: no keys were erased.
            ssd_chipoff_protected: false,
        })
    }

    fn openers(&self, dev: u64, ino: u64) -> Result<Vec<Opener>> {
        let self_pid = std::process::id();
        let mut out = Vec::new();
        let pd = std::fs::read_dir("/proc").map_err(VanishError::Io)?;
        for ent in pd {
            let ent = ent?;
            let pid = match ent.file_name().to_string_lossy().parse::<u32>() {
                Ok(p) => p,
                Err(_) => continue,
            };
            if pid == self_pid {
                continue;
            }
            // Exiting processes/fds may disappear; inaccessible ones are not
            // evidence that no opener exists (e.g. hidepid/Yama restrictions).
            let fds = match proc_probe(std::fs::read_dir(ent.path().join("fd")))? {
                Some(fds) => fds,
                None => continue,
            };
            for fd_ent in fds {
                let fd_ent = fd_ent?;
                if let Some(md) = proc_probe(std::fs::metadata(fd_ent.path()))? {
                    if md.dev() as u64 == dev && md.ino() as u64 == ino {
                        let exe = std::fs::read_link(format!("/proc/{}/exe", pid))
                            .map(|l| l.to_string_lossy().into_owned())
                            .unwrap_or_else(|_| "?".into());
                        out.push(Opener { pid, exe });
                        break;
                    }
                }
            }
        }
        Ok(out)
    }

    fn open_handle(&self, t: &Target) -> Result<Box<dyn WipeHandle>> {
        Ok(Box::new(LinuxWipeHandle::open(t)?))
    }

    fn stream_names(&self, t: &Target) -> Result<Vec<(String, u64)>> {
        let all = s::llist_xattrs(&t.abs)?;
        Ok(all
            .into_iter()
            .filter(|(n, _)| n.starts_with("user."))
            .collect())
    }

    fn erase_stream(&self, t: &Target, name: &str) -> Result<()> {
        s::lremove_xattr(&t.abs, name)?;
        Ok(())
    }

    fn rename_to_tail(&self, t: &Target) -> Result<String> {
        let tail = format!(".{}", vanish_core::util::random_tail());
        let dirfd = s::openat_dir(&t.parent)?;
        let _guard = Fd(dirfd);
        s::renameat_dir(dirfd, &t.name, OsStr::new(&tail))?;
        s::fsync_fd(dirfd)?;
        Ok(tail)
    }

    fn fsync_dir(&self, dir: &Path) -> Result<()> {
        let fd = s::openat_dir(dir)?;
        let _g = Fd(fd);
        s::fsync_fd(fd)?;
        Ok(())
    }

    fn unlink(&self, t: &Target, tail: &str) -> Result<()> {
        let dirfd = s::openat_dir(&t.parent)?;
        let _g = Fd(dirfd);
        s::unlinkat_dir(dirfd, OsStr::new(tail), 0)?;
        s::fsync_fd(dirfd)?;
        Ok(())
    }

    fn rmdir(&self, t: &Target, tail: &str) -> Result<()> {
        let dirfd = s::openat_dir(&t.parent)?;
        let _g = Fd(dirfd);
        s::unlinkat_dir(dirfd, OsStr::new(tail), s::AT_REMOVEDIR)?;
        s::fsync_fd(dirfd)?;
        Ok(())
    }

    fn trim_mount(&self, mount: &Path) -> Result<bool> {
        match s::fitrim(mount) {
            Ok(_) => Ok(true),
            Err(error) if is_unsupported(&error) => Ok(false),
            Err(error) => Err(VanishError::Io(error)),
        }
    }

    fn swap_active(&self) -> Result<Vec<SwapEntry>> {
        swap_entries()
    }

    fn find_tails(&self, root: &Path) -> Result<Vec<PathBuf>> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let md = std::fs::symlink_metadata(&dir)?;
            if md.is_symlink() || !md.is_dir() {
                return Err(VanishError::UnsafePath(
                    "recovery root must be a directory, not a symlink".into(),
                ));
            }
            let rd = std::fs::read_dir(&dir).map_err(VanishError::Io)?;
            for ent in rd {
                let ent = ent?;
                let p = ent.path();
                let name = ent.file_name().to_string_lossy().into_owned();
                let md = std::fs::symlink_metadata(&p).map_err(VanishError::Io)?;
                if md.is_symlink() {
                    continue;
                }
                let is_tail = name.starts_with(vanish_core::TAIL_PREFIX);
                if md.is_dir() {
                    if is_tail {
                        out.push(p.clone());
                    }
                    stack.push(p);
                } else if is_tail {
                    out.push(p);
                }
            }
        }
        Ok(out)
    }
}

fn proc_probe<T>(result: std::io::Result<T>) -> std::io::Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

// ---------- handle ----------

mod wipe_handle {
    use super::*;

    pub struct LinuxWipeHandle {
        pub fd_direct: Option<Fd>,
        pub fd_buf: Fd,
        pub abs_path: PathBuf,
        pub buf: vanish_core::aligned::AlignedBuf,
        /// Отдельный выровненный буфер чтения (O_DIRECT требует выравнивания и юзер-буфера).
        pub verify_buf: vanish_core::aligned::AlignedBuf,
        pub len: u64,
        pub dev: u64,
        pub ino: u64,
        pub used_buf: bool,
    }

    impl LinuxWipeHandle {
        fn validate_fd(fd: &Fd, t: &Target) -> Result<libc::stat> {
            let st = s::fstat(fd.raw())?;
            if st.st_mode & libc::S_IFMT != libc::S_IFREG {
                return Err(VanishError::IdentityMismatch(
                    "opened object is not a regular file".into(),
                ));
            }
            if (st.st_dev as u64, st.st_ino as u64) != (t.dev, t.ino) {
                return Err(VanishError::IdentityMismatch("dev/ino after open".into()));
            }
            // The core owns hardlink consent; reject any change since that check.
            if st.st_nlink == 0 || st.st_nlink as u64 != u64::from(t.nlink) {
                return Err(VanishError::IdentityMismatch(
                    "nlink changed after preflight".into(),
                ));
            }
            Ok(st)
        }

        pub fn open(t: &Target) -> Result<Self> {
            Self::open_with(t, s::openat_name)
        }

        fn open_with(
            t: &Target,
            mut open: impl FnMut(i32, &OsStr, i32) -> std::io::Result<i32>,
        ) -> Result<Self> {
            if !t.abs.is_absolute()
                || t.abs.parent() != Some(t.parent.as_path())
                || t.abs.file_name() != Some(t.name.as_os_str())
            {
                return Err(VanishError::UnsafePath("inconsistent target path".into()));
            }
            let parent = Fd(s::openat_dir(&t.parent)?);
            // O_NONBLOCK prevents a substituted FIFO from hanging before fstat.
            let base_flags = libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
            let direct = match open(parent.raw(), &t.name, base_flags | libc::O_DIRECT) {
                Ok(fd) => Some(Fd(fd)),
                // On Linux ENOTSUP is the same errno as EOPNOTSUPP.
                Err(e)
                    if matches!(
                        e.raw_os_error(),
                        Some(libc::EINVAL) | Some(libc::EOPNOTSUPP) | Some(libc::ENOSYS)
                    ) =>
                {
                    None
                }
                Err(e) => return Err(VanishError::Io(e)),
            };
            if let Some(fd) = &direct {
                Self::validate_fd(fd, t)?;
            }
            let buffered = Fd(open(parent.raw(), &t.name, base_flags)?);
            let st = Self::validate_fd(&buffered, t)?;
            // Recheck both once acquired: neither descriptor may escape validation.
            if let Some(fd) = &direct {
                Self::validate_fd(fd, t)?;
            }
            Ok(LinuxWipeHandle {
                fd_direct: direct,
                fd_buf: buffered,
                abs_path: t.abs.clone(),
                buf: vanish_core::aligned::AlignedBuf::zeroed(vanish_core::aligned::CHUNK),
                verify_buf: vanish_core::aligned::AlignedBuf::zeroed(vanish_core::aligned::CHUNK),
                len: st.st_size as u64,
                dev: t.dev,
                ino: t.ino,
                used_buf: false,
            })
        }

        /// Выбор fd для записи/чтения: O_DIRECT если запись выровнена и он есть.
        /// Обновляет self.used_buf. Возвращает raw fd.
        fn pick_fd(&mut self, off64: u64, size: usize, want_direct: bool) -> i32 {
            let direct_ok = want_direct && self.fd_direct.is_some();
            let aligned = off64 % 4096 == 0 && size % 4096 == 0;
            if direct_ok && aligned {
                self.fd_direct.as_ref().unwrap().raw()
            } else {
                self.used_buf = true;
                self.fd_buf.raw()
            }
        }

        fn any_fd(&self) -> i32 {
            match &self.fd_direct {
                Some(f) => f.raw(),
                None => self.fd_buf.raw(),
            }
        }

        fn ensure_range(&self, off: u64, len: u64) -> Result<()> {
            let end = off.checked_add(len).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "I/O range overflow")
            })?;
            if end > self.len {
                return Err(VanishError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "I/O range exceeds opened file length",
                )));
            }
            Ok(())
        }
    }

    impl WipeHandle for LinuxWipeHandle {
        fn dev_ino(&self) -> (u64, u64) {
            (self.dev, self.ino)
        }

        fn len(&self) -> Result<u64> {
            Ok(self.len)
        }

        fn extents(&self) -> Result<Option<Vec<Extent>>> {
            // Shared extents are expected on COW filesystems; the strategy layer
            // only reaches them after an explicit --accept-cow decision. On a
            // non-COW filesystem SHARED means reflink/dedupe: a logical overwrite
            // COWs the data and leaves the old blocks readable, so fail closed.
            let allow_shared = s::statfs_magic(&self.abs_path)
                .map(|magic| fs_of_magic(magic).is_cow())
                .unwrap_or(false);
            match s::fiemap(self.any_fd(), allow_shared) {
                Ok(Some(list)) => Ok(Some(
                    list.into_iter()
                        .map(|(l, n)| Extent { logical: l, len: n })
                        .collect(),
                )),
                Ok(None) => Ok(None),
                Err(e) => Err(VanishError::Io(e)),
            }
        }

        fn overwrite(&mut self, off: u64, len: u64, gen: &mut PatternStream) -> Result<()> {
            self.ensure_range(off, len)?;
            let chunk = vanish_core::aligned::CHUNK as u64;
            let end = off.checked_add(len).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "overwrite range overflow")
            })?;
            let mut pos = off;
            while pos < end {
                let n = chunk.min(end - pos) as usize;
                {
                    let buf = self.buf.as_mut();
                    gen.fill(&mut buf[..n]);
                }
                let fd = self.pick_fd(pos, n, true);
                s::pwrite_at(fd, &self.buf[0..n], pos).map_err(VanishError::Io)?;
                pos += n as u64;
            }
            Ok(())
        }

        fn verify(&mut self, off: u64, len: u64, gen: &mut PatternStream) -> Result<()> {
            self.ensure_range(off, len)?;
            let chunk = vanish_core::aligned::CHUNK as u64;
            let end = off.checked_add(len).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "verify range overflow")
            })?;
            let mut pos = off;
            while pos < end {
                let n = chunk.min(end - pos) as usize;
                let fd = self.pick_fd(pos, n, true);
                // Читаем в выровненный буфер: при O_DIRECT юзер-буфер тоже должен быть выровнен.
                {
                    let raw = self.verify_buf.as_mut();
                    s::pread_exact_at(fd, &mut raw[..n], pos).map_err(VanishError::Io)?;
                }
                {
                    let buf = self.buf.as_mut();
                    gen.fill(&mut buf[..n]);
                }
                {
                    let raw_cmp = self.verify_buf.as_mut();
                    if &raw_cmp[..n] != &self.buf[0..n] {
                        return Err(VanishError::VerifyMismatch { offset: pos });
                    }
                }
                pos += n as u64;
            }
            Ok(())
        }

        fn sync(&self) -> Result<()> {
            s::fsync_fd(self.any_fd())?;
            Ok(())
        }

        fn punch(&mut self) -> Result<bool> {
            match s::fallocate_punch(self.any_fd(), self.len) {
                Ok(()) => Ok(true),
                Err(error) if is_unsupported(&error) => Ok(false),
                Err(error) => Err(VanishError::Io(error)),
            }
        }

        fn truncate0(&mut self) -> Result<()> {
            s::ftruncate0(self.any_fd())?;
            self.len = 0;
            Ok(())
        }

        fn dontneed(&self) -> Result<()> {
            s::fadvise_dontneed(self.fd_buf.raw())?;
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::test_support::TestDir;
        use vanish_core::config::PatternChoice;

        fn pattern() -> PatternStream {
            PatternStream::new(PatternChoice::Random, 0, [0x42; 32])
        }

        #[test]
        fn owned_file_overwrite_verify_and_sync() {
            let dir = TestDir::new();
            let len = 8192 + 31;
            let t = dir.file("target", &vec![0; len]);
            let mut handle = LinuxWipeHandle::open(&t).unwrap();
            assert_eq!(handle.dev_ino(), (t.dev, t.ino));
            assert_eq!(handle.len().unwrap(), len as u64);
            LinuxWipeHandle::validate_fd(&handle.fd_buf, &t).unwrap();
            if let Some(fd) = &handle.fd_direct {
                LinuxWipeHandle::validate_fd(fd, &t).unwrap();
            }
            handle.overwrite(0, len as u64, &mut pattern()).unwrap();
            handle.sync().unwrap();
            handle.verify(0, len as u64, &mut pattern()).unwrap();
            let mut expected = vec![0; len];
            pattern().fill(&mut expected);
            assert_eq!(std::fs::read(&t.abs).unwrap(), expected);
        }

        #[test]
        fn aligned_owned_file_uses_direct_fd_when_supported() {
            let dir = TestDir::new();
            let t = dir.file("target", &[0; 8192]);
            let mut handle = LinuxWipeHandle::open(&t).unwrap();
            let direct_available = handle.fd_direct.is_some();
            handle.overwrite(0, 8192, &mut pattern()).unwrap();
            handle.sync().unwrap();
            handle.verify(0, 8192, &mut pattern()).unwrap();
            assert_eq!(handle.used_buf, !direct_available);
        }

        #[test]
        fn verify_truncated_zero_file_is_unexpected_eof_not_stale_success() {
            let dir = TestDir::new();
            let t = dir.file("target", &[0; 31]);
            let mut handle = LinuxWipeHandle::open(&t).unwrap();
            let zero = || PatternStream::new(PatternChoice::Zero, 0, [0; 32]);
            handle.verify(0, 31, &mut zero()).unwrap();
            let file = std::fs::OpenOptions::new()
                .write(true)
                .open(&t.abs)
                .unwrap();
            file.set_len(1).unwrap();
            let error = handle.verify(0, 31, &mut zero()).unwrap_err();
            assert!(
                matches!(error, VanishError::Io(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof)
            );
        }

        #[test]
        fn rejects_identity_and_link_count_changes_without_writing() {
            let dir = TestDir::new();
            let t = dir.file("target", b"do not modify");
            let wrong = dir.file("other", b"other");
            let mut stale = t.clone();
            stale.ino = wrong.ino;
            assert!(matches!(
                LinuxWipeHandle::open(&stale),
                Err(VanishError::IdentityMismatch(_))
            ));
            std::fs::hard_link(&t.abs, dir.path().join("hardlink")).unwrap();
            assert!(matches!(
                LinuxWipeHandle::open(&t),
                Err(VanishError::IdentityMismatch(_))
            ));
            // Existing, unchanged hardlinks remain subject to core consent.
            let mut consented = t.clone();
            consented.nlink = 2;
            LinuxWipeHandle::open(&consented).unwrap();
            assert_eq!(std::fs::read(&t.abs).unwrap(), b"do not modify");
        }

        #[test]
        fn rejects_symlink_leaf_parent_and_nonregular_target() {
            let dir = TestDir::new();
            let t = dir.file("target", b"safe");
            let leaf = dir.path().join("leaf");
            std::os::unix::fs::symlink(&t.abs, &leaf).unwrap();
            let alias = Target::from_parts(leaf, t.dev, t.ino, t.size, t.nlink);
            assert!(LinuxWipeHandle::open(&alias).is_err());
            let parent = dir.path().join("parent");
            std::os::unix::fs::symlink(dir.path(), &parent).unwrap();
            let alias = Target::from_parts(parent.join("target"), t.dev, t.ino, t.size, t.nlink);
            assert!(LinuxWipeHandle::open(&alias).is_err());
            let md = std::fs::metadata(dir.path()).unwrap();
            let nonregular = Target::from_parts(
                dir.path().to_owned(),
                md.dev(),
                md.ino(),
                0,
                md.nlink() as u32,
            );
            assert!(LinuxWipeHandle::open(&nonregular).is_err());
        }

        fn lock(fd: i32) -> bool {
            unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) == 0 }
        }

        #[test]
        fn validates_wrong_direct_fd_and_drops_it_before_buffered_open() {
            let dir = TestDir::new();
            let t = dir.file("target", b"safe");
            let wrong = dir.file("wrong", b"safe too");
            let mut calls = 0;
            let result = LinuxWipeHandle::open_with(&t, |_, _, _| {
                calls += 1;
                let fd = s::open_path(&wrong.abs, libc::O_RDWR | libc::O_CLOEXEC)?;
                assert!(lock(fd));
                Ok(fd)
            });
            assert!(matches!(result, Err(VanishError::IdentityMismatch(_))));
            assert_eq!(calls, 1);
            // Closing the rejected fd releases its exclusive flock.
            let probe = Fd(s::open_path(&wrong.abs, libc::O_RDWR | libc::O_CLOEXEC).unwrap());
            assert!(lock(probe.raw()), "rejected direct fd leaked");
        }

        #[test]
        fn validates_buffered_fd_and_drops_both_on_replacement() {
            let dir = TestDir::new();
            let t = dir.file("target", b"safe");
            let wrong = dir.file("wrong", b"safe too");
            let mut calls = 0;
            let result = LinuxWipeHandle::open_with(&t, |parent, _, _| {
                let name = if calls == 0 { &t.name } else { &wrong.name };
                calls += 1;
                // Real regular-file fds; omit O_DIRECT only to make this fault
                // injection independent of filesystem support for direct I/O.
                let fd = s::openat_name(parent, name, libc::O_RDWR | libc::O_CLOEXEC)?;
                assert!(lock(fd));
                Ok(fd)
            });
            assert!(matches!(result, Err(VanishError::IdentityMismatch(_))));
            assert_eq!(calls, 2);
            for path in [&t.abs, &wrong.abs] {
                let probe = Fd(s::open_path(path, libc::O_RDWR | libc::O_CLOEXEC).unwrap());
                assert!(
                    lock(probe.raw()),
                    "fd leaked on buffered validation failure"
                );
            }
        }

        #[test]
        fn buffered_open_failure_drops_direct_fd() {
            let dir = TestDir::new();
            let t = dir.file("target", b"safe");
            let mut calls = 0;
            let result = LinuxWipeHandle::open_with(&t, |parent, name, _| {
                calls += 1;
                if calls == 2 {
                    return Err(std::io::Error::from_raw_os_error(libc::EACCES));
                }
                let fd = s::openat_name(parent, name, libc::O_RDWR | libc::O_CLOEXEC)?;
                assert!(lock(fd));
                Ok(fd)
            });
            assert!(
                matches!(result, Err(VanishError::Io(ref e)) if e.raw_os_error() == Some(libc::EACCES))
            );
            let probe = Fd(s::open_path(&t.abs, libc::O_RDWR | libc::O_CLOEXEC).unwrap());
            assert!(
                lock(probe.raw()),
                "direct fd leaked on buffered open failure"
            );
        }

        #[test]
        fn buffered_fallback_is_validated_when_direct_is_unsupported() {
            let dir = TestDir::new();
            let t = dir.file("target", b"safe");
            for errno in [libc::EINVAL, libc::EOPNOTSUPP, libc::ENOTSUP, libc::ENOSYS] {
                let mut calls = 0;
                let handle = LinuxWipeHandle::open_with(&t, |parent, name, flags| {
                    calls += 1;
                    if flags & libc::O_DIRECT != 0 {
                        return Err(std::io::Error::from_raw_os_error(errno));
                    }
                    s::openat_name(parent, name, flags)
                })
                .unwrap();
                assert_eq!(calls, 2);
                assert!(handle.fd_direct.is_none());
                LinuxWipeHandle::validate_fd(&handle.fd_buf, &t).unwrap();
            }
        }

        #[test]
        fn direct_open_errors_do_not_fall_back_or_write() {
            let dir = TestDir::new();
            let t = dir.file("target", b"unchanged");
            for errno in [
                libc::EACCES,
                libc::EPERM,
                libc::EIO,
                libc::EMFILE,
                libc::ENFILE,
                libc::ENOENT,
                libc::ELOOP,
            ] {
                let mut calls = 0;
                let result = LinuxWipeHandle::open_with(&t, |_, _, _| {
                    calls += 1;
                    Err(std::io::Error::from_raw_os_error(errno))
                });
                assert!(
                    matches!(result, Err(VanishError::Io(ref e)) if e.raw_os_error() == Some(errno))
                );
                assert_eq!(calls, 1);
            }
            assert_eq!(std::fs::read(&t.abs).unwrap(), b"unchanged");
        }

        #[test]
        fn overflowing_ranges_fail_before_io_or_pattern_consumption() {
            let dir = TestDir::new();
            let t = dir.file("target", b"unchanged");
            let mut handle = LinuxWipeHandle::open(&t).unwrap();
            let mut gen = pattern();
            let overwrite_error = handle.overwrite(1, u64::MAX, &mut gen).unwrap_err();
            let verify_error = handle.verify(u64::MAX, 1, &mut gen).unwrap_err();
            for error in [overwrite_error, verify_error] {
                assert!(
                    matches!(error, VanishError::Io(ref e) if e.kind() == std::io::ErrorKind::InvalidInput)
                );
            }
            assert_eq!(std::fs::read(&t.abs).unwrap(), b"unchanged");
            let mut expected = [0; 32];
            let mut actual = [0; 32];
            pattern().fill(&mut expected);
            gen.fill(&mut actual);
            assert_eq!(actual, expected);
        }

        #[test]
        fn link_change_between_opens_is_rejected() {
            let dir = TestDir::new();
            let t = dir.file("target", b"safe");
            let mut calls = 0;
            let result = LinuxWipeHandle::open_with(&t, |parent, name, _| {
                calls += 1;
                let fd = s::openat_name(parent, name, libc::O_RDWR | libc::O_CLOEXEC)?;
                if calls == 2 {
                    std::fs::hard_link(&t.abs, dir.path().join("new-hardlink"))?;
                }
                Ok(fd)
            });
            assert!(matches!(result, Err(VanishError::IdentityMismatch(_))));
        }

        #[test]
        fn rejects_nonregular_fd_even_if_identity_matches() {
            let dir = TestDir::new();
            let md = std::fs::metadata(dir.path()).unwrap();
            let t = Target::from_parts(
                dir.path().to_owned(),
                md.dev(),
                md.ino(),
                0,
                md.nlink() as u32,
            );
            let fd = Fd(s::openat_dir(dir.path()).unwrap());
            assert!(matches!(
                LinuxWipeHandle::validate_fd(&fd, &t),
                Err(VanishError::IdentityMismatch(_))
            ));
        }
    }
}

pub use wipe_handle::LinuxWipeHandle;

// ---------- device helpers (vanish device) ----------

pub struct DeviceResult {
    pub path: String,
    pub size: u64,
    pub method: &'static str,
    pub physical_guaranteed: bool,
}

/// Temporarily disabled: no path lookup, open, or destructive ioctl is permitted.
pub fn device_wipe(_dev_path: &Path) -> Result<DeviceResult> {
    Err(VanishError::NotPermitted(
        "destructive device wipe is disabled pending a safe device authorization design".into(),
    ))
}

pub fn avail_bytes(path: &Path) -> Result<u64> {
    Ok(s::free_bytes(path)?)
}

pub fn is_mounted_device(dev_path: &Path) -> bool {
    let want = dev_path.display().to_string();
    let data = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
    data.lines()
        .any(|l| l.split_whitespace().next() == Some(want.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestDir;
    use std::io::{Error, ErrorKind};

    const SWAP_HEADER: &str = "Filename\tType\tSize\tUsed\tPriority\n";

    #[test]
    fn unsupported_errno_policy_does_not_mask_io_errors() {
        for errno in [libc::EOPNOTSUPP, libc::ENOTTY, libc::EINVAL, libc::ENOSYS] {
            assert!(is_unsupported(&Error::from_raw_os_error(errno)));
        }
        for errno in [libc::EIO, libc::ENOSPC, libc::EPERM, libc::EEXIST] {
            assert!(!is_unsupported(&Error::from_raw_os_error(errno)));
        }
    }

    #[test]
    fn mount_unescape_decodes_octal_sequences() {
        assert_eq!(unescape_mount("/mnt/a\\040b"), "/mnt/a b");
        assert_eq!(unescape_mount("/mnt/tab\\011name"), "/mnt/tab\tname");
        assert_eq!(unescape_mount("/plain/path"), "/plain/path");
        assert_eq!(unescape_mount("/bad\\04"), "/bad\\04");
    }

    #[test]
    fn recovery_rejects_symlink_root_and_regular_file_root() {
        let dir = TestDir::new();
        let tail = dir.file(&format!("{}owned", vanish_core::TAIL_PREFIX), b"unchanged");
        let alias_dir = TestDir::new();
        let alias = alias_dir.path().join("root-link");
        std::os::unix::fs::symlink(dir.path(), &alias).unwrap();
        assert!(matches!(
            LinuxPlatform.find_tails(&alias),
            Err(VanishError::UnsafePath(_))
        ));
        assert!(matches!(
            LinuxPlatform.find_tails(&tail.abs),
            Err(VanishError::UnsafePath(_))
        ));
        assert_eq!(std::fs::read(&tail.abs).unwrap(), b"unchanged");
    }

    #[test]
    fn recovery_walks_normal_directories_but_not_child_symlinks() {
        let dir = TestDir::new();
        let outside = TestDir::new();
        outside.file(&format!("{}outside", vanish_core::TAIL_PREFIX), b"outside");
        std::os::unix::fs::symlink(outside.path(), dir.path().join("child-link")).unwrap();
        let tail = dir.file(&format!("{}owned", vanish_core::TAIL_PREFIX), b"owned");
        let child = dir.path().join("child");
        std::fs::create_dir(&child).unwrap();
        let nested = child.join(format!("{}nested", vanish_core::TAIL_PREFIX));
        std::fs::write(&nested, b"nested").unwrap();
        let mut found = LinuxPlatform.find_tails(dir.path()).unwrap();
        found.sort();
        let mut expected = vec![tail.abs, nested];
        expected.sort();
        assert_eq!(found, expected);
    }

    #[test]
    fn swap_parser_distinguishes_empty_from_unknown() {
        assert!(parse_swap_entries(SWAP_HEADER).unwrap().is_empty());
        let data = format!("{SWAP_HEADER}/owned/swap file 4 0 -2\n");
        let entries = parse_swap_entries(&data).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "/owned/swap");
        assert_eq!(entries[0].size, 4096);
        for invalid in [
            String::new(),
            "not a swaps header\n".into(),
            format!("{SWAP_HEADER}truncated\n"),
            format!("{SWAP_HEADER}/swap file not-a-size 0 -2\n"),
            format!("{SWAP_HEADER}/swap file {} 0 -2\n", u64::MAX),
        ] {
            assert_eq!(
                parse_swap_entries(&invalid).unwrap_err().kind(),
                ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn swap_probe_propagates_read_and_parse_errors() {
        let dir = TestDir::new();
        assert!(matches!(
            read_swap_entries(&dir.path().join("missing")),
            Err(VanishError::Io(_))
        ));
        let invalid = dir.file("invalid", b"invalid swaps\n");
        assert!(
            matches!(read_swap_entries(&invalid.abs), Err(VanishError::Io(ref e)) if e.kind() == ErrorKind::InvalidData)
        );
        let valid = dir.file("valid", SWAP_HEADER.as_bytes());
        assert!(read_swap_entries(&valid.abs).unwrap().is_empty());
    }

    #[test]
    fn busy_probe_permission_denied_is_not_no_openers() {
        let denied = proc_probe::<()>(Err(Error::from(ErrorKind::PermissionDenied)));
        assert_eq!(denied.unwrap_err().kind(), ErrorKind::PermissionDenied);
        assert!(proc_probe::<()>(Err(Error::from(ErrorKind::NotFound)))
            .unwrap()
            .is_none());
    }

    #[test]
    fn device_wipe_rejects_before_path_lookup_or_any_io() {
        let dir = TestDir::new();
        let t = dir.file("not-a-device", b"must remain unchanged");
        for path in [
            t.abs.as_path(),
            &dir.path().join("missing"),
            Path::new("nul\0path"),
        ] {
            assert!(matches!(
                device_wipe(path),
                Err(VanishError::NotPermitted(_))
            ));
        }
        assert_eq!(std::fs::read(&t.abs).unwrap(), b"must remain unchanged");
    }
}
