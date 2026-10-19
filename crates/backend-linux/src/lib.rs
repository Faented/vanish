//! backend-linux: реализация контракта vanish-core поверх syscall.

mod sys;

use std::ffi::OsStr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use sys as s;
use vanish_core::error::{Result, VanishError};
use vanish_core::fsinfo::{
    DeviceKind, EncryptionState, FsKind, JournalState, VolumeInfo,
};
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
    fstype: String,
    opts: String,
}

fn proc_mounts() -> Vec<MountRow> {
    let mut out = Vec::new();
    let data = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
    for line in data.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 4 {
            out.push(MountRow {
                dev: f[0].into(),
                mount: f[1].into(),
                fstype: f[2].into(),
                opts: f[3].into(),
            });
        }
    }
    out
}

fn mount_of(st_dev: u64) -> Option<MountRow> {
    for row in proc_mounts() {
        if let Ok((dev, _, _, _)) = s::stat_dev_ino(Path::new(&row.mount)) {
            if dev == st_dev {
                return Some(row);
            }
        }
    }
    None
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
        for cand in [dir.join("queue/rotational"), parent.join("queue/rotational")] {
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

fn swap_entries() -> Vec<SwapEntry> {
    let mut out = Vec::new();
    let data = std::fs::read_to_string("/proc/swaps").unwrap_or_default();
    for (i, line) in data.lines().enumerate() {
        if i == 0 || line.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 3 {
            out.push(SwapEntry {
                path: f[0].into(),
                size: f[2].parse::<u64>().unwrap_or(0) * 1024,
            });
        }
    }
    out
}

fn basename_of(p: &str) -> String {
    p.rsplit('/').next().unwrap_or(p).to_string()
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
        let row = mount_of(st_dev);
        let device_kind = if fs.is_ram() {
            DeviceKind::Ram
        } else {
            rotational(st_dev)
        };
        let encrypted = is_dm_crypt(st_dev);
        let journal = match fs {
            FsKind::Ext4 | FsKind::Ntfs | FsKind::F2fs => JournalState::Active,
            FsKind::Vfat | FsKind::Exfat | FsKind::Tmpfs | FsKind::Ramfs => JournalState::None,
            _ => JournalState::Unknown,
        };
        let dev_name = row.as_ref().map(|r| basename_of(&r.dev));
        let entries = swap_entries();
        let mut swap_sharing = false;
        for sw in &entries {
            let sw_path = Path::new(&sw.path);
            if let Ok((sdev, _, _, _)) = s::stat_dev_ino(sw_path) {
                if sdev == st_dev {
                    swap_sharing = true;
                    break;
                }
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
            ro_mount: row
                .as_ref()
                .map(|r| r.opts.split(',').any(|o| o.trim() == "ro"))
                .unwrap_or(false),
            swap_sharing_fs: swap_sharing,
            swap_pages_possible: !entries.is_empty(),
            ssd_chipoff_protected: encrypted == EncryptionState::Encrypted,
        })
    }

    fn openers(&self, dev: u64, ino: u64) -> Result<Vec<Opener>> {
        let self_pid = std::process::id();
        let mut out = Vec::new();
        let pd = std::fs::read_dir("/proc").map_err(VanishError::Io)?;
        for ent in pd.flatten() {
            let pid = match ent.file_name().to_string_lossy().parse::<u32>() {
                Ok(p) => p,
                Err(_) => continue,
            };
            if pid == self_pid {
                continue;
            }
            let fds = std::fs::read_dir(ent.path().join("fd"));
            if let Ok(fds) = fds {
                'next_fd: for fd_ent in fds.flatten() {
                    if let Ok(md) = std::fs::metadata(fd_ent.path()) {
                        use std::os::unix::fs::MetadataExt;
                        if md.dev() as u64 == dev && md.ino() as u64 == ino {
                            let exe =
                                std::fs::read_link(format!("/proc/{}/exe", pid))
                                    .map(|l| l.to_string_lossy().into_owned())
                                    .unwrap_or_else(|_| "?".into());
                            out.push(Opener { pid, exe });
                            break 'next_fd;
                        }
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
            Err(_) => Ok(false),
        }
    }

    fn swap_active(&self) -> Result<Vec<SwapEntry>> {
        Ok(swap_entries())
    }

    fn find_tails(&self, root: &Path) -> Result<Vec<PathBuf>> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let rd = std::fs::read_dir(&dir).map_err(VanishError::Io)?;
            for ent in rd.flatten() {
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
        pub fn open(t: &Target) -> Result<Self> {
            let base_flags = libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC;
            let direct = match s::open_path(&t.abs, base_flags | libc::O_DIRECT) {
                Ok(fd) => Some(Fd(fd)),
                Err(_) => None,
            };
            let buf_open = s::open_path(&t.abs, base_flags)?;
            let (dev, ino, size, _nlink) = s::fstat_dev_ino(buf_open)?;
            if (dev, ino) != (t.dev, t.ino) {
                return Err(VanishError::IdentityMismatch("dev/ino после open".into()));
            }
            Ok(LinuxWipeHandle {
                fd_direct: direct,
                fd_buf: Fd(buf_open),
                abs_path: t.abs.clone(),
                buf: vanish_core::aligned::AlignedBuf::zeroed(vanish_core::aligned::CHUNK),
                verify_buf: vanish_core::aligned::AlignedBuf::zeroed(vanish_core::aligned::CHUNK),
                len: size,
                dev,
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
    }

    impl WipeHandle for LinuxWipeHandle {
        fn dev_ino(&self) -> (u64, u64) {
            (self.dev, self.ino)
        }

        fn len(&self) -> Result<u64> {
            Ok(self.len)
        }

        fn extents(&self) -> Result<Option<Vec<Extent>>> {
            match s::fiemap(self.any_fd()) {
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
            let chunk = vanish_core::aligned::CHUNK as u64;
            let end = off + len;
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
            let chunk = vanish_core::aligned::CHUNK as u64;
            let end = off + len;
            let mut pos = off;
            while pos < end {
                let n = chunk.min(end - pos) as usize;
                let fd = self.pick_fd(pos, n, true);
                // Читаем в выровненный буфер: при O_DIRECT юзер-буфер тоже должен быть выровнен.
                {
                    let raw = self.verify_buf.as_mut();
                    s::pread_at(fd, &mut raw[..n], pos).map_err(VanishError::Io)?;
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
                Err(_) => Ok(false),
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
}

pub use wipe_handle::LinuxWipeHandle;

// ---------- device helpers (vanish device) ----------

pub struct DeviceResult {
    pub path: String,
    pub size: u64,
    pub method: &'static str,
    pub physical_guaranteed: bool,
}

pub fn device_wipe(dev_path: &Path) -> Result<DeviceResult> {
    let flags = libc::O_RDWR | libc::O_CLOEXEC;
    let fd = s::open_path(dev_path, flags)?;
    let _guard = Fd(fd);
    let size = s::blk_size64(fd)?;
    match s::blk_discard(fd, size, true) {
        Ok(_) => Ok(DeviceResult {
            path: dev_path.display().to_string(),
            size,
            method: "blksecdiscard",
            physical_guaranteed: true,
        }),
        Err(_) => {
            s::blk_discard(fd, size, false)?;
            Ok(DeviceResult {
                path: dev_path.display().to_string(),
                size,
                method: "blkdiscard",
                physical_guaranteed: false,
            })
        }
    }
}

pub fn avail_bytes(path: &Path) -> Result<u64> {
    Ok(s::free_bytes(path)?)
}

pub fn is_mounted_device(dev_path: &Path) -> bool {
    let want = dev_path.display().to_string();
    let data = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
    data.lines().any(|l| l.split_whitespace().next() == Some(want.as_str()))
}
