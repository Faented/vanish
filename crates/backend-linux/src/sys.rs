//! Raw-слой syscall: ioctl-номера, FIEMAP, FITRIM, FSIO metameta.

#![allow(dead_code)]

use std::ffi::{CString, OsStr};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};

pub const AT_FDCWD: i32 = -100;
pub const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
pub const AT_REMOVEDIR: i32 = 0x200;

pub const O_EXCL0: i32 = 0; // placeholder, actual flags приходят из libc

// ioctl magic (linux asm-generic):
pub const FS_IOC_FIEMAP: u64 = 0xC020_660B; // _IOWR('f', 11, struct fiemap)
pub const FITRIM: u64 = 0xC018_5879; // _IOWR('X', 121, struct fstrim_range)

pub const FALLOC_FL_KEEP_SIZE: i32 = 0x01;
pub const FALLOC_FL_PUNCH_HOLE: i32 = 0x02;

pub const POSIX_FADV_DONTNEED: i32 = 4;

// magic ФС
pub const MAGIC_EXT4: i64 = 0xEF53;
pub const MAGIC_XFS: i64 = 0x5846_5342;
pub const MAGIC_BTRFS: i64 = 0x9123_683E;
pub const MAGIC_TMPFS: i64 = 0x0102_1994;
pub const MAGIC_RAMFS: i64 = 0x8584_58B6;
pub const MAGIC_OVERLAY: i64 = 0x794C_7630;
pub const MAGIC_NFS: i64 = 0x6969;
pub const MAGIC_CIFS: i64 = 0xFF53_4D42;
pub const MAGIC_FUSE: i64 = 0x6573_5546;
pub const MAGIC_F2FS: i64 = 0xF2F5_2010;
pub const MAGIC_VFAT: i64 = 0x4d44;
pub const MAGIC_EXFAT: i64 = 0x2011;
pub const MAGIC_PROC: i64 = 0x9fa0;
pub const MAGIC_SYSFS: i64 = 0x6265_6572;
pub const MAGIC_DEVPTS: i64 = 0x1cd1;
pub const MAGIC_NTFS3: i64 = 0x7366_746E;
pub const MAGIC_NTFS: i64 = 0x5346_544E;
pub const MAGIC_ZFS: i64 = 0x2FC1_2FC1;

pub fn errno_str(e: io::Error) -> String {
    e.to_string()
}

fn cstr(p: &OsStr) -> io::Result<CString> {
    CString::new(p.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL byte"))
}

pub fn cpath(p: &Path) -> io::Result<CString> {
    cstr(p.as_os_str())
}

fn cstr_component(name: &OsStr) -> io::Result<CString> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a single filename",
        ));
    }
    CString::new(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "filename contains NUL byte"))
}

/// open с флагом: простой wrapper.
pub fn open_path(path: &Path, flags: i32) -> io::Result<i32> {
    let c = cpath(path)?;
    let fd = unsafe { libc::open(c.as_ptr(), flags) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd)
    }
}

pub fn openat_dir(parent: &Path) -> io::Result<i32> {
    // Walk from a pinned root/cwd, never following a symlink in any component.
    // This pins the directory reached now, not its historical pathname: a rename
    // of a directory before/during traversal is still possible.
    // Traversal needs search permission, not read permission, on ancestors.
    let flags = libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let start = if parent.is_absolute() {
        Path::new("/")
    } else {
        Path::new(".")
    };
    let mut dir = unsafe { OwnedFd::from_raw_fd(open_path(start, flags)?) };
    for component in parent.components() {
        match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => {
                let fd = openat_name(dir.as_raw_fd(), name, flags)?;
                dir = unsafe { OwnedFd::from_raw_fd(fd) };
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "parent traversal is not allowed",
                ))
            }
        }
    }
    // Only the final directory needs a readable fd for fsync. Reopen the pinned
    // directory itself, rather than resolving its pathname a second time.
    let dot = cstr(OsStr::new("."))?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            dot.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd)
    }
}

/// Open exactly one directory entry relative to a pinned directory.
pub fn openat_name(dirfd: i32, name: &OsStr, flags: i32) -> io::Result<i32> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a single filename",
        ));
    }
    let c = CString::new(bytes)?;
    let fd = unsafe { libc::openat(dirfd, c.as_ptr(), flags) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd)
    }
}

pub fn close_fd(fd: i32) {
    unsafe { libc::close(fd) };
}

pub fn fstat_dev_ino(fd: i32) -> io::Result<(u64, u64, u64, u64)> {
    let s = fstat(fd)?;
    Ok((
        s.st_dev as u64,
        s.st_ino as u64,
        s.st_size as u64,
        s.st_nlink as u64,
    ))
}

pub fn fstat(fd: i32) -> io::Result<libc::stat> {
    let mut s: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut s) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(s)
}

pub fn stat_dev_ino(path: &Path) -> io::Result<(u64, u64, u64, u64)> {
    let mut s: libc::stat = unsafe { std::mem::zeroed() };
    let c = cpath(path)?;
    if unsafe { libc::stat(c.as_ptr(), &mut s) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((
        s.st_dev as u64,
        s.st_ino as u64,
        s.st_size as u64,
        s.st_nlink as u64,
    ))
}

pub fn renameat_dir(dir_fd: i32, from: &OsStr, to: &OsStr) -> io::Result<()> {
    let a = cstr_component(from)?;
    let b = cstr_component(to)?;
    let rc = unsafe {
        libc::renameat2(
            dir_fd,
            a.as_ptr(),
            dir_fd,
            b.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if rc == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        // Some filesystems (e.g. VFAT) do not implement RENAME_NOREPLACE.
        // The caller's tail is a random 64-bit name; only fall back when the
        // kernel rejects the flag itself, never on EEXIST or an I/O error.
        Some(libc::EINVAL) | Some(libc::ENOSYS) | Some(libc::EOPNOTSUPP) => {
            if unsafe { libc::renameat(dir_fd, a.as_ptr(), dir_fd, b.as_ptr()) } != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
        _ => Err(error),
    }
}

pub fn unlinkat_dir(dir_fd: i32, name: &OsStr, flags: i32) -> io::Result<()> {
    let n = cstr_component(name)?;
    if unsafe { libc::unlinkat(dir_fd, n.as_ptr(), flags) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn fsync_fd(fd: i32) -> io::Result<()> {
    sync_with(
        || syscall_result(unsafe { libc::fsync(fd) }),
        || syscall_result(unsafe { libc::syncfs(fd) }),
    )
}

fn syscall_result(rc: i32) -> io::Result<()> {
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn retry_interrupted<T>(mut op: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    loop {
        match op() {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            result => return result,
        }
    }
}

fn sync_with(
    mut fsync: impl FnMut() -> io::Result<()>,
    syncfs: impl FnMut() -> io::Result<()>,
) -> io::Result<()> {
    match retry_interrupted(&mut fsync) {
        Err(e) if e.raw_os_error() == Some(libc::EINVAL) => retry_interrupted(syncfs),
        result => result,
    }
}

fn transfer_exact(
    total: usize,
    off: u64,
    zero_kind: io::ErrorKind,
    mut transfer: impl FnMut(usize, usize, libc::off_t) -> io::Result<usize>,
) -> io::Result<usize> {
    let mut done = 0;
    while done < total {
        let offset = off
            .checked_add(done as u64)
            .and_then(|n| libc::off_t::try_from(n).ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "file offset overflow"))?;
        let n = retry_interrupted(|| transfer(done, total - done, offset))?;
        if n == 0 {
            return Err(io::Error::new(zero_kind, "positional I/O made no progress"));
        }
        if n > total - done {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid I/O byte count",
            ));
        }
        done += n;
    }
    Ok(done)
}

pub fn pwrite_at(fd: i32, buf: &[u8], off: u64) -> io::Result<usize> {
    transfer_exact(
        buf.len(),
        off,
        io::ErrorKind::WriteZero,
        |done, remaining, offset| {
            let n = unsafe { libc::pwrite(fd, buf.as_ptr().add(done).cast(), remaining, offset) };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        },
    )
}

/// Fill the entire buffer or fail; EOF must never verify stale buffer bytes.
pub fn pread_exact_at(fd: i32, buf: &mut [u8], off: u64) -> io::Result<()> {
    transfer_exact(
        buf.len(),
        off,
        io::ErrorKind::UnexpectedEof,
        |done, remaining, offset| {
            let n =
                unsafe { libc::pread(fd, buf.as_mut_ptr().add(done).cast(), remaining, offset) };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        },
    )
    .map(|_| ())
}

pub fn ftruncate0(fd: i32) -> io::Result<()> {
    if unsafe { libc::ftruncate(fd, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn fallocate_punch(fd: i32, len: u64) -> io::Result<()> {
    let aligned_len = len
        .checked_add(4095)
        .map(|n| n & !4095)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "punch length overflow"))?;
    let off = libc::off_t::try_from(aligned_len)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "punch length too large"))?;
    if unsafe { libc::fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0, off) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn fadvise_dontneed(fd: i32) -> io::Result<()> {
    let r = unsafe { libc::posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED) };
    if r == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(r))
    }
}

// ---------- FIEMAP ----------

#[repr(C)]
struct Fiemap {
    fm_start: u64,
    fm_length: u64,
    fm_flags: u32,
    fm_mapped_extents: u32, // выход ядра: сколько экстентов заполнено
    fm_extent_count: u32,   // вход: ёмкость буфера
    fm_reserved: u32,
}

#[repr(C)]
struct FiemapExtent {
    fe_logical: u64,
    fe_physical: u64,
    fe_length: u64,
    fe_reserved64: [u64; 2],
    fe_flags: u32,
    fe_reserved: [u32; 3],
}

const FIEMAP_MAX_EXTENTS: usize = 64;
const SIZE_MAX: u64 = u64::MAX;

// struct fiemap flags
const FIEMAP_FLAG_SYNC: u32 = 0x0000_0001;
// struct fiemap_extent flags
const FIEMAP_EXTENT_LAST: u32 = 0x0000_0001;
const FIEMAP_EXTENT_UNKNOWN: u32 = 0x0000_0002;
const FIEMAP_EXTENT_ENCODED: u32 = 0x0000_0008;
const FIEMAP_EXTENT_DATA_ENCRYPTED: u32 = 0x0000_0080;
const FIEMAP_EXTENT_SHARED: u32 = 0x0000_2000;

/// Экстент, который нельзя безопасно перезаписать через логические смещения:
/// физическое расположение неизвестно, данные закодированы/зашифрованы ФС или
/// экстент разделяется с другим inode (reflink). SHARED разрешён только для
/// COW-ФС, где пользователь явно принял отсутствие физической гарантии.
fn ensure_fiemap_extent_safe(flags: u32, allow_shared: bool) -> io::Result<()> {
    let mut unsafe_flags =
        FIEMAP_EXTENT_UNKNOWN | FIEMAP_EXTENT_ENCODED | FIEMAP_EXTENT_DATA_ENCRYPTED;
    if !allow_shared {
        unsafe_flags |= FIEMAP_EXTENT_SHARED;
    }
    if flags & unsafe_flags != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "FIEMAP extent is shared/encoded/encrypted/unknown; logical overwrite cannot sanitize it",
        ));
    }
    Ok(())
}

#[repr(C)]
struct FiemapBuf {
    header: Fiemap,
    extents: [FiemapExtent; FIEMAP_MAX_EXTENTS],
}

/// Список экстентов; None, если FIEMAP не поддержан.
pub fn fiemap(fd: i32, allow_shared: bool) -> io::Result<Option<Vec<(u64, u64)>>> {
    let size = fstat(fd)?.st_size.max(0) as u64;
    let mut result: Vec<(u64, u64)> = Vec::new();
    let mut start: u64 = 0;
    while start < size {
        let mut buffer = FiemapBuf {
            header: Fiemap {
                fm_start: start,
                fm_length: size - start,
                fm_flags: FIEMAP_FLAG_SYNC,
                fm_mapped_extents: 0,
                fm_extent_count: FIEMAP_MAX_EXTENTS as u32,
                fm_reserved: 0,
            },
            extents: unsafe { std::mem::zeroed() },
        };
        let rc = ioctl_raw(
            fd,
            FS_IOC_FIEMAP,
            &mut buffer as *mut FiemapBuf as *mut libc::c_void,
        );
        if rc != 0 {
            let e = io::Error::last_os_error();
            if matches!(
                e.raw_os_error(),
                Some(libc::ENOTTY) | Some(libc::EINVAL) | Some(libc::ENOSYS)
            ) {
                return Ok(None);
            }
            return Err(e);
        }
        let got = buffer.header.fm_mapped_extents as usize;
        if got > FIEMAP_MAX_EXTENTS {
            // Ядро не должно отдавать больше, чем запрошено.
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        if got == 0 {
            break;
        }
        for ext in &buffer.extents[..got] {
            ensure_fiemap_extent_safe(ext.fe_flags, allow_shared)?;
            let next = fiemap_extent_end(ext.fe_logical, ext.fe_length)?;
            if ext.fe_logical < start || next <= start {
                // Прогресса нет (ноль-экстент/пересечение) — стоп с ошибкой.
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            result.push((ext.fe_logical, ext.fe_length));
            start = next;
            if ext.fe_flags & FIEMAP_EXTENT_LAST != 0 {
                return Ok(Some(result));
            }
        }
    }
    Ok(Some(result))
}

fn fiemap_extent_end(logical: u64, len: u64) -> io::Result<u64> {
    logical
        .checked_add(len)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "FIEMAP extent overflow"))
}

pub fn ioctl_raw(fd: i32, req: u64, arg: *mut libc::c_void) -> i32 {
    unsafe { libc::ioctl(fd, req as libc::c_ulong, arg) }
}

// ---------- FITRIM ----------

#[repr(C)]
struct FstrimRange {
    start: u64,
    len: u64,
    minlen: u64,
}

pub fn fitrim(dir_path: &Path) -> io::Result<bool> {
    let fd = open_path(
        dir_path,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
    )?;
    let mut rng = FstrimRange {
        start: 0,
        len: SIZE_MAX,
        minlen: 0,
    };
    let rc = ioctl_raw(
        fd,
        FITRIM,
        &mut rng as *mut FstrimRange as *mut libc::c_void,
    );
    close_fd(fd);
    if rc != 0 {
        let e = io::Error::last_os_error();
        return Err(e);
    }
    Ok(true)
}

// ---------- statfs ----------

pub fn statfs_magic(path: &Path) -> io::Result<i64> {
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    let c = cpath(path)?;
    if unsafe { libc::statfs(c.as_ptr(), &mut s) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(s.f_type as i64)
}

/// Свободно (bavail) * размер блока; libc gnu не экспортирует statvfs.
pub fn free_bytes(path: &Path) -> io::Result<u64> {
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    let c = cpath(path)?;
    if unsafe { libc::statfs(c.as_ptr(), &mut s) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((s.f_bavail as u64) * (s.f_bsize as u64))
}

// ---------- xattr ----------

pub fn llist_xattrs(path: &Path) -> io::Result<Vec<(String, u64)>> {
    let mut need = 4096usize;
    let c = cpath(path)?;
    let buf = loop {
        let mut b: Vec<u8> = Vec::with_capacity(need);
        b.resize(need, 0);
        let n = unsafe { libc::llistxattr(c.as_ptr(), b.as_mut_ptr() as *mut libc::c_char, need) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::ERANGE) {
                need *= 2;
                continue;
            }
            if e.raw_os_error() == Some(libc::ENOTSUP) {
                return Ok(vec![]);
            }
            return Err(e);
        }
        b.truncate(n as usize);
        break b;
    };
    let mut names: Vec<String> = Vec::new();
    let mut idx = 0usize;
    while idx < buf.len() {
        let end = buf[idx..]
            .iter()
            .position(|b| *b == 0)
            .map(|p| idx + p)
            .unwrap_or(buf.len());
        // Never round-trip a non-UTF-8 name through lossy text: lremovexattr
        // could then address a different (or nonexistent) attribute.
        let name = std::str::from_utf8(&buf[idx..end]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "xattr name is not valid UTF-8; refusing lossy erase",
            )
        })?;
        names.push(name.to_string());
        idx = end + 1;
    }
    let mut out = Vec::new();
    for n in &names {
        let nlen = lget_xattr_size(path, n)?;
        out.push((n.clone(), nlen));
    }
    Ok(out)
}

pub fn lget_xattr_size(path: &Path, name: &str) -> io::Result<u64> {
    let c = cpath(path)?;
    let n = CString::new(name.as_bytes())?;
    let r = unsafe { libc::lgetxattr(c.as_ptr(), n.as_ptr(), std::ptr::null_mut(), 0) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(r as u64)
}

pub fn lremove_xattr(path: &Path, name: &str) -> io::Result<()> {
    let c = cpath(path)?;
    let n = CString::new(name.as_bytes())?;
    if unsafe { libc::lremovexattr(c.as_ptr(), n.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// C-str хелперы больше не нужны; io-маппинг делает VanishError::Io через std::io::Error.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test_support::TestDir, Fd};
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn pinned_parent_allows_search_only_ancestors() {
        let dir = TestDir::new();
        let ancestor = dir.path().join("search-only");
        let parent = ancestor.join("parent");
        std::fs::create_dir(&ancestor).unwrap();
        std::fs::create_dir(&parent).unwrap();
        let file = parent.join("file");
        std::fs::write(&file, b"fixture").unwrap();

        struct RestorePermissions<'a>(&'a Path);
        impl Drop for RestorePermissions<'_> {
            fn drop(&mut self) {
                std::fs::set_permissions(self.0, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
        }
        let _restore = RestorePermissions(&ancestor);
        std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o111)).unwrap();
        // Root may bypass DAC; unprivileged runs also prove this fixture would
        // reject the old O_RDONLY traversal.
        if unsafe { libc::geteuid() } != 0 {
            assert_eq!(
                open_path(&ancestor, libc::O_RDONLY | libc::O_DIRECTORY)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
        }
        let _file = Fd(open_path(&file, libc::O_RDWR | libc::O_CLOEXEC).unwrap());
        let pinned = Fd(openat_dir(&parent).unwrap());
        fsync_fd(pinned.raw()).unwrap();
    }

    #[test]
    fn fiemap_extent_overflow_is_invalid_data() {
        assert_eq!(
            fiemap_extent_end(u64::MAX, 1).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(fiemap_extent_end(4096, 8192).unwrap(), 12288);
    }

    #[test]
    fn positional_io_owned_regular_file_and_short_eof() {
        let dir = TestDir::new();
        let t = dir.file("file", b"abcdefgh");
        let fd = Fd(open_path(&t.abs, libc::O_RDWR | libc::O_CLOEXEC).unwrap());
        assert_eq!(pwrite_at(fd.raw(), b"XYZ", 2).unwrap(), 3);
        let mut buf = [0; 8];
        pread_exact_at(fd.raw(), &mut buf, 0).unwrap();
        assert_eq!(&buf, b"abXYZfgh");
        let error = pread_exact_at(fd.raw(), &mut buf, 1).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        fsync_fd(fd.raw()).unwrap();
    }

    #[test]
    fn transfer_retries_interruptions_and_advances_short_io() {
        let mut results = [
            Err(io::Error::from(io::ErrorKind::Interrupted)),
            Ok(2),
            Ok(3),
        ]
        .into_iter();
        let mut calls = Vec::new();
        assert_eq!(
            transfer_exact(5, 10, io::ErrorKind::WriteZero, |done, remaining, off| {
                calls.push((done, remaining, off));
                results.next().unwrap()
            })
            .unwrap(),
            5
        );
        assert_eq!(calls, [(0, 5, 10), (0, 5, 10), (2, 3, 12)]);
    }

    #[test]
    fn zero_progress_is_error_for_reads_and_writes() {
        for kind in [io::ErrorKind::WriteZero, io::ErrorKind::UnexpectedEof] {
            let mut calls = 0;
            let error = transfer_exact(4, 0, kind, |_, _, _| {
                calls += 1;
                Ok(if calls == 1 { 2 } else { 0 })
            })
            .unwrap_err();
            assert_eq!(error.kind(), kind);
            assert_eq!(calls, 2);
        }
    }

    #[test]
    fn transfer_propagates_io_error_and_rejects_overflow() {
        let error = transfer_exact(1, 0, io::ErrorKind::WriteZero, |_, _, _| {
            Err(io::Error::from_raw_os_error(libc::EIO))
        })
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
        let error = transfer_exact(1, u64::MAX, io::ErrorKind::WriteZero, |_, _, _| {
            panic!("invalid offset must not reach syscall")
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn syncfs_fallback_failure_is_propagated() {
        let error = sync_with(
            || Err(io::Error::from_raw_os_error(libc::EINVAL)),
            || Err(io::Error::from_raw_os_error(libc::EIO)),
        )
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
        sync_with(
            || Err(io::Error::from_raw_os_error(libc::EINVAL)),
            || Ok(()),
        )
        .unwrap();
        let error = sync_with(
            || Err(io::Error::from_raw_os_error(libc::ENOSPC)),
            || panic!("only EINVAL permits fallback"),
        )
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ENOSPC));
    }

    #[test]
    fn sync_retries_interrupted_fsync_and_syncfs() {
        let mut fsync_calls = 0;
        let mut syncfs_calls = 0;
        sync_with(
            || {
                fsync_calls += 1;
                Err(io::Error::from_raw_os_error(if fsync_calls == 1 {
                    libc::EINTR
                } else {
                    libc::EINVAL
                }))
            },
            || {
                syncfs_calls += 1;
                if syncfs_calls == 1 {
                    Err(io::Error::from_raw_os_error(libc::EINTR))
                } else {
                    Ok(())
                }
            },
        )
        .unwrap();
        assert_eq!((fsync_calls, syncfs_calls), (2, 2));
    }

    #[test]
    fn pinned_parent_open_survives_path_replacement_without_following_it() {
        let dir = TestDir::new();
        let parent = dir.path().join("parent");
        let renamed = dir.path().join("renamed");
        let replacement = dir.path().join("replacement");
        std::fs::create_dir(&parent).unwrap();
        std::fs::create_dir(&replacement).unwrap();
        std::fs::write(parent.join("file"), b"pinned").unwrap();
        std::fs::write(replacement.join("file"), b"wrong").unwrap();
        let pinned = Fd(openat_dir(&parent).unwrap());
        std::fs::rename(&parent, &renamed).unwrap();
        std::os::unix::fs::symlink(&replacement, &parent).unwrap();
        assert!(openat_dir(&parent).is_err());
        let fd = Fd(openat_name(
            pinned.raw(),
            OsStr::new("file"),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
        .unwrap());
        let mut buf = [0; 6];
        pread_exact_at(fd.raw(), &mut buf, 0).unwrap();
        assert_eq!(&buf, b"pinned");
        for name in ["", ".", "..", "a/b", "nul\0name"] {
            assert!(openat_name(pinned.raw(), OsStr::new(name), libc::O_RDONLY).is_err());
        }
    }

    #[test]
    fn c_strings_and_components_reject_nul_and_separators() {
        assert!(cstr(OsStr::new("nul\0name")).is_err());
        for name in ["", ".", "..", "a/b", "nul\0name"] {
            assert!(cstr_component(OsStr::new(name)).is_err());
        }
        assert!(cstr_component(OsStr::new("plain")).is_ok());
    }

    #[test]
    fn fiemap_unsafe_extent_flags_are_rejected() {
        assert!(ensure_fiemap_extent_safe(FIEMAP_EXTENT_LAST, false).is_ok());
        // COW filesystems may report shared extents; only an explicit
        // accept-cow decision reaches this path with allow_shared=true.
        assert!(ensure_fiemap_extent_safe(FIEMAP_EXTENT_LAST | FIEMAP_EXTENT_SHARED, true).is_ok());
        for (flags, allow_shared) in [
            (FIEMAP_EXTENT_SHARED, false),
            (FIEMAP_EXTENT_ENCODED, true),
            (FIEMAP_EXTENT_DATA_ENCRYPTED, true),
            (FIEMAP_EXTENT_UNKNOWN, true),
            (FIEMAP_EXTENT_LAST | FIEMAP_EXTENT_ENCODED, true),
        ] {
            let error = ensure_fiemap_extent_safe(flags, allow_shared).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[test]
    fn renameat_dir_validates_names_and_moves_entry() {
        let dir = TestDir::new();
        let parent = dir.path().join("parent");
        std::fs::create_dir(&parent).unwrap();
        std::fs::write(parent.join("a"), b"x").unwrap();
        let fd = Fd(openat_dir(&parent).unwrap());
        renameat_dir(fd.raw(), OsStr::new("a"), OsStr::new("b")).unwrap();
        assert!(parent.join("b").exists());
        assert!(renameat_dir(fd.raw(), OsStr::new("b"), OsStr::new("a/b")).is_err());
        unlinkat_dir(fd.raw(), OsStr::new("b"), 0).unwrap();
        assert!(!parent.join("b").exists());
    }

    #[test]
    fn non_utf8_xattr_name_is_rejected_instead_of_lossy_erased() {
        let dir = TestDir::new();
        let t = dir.file("xattr", b"x");
        let path = CString::new(t.abs.as_os_str().as_bytes()).unwrap();
        let mut name = b"user.bad\xff".to_vec();
        name.push(0);
        let value = b"v";
        let rc = unsafe {
            libc::lsetxattr(
                path.as_ptr(),
                name.as_ptr().cast(),
                value.as_ptr().cast(),
                value.len(),
                0,
            )
        };
        if rc != 0 {
            // Some filesystems disallow arbitrary xattr names.
            return;
        }
        let error = llist_xattrs(&t.abs).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        unsafe {
            libc::lremovexattr(path.as_ptr(), name.as_ptr().cast());
        }
    }
}
