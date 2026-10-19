//! Raw-слой syscall: ioctl-номера, FIEMAP, FITRIM, BLKDISCARD, FSIO metameta.

#![allow(dead_code)]

use std::ffi::{CString, OsStr};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

pub const AT_FDCWD: i32 = -100;
pub const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
pub const AT_REMOVEDIR: i32 = 0x200;

pub const O_EXCL0: i32 = 0; // placeholder, actual flags приходят из libc

// ioctl magic (linux asm-generic):
pub const FS_IOC_FIEMAP: u64 = 0xC020_660B; // _IOWR('f', 11, struct fiemap)
pub const FITRIM: u64 = 0xC018_5879; // _IOWR('X', 121, struct fstrim_range)
pub const BLKGETSIZE64: u64 = 0x8008_1272; // _IOR(0x12, 114, u64)
pub const BLKDISCARD: u64 = 0x1277; // _IO(0x12, 119)
pub const BLKSECDISCARD: u64 = 0x127D; // _IO(0x12, 125)

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

fn cstr(p: &OsStr) -> CString {
    CString::new(p.as_bytes()).expect("C-str")
}

pub fn cpath(p: &Path) -> CString {
    cstr(p.as_os_str())
}

/// open с флагом: простой wrapper.
pub fn open_path(path: &Path, flags: i32) -> io::Result<i32> {
    let c = cpath(path);
    let fd = unsafe { libc::open(c.as_ptr(), flags) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd)
    }
}

pub fn openat_dir(parent: &Path) -> io::Result<i32> {
    let c = cpath(parent);
    let fd = unsafe {
        libc::openat(
            AT_FDCWD,
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
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
    let mut s: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut s) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((s.st_dev as u64, s.st_ino as u64, s.st_size as u64, s.st_nlink as u64))
}

pub fn stat_dev_ino(path: &Path) -> io::Result<(u64, u64, u64, u64)> {
    let mut s: libc::stat = unsafe { std::mem::zeroed() };
    let c = cpath(path);
    if unsafe { libc::stat(c.as_ptr(), &mut s) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((s.st_dev as u64, s.st_ino as u64, s.st_size as u64, s.st_nlink as u64))
}

pub fn renameat_dir(
    dir_fd: i32,
    from: &OsStr,
    to: &OsStr,
) -> io::Result<()> {
    let a = cstr(from);
    let b = cstr(to);
    if unsafe { libc::renameat(dir_fd, a.as_ptr(), dir_fd, b.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn unlinkat_dir(dir_fd: i32, name: &OsStr, flags: i32) -> io::Result<()> {
    let n = cstr(name);
    if unsafe { libc::unlinkat(dir_fd, n.as_ptr(), flags) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn fsync_fd(fd: i32) -> io::Result<()> {
    if unsafe { libc::fsync(fd) } != 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EINVAL) {
            // dirfd на некоторых ФС; syncfs fallback
            unsafe { libc::syncfs(fd) };
            return Ok(());
        }
        return Err(e);
    }
    Ok(())
}

pub fn pwrite_at(fd: i32, buf: &[u8], off: u64) -> io::Result<usize> {
    let total = buf.len();
    let mut sent = 0usize;
    let ptr = buf.as_ptr();
    while sent < total {
        let n = unsafe {
            libc::pwrite(
                fd,
                ptr.add(sent) as *const libc::c_void,
                total - sent,
                (off as u64 + sent as u64) as libc::off_t,
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e);
        }
        sent += n as usize;
    }
    Ok(sent)
}

pub fn pread_at(fd: i32, buf: &mut [u8], off: u64) -> io::Result<usize> {
    let total = buf.len();
    let mut got = 0usize;
    let ptr = buf.as_mut_ptr();
    while got < total {
        let n = unsafe {
            libc::pread(
                fd,
                ptr.add(got) as *mut libc::c_void,
                total - got,
                (off as u64 + got as u64) as libc::off_t,
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e);
        }
        if n == 0 {
            break;
        }
        got += n as usize;
    }
    Ok(got)
}

pub fn ftruncate0(fd: i32) -> io::Result<()> {
    if unsafe { libc::ftruncate(fd, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn fallocate_punch(fd: i32, len: u64) -> io::Result<()> {
    let aligned_len = ((len + 4095) / 4096) * 4096;
    if unsafe {
        libc::fallocate(
            fd,
            FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
            0,
            aligned_len as libc::off_t,
        )
    } != 0
    {
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

/// Список экстентов; None, если FIEMAP не поддержан.
pub fn fiemap(fd: i32) -> io::Result<Option<Vec<(u64, u64)>>> {
    let mut result: Vec<(u64, u64)> = Vec::new();
    let mut start: u64 = 0;
    loop {
        let mut exts: [FiemapExtent; FIEMAP_MAX_EXTENTS] =
            unsafe { std::mem::zeroed() };
        let mut header = Fiemap {
            fm_start: start,
            fm_length: SIZE_MAX,
            fm_flags: 0,
            fm_mapped_extents: 0,
            fm_extent_count: FIEMAP_MAX_EXTENTS as u32,
            fm_reserved: 0,
        };
        let hdr_size = std::mem::size_of::<Fiemap>();
        let ext_size = std::mem::size_of::<FiemapExtent>();
        // У gather-header: к ioctl передаём [header][extents]
        let blob_len = hdr_size + ext_size * FIEMAP_MAX_EXTENTS;
        let mut blob: Vec<u8> = Vec::with_capacity(blob_len);
        unsafe {
            blob.extend_from_slice(
                std::slice::from_raw_parts(
                    &header as *const Fiemap as *const u8,
                    hdr_size,
                ),
            );
            blob.extend_from_slice(std::slice::from_raw_parts(
                exts.as_ptr() as *const u8,
                ext_size * FIEMAP_MAX_EXTENTS,
            ));
            let rc = ioctl_raw(
                fd,
                FS_IOC_FIEMAP,
                blob.as_mut_ptr() as *mut libc::c_void,
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
            header = std::ptr::read(blob.as_ptr() as *const Fiemap);
            exts = std::ptr::read(blob.as_ptr().add(hdr_size) as *const [FiemapExtent; FIEMAP_MAX_EXTENTS]);
        }
        let got = header.fm_mapped_extents as usize;
        if got > FIEMAP_MAX_EXTENTS {
            // Ядро не должно отдавать больше, чем запрошено.
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        if got == 0 {
            break;
        }
        for i in 0..got {
            let ext = &exts[i];
            // EXTENT_EOF бит 9? IEEE: FIEMAP_EXTENT_LAST = 0x0001; skip hole flags 0x0004
            let last = ext.fe_flags & 0x0001 != 0;
            result.push((ext.fe_logical, ext.fe_length));
            let next = ext.fe_logical + ext.fe_length;
            if next <= start {
                // Прогресса нет (ноль-экстент/повтор) — чтобы не зависнуть, стоп с ошибкой.
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            start = next;
            if last {
                return Ok(Some(result));
            }
        }
    }
    Ok(Some(result))
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
    let fd = open_path(dir_path, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC)?;
    let mut rng = FstrimRange {
        start: 0,
        len: SIZE_MAX,
        minlen: 0,
    };
    let rc = ioctl_raw(fd, FITRIM, &mut rng as *mut FstrimRange as *mut libc::c_void);
    close_fd(fd);
    if rc != 0 {
        let e = io::Error::last_os_error();
        return Err(e);
    }
    Ok(true)
}

// ---------- blkdiscard / Block device ----------

pub fn blk_size64(fd: i32) -> io::Result<u64> {
    let mut size: u64 = 0;
    let rc = ioctl_raw(fd, BLKGETSIZE64, &mut size as *mut u64 as *mut libc::c_void);
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(size)
}

pub fn blk_discard(fd: i32, len: u64, secure: bool) -> io::Result<()> {
    let mut range: [u64; 2] = [0, len];
    let ioctl = if secure { BLKSECDISCARD } else { BLKDISCARD };
    let rc = ioctl_raw(fd, ioctl, range.as_mut_ptr() as *mut libc::c_void);
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// ---------- statfs ----------

pub fn statfs_magic(path: &Path) -> io::Result<i64> {
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    let c = cpath(path);
    if unsafe { libc::statfs(c.as_ptr(), &mut s) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(s.f_type as i64)
}

/// Свободно (bavail) * размер блока; libc gnu не экспортирует statvfs.
pub fn free_bytes(path: &Path) -> io::Result<u64> {
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    let c = cpath(path);
    if unsafe { libc::statfs(c.as_ptr(), &mut s) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((s.f_bavail as u64) * (s.f_bsize as u64))
}

// ---------- xattr ----------

pub fn llist_xattrs(path: &Path) -> io::Result<Vec<(String, u64)>> {
    let mut need = 4096usize;
    let c = cpath(path);
    let buf = loop {
        let mut b: Vec<u8> = Vec::with_capacity(need);
        b.resize(need, 0);
        let n = unsafe {
            libc::llistxattr(c.as_ptr(), b.as_mut_ptr() as *mut libc::c_char, need)
        };
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
        names.push(String::from_utf8_lossy(&buf[idx..end]).into_owned());
        idx = end + 1;
    }
    let mut out = Vec::new();
    for n in &names {
        let nlen = lget_xattr_size(path, n).unwrap_or(0);
        out.push((n.clone(), nlen));
    }
    Ok(out)
}

pub fn lget_xattr_size(path: &Path, name: &str) -> io::Result<u64> {
    let c = cpath(path);
    let n = CString::new(name.as_bytes())?;
    let r = unsafe { libc::lgetxattr(c.as_ptr(), n.as_ptr(), std::ptr::null_mut(), 0) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(r as u64)
}

pub fn lremove_xattr(path: &Path, name: &str) -> io::Result<()> {
    let c = cpath(path);
    let n = CString::new(name.as_bytes())?;
    if unsafe { libc::lremovexattr(c.as_ptr(), n.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// C-str хелперы больше не нужны; io-маппинг делает VanishError::Io через std::io::Error.
