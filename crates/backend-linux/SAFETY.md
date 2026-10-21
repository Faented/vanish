# Linux backend safety boundaries

`device_wipe` is temporarily disabled unconditionally. It returns
`VanishError::NotPermitted` without looking up the supplied path, opening anything,
or issuing an ioctl. The old block-discard syscall helpers have been removed.
The public result type remains for CLI compatibility; it is not evidence that
device wiping is available. A CLI dry-run must describe a plan without calling
destructive APIs.

## File handles

Opening a wipe handle walks the parent directory component by component with
`O_DIRECTORY | O_NOFOLLOW`, pins the resulting directory for both `openat` calls,
and disallows multi-component leaf names. Every successfully opened direct or
buffered fd is immediately RAII-owned and checked with `fstat` for regular-file
type, expected device/inode and unchanged nonzero link count. The direct fd is
checked again after opening the buffered fd. Existing multiple hardlinks still
require consent in the core; this backend has no independent consent parameter.
Buffered fallback is permitted only when direct I/O is unsupported (`EINVAL`,
`EOPNOTSUPP`/`ENOTSUP`, `ENOSYS`); other open errors are propagated.

This is **not** a complete namespace-race solution:

- The parent identity from preflight is not part of `Target`. Directory renames,
  mount changes and inode reuse before opening are not fully excluded.
- The pinned parent used for opening is not carried through all Platform calls.
  Rename/unlink/rmdir reopen a parent and still operate on a name. Even a
  check immediately before rename/unlink cannot atomically bind those syscalls
  to the inode that was checked.
- `stream_names`/`erase_stream` still use pathname-based `llistxattr`/
  `lremovexattr`, not the validated file handle. Parent/leaf replacement can
  redirect these calls. Listing/removing xattrs is not secure erasure of old
  xattr values, journal records or snapshots.
- Link counts, contents and file lengths can change after `fstat`; another
  process may write or add a link during wiping. No exclusive-access guarantee
  follows from these checks.
- A substituted nonregular object is rejected after open; `O_NONBLOCK` prevents
  a substituted FIFO from blocking, but open itself is not side-effect-free for
  every possible object type.
- Linux file opens preserve raw `OsStr` bytes, but Platform `unlink`/`rmdir`
  accept a UTF-8 `&str` tail. They cannot represent arbitrary non-UTF-8 Linux
  names. Callers must not pass a lossy conversion of an original basename: it
  could name a different entry. The core rejects non-UTF-8 basenames when no
  rename is performed; generated ASCII rename tails remain representable.
  Direct Platform callers must enforce the same rule. This API is unchanged,
  and the backend cannot recover the original bytes from a lossy string.
- Recovery refuses symlink/non-directory roots and propagates directory entry
  errors. Its pathname-based traversal still has a metadata-to-read_dir race;
  checking each directory before traversal is not equivalent to an fd-bound walk.

A future coordinated core API should retain validated file/parent capabilities
across xattr and finalization operations, define parent identity and concurrent
namespace mutation policy, and use fd-based xattr calls. The current Platform
API is intentionally unchanged in this patch.

## Probes and I/O

Unreadable or malformed `/proc/swaps` is an error, never an empty swap list.
`fsinfo` also refuses unknown swap-object metadata rather than assuming a
different device. This is a conservative local probe, not a complete model of
stacked storage (device mapper, RAID, containers or other mount namespaces).
Callers must propagate these errors rather than converting them to "safe".

Visible `/proc` process/fd permission and I/O errors are propagated by the busy
probe. Disappeared entries are tolerated. Processes hidden entirely by procfs
mount policy, other PID namespaces, memory mappings without fds, and processes
opening a file after the scan are not ruled out. An empty result is therefore
not proof of exclusive access.

Verification reads the entire requested buffer or returns `UnexpectedEof`.
Positional writes returning zero fail with `WriteZero`. Interrupted and short
I/O are retried with advancing offsets. A failed `syncfs` fallback is propagated;
successful sync is not a physical-erasure guarantee.
`ssd_chipoff_protected` is always false: detecting dm-crypt encryption does not
erase keys or establish a physical-erasure guarantee. Wipe/verify ranges and
FIEMAP extent ends use checked addition and reject overflow.

Tests use only exclusively created private temporary directories and regular
files, with fault injection for short/interrupted I/O and sync failures. They do
not touch block devices, mount filesystems, invoke root commands or run polygon
scripts. Fixtures prefer `/tmp/opencode` when it exists and otherwise use
`std::env::temp_dir()`. Private directories are created exclusively (not with
`create_dir_all`), and existing paths are never reused.
