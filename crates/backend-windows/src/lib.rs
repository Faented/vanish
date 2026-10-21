//! backend-windows: заглушка контракта v0.1 (реальная реализация в M4).
//! Компилируется на любой ОС; все операции возвращают Unsupported.

use std::path::{Path, PathBuf};

use vanish_core::error::{Result, VanishError};
use vanish_core::fsinfo::VolumeInfo;
use vanish_core::pattern::PatternStream;
use vanish_core::platform::{Extent, Opener, Platform, SwapEntry, Target, WipeHandle};

pub struct WindowsPlatform;

pub fn platform() -> Box<dyn Platform> {
    Box::new(WindowsPlatform)
}

impl Platform for WindowsPlatform {
    fn name(&self) -> &'static str {
        "windows-stub"
    }

    fn fsinfo(&self, _path: &Path) -> Result<VolumeInfo> {
        Err(VanishError::UnsupportedFs(
            "backend-windows в v0.1 — заглушка".into(),
        ))
    }

    fn openers(&self, _dev: u64, _ino: u64) -> Result<Vec<Opener>> {
        Ok(vec![])
    }

    fn open_handle(&self, _t: &Target) -> Result<Box<dyn WipeHandle>> {
        Err(VanishError::UnsupportedFs(
            "backend-windows в v0.1 — заглушка".into(),
        ))
    }

    fn stream_names(&self, _t: &Target) -> Result<Vec<(String, u64)>> {
        Ok(vec![])
    }

    fn erase_stream(&self, _t: &Target, _name: &str) -> Result<()> {
        Ok(())
    }

    fn rename_to_tail(&self, _t: &Target) -> Result<String> {
        Err(VanishError::UnsupportedFs(
            "backend-windows в v0.1 — заглушка".into(),
        ))
    }

    fn fsync_dir(&self, _dir: &Path) -> Result<()> {
        Err(VanishError::UnsupportedFs(
            "backend-windows в v0.1 — заглушка".into(),
        ))
    }

    fn unlink(&self, _t: &Target, _tail: &str) -> Result<()> {
        Err(VanishError::UnsupportedFs(
            "backend-windows в v0.1 — заглушка".into(),
        ))
    }

    fn rmdir(&self, _t: &Target, _tail: &str) -> Result<()> {
        Err(VanishError::UnsupportedFs(
            "backend-windows в v0.1 — заглушка".into(),
        ))
    }

    fn trim_mount(&self, _mount: &Path) -> Result<bool> {
        Ok(false)
    }

    fn swap_active(&self) -> Result<Vec<SwapEntry>> {
        Ok(vec![])
    }

    fn find_tails(&self, root: &Path) -> Result<Vec<PathBuf>> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            if let Ok(rd) = std::fs::read_dir(&dir) {
                for ent in rd.flatten() {
                    let p = ent.path();
                    let name = ent.file_name().to_string_lossy().into_owned();
                    if let Ok(md) = std::fs::symlink_metadata(&p) {
                        if md.is_dir() {
                            stack.push(p);
                        } else if name.starts_with(vanish_core::TAIL_PREFIX) {
                            out.push(p);
                        }
                    }
                }
            }
        }
        Ok(out)
    }
}

// ЗагBUFFER-fallback трейт-нужен компиляции: наличие фиктивного WipeHandle.
pub struct StubWipe;
impl WipeHandle for StubWipe {
    fn dev_ino(&self) -> (u64, u64) {
        (0, 0)
    }
    fn len(&self) -> Result<u64> {
        Ok(0)
    }
    fn extents(&self) -> Result<Option<Vec<Extent>>> {
        Ok(None)
    }
    fn overwrite(&mut self, _off: u64, _len: u64, _gen: &mut PatternStream) -> Result<()> {
        Err(VanishError::UnsupportedFs("stub".into()))
    }
    fn verify(&mut self, _off: u64, _len: u64, _gen: &mut PatternStream) -> Result<()> {
        Err(VanishError::UnsupportedFs("stub".into()))
    }
    fn sync(&self) -> Result<()> {
        Ok(())
    }
    fn punch(&mut self) -> Result<bool> {
        Ok(false)
    }
    fn truncate0(&mut self) -> Result<()> {
        Ok(())
    }
    fn dontneed(&self) -> Result<()> {
        Ok(())
    }
}
