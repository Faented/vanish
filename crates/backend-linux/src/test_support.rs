use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use vanish_core::platform::Target;

static NEXT: AtomicU64 = AtomicU64::new(0);

/// Private, exclusively created sandbox. Tests never open devices or need root.
pub(crate) struct TestDir(PathBuf);

impl TestDir {
    pub(crate) fn new() -> Self {
        let base = if Path::new("/tmp/opencode").is_dir() {
            PathBuf::from("/tmp/opencode")
        } else {
            std::env::temp_dir()
        };
        loop {
            let path = base.join(format!(
                "vanish-backend-linux-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Self(path),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("create test sandbox: {e}"),
            }
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }

    pub(crate) fn file(&self, name: &str, contents: &[u8]) -> Target {
        let path = self.0.join(name);
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(contents).unwrap();
        let md = file.metadata().unwrap();
        Target::from_parts(path, md.dev(), md.ino(), md.len(), md.nlink() as u32)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        // Only the private directory successfully created by this instance.
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
