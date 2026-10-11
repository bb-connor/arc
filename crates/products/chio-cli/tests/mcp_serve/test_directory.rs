use chio_test_support::ctx::TestUnwrap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) struct TestDir {
    path: PathBuf,
    _guard: MutexGuard<'static, ()>,
}

impl std::ops::Deref for TestDir {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.path.as_path()
    }
}

impl AsRef<Path> for TestDir {
    fn as_ref(&self) -> &Path {
        self.path.as_path()
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub(super) fn unique_test_dir() -> TestDir {
    static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let guard = TEST_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .test_unwrap("system time before unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("chio-cli-mcp-serve-{nonce}"));
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&path).test_unwrap("create private test dir");
    TestDir {
        path,
        _guard: guard,
    }
}
