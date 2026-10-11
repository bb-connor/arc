//! Authority fixture construction with an explicitly injected clock port.

use crate::{SqliteAuthorityStore, SqliteServingOwnerError};
use std::path::Path;

pub(crate) fn open_serving(
    database_path: impl AsRef<Path>,
    lock_root: impl AsRef<Path>,
) -> Result<SqliteAuthorityStore, SqliteServingOwnerError> {
    SqliteAuthorityStore::open_serving_with_clock(
        database_path,
        lock_root,
        chio_test_support::clock::clock(),
    )
}

pub(crate) fn secure_directory(path: &Path) {
    #[cfg(unix)]
    {
        use chio_test_support::ctx::TestUnwrap;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .test_unwrap("secure fixture directory");
    }
    #[cfg(not(unix))]
    let _ = path;
}
