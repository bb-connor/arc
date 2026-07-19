use std::path::{Path, PathBuf};

use chio_test_support::prelude::*;

pub fn trusted_temp_path(
    directory: &tempfile::TempDir,
    relative_path: impl AsRef<Path>,
) -> PathBuf {
    std::fs::canonicalize(directory.path())
        .test_unwrap()
        .join(relative_path)
}
