//! Filesystem fixtures with explicit authority-directory custody.
use std::path::PathBuf;

use chio_test_support::prelude::*;

pub(super) fn private_authority_database() -> (tempfile::TempDir, PathBuf) {
    let directory = chio_test_support::private_tempdir().test_expect("private authority directory");
    let database = directory.path().join("authority.sqlite");
    (directory, database)
}

pub(super) fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .test_expect("workspace root")
        .to_path_buf()
}
