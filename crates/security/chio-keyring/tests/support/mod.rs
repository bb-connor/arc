use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::{fs::OpenOptions, io::Write as _};

use chio_test_support::prelude::*;

pub fn private_tempdir() -> std::io::Result<tempfile::TempDir> {
    let mut builder = tempfile::Builder::new();
    #[cfg(unix)]
    builder.permissions(std::fs::Permissions::from_mode(0o700));
    builder.tempdir()
}

#[allow(dead_code)]
pub fn write_private_file(
    path: impl AsRef<Path>,
    contents: impl AsRef<[u8]>,
) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents.as_ref())?;
    file.sync_all()
}

pub fn trusted_temp_path(
    directory: &tempfile::TempDir,
    relative_path: impl AsRef<Path>,
) -> PathBuf {
    std::fs::canonicalize(directory.path())
        .test_unwrap()
        .join(relative_path)
}
