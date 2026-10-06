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

/// Grant another principal access to `path` through an extended ACL entry
/// while leaving its mode bits unchanged. Returns `false` when this host has
/// no tool that installs one.
#[cfg(unix)]
#[allow(dead_code)]
pub fn grant_foreign_acl(path: &Path) -> std::io::Result<bool> {
    let Some(mut command) = foreign_acl_command(path)? else {
        return Ok(false);
    };
    let status = match command
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
    {
        Ok(status) => status,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if !status.success() {
        return Err(std::io::Error::other("could not install a test ACL entry"));
    }
    Ok(true)
}

#[cfg(target_vendor = "apple")]
fn foreign_acl_command(path: &Path) -> std::io::Result<Option<std::process::Command>> {
    let entry = if std::fs::symlink_metadata(path)?.is_dir() {
        "everyone allow add_file,add_subdirectory,delete_child"
    } else {
        "everyone allow read,write"
    };
    let mut command = std::process::Command::new("/bin/chmod");
    command.args(["+a", entry]).arg(path);
    Ok(Some(command))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn foreign_acl_command(path: &Path) -> std::io::Result<Option<std::process::Command>> {
    let mut command = std::process::Command::new("setfacl");
    command.args(["-m", "u:65534:rwx"]).arg(path);
    Ok(Some(command))
}

#[cfg(all(
    unix,
    not(any(target_vendor = "apple", target_os = "linux", target_os = "android"))
))]
fn foreign_acl_command(_path: &Path) -> std::io::Result<Option<std::process::Command>> {
    Ok(None)
}
