use std::path::{Path, PathBuf};

use chio_sqlite_file_identity::SqliteFileIdentity;

use super::SqliteApprovalReplayStoreError;

pub(super) fn prepare(path: &Path) -> Result<PathBuf, SqliteApprovalReplayStoreError> {
    let text = path.to_string_lossy();
    if text.is_empty() || text == ":memory:" || text.starts_with("file:") {
        return Err(SqliteApprovalReplayStoreError::InvalidPath);
    }
    let name = path
        .file_name()
        .ok_or(SqliteApprovalReplayStoreError::InvalidPath)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let parent = parent.canonicalize()?;
    validate_ownership(&std::fs::metadata(&parent)?)?;
    let path = parent.join(name);
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => {
            return Err(SqliteApprovalReplayStoreError::InvalidPath);
        }
        Ok(metadata) => validate_file(&metadata)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        match std::fs::symlink_metadata(&sidecar) {
            Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => {
                return Err(SqliteApprovalReplayStoreError::InvalidPath);
            }
            Ok(metadata) => validate_file(&metadata)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(path)
}

#[cfg(unix)]
fn validate_ownership(metadata: &std::fs::Metadata) -> Result<(), SqliteApprovalReplayStoreError> {
    use std::os::unix::fs::MetadataExt;
    if metadata.uid() != nix::unistd::geteuid().as_raw() || metadata.mode() & 0o022 != 0 {
        return Err(SqliteApprovalReplayStoreError::InvalidPath);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_file(metadata: &std::fs::Metadata) -> Result<(), SqliteApprovalReplayStoreError> {
    use std::os::unix::fs::MetadataExt;
    validate_ownership(metadata)?;
    if metadata.nlink() != 1 {
        return Err(SqliteApprovalReplayStoreError::InvalidPath);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_ownership(_metadata: &std::fs::Metadata) -> Result<(), SqliteApprovalReplayStoreError> {
    Err(SqliteApprovalReplayStoreError::InvalidPath)
}

#[cfg(not(unix))]
fn validate_file(_metadata: &std::fs::Metadata) -> Result<(), SqliteApprovalReplayStoreError> {
    Err(SqliteApprovalReplayStoreError::InvalidPath)
}

#[cfg(unix)]
pub(super) fn verify(
    path: &Path,
    identity: SqliteFileIdentity,
) -> Result<(), SqliteApprovalReplayStoreError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.dev() != identity.device
        || metadata.ino() != identity.inode
        || metadata.nlink() != 1
        || identity.link_count != 1
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        return Err(SqliteApprovalReplayStoreError::FileIdentityChanged);
    }
    Ok(())
}

#[cfg(not(unix))]
pub(super) fn verify(
    _path: &Path,
    _identity: SqliteFileIdentity,
) -> Result<(), SqliteApprovalReplayStoreError> {
    Err(SqliteApprovalReplayStoreError::InvalidPath)
}
