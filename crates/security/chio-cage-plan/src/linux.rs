use super::{CageError, FileIdentity, ResourceKind};
use std::fs::File;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::linux::fs::MetadataExt;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;
const MAX_FDINFO_BYTES: u64 = 64 * 1024;

pub fn current_process_identity() -> crate::BrokerPeerIdentity {
    // SAFETY: these process-identity queries take no pointers and mutate no
    // Rust-owned memory.
    let uid = unsafe { libc::geteuid() };
    // SAFETY: this process-identity query has the same contract as `geteuid`.
    let gid = unsafe { libc::getegid() };
    crate::BrokerPeerIdentity::new(std::process::id(), uid, gid)
}

pub fn descriptor_identity(file: &File, path: Option<&Path>) -> Result<FileIdentity, CageError> {
    let display_path = path.unwrap_or_else(|| Path::new("<descriptor>"));
    let metadata = file
        .metadata()
        .map_err(|source| CageError::DescriptorMetadata {
            path: display_path.to_path_buf(),
            source,
        })?;
    let file_type = metadata.file_type();
    let kind = if file_type.is_file() {
        ResourceKind::RegularFile
    } else if file_type.is_dir() {
        ResourceKind::Directory
    } else if file_type.is_socket() {
        ResourceKind::UnixSocket
    } else if file_type.is_symlink() {
        return Err(CageError::SymbolicLink(display_path.to_path_buf()));
    } else {
        return Err(CageError::UnsupportedResourceKind(
            display_path.to_path_buf(),
        ));
    };
    Ok(FileIdentity {
        device: metadata.st_dev(),
        inode: metadata.st_ino(),
        mount_id: mount_id(file, display_path)?,
        mode: metadata.st_mode(),
        uid: metadata.st_uid(),
        gid: metadata.st_gid(),
        kind,
    })
}

fn mount_id(file: &File, path: &Path) -> Result<u64, CageError> {
    let fdinfo_path = format!("/proc/self/fdinfo/{}", file.as_raw_fd());
    let fdinfo_file = File::open(&fdinfo_path).map_err(|source| CageError::DescriptorMetadata {
        path: path.to_path_buf(),
        source,
    })?;
    let metadata = fdinfo_file
        .metadata()
        .map_err(|source| CageError::DescriptorMetadata {
            path: path.to_path_buf(),
            source,
        })?;
    if metadata.len() > MAX_FDINFO_BYTES {
        return Err(CageError::MissingMountIdentity(path.to_path_buf()));
    }
    let mut bytes = Vec::new();
    fdinfo_file
        .take(MAX_FDINFO_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| CageError::DescriptorMetadata {
            path: path.to_path_buf(),
            source,
        })?;
    let byte_count = u64::try_from(bytes.len())
        .map_err(|_| CageError::MissingMountIdentity(path.to_path_buf()))?;
    if byte_count > MAX_FDINFO_BYTES {
        return Err(CageError::MissingMountIdentity(path.to_path_buf()));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| CageError::MissingMountIdentity(path.to_path_buf()))?;
    text.lines()
        .find_map(|line| line.strip_prefix("mnt_id:\t"))
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| CageError::MissingMountIdentity(path.to_path_buf()))
}
