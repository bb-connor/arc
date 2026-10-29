//! Ownership, permission and positioned-I/O checks for the private files a
//! store keeps beside its SQLite database, such as rollback anchors.
//!
//! Every function refuses with [`std::io::ErrorKind::Unsupported`] off Unix,
//! where owner and mode identity cannot be established.

use std::fs::{File, Metadata};
use std::io;

/// A directory owned by the effective user that neither group nor others can
/// write.
#[cfg(unix)]
pub fn private_directory(metadata: &Metadata) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt as _;

    Ok(metadata.file_type().is_dir()
        && metadata.uid() == nix::unistd::geteuid().as_raw()
        && metadata.mode() & 0o022 == 0)
}

#[cfg(not(unix))]
pub fn private_directory(_metadata: &Metadata) -> io::Result<bool> {
    Err(unsupported())
}

/// A regular single-link file owned by the effective user with mode 0600.
#[cfg(unix)]
pub fn private_file(metadata: &Metadata) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt as _;

    Ok(metadata.file_type().is_file()
        && metadata.nlink() == 1
        && metadata.uid() == nix::unistd::geteuid().as_raw()
        && metadata.mode() & 0o777 == 0o600)
}

#[cfg(not(unix))]
pub fn private_file(_metadata: &Metadata) -> io::Result<bool> {
    Err(unsupported())
}

/// The device and inode that identify a file across reopen.
#[cfg(unix)]
pub fn device_inode(metadata: &Metadata) -> io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;

    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
pub fn device_inode(_metadata: &Metadata) -> io::Result<(u64, u64)> {
    Err(unsupported())
}

/// Fill `bytes` from `offset`, failing on a short file.
#[cfg(unix)]
#[allow(
    clippy::indexing_slicing,
    reason = "The OS read or write count cannot exceed the supplied buffer length."
)]
pub fn read_exact_at(file: &File, mut bytes: &mut [u8], mut offset: usize) -> io::Result<()> {
    use std::os::unix::fs::FileExt as _;

    while !bytes.is_empty() {
        let read = file.read_at(bytes, io_offset(offset)?)?;
        if read == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        offset += read;
        bytes = &mut bytes[read..];
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn read_exact_at(_file: &File, _bytes: &mut [u8], _offset: usize) -> io::Result<()> {
    Err(unsupported())
}

/// Write all of `bytes` at `offset` without moving the file cursor.
#[cfg(unix)]
#[allow(
    clippy::indexing_slicing,
    reason = "The OS read or write count cannot exceed the supplied buffer length."
)]
pub fn write_all_at(file: &File, mut bytes: &[u8], mut offset: usize) -> io::Result<()> {
    use std::os::unix::fs::FileExt as _;

    while !bytes.is_empty() {
        let written = file.write_at(bytes, io_offset(offset)?)?;
        if written == 0 {
            return Err(io::Error::from(io::ErrorKind::WriteZero));
        }
        offset += written;
        bytes = &bytes[written..];
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn write_all_at(_file: &File, _bytes: &[u8], _offset: usize) -> io::Result<()> {
    Err(unsupported())
}

#[cfg(unix)]
fn io_offset(offset: usize) -> io::Result<u64> {
    u64::try_from(offset).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "file custody offset overflowed u64",
        )
    })
}

#[cfg(not(unix))]
fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "file custody requires Unix owner, mode and positioned I/O",
    )
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn private_directory_and_file_follow_owner_and_mode() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        assert!(private_directory(&std::fs::metadata(directory.path())?)?);
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o770))?;
        assert!(!private_directory(&std::fs::metadata(directory.path())?)?);
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;

        let path = directory.path().join("anchor");
        std::fs::write(&path, b"")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        assert!(private_file(&std::fs::metadata(&path)?)?);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
        assert!(!private_file(&std::fs::metadata(&path)?)?);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        std::fs::hard_link(&path, directory.path().join("second-link"))?;
        assert!(!private_file(&std::fs::metadata(&path)?)?);
        Ok(())
    }

    #[test]
    fn positioned_io_round_trips_and_refuses_a_short_file() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(directory.path().join("slots"))?;
        write_all_at(&file, b"slot", 4)?;
        let mut read = [0_u8; 4];
        read_exact_at(&file, &mut read, 4)?;
        assert_eq!(&read, b"slot");
        let (device, inode) = device_inode(&file.metadata()?)?;
        assert_eq!(device_inode(&file.metadata()?)?, (device, inode));
        let mut beyond = [0_u8; 4];
        let error = read_exact_at(&file, &mut beyond, 6)
            .err()
            .ok_or_else(|| io::Error::other("a short file was read in full"))?;
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        Ok(())
    }
}
