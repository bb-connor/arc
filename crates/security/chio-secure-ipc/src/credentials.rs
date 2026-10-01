//! Descriptor-bound custody checks for credentials delivered by systemd.

use std::fs::File;
use std::io;

/// Recognize systemd's root-owned, read-only credential with an ACL granting
/// read access to exactly the selected service user. The group mode bits are
/// the ACL mask, not a grant to the owning group. Never trust the pathname or
/// CREDENTIALS_DIRECTORY alone as evidence of this custody.
#[cfg(target_os = "linux")]
pub fn is_systemd_credential(file: &File, service_uid: u32) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o440
        || service_uid == 0
    {
        return Ok(false);
    }
    let filesystem = rustix::fs::fstatfs(file)?;
    // RAMFS_MAGIC from Linux's uapi/linux/magic.h is not exported by libc.
    if filesystem.f_type != libc::TMPFS_MAGIC && filesystem.f_type as u64 != 0x8584_58f6 {
        return Ok(false);
    }
    if !rustix::fs::fstatvfs(file)?
        .f_flag
        .contains(rustix::fs::StatVfsMountFlags::RDONLY)
    {
        return Ok(false);
    }
    let mut acl = [0_u8; 44];
    match rustix::fs::fgetxattr(file, "system.posix_acl_access", &mut acl[..]) {
        Ok(44) => Ok(acl == credential_acl(service_uid)),
        Ok(_) => Ok(false),
        Err(rustix::io::Errno::NODATA | rustix::io::Errno::RANGE | rustix::io::Errno::NOTSUP) => {
            Ok(false)
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(not(target_os = "linux"))]
pub fn is_systemd_credential(_file: &File, _service_uid: u32) -> io::Result<bool> {
    Ok(false)
}

#[cfg(target_os = "linux")]
fn credential_acl(service_uid: u32) -> [u8; 44] {
    let mut acl = [0_u8; 44];
    acl[..4].copy_from_slice(&2_u32.to_le_bytes());
    // Linux POSIX ACL xattr v2: owner, named user, owning group, mask, other.
    for (entry, (tag, permissions, uid)) in acl[4..].chunks_exact_mut(8).zip([
        (0x01_u16, 4_u16, u32::MAX),
        (0x02, 4, service_uid),
        (0x04, 0, u32::MAX),
        (0x10, 4, u32::MAX),
        (0x20, 0, u32::MAX),
    ]) {
        entry[..2].copy_from_slice(&tag.to_le_bytes());
        entry[2..4].copy_from_slice(&permissions.to_le_bytes());
        entry[4..].copy_from_slice(&uid.to_le_bytes());
    }
    acl
}

/// An anonymous inherited secret may replace a private named file only when
/// it is read-only and the kernel has permanently sealed every mutation.
#[cfg(target_os = "linux")]
pub fn is_sealed_credential(file: &File) -> io::Result<bool> {
    use rustix::fs::{fcntl_get_seals, fcntl_getfl, OFlags, SealFlags};

    if fcntl_getfl(file)?.intersects(OFlags::WRONLY | OFlags::RDWR) {
        return Ok(false);
    }
    let required = SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE;
    match fcntl_get_seals(file) {
        Ok(seals) => Ok(seals.contains(required)),
        Err(rustix::io::Errno::INVAL) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

#[cfg(not(target_os = "linux"))]
pub fn is_sealed_credential(_file: &File) -> io::Result<bool> {
    Ok(false)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use chio_test_support::prelude::*;
    use rustix::fs::{fchmod, fcntl_add_seals, memfd_create, MemfdFlags, Mode, SealFlags};
    use std::io::Write;
    use std::os::fd::AsRawFd;

    #[test]
    fn anonymous_credentials_require_read_only_handles_and_all_seals() -> io::Result<()> {
        let mut file = File::from(memfd_create(
            c"credential-custody-test",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
        )?);
        fchmod(&file, Mode::RUSR | Mode::WUSR)?;
        file.write_all(&[42; 32])?;
        let read_only = File::open(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
        assert!(!is_sealed_credential(&read_only)?);
        fcntl_add_seals(&file, SealFlags::SHRINK | SealFlags::GROW)?;
        assert!(!is_sealed_credential(&read_only)?);
        fcntl_add_seals(&file, SealFlags::WRITE | SealFlags::SEAL)?;
        assert!(
            !is_sealed_credential(&file)?,
            "a writable handle must be refused"
        );
        assert!(is_sealed_credential(&read_only)?);
        let secret = crate::InheritedSecretFile { file: read_only };
        secret
            .validate_private_regular_file(rustix::process::geteuid().as_raw(), "test")
            .test_expect("sealed descriptor retains custody");
        assert!(secret
            .validate_private_regular_file(u32::MAX, "test")
            .is_err());
        Ok(())
    }

    #[test]
    fn ordinary_unlinked_files_do_not_gain_sealed_credential_custody() -> io::Result<()> {
        let secret = crate::InheritedSecretFile {
            file: tempfile::tempfile()?,
        };
        assert!(secret
            .validate_private_regular_file(rustix::process::geteuid().as_raw(), "test")
            .is_err());
        assert!(!is_systemd_credential(
            &secret.file,
            rustix::process::geteuid().as_raw()
        )?);
        Ok(())
    }
}
