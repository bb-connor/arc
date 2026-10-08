use std::fs::{File, Metadata};
use std::io;
use std::os::unix::fs::MetadataExt;

use crate::error::{refuse, Refusal};

pub(crate) const ROOT_UID: u32 = 0;

/// The effective user ID of this process.
#[must_use]
pub fn effective_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// Who may own a custody object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Owner {
    /// Only the effective user of this process.
    EffectiveUser,
    /// The effective user of this process or root.
    EffectiveUserOrRoot,
    /// Exactly this numeric user.
    Uid(u32),
    /// Any user. Custody then rests on the mode, link and directory rules.
    Unchecked,
}

impl Owner {
    pub(crate) fn permits(self, uid: u32) -> bool {
        match self {
            Self::EffectiveUser => uid == effective_uid(),
            Self::EffectiveUserOrRoot => uid == effective_uid() || uid == ROOT_UID,
            Self::Uid(expected) => uid == expected,
            Self::Unchecked => true,
        }
    }
}

/// The ownership and permission rules one custody object must satisfy.
///
/// Every call site constructs its policy explicitly; there is no default.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnerPolicy {
    /// Who may own the object.
    pub owner: Owner,
    /// Permission bits that must all be clear.
    pub forbidden_mode: u32,
    /// Refuse a regular file with more than one hard link. Directories are
    /// exempt, since their link count includes their subdirectories.
    pub require_single_link: bool,
    /// Refuse an object carrying an extended POSIX ACL. Platforms without ACL
    /// inspection refuse every object when this is set.
    pub reject_acl: bool,
}

#[derive(Clone, Copy)]
pub(crate) enum Subject {
    File,
    Directory,
}

impl Subject {
    fn label(self) -> &'static str {
        match self {
            Self::File => "private file",
            Self::Directory => "private directory",
        }
    }
}

impl OwnerPolicy {
    /// Checks a regular file's metadata without inspecting its ACL.
    pub(crate) fn check_file_metadata(&self, metadata: &Metadata) -> io::Result<()> {
        if !metadata.file_type().is_file() {
            return Err(refuse(
                io::ErrorKind::InvalidData,
                Refusal::NotRegularFile,
                "private file must be a regular file",
            ));
        }
        self.check_owner(metadata, Subject::File)?;
        self.check_mode(metadata, Subject::File)?;
        if self.require_single_link && metadata.nlink() != 1 {
            return Err(refuse(
                io::ErrorKind::PermissionDenied,
                Refusal::LinkCount,
                "private file must have exactly one hard link",
            ));
        }
        Ok(())
    }

    /// Checks an opened regular file, including its ACL when required.
    pub(crate) fn check_file(&self, metadata: &Metadata, file: &File) -> io::Result<()> {
        self.check_file_metadata(metadata)?;
        self.check_acl(file, Subject::File)
    }

    /// Checks the owner rule of a file or directory.
    pub(crate) fn check_owner(&self, metadata: &Metadata, subject: Subject) -> io::Result<()> {
        if self.owner.permits(metadata.uid()) {
            return Ok(());
        }
        let label = subject.label();
        let message = match self.owner {
            Owner::EffectiveUser => format!("{label} must be owned by the effective user"),
            Owner::EffectiveUserOrRoot => {
                format!("{label} must be owned by the effective user or root")
            }
            Owner::Uid(uid) => format!("{label} must be owned by uid {uid}"),
            Owner::Unchecked => format!("{label} has an untrusted owner"),
        };
        Err(refuse(
            io::ErrorKind::PermissionDenied,
            Refusal::Owner,
            message,
        ))
    }

    /// Checks the forbidden permission bits of a file or directory.
    pub(crate) fn check_mode(&self, metadata: &Metadata, subject: Subject) -> io::Result<()> {
        let forbidden = self.forbidden_mode & 0o7777;
        if metadata.mode() & forbidden == 0 {
            return Ok(());
        }
        let label = subject.label();
        let message = match forbidden {
            0o022 => format!("{label} must not be group or world writable"),
            0o077 => format!("{label} must not be accessible by group or others"),
            0o177 => format!("{label} must have mode 0600 or stricter"),
            other => format!("{label} must not carry permission bits {other:04o}"),
        };
        Err(refuse(
            io::ErrorKind::PermissionDenied,
            Refusal::Mode,
            message,
        ))
    }

    /// Checks the ACL rule of an opened file or directory.
    pub(crate) fn check_acl(&self, handle: &File, subject: Subject) -> io::Result<()> {
        if !self.reject_acl || !has_extended_acl(handle)? {
            return Ok(());
        }
        Err(refuse(
            io::ErrorKind::PermissionDenied,
            Refusal::Acl,
            format!("{} must not carry an extended ACL", subject.label()),
        ))
    }

    /// Refuses a policy that needs an ACL check when no descriptor is open.
    pub(crate) fn require_no_acl_rule(&self) -> io::Result<()> {
        if self.reject_acl {
            return Err(refuse(
                io::ErrorKind::PermissionDenied,
                Refusal::Acl,
                "private file ACL cannot be inspected without an open descriptor",
            ));
        }
        Ok(())
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn has_extended_acl(handle: &File) -> io::Result<bool> {
    use rustix::io::Errno;

    for attribute in ["system.posix_acl_access", "system.posix_acl_default"] {
        let mut value = Vec::<u8>::with_capacity(1);
        match rustix::fs::fgetxattr(handle, attribute, &mut value) {
            Ok(_) | Err(Errno::RANGE) => return Ok(true),
            Err(Errno::NODATA | Errno::NOTSUP) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(false)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn has_extended_acl(_handle: &File) -> io::Result<bool> {
    Err(refuse(
        io::ErrorKind::Unsupported,
        Refusal::Acl,
        "extended ACL inspection is unavailable on this platform",
    ))
}
