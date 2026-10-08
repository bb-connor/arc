use std::ffi::OsStr;
use std::fs::{self, File, Metadata};
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{fchmod, mkdirat, openat, Mode, OFlags};
use rustix::io::Errno;

use crate::error::{invalid_path, refuse, Refusal};
use crate::policy::{effective_uid, OwnerPolicy, Subject, ROOT_UID};

/// What preparation does with a target directory that already exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Existing {
    /// Check the existing mode against the policy and leave it unchanged.
    Validate,
    /// Reset the existing mode to 0700.
    Harden,
}

/// Open flags for the target directory and for synchronizing directories.
pub(crate) fn read_flags() -> OFlags {
    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::DIRECTORY | OFlags::NOFOLLOW
}

/// Open flags for directories that are only walked.
///
/// Walking a directory needs execute permission, not read: an ancestor with
/// mode 0711 is traversable by ordinary path resolution, so the
/// descriptor-relative walk must traverse it too. Platforms with neither a
/// traversal-only nor a search-only mode fall back to read access, which
/// refuses such an ancestor rather than admitting an unchecked one.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn traversal_flags() -> io::Result<OFlags> {
    Ok(OFlags::CLOEXEC | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::PATH)
}

#[cfg(any(
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "illumos",
    target_os = "solaris",
))]
pub(crate) fn traversal_flags() -> io::Result<OFlags> {
    let search = u32::try_from(libc::O_SEARCH)
        .map_err(|_| io::Error::other("the search-only open mode does not fit open flags"))?;
    Ok(OFlags::CLOEXEC | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::from_bits_retain(search))
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "illumos",
    target_os = "solaris",
)))]
pub(crate) fn traversal_flags() -> io::Result<OFlags> {
    Ok(read_flags())
}

/// Converts permission bits to a creation mode. Only the nine permission bits
/// are accepted; set-id and sticky bits are never requested at creation.
pub(crate) fn permission_mode(mode: u32) -> io::Result<Mode> {
    if mode & !0o777 != 0 {
        return Err(refuse(
            io::ErrorKind::InvalidInput,
            Refusal::InvalidMode,
            format!("creation mode {mode:o} must contain only permission bits"),
        ));
    }
    let bits = [
        (0o400, Mode::RUSR),
        (0o200, Mode::WUSR),
        (0o100, Mode::XUSR),
        (0o040, Mode::RGRP),
        (0o020, Mode::WGRP),
        (0o010, Mode::XGRP),
        (0o004, Mode::ROTH),
        (0o002, Mode::WOTH),
        (0o001, Mode::XOTH),
    ];
    let mut flags = Mode::empty();
    for (bit, flag) in bits {
        if mode & bit != 0 {
            flags |= flag;
        }
    }
    Ok(flags)
}

/// Makes `path` absolute against the working directory.
///
/// A first component that is a root-owned alias, such as `/tmp` on macOS, is
/// resolved once so the no-follow walk can proceed; it is resolved only when
/// the filesystem root itself is trusted.
pub(crate) fn absolute_path(path: &Path) -> io::Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };

    let mut components = absolute.components();
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(invalid_path("Unix private directory path must be absolute"));
    }
    let Some(Component::Normal(first)) = components.next() else {
        return Ok(absolute);
    };
    let root_child = Path::new("/").join(first);
    let metadata = match fs::symlink_metadata(&root_child) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(absolute),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_symlink() {
        return Ok(absolute);
    }

    let root_metadata = fs::metadata(Path::new("/"))?;
    if root_metadata.uid() != ROOT_UID {
        return Err(refuse(
            io::ErrorKind::PermissionDenied,
            Refusal::AncestorOwner,
            "refusing to resolve a root alias from untrusted root ancestry",
        ));
    }
    if root_metadata.mode() & 0o022 != 0 {
        return Err(refuse(
            io::ErrorKind::PermissionDenied,
            Refusal::AncestorWritable,
            "refusing to resolve a root alias from untrusted root ancestry",
        ));
    }
    let mut resolved = fs::canonicalize(root_child)?;
    for component in components {
        resolved.push(component.as_os_str());
    }
    Ok(resolved)
}

/// Walks an absolute path from `/` without following symlinks, creating every
/// missing directory at 0700, and returns a read descriptor for the target
/// with its resolved path.
///
/// Each directory above the target must be owned by the effective user or
/// root and must not be writable by others unless it is sticky; an entry in a
/// sticky directory must itself be owned by the effective user or root. The
/// target must satisfy `policy`.
pub(crate) fn prepare(
    path: &Path,
    policy: &OwnerPolicy,
    existing: Existing,
) -> io::Result<(File, PathBuf)> {
    let components = path.components().collect::<Vec<_>>();
    let mut resolved_positions = Vec::new();
    for (index, component) in components.iter().enumerate() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(_) => resolved_positions.push(index),
            Component::ParentDir => {
                if resolved_positions.pop().is_none() {
                    return Err(below_root());
                }
            }
            Component::Prefix(_) => return Err(platform_prefix()),
        }
    }
    let final_position = resolved_positions.last().copied().ok_or_else(below_root)?;

    let root = File::from(rustix::fs::open(
        Path::new("/"),
        traversal_flags()?,
        Mode::empty(),
    )?);
    let mut directories = vec![(root, false)];
    let mut resolved = PathBuf::from("/");
    let effective_uid = effective_uid();

    for (index, component) in components.into_iter().enumerate() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Prefix(_) => return Err(platform_prefix()),
            Component::ParentDir => {
                if directories.len() == 1 {
                    return Err(below_root());
                }
                directories.pop();
                resolved.pop();
            }
            Component::Normal(name) => {
                let (parent, _) = directories.last().ok_or_else(empty_stack)?;
                let parent_metadata = parent.metadata()?;
                let flags = if index == final_position {
                    read_flags()
                } else {
                    traversal_flags()?
                };
                let (child, created) = match openat(parent, name, flags, Mode::empty()) {
                    Ok(descriptor) => (File::from(descriptor), false),
                    Err(Errno::NOENT) => {
                        check_ancestor(&parent_metadata, None, effective_uid)?;
                        let created = match mkdirat(parent, name, Mode::RWXU) {
                            Ok(()) => true,
                            Err(Errno::EXIST) => false,
                            Err(error) => return Err(error.into()),
                        };
                        let child = openat(parent, name, flags, Mode::empty()).map_err(|error| {
                            let error = io::Error::from(error);
                            io::Error::new(
                                error.kind(),
                                format!(
                                    "failed to reopen private directory component {}: {error}",
                                    resolved.join(name).display(),
                                ),
                            )
                        })?;
                        if created {
                            harden_component(parent, name).map_err(|error| {
                                io::Error::new(
                                    error.kind(),
                                    format!(
                                        "failed to secure private directory component {}: {error}",
                                        resolved.join(name).display()
                                    ),
                                )
                            })?;
                        }
                        (File::from(child), created)
                    }
                    Err(error) => {
                        let error = io::Error::from(error);
                        return Err(io::Error::new(
                            error.kind(),
                            format!(
                                "failed to open private directory component {}: {error}",
                                resolved.join(name).display(),
                            ),
                        ));
                    }
                };
                let child_metadata = child.metadata()?;
                check_ancestor(&parent_metadata, Some(child_metadata.uid()), effective_uid)?;
                directories.push((child, created));
                resolved.push(name);
            }
        }
    }

    if directories.len() == 1 {
        return Err(below_root());
    }
    let (target, created) = directories.pop().ok_or_else(empty_stack)?;
    let target_metadata = target.metadata()?;
    policy.check_owner(&target_metadata, Subject::Directory)?;
    match existing {
        Existing::Harden => fchmod(&target, Mode::RWXU)?,
        Existing::Validate if created => {}
        Existing::Validate => policy.check_mode(&target_metadata, Subject::Directory)?,
    }
    policy.check_acl(&target, Subject::Directory)?;
    Ok((target, resolved))
}

/// Opens one existing child directory below a pinned directory and checks it
/// against `policy`.
pub(crate) fn open_child_directory(
    parent: &File,
    component: &OsStr,
    policy: &OwnerPolicy,
) -> io::Result<File> {
    // An ACL can be read only through a descriptor opened for reading.
    let flags = if policy.reject_acl {
        read_flags()
    } else {
        traversal_flags()?
    };
    let child = File::from(openat(parent, component, flags, Mode::empty())?);
    let metadata = child.metadata()?;
    policy.check_owner(&metadata, Subject::Directory)?;
    policy.check_mode(&metadata, Subject::Directory)?;
    policy.check_acl(&child, Subject::Directory)?;
    Ok(child)
}

/// Splits a relative path into its normal components.
pub(crate) fn relative_components(path: &Path) -> io::Result<Vec<&OsStr>> {
    let components = path
        .components()
        .map(|component| match component {
            Component::Normal(name) => Ok(name),
            Component::Prefix(_)
            | Component::RootDir
            | Component::CurDir
            | Component::ParentDir => Err(invalid_path(
                "private relative path must contain only normal components",
            )),
        })
        .collect::<io::Result<Vec<_>>>()?;
    if components.is_empty() {
        return Err(invalid_path("private relative path must not be empty"));
    }
    Ok(components)
}

/// Flushes a directory's entries to stable storage.
pub(crate) fn sync_directory(directory: &File) -> io::Result<()> {
    File::from(openat(directory, Path::new("."), read_flags(), Mode::empty())?).sync_all()
}

fn harden_component(parent: &File, component: &OsStr) -> io::Result<()> {
    let child = openat(parent, component, read_flags(), Mode::empty())?;
    fchmod(&child, Mode::RWXU)?;
    Ok(())
}

fn check_ancestor(parent: &Metadata, child_uid: Option<u32>, effective_uid: u32) -> io::Result<()> {
    let parent_uid = parent.uid();
    let parent_mode = parent.mode();
    if parent_uid != effective_uid && parent_uid != ROOT_UID {
        return Err(refuse(
            io::ErrorKind::PermissionDenied,
            Refusal::AncestorOwner,
            "private directory ancestry must be owned by the effective user or root",
        ));
    }
    if parent_mode & 0o022 != 0 {
        if parent_mode & 0o1000 == 0 {
            return Err(refuse(
                io::ErrorKind::PermissionDenied,
                Refusal::AncestorWritable,
                "private directory ancestry must not be group or world writable unless sticky",
            ));
        }
        if child_uid.is_some_and(|uid| uid != effective_uid && uid != ROOT_UID) {
            return Err(refuse(
                io::ErrorKind::PermissionDenied,
                Refusal::StickyEntryOwner,
                "private directory entry in sticky ancestry must be owned by the effective user or root",
            ));
        }
    }
    Ok(())
}

fn below_root() -> io::Error {
    invalid_path("private directory path must name a directory below the filesystem root")
}

fn platform_prefix() -> io::Error {
    invalid_path("Unix private directory path must not contain a platform prefix")
}

fn empty_stack() -> io::Error {
    io::Error::other("private directory descriptor stack is empty")
}
