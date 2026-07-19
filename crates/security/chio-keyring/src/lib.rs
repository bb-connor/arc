//! Authority key transparency with immutable events and transactional replay.

mod checkpoint;
mod enterprise_receipt;
mod error;
mod event;
mod ipc;
mod router;
mod runtime;
mod service;
mod sqlite;
mod state;
mod store;
mod sync;
mod time;
mod verifier;
mod witness;

pub use checkpoint::*;
pub use enterprise_receipt::*;
pub use error::{KeyringError, Result};
pub use event::*;
pub use ipc::*;
pub use router::*;
pub use runtime::*;
pub use service::*;
pub use sqlite::SqliteKeyLogStore;
pub use state::*;
pub use store::*;
pub use sync::*;
pub use time::*;
pub use verifier::*;
pub use witness::*;

pub const MAX_CANONICAL_RECORD_BYTES: usize = 1_048_576;

#[cfg(unix)]
const TRUSTED_ROOT_UID: u32 = 0;

pub(crate) struct DurableSqliteFile {
    file: std::fs::File,
    _parent: std::fs::File,
    path: std::path::PathBuf,
    identity: chio_core_types::Hash,
}

impl DurableSqliteFile {
    #[must_use]
    pub(crate) fn identity(&self) -> chio_core_types::Hash {
        self.identity
    }

    pub(crate) fn validate_path_binding(&self, path: &std::path::Path) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            let current_parent = open_trusted_sqlite_parent(path)?;
            let retained_parent = self._parent.metadata()?;
            let current_parent = current_parent.metadata()?;
            if retained_parent.dev() != current_parent.dev()
                || retained_parent.ino() != current_parent.ino()
            {
                return Err(KeyringError::StateInvariant(
                    "key-log database parent changed after its descriptor was retained",
                ));
            }
        }
        let path_metadata = std::fs::symlink_metadata(path)?;
        let file_metadata = self.file.metadata()?;
        if path_metadata.file_type().is_symlink()
            || !path_metadata.file_type().is_file()
            || !file_metadata.file_type().is_file()
        {
            return Err(KeyringError::StateInvariant(
                "key-log database descriptor must remain bound to a regular file",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            if path_metadata.dev() != file_metadata.dev()
                || path_metadata.ino() != file_metadata.ino()
                || file_metadata.nlink() != 1
            {
                return Err(KeyringError::StateInvariant(
                    "key-log database descriptor identity changed or is hard-linked",
                ));
            }
            validate_trusted_file_security(&self.file, &file_metadata)?;
        }
        Ok(())
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.validate_path_binding(&self.path)
    }

    pub(crate) fn validate_live_connection(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<()> {
        self.validate()?;
        validate_sqlite_main_database_live_path_binding(connection)
    }
}

pub(crate) fn open_durable_sqlite_file(
    path: &std::path::Path,
    create_if_missing: bool,
    writable: bool,
) -> Result<DurableSqliteFile> {
    reject_ephemeral_sqlite_path(path)?;
    // Rusqlite does not expose the SQLite VFS descriptor. Retaining this
    // securely opened descriptor and bracketing Connection::open is sound only
    // when an untrusted OS principal cannot swap the directory entry during
    // that interval, so the parent-directory write-permission boundary is mandatory.
    let parent = open_trusted_sqlite_parent(path)?;
    #[cfg(unix)]
    let file = open_durable_sqlite_file_at(&parent, path, create_if_missing, writable);
    #[cfg(not(unix))]
    let file = {
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .write(writable)
            .create(create_if_missing)
            .truncate(false);
        options.open(path)
    };
    let file = file.map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            KeyringError::StateInvariant(
                "key-log database must already exist as a durable regular file",
            )
        } else {
            KeyringError::Io(error)
        }
    })?;
    let identity = durable_storage_identity_for_file(&file, path)?;
    let opened = DurableSqliteFile {
        file,
        _parent: parent,
        path: path.to_path_buf(),
        identity,
    };
    opened.validate_path_binding(path)?;
    Ok(opened)
}

fn open_trusted_sqlite_parent(path: &std::path::Path) -> Result<std::fs::File> {
    if !path.is_absolute() {
        return Err(KeyringError::StateInvariant(
            "key-log database path must be absolute",
        ));
    }
    let parent_path = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or(KeyringError::StateInvariant(
            "key-log database path must have a parent directory",
        ))?;
    #[cfg(unix)]
    {
        open_trusted_unix_directory_chain(parent_path)
    }
    #[cfg(not(unix))]
    {
        let path_metadata = std::fs::symlink_metadata(parent_path)?;
        let parent = open_directory_descriptor(parent_path)?;
        let descriptor_metadata = parent.metadata()?;
        if path_metadata.file_type().is_symlink()
            || !path_metadata.file_type().is_dir()
            || !descriptor_metadata.file_type().is_dir()
        {
            return Err(KeyringError::StateInvariant(
                "key-log database parent must be a stable directory",
            ));
        }
        Ok(parent)
    }
}

/// Read a custody-sensitive policy or public-key file through a retained,
/// trusted parent-directory descriptor. The file may be group/world readable,
/// but it must not be writable by either, delegated through an extended ACL,
/// foreign-owned, hard-linked, symlinked, or rebound while being read.
pub fn read_custody_sensitive_file(
    path: impl AsRef<std::path::Path>,
    maximum_bytes: usize,
) -> Result<Vec<u8>> {
    read_custody_sensitive_file_with_metadata(path.as_ref(), maximum_bytes).map(|(bytes, _)| bytes)
}

pub(crate) fn read_custody_sensitive_file_with_metadata(
    path: &std::path::Path,
    maximum_bytes: usize,
) -> Result<(Vec<u8>, std::fs::Metadata)> {
    use std::io::Read as _;

    if !path.is_absolute() {
        return Err(KeyringError::StateInvariant(
            "custody-sensitive input path must be absolute",
        ));
    }
    let parent_path = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or(KeyringError::StateInvariant(
            "custody-sensitive input path must have a parent directory",
        ))?;
    let file_name = path.file_name().ok_or(KeyringError::StateInvariant(
        "custody-sensitive input path must have a file name",
    ))?;

    #[cfg(unix)]
    let parent = open_trusted_unix_directory_chain(parent_path)?;
    #[cfg(not(unix))]
    let _parent = {
        let path_metadata = std::fs::symlink_metadata(parent_path)?;
        let parent = open_directory_descriptor(parent_path)?;
        let descriptor_metadata = parent.metadata()?;
        if path_metadata.file_type().is_symlink()
            || !path_metadata.file_type().is_dir()
            || !descriptor_metadata.file_type().is_dir()
        {
            return Err(KeyringError::StateInvariant(
                "custody-sensitive input parent must be a stable directory",
            ));
        }
        parent
    };

    let path_metadata_before = std::fs::symlink_metadata(path)?;
    if path_metadata_before.file_type().is_symlink() || !path_metadata_before.file_type().is_file()
    {
        return Err(KeyringError::StateInvariant(
            "custody-sensitive input must be an existing regular file",
        ));
    }

    #[cfg(unix)]
    let mut file = {
        let descriptor = rustix::fs::openat(
            &parent,
            file_name,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| KeyringError::Io(error.into()))?;
        std::fs::File::from(descriptor)
    };
    #[cfg(not(unix))]
    let mut file = {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        options.open(path)?
    };

    let metadata_before = file.metadata()?;
    if !metadata_before.file_type().is_file() {
        return Err(KeyringError::StateInvariant(
            "custody-sensitive input must be an existing regular file",
        ));
    }
    #[cfg(unix)]
    {
        validate_custody_sensitive_file_security(&file, &metadata_before)?;
        if !unix_metadata_identity_matches(&path_metadata_before, &metadata_before) {
            return Err(KeyringError::StateInvariant(
                "custody-sensitive input changed while it was opened",
            ));
        }
    }

    let maximum_bytes_u64 = u64::try_from(maximum_bytes).map_err(|_| KeyringError::NumericRange)?;
    if metadata_before.len() > maximum_bytes_u64 {
        return Err(KeyringError::Canonical(
            "custody-sensitive input exceeds its byte limit".to_string(),
        ));
    }
    let read_limit = maximum_bytes_u64
        .checked_add(1)
        .ok_or(KeyringError::NumericRange)?;
    let mut bytes = Vec::with_capacity(maximum_bytes);
    (&mut file).take(read_limit).read_to_end(&mut bytes)?;
    if bytes.len() > maximum_bytes {
        return Err(KeyringError::Canonical(
            "custody-sensitive input exceeds its byte limit".to_string(),
        ));
    }

    let metadata_after = file.metadata()?;
    let path_metadata_after = std::fs::symlink_metadata(path)?;
    if path_metadata_after.file_type().is_symlink()
        || !path_metadata_after.file_type().is_file()
        || metadata_after.len()
            != u64::try_from(bytes.len()).map_err(|_| KeyringError::NumericRange)?
    {
        return Err(KeyringError::StateInvariant(
            "custody-sensitive input changed while it was read",
        ));
    }
    #[cfg(unix)]
    {
        validate_custody_sensitive_file_security(&file, &metadata_after)?;
        if !unix_metadata_identity_matches(&metadata_before, &metadata_after)
            || !unix_metadata_identity_matches(&path_metadata_after, &metadata_after)
            || !unix_metadata_revision_matches(&metadata_before, &metadata_after)
        {
            return Err(KeyringError::StateInvariant(
                "custody-sensitive input changed while it was read",
            ));
        }
        let retained_parent_metadata = parent.metadata()?;
        let current_parent = open_trusted_unix_directory_chain(parent_path)?;
        let current_parent_metadata = current_parent.metadata()?;
        if !unix_metadata_identity_matches(&retained_parent_metadata, &current_parent_metadata) {
            return Err(KeyringError::StateInvariant(
                "custody-sensitive input parent changed while it was read",
            ));
        }
    }
    Ok((bytes, metadata_after))
}

#[cfg(unix)]
fn validate_custody_sensitive_file_security(
    file: &std::fs::File,
    metadata: &std::fs::Metadata,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let effective_uid = rustix::process::geteuid().as_raw();
    validate_custody_sensitive_file_security_values(
        metadata.uid(),
        effective_uid,
        metadata.mode(),
        metadata.nlink(),
        trusted_file_has_extended_acl(file)?,
    )
}

#[cfg(unix)]
fn validate_custody_sensitive_file_security_values(
    owner_uid: u32,
    effective_uid: u32,
    mode: u32,
    link_count: u64,
    has_extended_acl: bool,
) -> Result<()> {
    if (owner_uid != effective_uid && owner_uid != TRUSTED_ROOT_UID)
        || mode & 0o022 != 0
        || link_count != 1
        || has_extended_acl
    {
        return Err(KeyringError::StateInvariant(
            "custody-sensitive input must have trusted ownership, no untrusted write access or ACL, and one hard link",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn unix_metadata_identity_matches(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(unix)]
fn unix_metadata_revision_matches(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

fn open_directory_descriptor(path: &std::path::Path) -> Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        let flags = rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW;
        let flags = i32::try_from(flags.bits()).map_err(|_| KeyringError::NumericRange)?;
        options.custom_flags(flags);
    }
    options.open(path).map_err(KeyringError::Io)
}

#[cfg(unix)]
fn open_trusted_unix_directory_chain(parent_path: &std::path::Path) -> Result<std::fs::File> {
    use std::os::unix::fs::MetadataExt;

    let mut names = Vec::new();
    for component in parent_path.components() {
        match component {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(name) => names.push(name.to_os_string()),
            std::path::Component::Prefix(_) => {
                return Err(KeyringError::StateInvariant(
                    "key-log database path has an unsupported prefix",
                ));
            }
            std::path::Component::CurDir | std::path::Component::ParentDir => {
                return Err(KeyringError::StateInvariant(
                    "key-log database path must not contain dot components",
                ));
            }
        }
    }

    let effective_uid = rustix::process::geteuid().as_raw();
    let mut directory = open_directory_descriptor(std::path::Path::new("/"))?;
    let root_metadata = directory.metadata()?;
    validate_trusted_parent_security(
        root_metadata.uid(),
        effective_uid,
        root_metadata.mode(),
        trusted_file_has_extended_acl(&directory)?,
        !names.is_empty(),
    )?;
    let name_count = names.len();
    for (index, name) in names.into_iter().enumerate() {
        let descriptor = rustix::fs::openat(
            &directory,
            &name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| KeyringError::Io(error.into()))?;
        let next = std::fs::File::from(descriptor);
        let descriptor_metadata = next.metadata()?;
        if !descriptor_metadata.file_type().is_dir() {
            return Err(KeyringError::StateInvariant(
                "key-log database ancestor is not a directory",
            ));
        }
        validate_trusted_parent_security(
            descriptor_metadata.uid(),
            effective_uid,
            descriptor_metadata.mode(),
            trusted_file_has_extended_acl(&next)?,
            index + 1 != name_count,
        )?;
        directory = next;
    }
    Ok(directory)
}

#[cfg(unix)]
fn open_durable_sqlite_file_at(
    parent: &std::fs::File,
    path: &std::path::Path,
    create_if_missing: bool,
    writable: bool,
) -> std::io::Result<std::fs::File> {
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "key-log database path has no file name",
        )
    })?;
    let mut flags = rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW;
    flags |= if writable {
        rustix::fs::OFlags::RDWR
    } else {
        rustix::fs::OFlags::RDONLY
    };
    if create_if_missing {
        flags |= rustix::fs::OFlags::CREATE;
    }
    rustix::fs::openat(
        parent,
        file_name,
        flags,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .map(std::fs::File::from)
    .map_err(Into::into)
}

#[cfg(unix)]
fn validate_trusted_parent_security(
    owner_uid: u32,
    effective_uid: u32,
    mode: u32,
    has_extended_acl: bool,
    allow_sticky_write: bool,
) -> Result<()> {
    let writable_by_group_or_world = mode & 0o022 != 0;
    let sticky_directory = mode & 0o1000 != 0;
    if (owner_uid != effective_uid && owner_uid != TRUSTED_ROOT_UID)
        || (writable_by_group_or_world && !(allow_sticky_write && sticky_directory))
        || has_extended_acl
    {
        return Err(KeyringError::StateInvariant(
            "key-log database parent must be owned by the service or root and grant no untrusted write access or extended ACL",
        ));
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn trusted_file_has_extended_acl(file: &std::fs::File) -> Result<bool> {
    for attribute in ["system.posix_acl_access", "system.posix_acl_default"] {
        let mut value = Vec::<u8>::with_capacity(1);
        match rustix::fs::fgetxattr(file, attribute, &mut value) {
            Ok(_) | Err(rustix::io::Errno::RANGE) => return Ok(true),
            Err(error) if error == rustix::io::Errno::NODATA => {}
            Err(error) if error == rustix::io::Errno::NOTSUP => {}
            Err(error) => return Err(KeyringError::Io(error.into())),
        }
    }
    Ok(false)
}

#[cfg(target_vendor = "apple")]
fn trusted_file_has_extended_acl(file: &std::fs::File) -> Result<bool> {
    use std::os::fd::AsRawFd;

    type Acl = *mut std::ffi::c_void;
    unsafe extern "C" {
        fn acl_get_fd_np(fd: std::os::raw::c_int, acl_type: std::os::raw::c_int) -> Acl;
        fn acl_get_entry(
            acl: Acl,
            entry_id: std::os::raw::c_int,
            entry: *mut *mut std::ffi::c_void,
        ) -> std::os::raw::c_int;
        fn acl_get_tag_type(
            entry: *mut std::ffi::c_void,
            tag_type: *mut std::os::raw::c_int,
        ) -> std::os::raw::c_int;
        fn acl_free(value: *mut std::ffi::c_void) -> std::os::raw::c_int;
    }

    const ACL_TYPE_EXTENDED: std::os::raw::c_int = 0x100;
    const ACL_FIRST_ENTRY: std::os::raw::c_int = 0;
    const ACL_NEXT_ENTRY: std::os::raw::c_int = -1;
    // SAFETY: `file` owns a valid descriptor and ACL_TYPE_EXTENDED is the
    // platform-defined ACL type. The returned allocation is released below.
    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        let error = std::io::Error::last_os_error();
        // Darwin reports ENOENT when a valid descriptor has no extended ACL
        // object. Descriptor metadata was already read successfully, so this
        // means that no additional ACL authority exists rather than that the
        // file disappeared.
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(false);
        }
        return Err(KeyringError::Io(error));
    }
    let mut entry = std::ptr::null_mut();
    // SAFETY: `acl` is a live ACL object and `entry` points to writable storage.
    let mut entry_result = unsafe { acl_get_entry(acl, ACL_FIRST_ENTRY, &mut entry) };
    let mut acl_error = None;
    let mut grants_additional_authority = false;
    while entry_result == 1 {
        let mut tag_type = 0;
        // SAFETY: `entry` was returned by `acl_get_entry` for the live ACL.
        if unsafe { acl_get_tag_type(entry, &mut tag_type) } != 0 {
            acl_error = Some(std::io::Error::last_os_error());
            break;
        }
        // A deny-only entry cannot add authority. Any allow or unknown tag is
        // rejected conservatively without trying to reproduce Darwin's ACL
        // precedence rules.
        if apple_acl_tag_grants_additional_authority(tag_type) {
            grants_additional_authority = true;
            break;
        }
        // SAFETY: `acl` remains live and `entry` points to writable storage.
        entry_result = unsafe { acl_get_entry(acl, ACL_NEXT_ENTRY, &mut entry) };
    }
    if entry_result < 0 && acl_error.is_none() {
        acl_error = Some(std::io::Error::last_os_error());
    }
    // SAFETY: `acl` was allocated by `acl_get_fd_np` and is freed exactly once.
    let free_result = unsafe { acl_free(acl) };
    if let Some(error) = acl_error {
        return Err(KeyringError::Io(error));
    }
    if free_result != 0 {
        return Err(KeyringError::Io(std::io::Error::last_os_error()));
    }
    Ok(grants_additional_authority)
}

/// Inspect a Darwin file descriptor's extended ACL without exposing the FFI
/// boundary to unsafe-free persistence crates. Deny-only entries do not add
/// authority; allow or unknown entries are reported as authority-granting.
#[cfg(target_vendor = "apple")]
pub fn darwin_descriptor_grants_extended_acl_authority(file: &std::fs::File) -> Result<bool> {
    trusted_file_has_extended_acl(file)
}

/// Verify that SQLite's live main-database handle still names the file at the
/// path SQLite opened. This is the narrow FFI boundary for persistence crates
/// that otherwise forbid unsafe code.
///
/// The caller must separately retain and validate its expected file descriptor.
/// This check closes the gap where a different file occupies the database path
/// only while `sqlite3_open_v2` runs and the expected file is restored before a
/// subsequent path-based identity check.
pub fn validate_sqlite_main_database_live_path_binding(
    connection: &rusqlite::Connection,
) -> Result<()> {
    let mut has_moved = 0_i32;
    // SAFETY: `connection` remains borrowed for the complete synchronous call,
    // so its SQLite handle is live. The schema name is a static NUL-terminated
    // string and `has_moved` is writable storage of the exact integer type
    // required by SQLITE_FCNTL_HAS_MOVED. The call does not retain either
    // pointer after returning.
    let result = unsafe {
        rusqlite::ffi::sqlite3_file_control(
            connection.handle(),
            c"main".as_ptr(),
            rusqlite::ffi::SQLITE_FCNTL_HAS_MOVED,
            (&raw mut has_moved).cast(),
        )
    };
    if result != rusqlite::ffi::SQLITE_OK {
        return Err(KeyringError::Storage(format!(
            "SQLITE_FCNTL_HAS_MOVED failed: {}",
            rusqlite::ffi::Error::new(result)
        )));
    }
    if has_moved != 0 {
        return Err(KeyringError::StateInvariant(
            "SQLite main database handle is no longer bound to its opened path",
        ));
    }
    Ok(())
}

#[cfg(target_vendor = "apple")]
fn apple_acl_tag_grants_additional_authority(tag_type: std::os::raw::c_int) -> bool {
    const ACL_EXTENDED_DENY: std::os::raw::c_int = 2;

    tag_type != ACL_EXTENDED_DENY
}

#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android", target_vendor = "apple"))
))]
fn trusted_file_has_extended_acl(_file: &std::fs::File) -> Result<bool> {
    Err(KeyringError::StateInvariant(
        "key-log database parent ACL inspection is unsupported on this platform",
    ))
}

#[cfg(unix)]
fn validate_trusted_file_security(
    file: &std::fs::File,
    metadata: &std::fs::Metadata,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let effective_uid = rustix::process::geteuid().as_raw();
    if (metadata.uid() != effective_uid && metadata.uid() != TRUSTED_ROOT_UID)
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
        || trusted_file_has_extended_acl(file)?
    {
        return Err(KeyringError::StateInvariant(
            "key-log database file must have trusted ownership, no untrusted write access or ACL, and one hard link",
        ));
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod storage_identity_tests {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    use super::open_trusted_unix_directory_chain;
    use super::{
        open_durable_sqlite_file, validate_custody_sensitive_file_security_values,
        validate_trusted_parent_security,
    };

    #[test]
    fn retained_sqlite_descriptor_detects_hardlinks_and_path_rebinding() -> std::io::Result<()> {
        use std::os::unix::fs::OpenOptionsExt;

        let directory = tempfile::tempdir()?;
        let trusted_directory = std::fs::canonicalize(directory.path())?;
        let database = trusted_directory.join("key-log.sqlite3");
        let hardlink = trusted_directory.join("key-log-hardlink.sqlite3");
        let displaced = trusted_directory.join("key-log-displaced.sqlite3");
        let retained =
            open_durable_sqlite_file(&database, true, true).map_err(std::io::Error::other)?;

        std::fs::hard_link(&database, &hardlink)?;
        assert!(retained.validate().is_err());
        std::fs::remove_file(&hardlink)?;
        assert!(retained.validate().is_ok());

        std::fs::rename(&database, &displaced)?;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&database)?;
        assert!(retained.validate().is_err());
        Ok(())
    }

    #[test]
    fn trusted_parent_policy_rejects_foreign_owner_acl_and_mode_writes() {
        assert!(validate_trusted_parent_security(501, 501, 0o700, false, false).is_ok());
        assert!(validate_trusted_parent_security(0, 501, 0o755, false, false).is_ok());
        assert!(validate_trusted_parent_security(0, 501, 0o1777, false, true).is_ok());
        assert!(validate_trusted_parent_security(502, 501, 0o700, false, false).is_err());
        assert!(validate_trusted_parent_security(501, 501, 0o720, false, false).is_err());
        assert!(validate_trusted_parent_security(501, 501, 0o1777, false, false).is_err());
        assert!(validate_trusted_parent_security(501, 501, 0o700, true, false).is_err());
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn trusted_parent_policy_requires_private_child_below_system_temp_directory(
    ) -> std::io::Result<()> {
        let directory = tempfile::tempdir()?;
        let trusted_directory = std::fs::canonicalize(directory.path())?;

        assert!(open_trusted_unix_directory_chain(&trusted_directory).is_ok());
        assert!(open_trusted_unix_directory_chain(std::path::Path::new("/tmp")).is_err());
        Ok(())
    }

    #[test]
    fn trusted_file_policy_rejects_group_or_world_readability() {
        assert_ne!(0o644 & 0o077, 0);
        assert_eq!(0o600 & 0o077, 0);
    }

    #[test]
    fn custody_sensitive_file_policy_rejects_foreign_owner_writes_links_and_acl() {
        assert!(validate_custody_sensitive_file_security_values(501, 501, 0o644, 1, false).is_ok());
        assert!(validate_custody_sensitive_file_security_values(0, 501, 0o644, 1, false).is_ok());
        assert!(
            validate_custody_sensitive_file_security_values(502, 501, 0o644, 1, false).is_err()
        );
        assert!(
            validate_custody_sensitive_file_security_values(501, 501, 0o664, 1, false).is_err()
        );
        assert!(
            validate_custody_sensitive_file_security_values(501, 501, 0o644, 2, false).is_err()
        );
        assert!(validate_custody_sensitive_file_security_values(501, 501, 0o644, 1, true).is_err());
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn apple_acl_policy_accepts_deny_only_and_rejects_allow_entries() {
        use super::apple_acl_tag_grants_additional_authority;

        assert!(!apple_acl_tag_grants_additional_authority(2));
        assert!(apple_acl_tag_grants_additional_authority(1));
        assert!(apple_acl_tag_grants_additional_authority(99));
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn apple_acl_inspection_accepts_a_file_without_an_extended_acl() -> std::io::Result<()> {
        use std::os::unix::fs::OpenOptionsExt;

        let directory = tempfile::tempdir()?;
        let trusted_directory = std::fs::canonicalize(directory.path())?;
        let path = trusted_directory.join("no-extended-acl.sqlite3");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        let grants_additional_authority =
            super::trusted_file_has_extended_acl(&file).map_err(std::io::Error::other)?;
        assert!(!grants_additional_authority);
        Ok(())
    }
}

fn reject_ephemeral_sqlite_path(path: &std::path::Path) -> Result<()> {
    let path_text = path.to_string_lossy();
    if path_text == ":memory:" || path_text.to_ascii_lowercase().starts_with("file:") {
        return Err(KeyringError::StateInvariant(
            "key-log storage must be backed by a durable filesystem path",
        ));
    }
    Ok(())
}

pub(crate) fn durable_storage_identity_for_file(
    file: &std::fs::File,
    _path: &std::path::Path,
) -> Result<chio_core_types::Hash> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(KeyringError::StateInvariant(
            "service storage must be a durable regular file",
        ));
    }
    #[cfg(unix)]
    {
        use serde::Serialize;
        use std::os::unix::fs::MetadataExt;

        #[derive(Serialize)]
        struct StorageIdentity {
            schema: &'static str,
            device: u64,
            inode: u64,
        }
        Ok(chio_core_types::sha256(
            &chio_core_types::canonical_json_bytes(&StorageIdentity {
                schema: "chio.key-log.storage-identity.v1",
                device: metadata.dev(),
                inode: metadata.ino(),
            })?,
        ))
    }
    #[cfg(not(unix))]
    {
        use serde::Serialize;

        #[derive(Serialize)]
        struct StorageIdentity<'a> {
            schema: &'static str,
            canonical_path: &'a std::path::Path,
        }
        let canonical_path = std::fs::canonicalize(_path)?;
        Ok(chio_core_types::sha256(
            &chio_core_types::canonical_json_bytes(&StorageIdentity {
                schema: "chio.key-log.storage-identity.v1",
                canonical_path: &canonical_path,
            })?,
        ))
    }
}

pub(crate) fn require_existing_durable_sqlite_path(path: &std::path::Path) -> Result<()> {
    reject_ephemeral_sqlite_path(path)?;
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            KeyringError::StateInvariant(
                "key-log database must already exist as a durable regular file",
            )
        } else {
            KeyringError::Io(error)
        }
    })?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(KeyringError::StateInvariant(
            "key-log database must already exist as a durable regular file",
        ));
    }
    Ok(())
}

pub(crate) fn provision_durable_sqlite_path(path: &std::path::Path) -> Result<()> {
    reject_ephemeral_sqlite_path(path)?;
    #[cfg(unix)]
    {
        let parent = open_trusted_sqlite_parent(path)?;
        let file_name = path.file_name().ok_or(KeyringError::StateInvariant(
            "key-log database path has no file name",
        ))?;
        let descriptor = rustix::fs::openat(
            &parent,
            file_name,
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .map_err(|error| KeyringError::Io(error.into()))?;
        let file = std::fs::File::from(descriptor);
        file.sync_all().map_err(KeyringError::Io)?;
        parent.sync_all().map_err(KeyringError::Io)
    }
    #[cfg(not(unix))]
    {
        let file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .map_err(KeyringError::Io)?;
        file.sync_all().map_err(KeyringError::Io)
    }
}

pub(crate) fn persist_or_validate_policy_binding(
    connection: &rusqlite::Connection,
    policy: &KeyLogPolicy,
    durable_state_exists: bool,
) -> Result<()> {
    use rusqlite::OptionalExtension;

    let expected_witness = policy.witness_roster_binding()?.to_string();
    let expected_recovery = policy.recovery_policy_binding()?.to_string();
    let expected_artifact_time = policy.artifact_time_policy_binding()?.to_string();
    let expected_auditor = policy.auditor_policy_binding()?.to_string();
    let expected_configuration = policy.configuration_binding()?.to_string();
    let existing = connection
        .query_row(
            "SELECT witness_roster_binding, recovery_policy_binding, artifact_time_policy_binding, auditor_policy_binding, configuration_binding FROM keyring_policy_binding WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?;
    match existing {
        Some((witness, recovery, artifact_time, auditor, configuration))
            if witness == expected_witness
                && recovery == expected_recovery
                && artifact_time == expected_artifact_time
                && auditor == expected_auditor
                && configuration == expected_configuration =>
        {
            Ok(())
        }
        Some(_) => Err(KeyringError::StateInvariant(
            "durable key-log policy binding does not match configured trust roots",
        )),
        None if durable_state_exists => Err(KeyringError::StateInvariant(
            "durable key-log state predates its required policy binding",
        )),
        None => {
            connection.execute(
                "INSERT INTO keyring_policy_binding (singleton, witness_roster_binding, recovery_policy_binding, artifact_time_policy_binding, auditor_policy_binding, configuration_binding) VALUES (1, ?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    expected_witness,
                    expected_recovery,
                    expected_artifact_time,
                    expected_auditor,
                    expected_configuration
                ],
            )?;
            Ok(())
        }
    }
}

pub(crate) fn from_bounded_json<T>(bytes: &[u8]) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    if bytes.len() > MAX_CANONICAL_RECORD_BYTES {
        return Err(KeyringError::Canonical(
            "canonical record exceeds 1048576 bytes".to_string(),
        ));
    }
    Ok(serde_json::from_slice(bytes)?)
}
