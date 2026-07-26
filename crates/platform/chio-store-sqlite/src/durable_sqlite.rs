use std::ffi::OsStr;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rusqlite::{Connection, OpenFlags};

#[cfg(unix)]
const SQLITE_AUTHORITY_SIDECAR_SUFFIXES: [&str; 3] = ["-wal", "-shm", "-journal"];

/// Failure to bind a durable SQLite authority to a trusted local file.
#[derive(Debug, thiserror::Error)]
pub enum DurableSqliteError {
    #[error("durable SQLite authority conflict: {0}")]
    Conflict(String),
    #[error("durable SQLite authority I/O failure: {0}")]
    Io(#[from] std::io::Error),
    #[error("durable SQLite authority open failure: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// One retained, trusted parent directory for a family of SQLite authorities.
///
/// Every sibling is opened relative to this descriptor. The pathname is used
/// only by SQLite itself and is revalidated against the descriptor before and
/// after every connection open.
#[derive(Clone)]
pub struct TrustedSqliteDirectory {
    parent: Arc<File>,
    path: PathBuf,
}

impl std::fmt::Debug for TrustedSqliteDirectory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TrustedSqliteDirectory")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl TrustedSqliteDirectory {
    /// Retain the canonical parent of an absolute plain database path.
    pub fn open_for_database(path: impl AsRef<Path>) -> Result<Self, DurableSqliteError> {
        let path = path.as_ref();
        reject_volatile_database_path(path)?;
        let parent_path = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| {
                DurableSqliteError::Conflict(
                    "database path must have an existing parent directory".to_string(),
                )
            })?;
        let canonical_parent = fs::canonicalize(parent_path)?;
        #[cfg(unix)]
        let parent = open_trusted_unix_directory_chain(&canonical_parent)?;
        #[cfg(not(unix))]
        let parent = {
            return Err(DurableSqliteError::Conflict(
                "descriptor-bound durable SQLite authorities are unsupported on this platform"
                    .to_string(),
            ));
        };
        let directory = Self {
            parent: Arc::new(parent),
            path: canonical_parent,
        };
        directory.validate()?;
        Ok(directory)
    }

    /// Return the canonical sibling path for a single normal file name.
    pub fn sibling_path(
        &self,
        file_name: impl AsRef<OsStr>,
    ) -> Result<PathBuf, DurableSqliteError> {
        let file_name = Path::new(file_name.as_ref());
        if file_name.components().count() != 1
            || !matches!(
                file_name.components().next(),
                Some(std::path::Component::Normal(_))
            )
        {
            return Err(DurableSqliteError::Conflict(
                "database sibling must be one normal file name".to_string(),
            ));
        }
        Ok(self.path.join(file_name))
    }

    /// Open one database file through the retained parent descriptor.
    pub fn open_database(
        &self,
        path: impl AsRef<Path>,
        create_if_missing: bool,
    ) -> Result<Arc<DurableSqliteFile>, DurableSqliteError> {
        let path = self.normalize_sibling_path(path.as_ref())?;
        self.validate()?;
        #[cfg(unix)]
        let file = open_database_file_at(&self.parent, &path, create_if_missing)?;
        #[cfg(not(unix))]
        let file = {
            let _ = create_if_missing;
            return Err(DurableSqliteError::Conflict(
                "descriptor-bound durable SQLite authorities are unsupported on this platform"
                    .to_string(),
            ));
        };
        let opened = Arc::new(DurableSqliteFile {
            file,
            directory: self.clone(),
            path,
        });
        opened.validate()?;
        Ok(opened)
    }

    /// Retain an existing database through a read-only descriptor.
    pub fn open_existing_database_read_only(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<Arc<DurableSqliteFile>, DurableSqliteError> {
        let path = self.normalize_sibling_path(path.as_ref())?;
        self.validate()?;
        #[cfg(unix)]
        let file = open_database_file_at_read_only(&self.parent, &path)?;
        #[cfg(not(unix))]
        let file = {
            return Err(DurableSqliteError::Conflict(
                "descriptor-bound read-only SQLite authorities are unsupported on this platform"
                    .to_string(),
            ));
        };
        let opened = Arc::new(DurableSqliteFile {
            file,
            directory: self.clone(),
            path,
        });
        opened.validate()?;
        Ok(opened)
    }

    fn normalize_sibling_path(&self, path: &Path) -> Result<PathBuf, DurableSqliteError> {
        reject_volatile_database_path(path)?;
        let file_name = path.file_name().ok_or_else(|| {
            DurableSqliteError::Conflict("database path has no file name".to_string())
        })?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| {
                DurableSqliteError::Conflict("database path has no parent directory".to_string())
            })?;
        let canonical_parent = fs::canonicalize(parent)?;
        if canonical_parent != self.path {
            return Err(DurableSqliteError::Conflict(format!(
                "database sibling parent `{}` does not match retained parent `{}`",
                canonical_parent.display(),
                self.path.display()
            )));
        }
        Ok(self.path.join(file_name))
    }

    fn validate(&self) -> Result<(), DurableSqliteError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            let current = open_trusted_unix_directory_chain(&self.path)?;
            let retained_metadata = self.parent.metadata()?;
            let current_metadata = current.metadata()?;
            if retained_metadata.dev() != current_metadata.dev()
                || retained_metadata.ino() != current_metadata.ino()
            {
                return Err(DurableSqliteError::Conflict(
                    "trusted database parent changed after its descriptor was retained".to_string(),
                ));
            }
        }
        Ok(())
    }
}

/// A retained file descriptor and pathname identity for one SQLite authority.
pub struct DurableSqliteFile {
    file: File,
    directory: TrustedSqliteDirectory,
    path: PathBuf,
}

impl std::fmt::Debug for DurableSqliteFile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurableSqliteFile")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl DurableSqliteFile {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Verify that the retained descriptor and its only directory entry still
    /// identify the same trusted regular file. Any existing SQLite WAL, shared
    /// memory, or rollback journal must satisfy the same file authority policy.
    pub fn validate(&self) -> Result<(), DurableSqliteError> {
        self.directory.validate()?;
        let path_metadata = fs::symlink_metadata(&self.path)?;
        let file_metadata = self.file.metadata()?;
        if path_metadata.file_type().is_symlink()
            || !path_metadata.file_type().is_file()
            || !file_metadata.file_type().is_file()
        {
            return Err(DurableSqliteError::Conflict(
                "database descriptor must remain bound to a regular file".to_string(),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            if path_metadata.dev() != file_metadata.dev()
                || path_metadata.ino() != file_metadata.ino()
                || file_metadata.nlink() != 1
            {
                return Err(DurableSqliteError::Conflict(
                    "database descriptor identity changed or is hard-linked".to_string(),
                ));
            }
            validate_trusted_database_file(&self.file, &file_metadata)?;
            self.validate_existing_sidecars()?;
        }
        Ok(())
    }

    /// Open SQLite without following a final symlink and bind its live main
    /// handle to this retained descriptor before the caller can use it.
    pub fn open_connection(&self, flags: OpenFlags) -> Result<Connection, DurableSqliteError> {
        self.validate()?;
        let connection =
            Connection::open_with_flags(&self.path, flags | OpenFlags::SQLITE_OPEN_NOFOLLOW)?;
        self.validate_live_connection(&connection)?;
        Ok(connection)
    }

    /// Open an exact read-only SQLite connection without creating a WAL shared-memory file.
    pub fn open_read_only_connection(&self) -> Result<Connection, DurableSqliteError> {
        self.validate()?;
        #[cfg(unix)]
        let wal_identity = self.required_existing_sidecar_identity("-wal")?;
        #[cfg(not(unix))]
        {
            return Err(DurableSqliteError::Conflict(
                "exact read-only WAL connections are unsupported on this platform".to_string(),
            ));
        }
        let uri = read_only_sqlite_uri(&self.path)?;
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
            | OpenFlags::SQLITE_OPEN_URI;
        let connection = Connection::open_with_flags(uri, flags)?;
        self.validate_live_connection(&connection)?;
        #[cfg(unix)]
        if self.required_existing_sidecar_identity("-wal")? != wal_identity {
            return Err(DurableSqliteError::Conflict(
                "SQLite WAL identity changed during exact read-only open".to_string(),
            ));
        }
        Ok(connection)
    }

    /// Revalidate the main file, SQLite sidecars, and the live main-file handle.
    pub fn validate_live_connection(
        &self,
        connection: &Connection,
    ) -> Result<(), DurableSqliteError> {
        self.validate()?;
        chio_keyring::validate_sqlite_main_database_live_path_binding(connection).map_err(
            |error| {
                DurableSqliteError::Conflict(format!(
                    "live SQLite connection is not bound to the retained database file: {error}"
                ))
            },
        )?;
        self.validate()
    }

    /// Persist the database inode and the retained directory entry, with the
    /// descriptor/path binding checked on both sides of the durability fence.
    pub fn sync_file_and_directory(&self) -> Result<(), DurableSqliteError> {
        self.validate()?;
        self.file.sync_all()?;
        self.directory.parent.sync_all()?;
        self.validate()
    }

    #[cfg(unix)]
    fn validate_existing_sidecars(&self) -> Result<(), DurableSqliteError> {
        let file_name = self.path.file_name().ok_or_else(|| {
            DurableSqliteError::Conflict("database path has no file name".to_string())
        })?;
        validate_existing_sqlite_sidecars_at(&self.directory.parent, file_name)
    }

    #[cfg(unix)]
    #[allow(
        clippy::useless_conversion,
        reason = "rustix dev_t is u64 on Linux but varies across supported Unix targets"
    )]
    fn required_existing_sidecar_identity(
        &self,
        suffix: &str,
    ) -> Result<SqliteSidecarIdentity, DurableSqliteError> {
        let file_name = self.path.file_name().ok_or_else(|| {
            DurableSqliteError::Conflict("database path has no file name".to_string())
        })?;
        let mut sidecar_name = file_name.to_os_string();
        sidecar_name.push(suffix);
        let metadata = rustix::fs::statat(
            &self.directory.parent,
            &sidecar_name,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|error| {
            DurableSqliteError::Conflict(format!(
                "required SQLite {suffix} sidecar is unavailable: {error}"
            ))
        })?;
        if validate_sqlite_sidecar_snapshot(&metadata, suffix)?
            != SqliteSidecarSnapshotState::Linked
        {
            return Err(DurableSqliteError::Conflict(format!(
                "required SQLite {suffix} sidecar is not linked"
            )));
        }
        Ok(SqliteSidecarIdentity {
            device: u64::try_from(metadata.st_dev).map_err(|_| {
                DurableSqliteError::Conflict(
                    "required SQLite sidecar has an invalid device identifier".to_string(),
                )
            })?,
            inode: metadata.st_ino,
        })
    }
}

fn reject_volatile_database_path(path: &Path) -> Result<(), DurableSqliteError> {
    let text = path.to_string_lossy();
    if text == ":memory:" || text.to_ascii_lowercase().starts_with("file:") {
        return Err(DurableSqliteError::Conflict(
            "database must use a durable plain filesystem path".to_string(),
        ));
    }
    if !path.is_absolute() {
        return Err(DurableSqliteError::Conflict(
            "database path must be absolute".to_string(),
        ));
    }
    if path.components().any(|component| {
        matches!(
            component,
            std::path::Component::CurDir | std::path::Component::ParentDir
        )
    }) {
        return Err(DurableSqliteError::Conflict(
            "database path must not contain dot components".to_string(),
        ));
    }
    Ok(())
}

fn read_only_sqlite_uri(path: &Path) -> Result<String, DurableSqliteError> {
    let path = path.to_str().ok_or_else(|| {
        DurableSqliteError::Conflict(
            "database path is not valid UTF-8 for an exact read-only SQLite URI".to_string(),
        )
    })?;
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut uri = String::with_capacity(path.len().saturating_add(32));
    uri.push_str("file:");
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.' | b'~') {
            uri.push(char::from(byte));
        } else {
            uri.push('%');
            uri.push(char::from(HEX[usize::from(byte >> 4)]));
            uri.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    uri.push_str("?mode=ro&readonly_shm=1");
    Ok(uri)
}

#[cfg(unix)]
fn open_trusted_unix_directory_chain(path: &Path) -> Result<File, DurableSqliteError> {
    let mut names = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(name) => names.push(name.to_os_string()),
            std::path::Component::Prefix(_) => {
                return Err(DurableSqliteError::Conflict(
                    "database path has an unsupported prefix".to_string(),
                ));
            }
            std::path::Component::CurDir | std::path::Component::ParentDir => {
                return Err(DurableSqliteError::Conflict(
                    "database path must not contain dot components".to_string(),
                ));
            }
        }
    }

    let effective_uid = rustix::process::geteuid().as_raw();
    let root = rustix::fs::open(
        "/",
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| DurableSqliteError::Io(error.into()))?;
    let mut directory = File::from(root);
    validate_trusted_parent_security(&directory, effective_uid, names.is_empty())?;
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
        .map_err(|error| DurableSqliteError::Io(error.into()))?;
        let next = File::from(descriptor);
        if !next.metadata()?.file_type().is_dir() {
            return Err(DurableSqliteError::Conflict(
                "database ancestor is not a directory".to_string(),
            ));
        }
        validate_trusted_parent_security(&next, effective_uid, index + 1 == name_count)?;
        directory = next;
    }
    Ok(directory)
}

#[cfg(unix)]
fn open_database_file_at(
    parent: &File,
    path: &Path,
    create_if_missing: bool,
) -> Result<File, DurableSqliteError> {
    let file_name = path.file_name().ok_or_else(|| {
        DurableSqliteError::Conflict("database path has no file name".to_string())
    })?;
    let base_flags =
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC;
    if !create_if_missing {
        return rustix::fs::openat(parent, file_name, base_flags, rustix::fs::Mode::empty())
            .map(File::from)
            .map_err(|error| DurableSqliteError::Io(error.into()));
    }

    match rustix::fs::openat(
        parent,
        file_name,
        base_flags | rustix::fs::OFlags::CREATE | rustix::fs::OFlags::EXCL,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    ) {
        Ok(descriptor) => {
            let file = File::from(descriptor);
            // SQLite opens the path only after this helper returns. Persist both
            // the empty inode and its directory entry first so a power loss cannot
            // erase a freshly provisioned authority between those two steps.
            file.sync_all()?;
            parent.sync_all()?;
            Ok(file)
        }
        Err(error) if error == rustix::io::Errno::EXIST => {
            rustix::fs::openat(parent, file_name, base_flags, rustix::fs::Mode::empty())
                .map(File::from)
                .map_err(|open_error| DurableSqliteError::Io(open_error.into()))
        }
        Err(error) => Err(DurableSqliteError::Io(error.into())),
    }
}

#[cfg(unix)]
fn open_database_file_at_read_only(parent: &File, path: &Path) -> Result<File, DurableSqliteError> {
    let file_name = path.file_name().ok_or_else(|| {
        DurableSqliteError::Conflict("database path has no file name".to_string())
    })?;
    rustix::fs::openat(
        parent,
        file_name,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| DurableSqliteError::Io(error.into()))
}

#[cfg(unix)]
/// Validate sidecar authority without opening the sidecar inode. Closing any
/// descriptor for a POSIX-locked SQLite sidecar can release locks held by other
/// SQLite connections in this process. The retained private directory blocks
/// sidecar ACL principals from traversing to these stat-validated files.
pub(crate) fn validate_existing_sqlite_sidecars_at(
    parent: &File,
    database_file_name: &OsStr,
) -> Result<(), DurableSqliteError> {
    validate_trusted_parent_security(parent, rustix::process::geteuid().as_raw(), true)?;
    for suffix in SQLITE_AUTHORITY_SIDECAR_SUFFIXES {
        validate_existing_sqlite_sidecar_at(parent, database_file_name, suffix)?;
    }
    Ok(())
}

#[cfg(unix)]
fn validate_existing_sqlite_sidecar_at(
    parent: &File,
    database_file_name: &OsStr,
    suffix: &str,
) -> Result<(), DurableSqliteError> {
    let mut sidecar_name = database_file_name.to_os_string();
    sidecar_name.push(suffix);
    validate_existing_sqlite_sidecar_with_stat(suffix, || {
        rustix::fs::statat(parent, &sidecar_name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
    })
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SqliteSidecarSnapshotState {
    Linked,
    Unlinked,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SqliteSidecarIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
fn validate_existing_sqlite_sidecar_with_stat<F>(
    suffix: &str,
    mut stat: F,
) -> Result<(), DurableSqliteError>
where
    F: FnMut() -> Result<rustix::fs::Stat, rustix::io::Errno>,
{
    let first = match stat() {
        Ok(metadata) => metadata,
        Err(error) if error == rustix::io::Errno::NOENT => return Ok(()),
        Err(error) => return Err(sqlite_sidecar_inspection_error(suffix, error)),
    };
    match validate_sqlite_sidecar_snapshot(&first, suffix)? {
        SqliteSidecarSnapshotState::Linked => Ok(()),
        SqliteSidecarSnapshotState::Unlinked => {
            let replacement = match stat() {
                Ok(metadata) => metadata,
                Err(error) if error == rustix::io::Errno::NOENT => return Ok(()),
                Err(error) => return Err(sqlite_sidecar_inspection_error(suffix, error)),
            };
            match validate_sqlite_sidecar_snapshot(&replacement, suffix)? {
                SqliteSidecarSnapshotState::Linked => Ok(()),
                SqliteSidecarSnapshotState::Unlinked => Err(DurableSqliteError::Conflict(format!(
                    "SQLite {suffix} sidecar was still unlinked on reinspection"
                ))),
            }
        }
    }
}

#[cfg(unix)]
fn validate_sqlite_sidecar_snapshot(
    metadata: &rustix::fs::Stat,
    suffix: &str,
) -> Result<SqliteSidecarSnapshotState, DurableSqliteError> {
    if rustix::fs::FileType::from_raw_mode(metadata.st_mode) != rustix::fs::FileType::RegularFile {
        return Err(DurableSqliteError::Conflict(format!(
            "SQLite {suffix} sidecar must be a regular non-symlink file"
        )));
    }
    let effective_uid = rustix::process::geteuid().as_raw();
    if (metadata.st_uid != effective_uid && metadata.st_uid != 0)
        || metadata.st_mode & 0o077 != 0
        || metadata.st_nlink > 1
    {
        return Err(DurableSqliteError::Conflict(format!(
            "SQLite {suffix} sidecar must have trusted ownership, mode 0600 or stricter, and one hard link"
        )));
    }
    if metadata.st_nlink == 0 {
        Ok(SqliteSidecarSnapshotState::Unlinked)
    } else {
        Ok(SqliteSidecarSnapshotState::Linked)
    }
}

#[cfg(unix)]
fn sqlite_sidecar_inspection_error(suffix: &str, error: rustix::io::Errno) -> DurableSqliteError {
    DurableSqliteError::Conflict(format!(
        "SQLite {suffix} sidecar could not be inspected relative to the retained database directory: {error}"
    ))
}

#[cfg(unix)]
fn validate_trusted_parent_security(
    directory: &File,
    effective_uid: u32,
    final_authority_directory: bool,
) -> Result<(), DurableSqliteError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = directory.metadata()?;
    let trusted_owner = metadata.uid() == effective_uid || metadata.uid() == 0;
    let group_or_world_writable = metadata.mode() & 0o022 != 0;
    let sticky = metadata.mode() & 0o1000 != 0;
    let unsafe_ancestor_write = !final_authority_directory && group_or_world_writable && !sticky;
    let final_directory_not_private = final_authority_directory && metadata.mode() & 0o777 != 0o700;
    if !trusted_owner
        || unsafe_ancestor_write
        || final_directory_not_private
        || file_grants_extended_acl_authority(directory)?
    {
        return Err(DurableSqliteError::Conflict(
            "database ancestors must have trusted ownership and no untrusted write authority; \
             the final authority directory must have mode 0700 and no authority-granting ACL"
                .to_string(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_trusted_database_file(
    file: &File,
    metadata: &fs::Metadata,
) -> Result<(), DurableSqliteError> {
    use std::os::unix::fs::MetadataExt;

    let effective_uid = rustix::process::geteuid().as_raw();
    if (metadata.uid() != effective_uid && metadata.uid() != 0)
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
        || file_grants_extended_acl_authority(file)?
    {
        return Err(DurableSqliteError::Conflict(
            "database file must have trusted ownership, mode 0600 or stricter, no authority-granting ACL, and one hard link"
                .to_string(),
        ));
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn file_grants_extended_acl_authority(file: &File) -> Result<bool, DurableSqliteError> {
    for attribute in ["system.posix_acl_access", "system.posix_acl_default"] {
        let mut value = Vec::<u8>::with_capacity(1);
        match rustix::fs::fgetxattr(file, attribute, &mut value) {
            Ok(_) | Err(rustix::io::Errno::RANGE) => return Ok(true),
            Err(error) if error == rustix::io::Errno::NODATA => {}
            Err(error) if error == rustix::io::Errno::NOTSUP => {}
            Err(error) => return Err(DurableSqliteError::Io(error.into())),
        }
    }
    Ok(false)
}

#[cfg(target_vendor = "apple")]
fn file_grants_extended_acl_authority(file: &File) -> Result<bool, DurableSqliteError> {
    chio_keyring::darwin_descriptor_grants_extended_acl_authority(file).map_err(|error| {
        DurableSqliteError::Conflict(format!("database ACL inspection failed: {error}"))
    })
}

#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android", target_vendor = "apple"))
))]
fn file_grants_extended_acl_authority(_file: &File) -> Result<bool, DurableSqliteError> {
    Err(DurableSqliteError::Conflict(
        "database ACL inspection is unsupported on this platform".to_string(),
    ))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    const WAL_LOCK_PROBE_PATH_ENV: &str = "CHIO_DURABLE_SQLITE_WAL_LOCK_PROBE_PATH";

    fn trusted_database(
        temporary: &tempfile::TempDir,
        name: &str,
    ) -> (PathBuf, Arc<DurableSqliteFile>) {
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
            .expect("restrict trusted database directory");
        let path = temporary.path().join(name);
        let directory = TrustedSqliteDirectory::open_for_database(&path)
            .expect("retain trusted database directory");
        let database = directory
            .open_database(&path, true)
            .expect("provision trusted database");
        (path, database)
    }

    fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        PathBuf::from(sidecar)
    }

    fn run_external_wal_lock_probe(path: &Path) -> std::process::Output {
        std::process::Command::new(std::env::current_exe().expect("locate current test binary"))
            .arg("durable_sqlite::tests::wal_lock_probe_child")
            .arg("--exact")
            .arg("--nocapture")
            .env(WAL_LOCK_PROBE_PATH_ENV, path)
            .output()
            .expect("run external WAL lock probe")
    }

    #[test]
    fn wal_lock_probe_child() {
        let Some(path) = std::env::var_os(WAL_LOCK_PROBE_PATH_ENV) else {
            return;
        };
        let connection = Connection::open(PathBuf::from(path)).expect("open WAL probe database");
        connection
            .busy_timeout(std::time::Duration::ZERO)
            .expect("configure WAL probe timeout");
        let committed_rows: i64 = connection
            .query_row("SELECT COUNT(*) FROM authority_state", [], |row| row.get(0))
            .expect("read committed WAL state");
        assert_eq!(committed_rows, 1);
        match connection.execute("INSERT INTO authority_state (id) VALUES (3)", []) {
            Ok(_) => panic!("external WAL writer bypassed the retained write lock"),
            Err(error)
                if matches!(
                    error.sqlite_error_code(),
                    Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
                ) => {}
            Err(error) => panic!("external WAL writer failed for an unexpected reason: {error}"),
        }
    }

    #[test]
    fn exclusive_database_provisioning_falls_back_to_the_same_validated_inode() {
        let temporary = tempfile::tempdir().expect("create trusted database directory");
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
            .expect("restrict trusted database directory");
        let path = temporary.path().join("authority.sqlite");
        let directory = TrustedSqliteDirectory::open_for_database(&path)
            .expect("retain trusted database directory");

        let created = directory
            .open_database(&path, true)
            .expect("provision database file exclusively");
        let created_metadata = created.file.metadata().expect("read created file identity");
        assert_eq!(created_metadata.mode() & 0o077, 0);
        assert_eq!(created_metadata.nlink(), 1);

        let existing = directory
            .open_database(&path, true)
            .expect("open the safely existing database file");
        let existing_metadata = existing
            .file
            .metadata()
            .expect("read existing file identity");
        assert_eq!(created_metadata.dev(), existing_metadata.dev());
        assert_eq!(created_metadata.ino(), existing_metadata.ino());
        created
            .validate()
            .expect("created descriptor remains bound");
        existing
            .validate()
            .expect("fallback descriptor remains bound");
    }

    #[test]
    fn durable_sqlite_requires_a_private_final_authority_directory() {
        let temporary = tempfile::tempdir().expect("create database directory");
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o750))
            .expect("make database directory group-traversable");
        let path = temporary.path().join("authority.sqlite");

        let error = TrustedSqliteDirectory::open_for_database(&path)
            .expect_err("accepted a non-private final authority directory");
        assert!(error.to_string().contains("mode 0700"));
    }

    #[test]
    fn existing_sqlite_sidecars_must_be_private_regular_single_link_files() {
        for suffix in ["-wal", "-shm", "-journal"] {
            let temporary = tempfile::tempdir().expect("create trusted database directory");
            let (path, database) = trusted_database(&temporary, "symlink.sqlite");
            let target = temporary.path().join("symlink-target");
            fs::write(&target, b"untrusted sidecar target").expect("write symlink target");
            fs::set_permissions(&target, fs::Permissions::from_mode(0o600))
                .expect("restrict symlink target");
            symlink(&target, sidecar_path(&path, suffix)).expect("create sidecar symlink");
            assert!(database.validate().is_err(), "accepted {suffix} symlink");

            let temporary = tempfile::tempdir().expect("create trusted database directory");
            let (path, database) = trusted_database(&temporary, "hardlink.sqlite");
            let target = temporary.path().join("hardlink-target");
            fs::write(&target, b"untrusted sidecar target").expect("write hardlink target");
            fs::set_permissions(&target, fs::Permissions::from_mode(0o600))
                .expect("restrict hardlink target");
            fs::hard_link(&target, sidecar_path(&path, suffix)).expect("create sidecar hardlink");
            assert!(database.validate().is_err(), "accepted {suffix} hardlink");

            let temporary = tempfile::tempdir().expect("create trusted database directory");
            let (path, database) = trusted_database(&temporary, "mode.sqlite");
            let sidecar = sidecar_path(&path, suffix);
            fs::write(&sidecar, b"untrusted sidecar mode").expect("write permissive sidecar");
            fs::set_permissions(&sidecar, fs::Permissions::from_mode(0o640))
                .expect("make sidecar group-readable");
            assert!(
                database.validate().is_err(),
                "accepted permissive {suffix} mode"
            );

            let temporary = tempfile::tempdir().expect("create trusted database directory");
            let (path, database) = trusted_database(&temporary, "nonregular.sqlite");
            fs::create_dir(sidecar_path(&path, suffix)).expect("create sidecar directory");
            assert!(
                database.validate().is_err(),
                "accepted non-regular {suffix}"
            );
        }
    }

    #[test]
    fn unlinked_sidecar_snapshot_gets_one_strict_reinspection() {
        let temporary = tempfile::tempdir().expect("create trusted database directory");
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
            .expect("restrict trusted database directory");
        let parent = File::open(temporary.path()).expect("open trusted database directory");
        let sidecar_name = OsStr::new("authority.sqlite-wal");
        let sidecar_path = temporary.path().join(sidecar_name);
        fs::write(&sidecar_path, b"retiring WAL").expect("write retiring WAL");
        fs::set_permissions(&sidecar_path, fs::Permissions::from_mode(0o600))
            .expect("restrict retiring WAL");
        let retiring = File::open(&sidecar_path).expect("retain retiring WAL");
        fs::remove_file(&sidecar_path).expect("unlink retiring WAL");
        let retired_snapshot = rustix::fs::fstat(&retiring).expect("inspect retiring WAL");
        assert_eq!(retired_snapshot.st_nlink, 0);

        let mut absent_calls = 0_u8;
        validate_existing_sqlite_sidecar_with_stat("-wal", || {
            absent_calls += 1;
            if absent_calls == 1 {
                rustix::fs::fstat(&retiring)
            } else {
                rustix::fs::statat(&parent, sidecar_name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
            }
        })
        .expect("accept a retired sidecar whose name is now absent");
        assert_eq!(absent_calls, 2);

        fs::write(&sidecar_path, b"replacement WAL").expect("write replacement WAL");
        fs::set_permissions(&sidecar_path, fs::Permissions::from_mode(0o600))
            .expect("restrict replacement WAL");
        let mut replacement_calls = 0_u8;
        validate_existing_sqlite_sidecar_with_stat("-wal", || {
            replacement_calls += 1;
            if replacement_calls == 1 {
                rustix::fs::fstat(&retiring)
            } else {
                rustix::fs::statat(&parent, sidecar_name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
            }
        })
        .expect("accept an independently valid replacement sidecar");
        assert_eq!(replacement_calls, 2);

        fs::remove_file(&sidecar_path).expect("remove valid replacement WAL");
        let hardlink_target = temporary.path().join("hardlink-target");
        fs::write(&hardlink_target, b"hard-linked WAL").expect("write hard-link target");
        fs::set_permissions(&hardlink_target, fs::Permissions::from_mode(0o600))
            .expect("restrict hard-link target");
        fs::hard_link(&hardlink_target, &sidecar_path).expect("install hard-linked replacement");
        let mut hardlink_calls = 0_u8;
        let hardlink_error = validate_existing_sqlite_sidecar_with_stat("-wal", || {
            hardlink_calls += 1;
            if hardlink_calls == 1 {
                rustix::fs::fstat(&retiring)
            } else {
                rustix::fs::statat(&parent, sidecar_name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
            }
        })
        .expect_err("accepted a hard-linked replacement sidecar");
        assert!(hardlink_error.to_string().contains("one hard link"));
        assert_eq!(hardlink_calls, 2);

        let mut repeated_unlink_calls = 0_u8;
        let repeated_unlink_error = validate_existing_sqlite_sidecar_with_stat("-wal", || {
            repeated_unlink_calls += 1;
            rustix::fs::fstat(&retiring)
        })
        .expect_err("accepted two consecutive unlinked sidecar snapshots");
        assert!(repeated_unlink_error.to_string().contains("still unlinked"));
        assert_eq!(repeated_unlink_calls, 2);

        let mut inspection_error_calls = 0_u8;
        let inspection_error = validate_existing_sqlite_sidecar_with_stat("-wal", || {
            inspection_error_calls += 1;
            if inspection_error_calls == 1 {
                rustix::fs::fstat(&retiring)
            } else {
                Err(rustix::io::Errno::IO)
            }
        })
        .expect_err("accepted a failed sidecar reinspection");
        assert!(inspection_error
            .to_string()
            .contains("could not be inspected"));
        assert_eq!(inspection_error_calls, 2);

        let hardlinked = File::open(&sidecar_path).expect("open hard-linked replacement");
        let mut first_hardlink_calls = 0_u8;
        validate_existing_sqlite_sidecar_with_stat("-wal", || {
            first_hardlink_calls += 1;
            rustix::fs::fstat(&hardlinked)
        })
        .expect_err("retried a first hard-linked sidecar snapshot");
        assert_eq!(first_hardlink_calls, 1);
    }

    #[test]
    fn private_regular_sqlite_sidecars_are_accepted() {
        let temporary = tempfile::tempdir().expect("create trusted database directory");
        let (path, database) = trusted_database(&temporary, "private.sqlite");
        for suffix in ["-wal", "-shm", "-journal"] {
            let sidecar = sidecar_path(&path, suffix);
            fs::write(&sidecar, b"trusted sidecar").expect("write trusted sidecar");
            fs::set_permissions(&sidecar, fs::Permissions::from_mode(0o600))
                .expect("restrict trusted sidecar");
        }

        database
            .validate()
            .expect("private regular sidecars satisfy the authority policy");
    }

    #[test]
    fn live_sqlite_sidecars_are_revalidated_before_connection_use() {
        let temporary = tempfile::tempdir().expect("create trusted database directory");
        let (path, database) = trusted_database(&temporary, "live.sqlite");
        let connection = database
            .open_connection(OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX)
            .expect("open trusted database connection");
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL; CREATE TABLE authority_state (id INTEGER PRIMARY KEY); INSERT INTO authority_state (id) VALUES (1);",
            )
            .expect("configure WAL database");
        let wal = sidecar_path(&path, "-wal");
        assert!(wal.exists(), "WAL configuration did not create its sidecar");
        fs::set_permissions(&wal, fs::Permissions::from_mode(0o640))
            .expect("make live WAL sidecar group-readable");

        assert!(
            database.validate_live_connection(&connection).is_err(),
            "accepted a live WAL sidecar after its authority widened"
        );
    }

    #[test]
    fn sidecar_validation_preserves_a_live_wal_writer_lock() {
        let temporary = tempfile::tempdir().expect("create trusted database directory");
        let (path, database) = trusted_database(&temporary, "wal-lock.sqlite");
        let connection = database
            .open_connection(OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX)
            .expect("open trusted database connection");
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL; \
                 CREATE TABLE authority_state (id INTEGER PRIMARY KEY); \
                 INSERT INTO authority_state (id) VALUES (1); \
                 BEGIN IMMEDIATE; \
                 INSERT INTO authority_state (id) VALUES (2)",
            )
            .expect("hold a live WAL write transaction");

        let baseline = run_external_wal_lock_probe(&path);
        assert!(
            baseline.status.success(),
            "WAL lock baseline probe failed: {}{}",
            String::from_utf8_lossy(&baseline.stdout),
            String::from_utf8_lossy(&baseline.stderr)
        );
        database
            .validate_live_connection(&connection)
            .expect("validate live WAL authority without opening its sidecars");
        let after_validation = run_external_wal_lock_probe(&path);
        connection
            .execute_batch("ROLLBACK")
            .expect("release parent WAL write transaction");
        assert!(
            after_validation.status.success(),
            "sidecar validation released the live WAL lock: {}{}",
            String::from_utf8_lossy(&after_validation.stdout),
            String::from_utf8_lossy(&after_validation.stderr)
        );
    }
}
