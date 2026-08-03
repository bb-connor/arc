use std::collections::{HashMap, HashSet};
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;
#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(test)]
use chio_core::capability::token::CapabilityToken;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use tracing::warn;

use super::{
    session_now_millis, validate_resume_record_integrity_with_keyring,
    validate_terminal_fence_integrity, validate_terminal_tombstone_integrity, CliError,
    RemoteSessionDiagnosticRecord, RemoteSessionHmacKeyring, RemoteSessionResumeRecord,
    RemoteSessionTerminalFence, RemoteSessionTombstoneRecord,
};

pub(super) const SESSION_ACTIVE_TABLE: &str = "remote_active_sessions";
pub(super) const SESSION_TOMBSTONE_TABLE: &str = "remote_session_tombstones";
pub(super) const SESSION_TERMINAL_FENCE_TABLE: &str = "remote_session_terminal_fences";

#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(super) struct RemoteSessionStoreLifecycleLease {
    parent_path: PathBuf,
    parent: std::fs::File,
    file_name: std::ffi::OsString,
    file: std::fs::File,
    path: PathBuf,
    parent_device: u64,
    parent_inode: u64,
    device: u64,
    inode: u64,
    acquisition_pid: rustix::process::Pid,
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
struct RegisteredSessionStoreLease {
    parent_path: PathBuf,
    parent_descriptor: std::os::fd::RawFd,
    file_descriptor: std::os::fd::RawFd,
    file_name: std::ffi::OsString,
    parent_device: u64,
    parent_inode: u64,
    device: u64,
    inode: u64,
}

#[cfg(target_os = "linux")]
fn process_session_store_leases(
) -> &'static std::sync::Mutex<HashMap<(u64, u64), RegisteredSessionStoreLease>> {
    static LEASES: std::sync::OnceLock<
        std::sync::Mutex<HashMap<(u64, u64), RegisteredSessionStoreLease>>,
    > = std::sync::OnceLock::new();
    LEASES.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

#[cfg(target_os = "linux")]
pub(super) fn canonical_session_database_path(path: &FsPath) -> Result<PathBuf, CliError> {
    let file_name = path.file_name().ok_or_else(|| {
        CliError::cli_other_error(format!(
            "remote MCP session database path {} has no file name",
            path.display()
        ))
    })?;
    let parent = path.parent().unwrap_or_else(|| FsPath::new("."));
    let canonical_parent = std::fs::canonicalize(parent).map_err(|error| {
        CliError::cli_other_error(format!(
            "canonicalize remote MCP session database parent {}: {error}",
            parent.display()
        ))
    })?;
    validate_trusted_session_database_ancestors(&canonical_parent)?;
    Ok(canonical_parent.join(file_name))
}

#[cfg(not(target_os = "linux"))]
pub(super) fn canonical_session_database_path(path: &FsPath) -> Result<PathBuf, CliError> {
    Err(CliError::cli_other_error(format!(
        "remote MCP session database {} requires Linux retained-dirfd pathname custody",
        path.display()
    )))
}

#[cfg(target_os = "linux")]
impl RemoteSessionStoreLifecycleLease {
    pub(super) fn acquire(path: &FsPath) -> Result<Self, CliError> {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::MetadataExt as _;

        let path = canonical_session_database_path(path)?;
        let parent_path = path
            .parent()
            .ok_or_else(|| {
                CliError::cli_other_error(
                    "remote MCP session database path has no parent".to_string(),
                )
            })?
            .to_path_buf();
        let file_name = path
            .file_name()
            .ok_or_else(|| {
                CliError::cli_other_error(
                    "remote MCP session database path has no file name".to_string(),
                )
            })?
            .to_os_string();
        let parent = open_trusted_session_database_directory_chain(&parent_path)?;
        validate_session_database_auxiliary_files_at(&parent, &file_name)?;
        let file = open_session_database_file_at(&parent, &file_name, true).map_err(|error| {
            CliError::cli_other_error(format!(
                "open remote MCP session database {} for exclusive ownership: {error}",
                path.display()
            ))
        })?;
        let metadata = file.metadata().map_err(|error| {
            CliError::cli_other_error(format!(
                "inspect remote MCP session database {}: {error}",
                path.display()
            ))
        })?;
        validate_session_database_file_metadata(&metadata)?;
        let parent_metadata = parent.metadata().map_err(|error| {
            CliError::cli_other_error(format!(
                "inspect remote MCP session database parent {}: {error}",
                parent_path.display()
            ))
        })?;
        rustix::fs::flock(
            &file,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "remote MCP session database {} is already owned by another server instance: {error}",
                path.display()
            ))
        })?;
        let device = metadata.dev();
        let inode = metadata.ino();
        let mut leases = process_session_store_leases().lock().map_err(|_| {
            CliError::cli_other_error(
                "remote MCP session database ownership registry is unavailable".to_string(),
            )
        })?;
        if leases.contains_key(&(device, inode)) {
            return Err(CliError::cli_other_error(format!(
                "remote MCP session database {} is already owned by another server instance in this process",
                path.display()
            )));
        }
        leases.insert(
            (device, inode),
            RegisteredSessionStoreLease {
                parent_path: parent_path.clone(),
                parent_descriptor: parent.as_raw_fd(),
                file_descriptor: file.as_raw_fd(),
                file_name: file_name.clone(),
                parent_device: parent_metadata.dev(),
                parent_inode: parent_metadata.ino(),
                device,
                inode,
            },
        );
        drop(leases);
        let lease = Self {
            parent_path,
            parent,
            file_name,
            file,
            path,
            parent_device: parent_metadata.dev(),
            parent_inode: parent_metadata.ino(),
            device,
            inode,
            acquisition_pid: rustix::process::getpid(),
        };
        lease.ensure_owned()?;
        Ok(lease)
    }

    pub(super) fn ensure_owned(&self) -> Result<(), CliError> {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::MetadataExt as _;

        if self.acquisition_pid != rustix::process::getpid() {
            return Err(CliError::cli_other_error(format!(
                "remote MCP session database {} lease was inherited across a process boundary",
                self.path.display()
            )));
        }
        rustix::fs::flock(
            &self.file,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "remote MCP session database {} ownership was lost: {error}",
                self.path.display()
            ))
        })?;
        let current_parent = open_trusted_session_database_directory_chain(&self.parent_path)?;
        let current_parent_metadata = current_parent.metadata().map_err(|error| {
            CliError::cli_other_error(format!(
                "inspect current remote MCP session database parent {}: {error}",
                self.parent_path.display()
            ))
        })?;
        let retained_parent_metadata = self.parent.metadata().map_err(|error| {
            CliError::cli_other_error(format!(
                "inspect retained remote MCP session database parent {}: {error}",
                self.parent_path.display()
            ))
        })?;
        let path_file = open_session_database_file_at(&self.parent, &self.file_name, false)?;
        let path_metadata = path_file.metadata().map_err(|error| {
            CliError::cli_other_error(format!(
                "inspect current remote MCP session database {}: {error}",
                self.path.display()
            ))
        })?;
        let metadata = self.file.metadata().map_err(|error| {
            CliError::cli_other_error(format!(
                "inspect retained remote MCP session database {}: {error}",
                self.path.display()
            ))
        })?;
        validate_session_database_file_metadata(&path_metadata)?;
        validate_session_database_file_metadata(&metadata)?;
        if metadata.dev() != self.device || metadata.ino() != self.inode {
            return Err(CliError::cli_other_error(format!(
                "remote MCP session database {} changed identity after ownership acquisition",
                self.path.display()
            )));
        }
        if current_parent_metadata.dev() != self.parent_device
            || current_parent_metadata.ino() != self.parent_inode
            || retained_parent_metadata.dev() != self.parent_device
            || retained_parent_metadata.ino() != self.parent_inode
            || path_metadata.dev() != self.device
            || path_metadata.ino() != self.inode
        {
            return Err(CliError::cli_other_error(format!(
                "remote MCP session database {} or its parent changed identity after ownership acquisition",
                self.path.display()
            )));
        }
        let registered_descriptor = process_session_store_leases()
            .lock()
            .map_err(|_| {
                CliError::cli_other_error(
                    "remote MCP session database ownership registry is unavailable".to_string(),
                )
            })?
            .get(&(self.device, self.inode))
            .cloned();
        if registered_descriptor
            .as_ref()
            .map(|lease| lease.file_descriptor)
            != Some(self.file.as_raw_fd())
        {
            return Err(CliError::cli_other_error(format!(
                "remote MCP session database {} no longer owns its registered lifecycle lease",
                self.path.display()
            )));
        }
        validate_session_database_auxiliary_files_at(&self.parent, &self.file_name)?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for RemoteSessionStoreLifecycleLease {
    fn drop(&mut self) {
        if let Ok(mut leases) = process_session_store_leases().lock() {
            leases.remove(&(self.device, self.inode));
        }
    }
}

#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
pub(super) struct RemoteSessionStoreLifecycleLease;

#[cfg(not(target_os = "linux"))]
impl RemoteSessionStoreLifecycleLease {
    pub(super) fn acquire(path: &FsPath) -> Result<Self, CliError> {
        Err(CliError::cli_other_error(format!(
            "remote MCP session database {} requires Linux retained-dirfd lifecycle custody",
            path.display()
        )))
    }

    pub(super) fn ensure_owned(&self) -> Result<(), CliError> {
        Err(CliError::cli_other_error(
            "remote MCP session database lifecycle leases are unavailable on this platform"
                .to_string(),
        ))
    }
}

#[cfg(target_os = "linux")]
fn validate_session_database_file_metadata(metadata: &std::fs::Metadata) -> Result<(), CliError> {
    use std::os::unix::fs::MetadataExt as _;

    let effective_uid = rustix::process::geteuid().as_raw();
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
        || (metadata.uid() != effective_uid && metadata.uid() != 0)
    {
        return Err(CliError::cli_other_error(
            "remote MCP session database must be a private regular file with trusted ownership, mode 0600 or stricter, and one hard link"
                .to_string(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_trusted_session_database_ancestors(directory: &FsPath) -> Result<(), CliError> {
    use std::os::unix::fs::MetadataExt as _;

    let effective_uid = rustix::process::geteuid().as_raw();
    for ancestor in directory.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor).map_err(|error| {
            CliError::cli_other_error(format!(
                "inspect remote MCP session database ancestor {}: {error}",
                ancestor.display()
            ))
        })?;
        let mode = metadata.mode();
        let writable_by_others = mode & 0o022 != 0;
        let root_sticky_directory = metadata.uid() == 0 && mode & 0o1000 != 0;
        if metadata.file_type().is_symlink()
            || !metadata.file_type().is_dir()
            || (metadata.uid() != effective_uid && metadata.uid() != 0)
            || (writable_by_others && !root_sticky_directory)
        {
            return Err(CliError::cli_other_error(format!(
                "remote MCP session database ancestor {} is not a trusted directory",
                ancestor.display()
            )));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_trusted_session_database_directory_chain(
    parent_path: &FsPath,
) -> Result<std::fs::File, CliError> {
    let mut names = Vec::new();
    for component in parent_path.components() {
        match component {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(name) => names.push(name.to_os_string()),
            std::path::Component::Prefix(_)
            | std::path::Component::CurDir
            | std::path::Component::ParentDir => {
                return Err(CliError::cli_other_error(
                    "remote MCP session database path contains an unsupported component"
                        .to_string(),
                ));
            }
        }
    }
    let root = rustix::fs::open(
        "/",
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "open remote MCP session database root directory: {error}"
        ))
    })?;
    let mut directory = std::fs::File::from(root);
    validate_session_database_directory_descriptor(&directory, !names.is_empty())?;
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
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "open remote MCP session database ancestor: {error}"
            ))
        })?;
        let next = std::fs::File::from(descriptor);
        validate_session_database_directory_descriptor(&next, index + 1 != name_count)?;
        directory = next;
    }
    Ok(directory)
}

#[cfg(target_os = "linux")]
fn validate_session_database_directory_descriptor(
    directory: &std::fs::File,
    allow_root_sticky_write: bool,
) -> Result<(), CliError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = directory.metadata().map_err(|error| {
        CliError::cli_other_error(format!(
            "inspect remote MCP session database ancestor descriptor: {error}"
        ))
    })?;
    let effective_uid = rustix::process::geteuid().as_raw();
    let writable = metadata.mode() & 0o022 != 0;
    let root_sticky = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
    if !metadata.file_type().is_dir()
        || (metadata.uid() != effective_uid && metadata.uid() != 0)
        || (writable && !(allow_root_sticky_write && root_sticky))
    {
        return Err(CliError::cli_other_error(
            "remote MCP session database ancestor chain grants untrusted write authority"
                .to_string(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_session_database_file_at(
    parent: &std::fs::File,
    file_name: &std::ffi::OsStr,
    create: bool,
) -> Result<std::fs::File, CliError> {
    let mut flags =
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW;
    if create {
        flags |= rustix::fs::OFlags::CREATE;
    }
    rustix::fs::openat(
        parent,
        file_name,
        flags,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .map(std::fs::File::from)
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "open retained remote MCP session database entry: {error}"
        ))
    })
}

#[cfg(target_os = "linux")]
fn require_active_session_store_lease(
    path: &FsPath,
) -> Result<RegisteredSessionStoreLease, CliError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        CliError::cli_other_error(format!(
            "inspect leased remote MCP session database {}: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(CliError::cli_other_error(format!(
            "remote MCP session database {} is not a regular non-symlink file",
            path.display()
        )));
    }
    let lease = process_session_store_leases()
        .lock()
        .map_err(|_| {
            CliError::cli_other_error(
                "remote MCP session database ownership registry is unavailable".to_string(),
            )
        })?
        .get(&(metadata.dev(), metadata.ino()))
        .cloned()
        .ok_or_else(|| {
            CliError::cli_other_error(format!(
                "remote MCP session database {} has no active process-lifetime ownership lease",
                path.display()
            ))
        })?;
    if lease.device != metadata.dev() || lease.inode != metadata.ino() {
        return Err(CliError::cli_other_error(format!(
            "remote MCP session database {} changed identity after lease lookup",
            path.display()
        )));
    }
    let current_parent = open_trusted_session_database_directory_chain(&lease.parent_path)?;
    let current_parent_metadata = current_parent.metadata().map_err(|error| {
        CliError::cli_other_error(format!(
            "inspect current remote MCP session database parent {}: {error}",
            lease.parent_path.display()
        ))
    })?;
    if current_parent_metadata.dev() != lease.parent_device
        || current_parent_metadata.ino() != lease.parent_inode
    {
        return Err(CliError::cli_other_error(format!(
            "remote MCP session database parent {} changed identity after lease acquisition",
            lease.parent_path.display()
        )));
    }
    let retained_parent_path = PathBuf::from(format!("/proc/self/fd/{}", lease.parent_descriptor));
    let retained_file_path = PathBuf::from(format!("/proc/self/fd/{}", lease.file_descriptor));
    let retained_parent_metadata = std::fs::metadata(&retained_parent_path).map_err(|error| {
        CliError::cli_other_error(format!(
            "inspect retained remote MCP session database parent descriptor: {error}"
        ))
    })?;
    let retained_file_metadata = std::fs::metadata(&retained_file_path).map_err(|error| {
        CliError::cli_other_error(format!(
            "inspect retained remote MCP session database file descriptor: {error}"
        ))
    })?;
    if retained_parent_metadata.dev() != lease.parent_device
        || retained_parent_metadata.ino() != lease.parent_inode
        || retained_file_metadata.dev() != lease.device
        || retained_file_metadata.ino() != lease.inode
    {
        return Err(CliError::cli_other_error(
            "remote MCP session database retained descriptors changed identity".to_string(),
        ));
    }
    validate_session_database_file_metadata(&metadata)?;
    validate_session_database_file_metadata(&retained_file_metadata)?;
    validate_session_database_auxiliary_files_registered(&lease)?;
    Ok(lease)
}

#[cfg(target_os = "linux")]
fn anchored_session_database_path(
    lease: &RegisteredSessionStoreLease,
    suffix: Option<&str>,
) -> PathBuf {
    let mut path = PathBuf::from("/proc/self/fd");
    path.push(lease.parent_descriptor.to_string());
    let mut file_name = lease.file_name.clone();
    if let Some(suffix) = suffix {
        file_name.push(suffix);
    }
    path.push(file_name);
    path
}

#[cfg(target_os = "linux")]
fn validate_session_database_auxiliary_files_registered(
    lease: &RegisteredSessionStoreLease,
) -> Result<(), CliError> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let auxiliary = anchored_session_database_path(lease, Some(suffix));
        let metadata = match std::fs::symlink_metadata(&auxiliary) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(CliError::cli_other_error(format!(
                    "inspect remote MCP session database auxiliary file {}: {error}",
                    auxiliary.display()
                )));
            }
        };
        if metadata.file_type().is_symlink() {
            return Err(CliError::cli_other_error(format!(
                "remote MCP session database auxiliary file {} is not private",
                auxiliary.display()
            )));
        }
        validate_session_database_file_metadata(&metadata)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_session_database_auxiliary_files_at(
    parent: &std::fs::File,
    file_name: &std::ffi::OsStr,
) -> Result<(), CliError> {
    use std::os::fd::AsRawFd as _;

    let lease = RegisteredSessionStoreLease {
        parent_path: PathBuf::new(),
        parent_descriptor: parent.as_raw_fd(),
        file_descriptor: -1,
        file_name: file_name.to_os_string(),
        parent_device: 0,
        parent_inode: 0,
        device: 0,
        inode: 0,
    };
    validate_session_database_auxiliary_files_registered(&lease)
}

pub(super) struct LoadedActiveSessionRecords {
    pub(super) records: Vec<RemoteSessionResumeRecord>,
    pub(super) invalid_session_ids: Vec<String>,
}

struct LoadedTerminalState {
    blocked_session_ids: HashSet<String>,
    tombstones: HashMap<String, RemoteSessionTombstoneRecord>,
    fences: HashMap<String, RemoteSessionTerminalFence>,
}

#[cfg(target_os = "linux")]
pub(super) fn open_session_state_db(path: &FsPath) -> Result<Connection, CliError> {
    use std::os::unix::fs::MetadataExt as _;

    let proc_descriptors = std::fs::metadata("/proc/self/fd").map_err(|error| {
        CliError::cli_other_error(format!(
            "remote MCP session database custody requires /proc/self/fd: {error}"
        ))
    })?;
    if !proc_descriptors.is_dir() {
        return Err(CliError::cli_other_error(
            "remote MCP session database custody requires mounted /proc/self/fd".to_string(),
        ));
    }
    let canonical_path = canonical_session_database_path(path)?;
    let lease = require_active_session_store_lease(&canonical_path)?;
    let anchored_path = anchored_session_database_path(&lease, None);
    let conn = Connection::open_with_flags(
        &anchored_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
            | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let sqlite_path = conn
        .query_row("PRAGMA database_list", [], |row| row.get::<_, String>(2))
        .map(PathBuf::from)?;
    let sqlite_metadata = std::fs::metadata(&sqlite_path).map_err(|error| {
        CliError::cli_other_error(format!(
            "inspect SQLite remote MCP session database identity {}: {error}",
            sqlite_path.display()
        ))
    })?;
    if sqlite_metadata.dev() != lease.device || sqlite_metadata.ino() != lease.inode {
        return Err(CliError::cli_other_error(format!(
            "SQLite opened a different remote MCP session database identity for {}",
            canonical_path.display()
        )));
    }
    let journal_mode = conn.query_row("PRAGMA journal_mode=DELETE", [], |row| {
        row.get::<_, String>(0)
    })?;
    if !journal_mode.eq_ignore_ascii_case("delete") {
        return Err(CliError::cli_other_error(format!(
            "remote MCP session database refused DELETE journal mode and remained in {journal_mode} mode"
        )));
    }
    conn.execute_batch("PRAGMA synchronous=FULL;")?;
    let synchronous = conn.query_row("PRAGMA synchronous", [], |row| row.get::<_, i64>(0))?;
    if synchronous != 2 {
        return Err(CliError::cli_other_error(format!(
            "remote MCP session database refused FULL synchronous mode and reported {synchronous}"
        )));
    }
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {active_table} (
            session_id TEXT PRIMARY KEY NOT NULL,
            updated_at INTEGER NOT NULL,
            record_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS {tombstone_table} (
            session_id TEXT PRIMARY KEY NOT NULL,
            terminal_at INTEGER NOT NULL,
            record_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS {fence_table} (
            session_id TEXT PRIMARY KEY NOT NULL,
            terminal_at INTEGER NOT NULL,
            terminal_epoch INTEGER NOT NULL,
            record_json TEXT NOT NULL
        );",
        active_table = SESSION_ACTIVE_TABLE,
        tombstone_table = SESSION_TOMBSTONE_TABLE,
        fence_table = SESSION_TERMINAL_FENCE_TABLE,
    ))?;
    let observed = require_active_session_store_lease(&canonical_path)?;
    if observed.parent_descriptor != lease.parent_descriptor
        || observed.file_descriptor != lease.file_descriptor
        || observed.parent_device != lease.parent_device
        || observed.parent_inode != lease.parent_inode
        || observed.device != lease.device
        || observed.inode != lease.inode
        || observed.file_name != lease.file_name
    {
        return Err(CliError::cli_other_error(format!(
            "remote MCP session database {} changed retained binding while SQLite was active",
            canonical_path.display()
        )));
    }
    validate_session_database_auxiliary_files_registered(&lease)?;
    Ok(conn)
}

#[cfg(not(target_os = "linux"))]
pub(super) fn open_session_state_db(path: &FsPath) -> Result<Connection, CliError> {
    Err(CliError::cli_other_error(format!(
        "persistent remote MCP session database {} is unsupported without Linux retained-dirfd custody",
        path.display()
    )))
}

pub(super) fn load_active_session_records(
    path: &FsPath,
    keyring: &RemoteSessionHmacKeyring,
) -> Result<LoadedActiveSessionRecords, CliError> {
    load_active_session_records_at(path, keyring, session_now_millis())
}

fn load_active_session_records_at(
    path: &FsPath,
    keyring: &RemoteSessionHmacKeyring,
    now: u64,
) -> Result<LoadedActiveSessionRecords, CliError> {
    let conn = open_session_state_db(path)?;
    let terminal_state = load_terminal_state(&conn, keyring, now)?;
    let mut stmt = conn.prepare(&format!(
        "SELECT session_id, record_json FROM {table}",
        table = SESSION_ACTIVE_TABLE,
    ))?;
    let mut rows = stmt.query([])?;
    let mut records = Vec::new();
    let mut invalid_session_ids = Vec::new();

    while let Some(row) = rows.next()? {
        let session_id: String = row.get(0)?;
        let record_json: String = row.get(1)?;
        if terminal_state.blocked_session_ids.contains(&session_id) {
            let terminal_generation = terminal_state
                .fences
                .get(&session_id)
                .map(|fence| fence.resume_generation)
                .or_else(|| {
                    terminal_state
                        .tombstones
                        .get(&session_id)
                        .map(|tombstone| tombstone.resume_generation)
                });
            warn!(
                session_id = %session_id,
                terminal_generation = ?terminal_generation,
                "dropping persisted MCP active session row because retained terminal state blocks replay"
            );
            invalid_session_ids.push(session_id);
            continue;
        }
        match serde_json::from_str::<RemoteSessionResumeRecord>(&record_json) {
            Ok(record) if record.session_id == session_id => {
                match validate_resume_record_integrity_with_keyring(keyring, &record, now) {
                    Ok(()) => records.push(record),
                    Err(error) => {
                        warn!(
                            session_id = %session_id,
                            error = %error,
                            "dropping persisted MCP session row with invalid authenticated state"
                        );
                        invalid_session_ids.push(session_id);
                    }
                }
            }
            Ok(record) => {
                warn!(
                    session_id = %session_id,
                    record_session_id = %record.session_id,
                    "dropping persisted MCP session row whose primary key does not match the stored session payload"
                );
                invalid_session_ids.push(session_id);
            }
            Err(error) => {
                warn!(
                    session_id = %session_id,
                    error = %error,
                    "dropping malformed persisted MCP session row"
                );
                invalid_session_ids.push(session_id);
            }
        }
    }

    Ok(LoadedActiveSessionRecords {
        records,
        invalid_session_ids,
    })
}

pub(super) fn load_terminal_session_records(
    path: &FsPath,
    keyring: &RemoteSessionHmacKeyring,
) -> Result<HashMap<String, Arc<RemoteSessionDiagnosticRecord>>, CliError> {
    let conn = open_session_state_db(path)?;
    let terminal_state = load_terminal_state(&conn, keyring, session_now_millis())?;
    let mut records = HashMap::new();
    for (session_id, tombstone) in terminal_state.tombstones {
        let Some(fence) = terminal_state.fences.get(&session_id) else {
            warn!(
                session_id = %session_id,
                "dropping terminal MCP session tombstone without an authenticated generation fence"
            );
            continue;
        };
        if tombstone.resume_generation != fence.resume_generation
            || tombstone.terminal_epoch != fence.terminal_epoch
            || tombstone.record.terminal_at != fence.terminal_at
            || tombstone.record.lifecycle.state != fence.terminal_state
        {
            warn!(
                session_id = %session_id,
                "dropping terminal MCP session tombstone whose generation fence does not match"
            );
            continue;
        }
        records.insert(session_id, Arc::new(tombstone.record));
    }
    Ok(records)
}

fn load_terminal_state(
    conn: &Connection,
    keyring: &RemoteSessionHmacKeyring,
    now: u64,
) -> Result<LoadedTerminalState, CliError> {
    let mut blocked_session_ids = HashSet::new();
    let mut tombstones = HashMap::new();
    let mut fences = HashMap::new();

    let mut tombstone_stmt = conn.prepare(&format!(
        "SELECT session_id, record_json FROM {table}",
        table = SESSION_TOMBSTONE_TABLE,
    ))?;
    let mut tombstone_rows = tombstone_stmt.query([])?;
    while let Some(row) = tombstone_rows.next()? {
        let session_id: String = row.get(0)?;
        let record_json: String = row.get(1)?;
        blocked_session_ids.insert(session_id.clone());
        match parse_terminal_session_record(&session_id, &record_json, keyring, now) {
            Ok(record) => {
                tombstones.insert(session_id, record);
            }
            Err(error) => {
                warn!(
                    session_id = %session_id,
                    error = %error,
                    "retaining terminal replay fence for invalid MCP session tombstone"
                );
            }
        }
    }

    let mut fence_stmt = conn.prepare(&format!(
        "SELECT session_id, record_json FROM {table}",
        table = SESSION_TERMINAL_FENCE_TABLE,
    ))?;
    let mut fence_rows = fence_stmt.query([])?;
    while let Some(row) = fence_rows.next()? {
        let session_id: String = row.get(0)?;
        let record_json: String = row.get(1)?;
        blocked_session_ids.insert(session_id.clone());
        match parse_terminal_fence(&session_id, &record_json, keyring, now) {
            Ok(fence) => {
                fences.insert(session_id, fence);
            }
            Err(error) => {
                warn!(
                    session_id = %session_id,
                    error = %error,
                    "retaining terminal replay block for invalid MCP session generation fence"
                );
            }
        }
    }

    Ok(LoadedTerminalState {
        blocked_session_ids,
        tombstones,
        fences,
    })
}

fn parse_terminal_session_record(
    session_id: &str,
    record_json: &str,
    keyring: &RemoteSessionHmacKeyring,
    now: u64,
) -> Result<RemoteSessionTombstoneRecord, CliError> {
    let tombstone: RemoteSessionTombstoneRecord =
        serde_json::from_str(record_json).map_err(|error| {
            CliError::cli_other_error(format!(
                "parse terminal MCP session tombstone {session_id}: {error}"
            ))
        })?;
    if tombstone.record.session_id != session_id {
        return Err(CliError::cli_other_error(format!(
            "terminal MCP session tombstone row {session_id} does not match payload {}",
            tombstone.record.session_id
        )));
    }
    validate_terminal_tombstone_integrity(keyring, &tombstone, now)?;
    Ok(tombstone)
}

fn parse_terminal_fence(
    session_id: &str,
    record_json: &str,
    keyring: &RemoteSessionHmacKeyring,
    now: u64,
) -> Result<RemoteSessionTerminalFence, CliError> {
    let fence: RemoteSessionTerminalFence = serde_json::from_str(record_json).map_err(|error| {
        CliError::cli_other_error(format!(
            "parse terminal MCP session generation fence {session_id}: {error}"
        ))
    })?;
    if fence.session_id != session_id {
        return Err(CliError::cli_other_error(format!(
            "terminal MCP session generation fence row {session_id} does not match payload {}",
            fence.session_id
        )));
    }
    validate_terminal_fence_integrity(keyring, &fence, now)?;
    Ok(fence)
}

#[cfg(test)]
pub(super) fn stored_capability_issuers_are_trusted(
    kernel: &chio_kernel::ChioKernel,
    capabilities: &[CapabilityToken],
) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    capabilities.iter().all(|capability| {
        kernel
            .verify_stored_capability_for_reuse(capability, now)
            .is_ok()
    })
}

pub(super) fn prepare_terminal_session_transition(
    path: &FsPath,
    fence: &RemoteSessionTerminalFence,
    keyring: &RemoteSessionHmacKeyring,
) -> Result<(), CliError> {
    let now = session_now_millis();
    validate_terminal_fence_integrity(keyring, fence, now)?;

    let mut conn = open_session_state_db(path)?;
    let transaction = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let existing_tombstone: i64 = transaction.query_row(
        &format!(
            "SELECT COUNT(*) FROM {table} WHERE session_id = ?1",
            table = SESSION_TOMBSTONE_TABLE,
        ),
        params![fence.session_id.as_str()],
        |row| row.get(0),
    )?;
    if existing_tombstone != 0 {
        return Err(CliError::cli_other_error(format!(
            "terminal MCP session {} already has a finalized tombstone",
            fence.session_id
        )));
    }
    let active_record_json: Option<String> = transaction
        .query_row(
            &format!(
                "SELECT record_json FROM {table} WHERE session_id = ?1",
                table = SESSION_ACTIVE_TABLE,
            ),
            params![fence.session_id.as_str()],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(active_record_json) = active_record_json {
        let active: RemoteSessionResumeRecord =
            serde_json::from_str(&active_record_json).map_err(|error| {
                CliError::cli_other_error(format!(
                    "active MCP session {} is malformed during terminalization: {error}",
                    fence.session_id
                ))
            })?;
        if active.session_id != fence.session_id {
            return Err(CliError::cli_other_error(format!(
                "active MCP session row {} contains state for {} during terminalization",
                fence.session_id, active.session_id
            )));
        }
        validate_resume_record_integrity_with_keyring(keyring, &active, now)?;
        if fence.resume_generation <= active.resume_generation {
            return Err(CliError::cli_other_error(format!(
                "terminal MCP session {} generation {} does not advance active generation {}",
                fence.session_id, fence.resume_generation, active.resume_generation
            )));
        }
    }
    let existing_fence_json: Option<String> = transaction
        .query_row(
            &format!(
                "SELECT record_json FROM {table} WHERE session_id = ?1",
                table = SESSION_TERMINAL_FENCE_TABLE,
            ),
            params![fence.session_id.as_str()],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(existing_fence_json) = existing_fence_json {
        let existing = parse_terminal_fence(&fence.session_id, &existing_fence_json, keyring, now)?;
        if existing.terminal_epoch != fence.terminal_epoch
            || existing.resume_generation != fence.resume_generation
            || existing.terminal_at != fence.terminal_at
            || existing.terminal_state != fence.terminal_state
            || existing.resume_integrity != fence.resume_integrity
        {
            return Err(CliError::cli_other_error(format!(
                "terminal MCP session {} attempted to rewrite retained terminal intent epoch {}",
                fence.session_id, fence.terminal_epoch
            )));
        }
    }

    let fence_json = serde_json::to_string(fence)?;
    transaction.execute(
        &format!(
            "INSERT INTO {table} (session_id, terminal_at, terminal_epoch, record_json)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(session_id) DO UPDATE SET
                 terminal_at = excluded.terminal_at,
                 terminal_epoch = excluded.terminal_epoch,
                 record_json = excluded.record_json",
            table = SESSION_TERMINAL_FENCE_TABLE,
        ),
        params![
            fence.session_id.as_str(),
            fence.terminal_at as i64,
            fence.terminal_epoch as i64,
            fence_json,
        ],
    )?;
    transaction.execute(
        &format!(
            "DELETE FROM {table} WHERE session_id = ?1",
            table = SESSION_ACTIVE_TABLE,
        ),
        params![fence.session_id.as_str()],
    )?;
    transaction.commit()?;
    Ok(())
}

pub(super) fn finalize_terminal_session_transition(
    path: &FsPath,
    tombstone: &RemoteSessionTombstoneRecord,
    keyring: &RemoteSessionHmacKeyring,
) -> Result<(), CliError> {
    let now = session_now_millis();
    validate_terminal_tombstone_integrity(keyring, tombstone, now)?;
    let mut conn = open_session_state_db(path)?;
    let transaction = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let active_rows: i64 = transaction.query_row(
        &format!(
            "SELECT COUNT(*) FROM {table} WHERE session_id = ?1",
            table = SESSION_ACTIVE_TABLE,
        ),
        params![tombstone.record.session_id.as_str()],
        |row| row.get(0),
    )?;
    if active_rows != 0 {
        return Err(CliError::cli_other_error(format!(
            "refusing to finalize terminal MCP session {} while active state remains",
            tombstone.record.session_id
        )));
    }

    let fence_json: String = transaction
        .query_row(
            &format!(
                "SELECT record_json FROM {table} WHERE session_id = ?1",
                table = SESSION_TERMINAL_FENCE_TABLE,
            ),
            params![tombstone.record.session_id.as_str()],
            |row| row.get(0),
        )
        .optional()?
        .ok_or_else(|| {
            CliError::cli_other_error(format!(
                "terminal MCP session {} has no prepared terminal intent",
                tombstone.record.session_id
            ))
        })?;
    let fence = parse_terminal_fence(&tombstone.record.session_id, &fence_json, keyring, now)?;
    if tombstone.resume_generation != fence.resume_generation
        || tombstone.terminal_epoch != fence.terminal_epoch
        || tombstone.record.terminal_at != fence.terminal_at
        || tombstone.record.lifecycle.state != fence.terminal_state
    {
        return Err(CliError::cli_other_error(format!(
            "terminal MCP session {} tombstone does not match its prepared terminal intent",
            tombstone.record.session_id
        )));
    }

    let existing_tombstone_json: Option<String> = transaction
        .query_row(
            &format!(
                "SELECT record_json FROM {table} WHERE session_id = ?1",
                table = SESSION_TOMBSTONE_TABLE,
            ),
            params![tombstone.record.session_id.as_str()],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(existing_tombstone_json) = existing_tombstone_json {
        let existing = parse_terminal_session_record(
            &tombstone.record.session_id,
            &existing_tombstone_json,
            keyring,
            now,
        )?;
        if existing.resume_integrity != tombstone.resume_integrity {
            return Err(CliError::cli_other_error(format!(
                "terminal MCP session {} attempted to rewrite its finalized tombstone",
                tombstone.record.session_id
            )));
        }
        transaction.commit()?;
        return Ok(());
    }

    let tombstone_json = serde_json::to_string(tombstone)?;
    transaction.execute(
        &format!(
            "INSERT INTO {table} (session_id, terminal_at, record_json)
             VALUES (?1, ?2, ?3)",
            table = SESSION_TOMBSTONE_TABLE,
        ),
        params![
            tombstone.record.session_id.as_str(),
            tombstone.record.terminal_at as i64,
            tombstone_json,
        ],
    )?;
    transaction.commit()?;
    Ok(())
}

#[cfg(test)]
#[cfg(target_os = "linux")]
pub(super) fn persist_terminal_session_transition(
    path: &FsPath,
    tombstone: &RemoteSessionTombstoneRecord,
    fence: &RemoteSessionTerminalFence,
    keyring: &RemoteSessionHmacKeyring,
) -> Result<(), CliError> {
    prepare_terminal_session_transition(path, fence, keyring)?;
    finalize_terminal_session_transition(path, tombstone, keyring)
}

pub(super) fn persist_active_session_record(
    path: &FsPath,
    record: &RemoteSessionResumeRecord,
    keyring: &RemoteSessionHmacKeyring,
) -> Result<(), CliError> {
    let now = session_now_millis();
    validate_resume_record_integrity_with_keyring(keyring, record, now)?;
    let mut conn = open_session_state_db(path)?;
    let transaction = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let terminal_rows: i64 = transaction.query_row(
        &format!(
            "SELECT
                (SELECT COUNT(*) FROM {tombstone_table} WHERE session_id = ?1) +
                (SELECT COUNT(*) FROM {fence_table} WHERE session_id = ?1)",
            tombstone_table = SESSION_TOMBSTONE_TABLE,
            fence_table = SESSION_TERMINAL_FENCE_TABLE,
        ),
        params![record.session_id.as_str()],
        |row| row.get(0),
    )?;
    if terminal_rows != 0 {
        return Err(CliError::cli_other_error(format!(
            "refusing to persist active MCP session {} over retained terminal state",
            record.session_id
        )));
    }

    let existing_json: Option<String> = transaction
        .query_row(
            &format!(
                "SELECT record_json FROM {table} WHERE session_id = ?1",
                table = SESSION_ACTIVE_TABLE,
            ),
            params![record.session_id.as_str()],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(existing_json) = existing_json {
        let existing: RemoteSessionResumeRecord =
            serde_json::from_str(&existing_json).map_err(|error| {
                CliError::cli_other_error(format!(
                    "existing MCP session {} has malformed authenticated state: {error}",
                    record.session_id
                ))
            })?;
        if existing.session_id != record.session_id {
            return Err(CliError::cli_other_error(format!(
                "existing MCP session row {} contains authenticated state for {}",
                record.session_id, existing.session_id
            )));
        }
        validate_resume_record_integrity_with_keyring(keyring, &existing, now)?;
        if record.resume_generation <= existing.resume_generation {
            return Err(CliError::cli_other_error(format!(
                "refusing to roll back active MCP session {} generation {} to {}",
                record.session_id, existing.resume_generation, record.resume_generation
            )));
        }
    }

    let record_json = serde_json::to_string(record)?;
    transaction.execute(
        &format!(
            "INSERT INTO {table} (session_id, updated_at, record_json)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(session_id) DO UPDATE SET
                 updated_at = excluded.updated_at,
                 record_json = excluded.record_json",
            table = SESSION_ACTIVE_TABLE,
        ),
        params![record.session_id.as_str(), now as i64, record_json,],
    )?;
    transaction.commit()?;
    Ok(())
}

pub(super) fn delete_active_session_record(
    path: &FsPath,
    session_id: &str,
) -> Result<(), CliError> {
    let conn = open_session_state_db(path)?;
    conn.execute(
        &format!(
            "DELETE FROM {table} WHERE session_id = ?1",
            table = SESSION_ACTIVE_TABLE,
        ),
        params![session_id],
    )?;
    Ok(())
}

pub(super) fn purge_terminal_session_records_before(
    path: &FsPath,
    cutoff: u64,
) -> Result<(), CliError> {
    let conn = open_session_state_db(path)?;
    conn.execute(
        &format!(
            "DELETE FROM {terminal_table}
             WHERE terminal_at < ?1
               AND NOT EXISTS (
                   SELECT 1 FROM {active_table}
                   WHERE {active_table}.session_id = {terminal_table}.session_id
               )",
            active_table = SESSION_ACTIVE_TABLE,
            terminal_table = SESSION_TOMBSTONE_TABLE,
        ),
        params![cutoff as i64],
    )?;
    Ok(())
}
