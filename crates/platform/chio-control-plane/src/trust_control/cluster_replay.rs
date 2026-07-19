use super::*;
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};

const CLUSTER_REPLAY_SCHEMA_VERSION: i64 = 2;
const CLUSTER_REPLAY_CAPACITY_PER_PEER: i64 = 4_096;

static CLUSTER_REPLAY_BINDINGS: LazyLock<Mutex<HashMap<PathBuf, Arc<ClusterReplayFileBinding>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

struct ClusterReplayFileBinding {
    parent_path: PathBuf,
    parent: std::fs::File,
    file_name: std::ffi::OsString,
    file: std::fs::File,
    #[cfg(unix)]
    parent_device: u64,
    #[cfg(unix)]
    parent_inode: u64,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl ClusterReplayFileBinding {
    fn open(path: PathBuf) -> Result<Self, CliError> {
        ensure_secure_cluster_replay_platform()?;
        let parent_path = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| {
                CliError::cli_other_error(
                    "cluster peer replay database path has no parent".to_string(),
                )
            })?
            .to_path_buf();
        let file_name = path
            .file_name()
            .ok_or_else(|| {
                CliError::cli_other_error(
                    "cluster peer replay database path has no file name".to_string(),
                )
            })?
            .to_os_string();
        let parent = open_trusted_cluster_replay_directory_chain(&parent_path)?;
        let file = open_cluster_replay_file_at(&parent, &file_name, true)?;
        let metadata = file.metadata().map_err(cluster_replay_storage_error)?;
        let parent_metadata = parent.metadata().map_err(cluster_replay_storage_error)?;
        validate_cluster_replay_file_descriptor(&file, &metadata)?;
        let binding = Self {
            parent_path,
            parent,
            file_name,
            #[cfg(unix)]
            parent_device: unix_file_device(&parent_metadata),
            #[cfg(unix)]
            parent_inode: unix_file_inode(&parent_metadata),
            #[cfg(unix)]
            device: unix_file_device(&metadata),
            #[cfg(unix)]
            inode: unix_file_inode(&metadata),
            file,
        };
        binding.validate()?;
        Ok(binding)
    }

    fn validate(&self) -> Result<(), CliError> {
        let current_parent = open_trusted_cluster_replay_directory_chain(&self.parent_path)?;
        let current_parent_metadata = current_parent
            .metadata()
            .map_err(cluster_replay_storage_error)?;
        let retained_parent_metadata = self
            .parent
            .metadata()
            .map_err(cluster_replay_storage_error)?;
        let path_file = open_cluster_replay_file_at(&self.parent, &self.file_name, false)?;
        let path_metadata = path_file.metadata().map_err(cluster_replay_storage_error)?;
        let file_metadata = self.file.metadata().map_err(cluster_replay_storage_error)?;
        if !path_metadata.file_type().is_file() || !file_metadata.file_type().is_file() {
            return Err(CliError::cli_other_error(
                "cluster peer replay database must remain bound to a regular non-symlink file"
                    .to_string(),
            ));
        }
        validate_cluster_replay_file_descriptor(&path_file, &path_metadata)?;
        validate_cluster_replay_file_descriptor(&self.file, &file_metadata)?;
        #[cfg(unix)]
        if unix_file_device(&current_parent_metadata) != self.parent_device
            || unix_file_inode(&current_parent_metadata) != self.parent_inode
            || unix_file_device(&retained_parent_metadata) != self.parent_device
            || unix_file_inode(&retained_parent_metadata) != self.parent_inode
            || unix_file_device(&path_metadata) != self.device
            || unix_file_inode(&path_metadata) != self.inode
            || unix_file_device(&file_metadata) != self.device
            || unix_file_inode(&file_metadata) != self.inode
        {
            return Err(CliError::cli_other_error(
                "cluster peer replay database path identity changed after initialization"
                    .to_string(),
            ));
        }
        for suffix in ["-wal", "-shm", "-journal"] {
            validate_cluster_replay_sidecar(&self.parent, &self.file_name, suffix)?;
        }
        Ok(())
    }
}

pub(crate) fn initialize_cluster_peer_replay_ledger(path: &Path) -> Result<(), CliError> {
    let resolved_path = resolve_cluster_replay_database_path(path)?;
    let binding = Arc::new(ClusterReplayFileBinding::open(resolved_path.clone())?);
    let mut connection = open_bound_cluster_replay_connection(&binding)?;
    configure_cluster_replay_connection(&connection).map_err(cluster_replay_storage_error)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(cluster_replay_storage_error)?;
    transaction
        .execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS cluster_peer_replay_meta (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                schema_version INTEGER NOT NULL CHECK (schema_version = 2),
                max_observed_at INTEGER NOT NULL CHECK (max_observed_at >= 0)
            );
            INSERT OR IGNORE INTO cluster_peer_replay_meta
                (singleton, schema_version, max_observed_at)
            VALUES (1, 2, 0);
            CREATE TABLE IF NOT EXISTS cluster_peer_replay_nonces (
                peer_id TEXT NOT NULL,
                nonce TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                PRIMARY KEY (peer_id, nonce)
            ) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS cluster_peer_replay_nonces_expiry
            ON cluster_peer_replay_nonces (issued_at);
            "#,
        )
        .map_err(cluster_replay_storage_error)?;
    let schema_version = transaction
        .query_row(
            "SELECT schema_version FROM cluster_peer_replay_meta WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(cluster_replay_storage_error)?;
    if schema_version != CLUSTER_REPLAY_SCHEMA_VERSION {
        return Err(CliError::cli_other_error(format!(
            "cluster peer replay database schema version {schema_version} is unsupported"
        )));
    }
    transaction.commit().map_err(cluster_replay_storage_error)?;
    binding.validate()?;
    CLUSTER_REPLAY_BINDINGS
        .lock()
        .map_err(|_| {
            CliError::cli_other_error(
                "cluster peer replay database binding registry is unavailable".to_string(),
            )
        })?
        .insert(resolved_path, binding);
    Ok(())
}

pub(crate) fn consume_cluster_peer_nonce_durably(
    path: &Path,
    peer_id: &str,
    nonce: &str,
    issued_at: i64,
    now: i64,
) -> Result<(), Response> {
    let resolved_path = resolve_cluster_replay_database_path(path).map_err(|_| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster peer replay database path is unsafe",
        )
    })?;
    let binding = CLUSTER_REPLAY_BINDINGS
        .lock()
        .map_err(|_| {
            plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "cluster peer replay database binding registry is unavailable",
            )
        })?
        .get(&resolved_path)
        .cloned()
        .ok_or_else(|| {
            plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "cluster peer replay database was not securely initialized",
            )
        })?;
    binding.validate().map_err(|_| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster peer replay database path identity is invalid",
        )
    })?;
    let mut connection = open_bound_cluster_replay_connection(&binding).map_err(|_| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster peer replay database is unavailable",
        )
    })?;
    configure_cluster_replay_connection(&connection).map_err(|_| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster peer replay database could not be configured",
        )
    })?;
    binding.validate().map_err(|_| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster peer replay database path identity is invalid",
        )
    })?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| {
            plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "cluster peer replay database could not acquire its write fence",
            )
        })?;
    let (schema_version, max_observed_at) = transaction
        .query_row(
            "SELECT schema_version, max_observed_at FROM cluster_peer_replay_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .map_err(|_| {
            plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "cluster peer replay database watermark is unavailable",
            )
        })?;
    if schema_version != CLUSTER_REPLAY_SCHEMA_VERSION || max_observed_at < 0 {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster peer replay database watermark is invalid",
        ));
    }
    if max_observed_at > now.saturating_add(CLUSTER_AUTH_MAX_SKEW_SECS) {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster peer replay protection detected excessive wall-clock rollback",
        ));
    }
    let effective_now = now.max(max_observed_at);
    let earliest_accepted = effective_now.saturating_sub(CLUSTER_AUTH_MAX_SKEW_SECS);
    let latest_accepted = effective_now.saturating_add(CLUSTER_AUTH_MAX_SKEW_SECS);
    if issued_at < earliest_accepted || issued_at > latest_accepted {
        return Err(plain_http_error(
            StatusCode::UNAUTHORIZED,
            "cluster peer request freshness window is invalid",
        ));
    }
    transaction
        .execute(
            "UPDATE cluster_peer_replay_meta SET max_observed_at = ?1 WHERE singleton = 1",
            params![effective_now],
        )
        .map_err(|_| {
            plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "cluster peer replay database watermark update failed",
            )
        })?;
    let cutoff = effective_now.saturating_sub(CLUSTER_AUTH_MAX_SKEW_SECS);
    transaction
        .execute(
            "DELETE FROM cluster_peer_replay_nonces WHERE issued_at < ?1",
            params![cutoff],
        )
        .map_err(|_| {
            plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "cluster peer replay database pruning failed",
            )
        })?;
    let replayed = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM cluster_peer_replay_nonces WHERE peer_id = ?1 AND nonce = ?2)",
            params![peer_id, nonce],
            |row| row.get::<_, bool>(0),
        )
        .map_err(|_| {
            plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "cluster peer replay database lookup failed",
            )
        })?;
    if replayed {
        return Err(plain_http_error(
            StatusCode::UNAUTHORIZED,
            "cluster peer request nonce was already consumed",
        ));
    }
    let peer_nonce_count = transaction
        .query_row(
            "SELECT COUNT(*) FROM cluster_peer_replay_nonces WHERE peer_id = ?1",
            params![peer_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| {
            plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "cluster peer replay database capacity check failed",
            )
        })?;
    if peer_nonce_count >= CLUSTER_REPLAY_CAPACITY_PER_PEER {
        return Err(plain_http_error(
            StatusCode::TOO_MANY_REQUESTS,
            "cluster peer replay database capacity is exhausted",
        ));
    }
    transaction
        .execute(
            "INSERT INTO cluster_peer_replay_nonces (peer_id, nonce, issued_at) VALUES (?1, ?2, ?3)",
            params![peer_id, nonce, issued_at],
        )
        .map_err(|_| {
            plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "cluster peer replay database insert failed",
            )
        })?;
    transaction.commit().map_err(|_| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster peer replay database commit failed",
        )
    })?;
    binding.validate().map_err(|_| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster peer replay database path identity is invalid",
        )
    })
}

pub(crate) fn cluster_replay_path_aliases(
    replay_path: &Path,
    other_path: &Path,
) -> Result<bool, CliError> {
    let replay_target = resolve_cluster_file_target(replay_path, "cluster replay database")?;
    let other_target = resolve_cluster_file_target(other_path, "cluster storage")?;
    if replay_target == other_target {
        return Ok(true);
    }
    let replay_existing = std::fs::canonicalize(replay_path).ok();
    let other_existing = std::fs::canonicalize(other_path).ok();
    if replay_existing.as_ref() == Some(&other_target)
        || other_existing.as_ref() == Some(&replay_target)
        || replay_existing
            .as_ref()
            .zip(other_existing.as_ref())
            .is_some_and(|(replay, other)| replay == other)
    {
        return Ok(true);
    }
    #[cfg(unix)]
    if let (Ok(replay_metadata), Ok(other_metadata)) = (
        std::fs::metadata(replay_path),
        std::fs::metadata(other_path),
    ) {
        use std::os::unix::fs::MetadataExt;

        if replay_metadata.dev() == other_metadata.dev()
            && replay_metadata.ino() == other_metadata.ino()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn resolve_cluster_replay_database_path(path: &Path) -> Result<PathBuf, CliError> {
    let path_text = path.to_string_lossy();
    if path_text == ":memory:" || path_text.to_ascii_lowercase().starts_with("file:") {
        return Err(CliError::cli_other_error(
            "cluster replay database must use a durable filesystem path".to_string(),
        ));
    }
    if !path.is_absolute() {
        return Err(CliError::cli_other_error(
            "cluster replay database path must be absolute".to_string(),
        ));
    }
    if cluster_path_contains_dot_component(path) {
        return Err(CliError::cli_other_error(
            "cluster replay database path must not contain dot components".to_string(),
        ));
    }
    if path.parent().is_none() || path.file_name().is_none() {
        return Err(CliError::cli_other_error(
            "cluster replay database path is incomplete".to_string(),
        ));
    }
    Ok(path.to_path_buf())
}

fn resolve_cluster_file_target(path: &Path, label: &str) -> Result<PathBuf, CliError> {
    let path_text = path.to_string_lossy();
    if path_text == ":memory:" || path_text.to_ascii_lowercase().starts_with("file:") {
        return Err(CliError::cli_other_error(format!(
            "{label} must use a durable filesystem path"
        )));
    }
    if !path.is_absolute() {
        return Err(CliError::cli_other_error(format!(
            "{label} path must be absolute"
        )));
    }
    if cluster_path_contains_dot_component(path) {
        return Err(CliError::cli_other_error(format!(
            "{label} path must not contain dot components"
        )));
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| CliError::cli_other_error(format!("{label} path has no parent")))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| CliError::cli_other_error(format!("{label} path has no file name")))?;
    let resolved_parent = std::fs::canonicalize(parent).map_err(|error| {
        CliError::cli_other_error(format!("{label} parent is unavailable: {error}"))
    })?;
    Ok(resolved_parent.join(file_name))
}

#[cfg(unix)]
fn cluster_path_contains_dot_component(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;

    path.as_os_str()
        .as_bytes()
        .split(|byte| *byte == b'/')
        .any(|component| component == b"." || component == b"..")
}

#[cfg(not(unix))]
fn cluster_path_contains_dot_component(path: &Path) -> bool {
    path.components().any(|component| {
        matches!(
            component,
            std::path::Component::CurDir | std::path::Component::ParentDir
        )
    })
}

fn open_bound_cluster_replay_connection(
    binding: &ClusterReplayFileBinding,
) -> Result<Connection, CliError> {
    binding.validate()?;
    ensure_secure_cluster_replay_platform()?;
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    #[cfg(target_os = "linux")]
    let anchored_path = {
        use std::os::fd::AsRawFd;

        let mut anchored = PathBuf::from("/proc/self/fd");
        anchored.push(binding.parent.as_raw_fd().to_string());
        anchored.push(&binding.file_name);
        anchored
    };
    #[cfg(target_os = "macos")]
    // Darwin exposes an open file through /dev/fd, but does not permit
    // directory traversal through a retained directory descriptor there.
    // The pathname is safe to reuse after the openat custody checks because
    // every ancestor rejects symlinks, untrusted write authority, and
    // authority-granting ACLs. SQLite also receives SQLITE_OPEN_NOFOLLOW, and
    // the opened database identity is compared with the retained file below.
    let anchored_path = binding.parent_path.join(&binding.file_name);
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let anchored_path = PathBuf::new();
    let connection =
        Connection::open_with_flags(&anchored_path, flags).map_err(cluster_replay_storage_error)?;
    let sqlite_path = connection
        .query_row("PRAGMA database_list", [], |row| row.get::<_, String>(2))
        .map(PathBuf::from)
        .map_err(cluster_replay_storage_error)?;
    let sqlite_metadata = std::fs::metadata(&sqlite_path).map_err(cluster_replay_storage_error)?;
    let retained_metadata = binding
        .file
        .metadata()
        .map_err(cluster_replay_storage_error)?;
    #[cfg(unix)]
    if unix_file_device(&sqlite_metadata) != unix_file_device(&retained_metadata)
        || unix_file_inode(&sqlite_metadata) != unix_file_inode(&retained_metadata)
    {
        return Err(CliError::cli_other_error(
            "SQLite opened a different cluster replay database identity".to_string(),
        ));
    }
    binding.validate()?;
    Ok(connection)
}

pub(crate) fn ensure_secure_cluster_replay_platform() -> Result<(), CliError> {
    #[cfg(target_os = "linux")]
    {
        let metadata = std::fs::metadata("/proc/self/fd").map_err(|error| {
            CliError::cli_other_error(format!(
                "cluster replay protection requires a mounted /proc/self/fd: {error}"
            ))
        })?;
        if !metadata.is_dir() {
            return Err(CliError::cli_other_error(
                "cluster replay protection requires /proc/self/fd to be a directory".to_string(),
            ));
        }
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(CliError::cli_other_error(
            "clustered trust control is unsupported on this platform because SQLite cannot be opened through a retained directory descriptor"
                .to_string(),
        ))
    }
}

fn configure_cluster_replay_connection(connection: &Connection) -> Result<(), rusqlite::Error> {
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.execute_batch(
        "PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;",
    )
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn open_trusted_cluster_replay_directory_chain(
    parent_path: &Path,
) -> Result<std::fs::File, CliError> {
    let mut names = Vec::new();
    for component in parent_path.components() {
        match component {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(name) => names.push(name.to_os_string()),
            std::path::Component::Prefix(_) => {
                return Err(CliError::cli_other_error(
                    "cluster replay database path has an unsupported prefix".to_string(),
                ));
            }
            std::path::Component::CurDir | std::path::Component::ParentDir => {
                return Err(CliError::cli_other_error(
                    "cluster replay database path must not contain dot components".to_string(),
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
    .map_err(cluster_replay_storage_error)?;
    let mut directory = std::fs::File::from(root);
    validate_cluster_replay_directory_descriptor(&directory, !names.is_empty())?;
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
        .map_err(cluster_replay_storage_error)?;
        let next = std::fs::File::from(descriptor);
        validate_cluster_replay_directory_descriptor(&next, index + 1 != name_count)?;
        directory = next;
    }
    Ok(directory)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn open_trusted_cluster_replay_directory_chain(
    _parent_path: &Path,
) -> Result<std::fs::File, CliError> {
    ensure_secure_cluster_replay_platform()?;
    Err(CliError::cli_other_error(
        "secure cluster replay directory traversal is unavailable".to_string(),
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn validate_cluster_replay_directory_descriptor(
    directory: &std::fs::File,
    allow_sticky_write: bool,
) -> Result<(), CliError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = directory.metadata().map_err(cluster_replay_storage_error)?;
    let effective_uid = rustix::process::geteuid().as_raw();
    let trusted_owner = metadata.uid() == effective_uid || metadata.uid() == 0;
    let group_or_world_writable = metadata.mode() & 0o022 != 0;
    let sticky = metadata.mode() & 0o1000 != 0;
    if !metadata.file_type().is_dir()
        || !trusted_owner
        || (group_or_world_writable && !(allow_sticky_write && sticky))
        || cluster_replay_descriptor_grants_extended_acl_authority(directory)?
    {
        return Err(CliError::cli_other_error(
            "cluster peer replay database ancestor chain grants untrusted write authority"
                .to_string(),
        ));
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn open_cluster_replay_file_at(
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
    .map_err(cluster_replay_storage_error)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn open_cluster_replay_file_at(
    _parent: &std::fs::File,
    _file_name: &std::ffi::OsStr,
    _create: bool,
) -> Result<std::fs::File, CliError> {
    ensure_secure_cluster_replay_platform()?;
    Err(CliError::cli_other_error(
        "secure cluster replay file opening is unavailable".to_string(),
    ))
}

fn validate_cluster_replay_file_descriptor(
    _file: &std::fs::File,
    metadata: &std::fs::Metadata,
) -> Result<(), CliError> {
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(CliError::cli_other_error(
            "cluster peer replay database must be a regular non-symlink file".to_string(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let effective_uid = rustix::process::geteuid().as_raw();
        if (metadata.uid() != effective_uid && metadata.uid() != 0)
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
            || cluster_replay_descriptor_grants_extended_acl_authority(_file)?
        {
            return Err(CliError::cli_other_error(
                "cluster peer replay database must have trusted ownership, mode 0600 or stricter, no authority-granting ACL, and one hard link"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn validate_cluster_replay_sidecar(
    parent: &std::fs::File,
    file_name: &std::ffi::OsStr,
    suffix: &str,
) -> Result<(), CliError> {
    let mut sidecar = file_name.to_os_string();
    sidecar.push(suffix);
    match rustix::fs::openat(
        parent,
        &sidecar,
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    ) {
        Ok(descriptor) => {
            let file = std::fs::File::from(descriptor);
            validate_cluster_replay_file_descriptor(
                &file,
                &file.metadata().map_err(cluster_replay_storage_error)?,
            )
        }
        Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
        Err(error) => Err(cluster_replay_storage_error(error)),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn validate_cluster_replay_sidecar(
    _parent: &std::fs::File,
    _file_name: &std::ffi::OsStr,
    _suffix: &str,
) -> Result<(), CliError> {
    ensure_secure_cluster_replay_platform()
}

#[cfg(target_vendor = "apple")]
fn cluster_replay_descriptor_grants_extended_acl_authority(
    file: &std::fs::File,
) -> Result<bool, CliError> {
    chio_keyring::darwin_descriptor_grants_extended_acl_authority(file)
        .map_err(|error| CliError::cli_other_error(error.to_string()))
}

#[cfg(all(unix, not(target_vendor = "apple")))]
fn cluster_replay_descriptor_grants_extended_acl_authority(
    _file: &std::fs::File,
) -> Result<bool, CliError> {
    Ok(false)
}

#[cfg(unix)]
fn unix_file_device(metadata: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    metadata.dev()
}

#[cfg(unix)]
fn unix_file_inode(metadata: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    metadata.ino()
}

fn cluster_replay_storage_error(error: impl std::fmt::Display) -> CliError {
    CliError::cli_other_error(format!(
        "cluster peer replay database is unavailable: {error}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_test_support::prelude::*;

    fn trusted_temp_path(temp: &tempfile::TempDir, name: &str) -> PathBuf {
        std::fs::canonicalize(temp.path()).test_unwrap().join(name)
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn consumed_nonce_remains_rejected_after_receiver_restart() {
        let temp = tempfile::tempdir().test_unwrap();
        let path = trusted_temp_path(&temp, "cluster-replay.sqlite3");
        initialize_cluster_peer_replay_ledger(&path).test_unwrap();
        consume_cluster_peer_nonce_durably(
            &path,
            "https://node-a.example",
            "d94ce2a3-cc58-4bd0-89ca-4eb196e9baf7",
            1_000,
            1_000,
        )
        .test_unwrap();

        initialize_cluster_peer_replay_ledger(&path).test_unwrap();
        let replay = consume_cluster_peer_nonce_durably(
            &path,
            "https://node-a.example",
            "d94ce2a3-cc58-4bd0-89ca-4eb196e9baf7",
            1_000,
            1_001,
        )
        .test_unwrap_err();
        assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn missing_replay_database_fails_closed_instead_of_recreating_state() {
        let temp = tempfile::tempdir().test_unwrap();
        let path = trusted_temp_path(&temp, "missing.sqlite3");
        let failure = consume_cluster_peer_nonce_durably(
            &path,
            "https://node-a.example",
            "af6b4f75-37db-4458-a742-ee9b4eb78624",
            1_000,
            1_000,
        )
        .test_unwrap_err();
        assert_eq!(failure.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(!path.exists());
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn forward_clock_jump_then_rollback_cannot_reopen_a_pruned_nonce_window() {
        let temp = tempfile::tempdir().test_unwrap();
        let path = trusted_temp_path(&temp, "cluster-replay.sqlite3");
        initialize_cluster_peer_replay_ledger(&path).test_unwrap();
        consume_cluster_peer_nonce_durably(
            &path,
            "https://node-a.example",
            "d94ce2a3-cc58-4bd0-89ca-4eb196e9baf7",
            1_000,
            1_000,
        )
        .test_unwrap();
        consume_cluster_peer_nonce_durably(
            &path,
            "https://node-a.example",
            "af6b4f75-37db-4458-a742-ee9b4eb78624",
            5_000,
            5_000,
        )
        .test_unwrap();

        initialize_cluster_peer_replay_ledger(&path).test_unwrap();
        let rollback = consume_cluster_peer_nonce_durably(
            &path,
            "https://node-a.example",
            "d94ce2a3-cc58-4bd0-89ca-4eb196e9baf7",
            1_000,
            1_001,
        )
        .test_unwrap_err();
        assert_eq!(rollback.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn replay_database_rejects_symlinks_hardlinks_and_unsafe_mode() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let temp = tempfile::tempdir().test_unwrap();
        let trusted_temp = std::fs::canonicalize(temp.path()).test_unwrap();
        let target = trusted_temp.join("target.sqlite3");
        std::fs::write(&target, []).test_unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).test_unwrap();

        let symlink_path = trusted_temp.join("symlink.sqlite3");
        symlink(&target, &symlink_path).test_unwrap();
        assert!(initialize_cluster_peer_replay_ledger(&symlink_path).is_err());

        let hardlink_path = trusted_temp.join("hardlink.sqlite3");
        std::fs::hard_link(&target, &hardlink_path).test_unwrap();
        assert!(initialize_cluster_peer_replay_ledger(&target).is_err());
        std::fs::remove_file(&hardlink_path).test_unwrap();

        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).test_unwrap();
        assert!(initialize_cluster_peer_replay_ledger(&target).is_err());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn replay_database_rejects_symlinked_and_untrusted_ancestor_chains() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let temp = tempfile::tempdir().test_unwrap();
        let trusted_temp = std::fs::canonicalize(temp.path()).test_unwrap();
        let real_parent = trusted_temp.join("real-parent");
        std::fs::create_dir(&real_parent).test_unwrap();
        let alias_parent = trusted_temp.join("alias-parent");
        symlink(&real_parent, &alias_parent).test_unwrap();
        assert!(initialize_cluster_peer_replay_ledger(
            &alias_parent.join("cluster-replay.sqlite3")
        )
        .is_err());

        let unsafe_parent = trusted_temp.join("unsafe-parent");
        std::fs::create_dir(&unsafe_parent).test_unwrap();
        std::fs::set_permissions(&unsafe_parent, std::fs::Permissions::from_mode(0o777))
            .test_unwrap();
        assert!(initialize_cluster_peer_replay_ledger(
            &unsafe_parent.join("cluster-replay.sqlite3")
        )
        .is_err());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn replay_database_detects_parent_and_file_identity_replacement() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().test_unwrap();
        let trusted_temp = std::fs::canonicalize(temp.path()).test_unwrap();
        let parent = trusted_temp.join("replay-parent");
        std::fs::create_dir(&parent).test_unwrap();
        let path = parent.join("cluster-replay.sqlite3");
        initialize_cluster_peer_replay_ledger(&path).test_unwrap();

        let moved_parent = trusted_temp.join("replay-parent-moved");
        std::fs::rename(&parent, &moved_parent).test_unwrap();
        std::fs::create_dir(&parent).test_unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).test_unwrap();
        let parent_replaced = consume_cluster_peer_nonce_durably(
            &path,
            "https://node-a.example",
            "4b03d0ec-9bc5-49e8-976c-872c2db6e26d",
            1_000,
            1_000,
        )
        .test_unwrap_err();
        assert_eq!(parent_replaced.status(), StatusCode::SERVICE_UNAVAILABLE);

        let second_parent = trusted_temp.join("second-parent");
        std::fs::create_dir(&second_parent).test_unwrap();
        let second_path = second_parent.join("cluster-replay.sqlite3");
        initialize_cluster_peer_replay_ledger(&second_path).test_unwrap();
        let displaced_file = second_parent.join("cluster-replay-displaced.sqlite3");
        std::fs::rename(&second_path, &displaced_file).test_unwrap();
        std::fs::write(&second_path, []).test_unwrap();
        std::fs::set_permissions(&second_path, std::fs::Permissions::from_mode(0o600))
            .test_unwrap();
        let file_replaced = consume_cluster_peer_nonce_durably(
            &second_path,
            "https://node-a.example",
            "559884ae-f588-453d-9a5e-37e173e281fb",
            1_000,
            1_000,
        )
        .test_unwrap_err();
        assert_eq!(file_replaced.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn replay_database_rejects_relative_and_dot_component_paths() {
        assert!(initialize_cluster_peer_replay_ledger(Path::new("relative.sqlite3")).is_err());
        let temp = tempfile::tempdir().test_unwrap();
        let dot_path = temp.path().join(".").join("replay.sqlite3");
        assert!(initialize_cluster_peer_replay_ledger(&dot_path).is_err());
    }
}
