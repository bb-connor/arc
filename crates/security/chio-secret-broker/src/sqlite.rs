#[cfg(not(unix))]
use std::fs::OpenOptions;
use std::fs::{self, File};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use chio_core_types::canonical_json_bytes;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Transaction};

use crate::budget::ExecutionQuota;
use crate::store::{
    AttemptIds, AttemptRecord, AttemptRegistration, AttemptState, AttemptStore,
    AttemptTransitionEvidence, RegisterAttemptOutcome,
};
use crate::{validate_digest, BrokerError, Result};

pub struct SqliteAttemptStore {
    connection: Mutex<Connection>,
    durable_file: Option<DurableBrokerDatabaseFile>,
}

pub(crate) struct ProductionSqliteAttemptStore {
    store: Arc<SqliteAttemptStore>,
}

pub(crate) struct DurableBrokerDatabaseFile {
    file: File,
    path: PathBuf,
    #[cfg(unix)]
    parent: File,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl SqliteAttemptStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let durable_file = DurableBrokerDatabaseFile::open(path)?;
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(storage)?;
        durable_file.validate_path_binding(path)?;
        let store = Self {
            connection: Mutex::new(connection),
            durable_file: Some(durable_file),
        };
        store.migrate()?;
        store.validate_durable_binding(path)?;
        Ok(store)
    }

    #[cfg(test)]
    pub(crate) fn open_in_memory() -> Result<Self> {
        let connection = Connection::open_in_memory().map_err(storage)?;
        let store = Self {
            connection: Mutex::new(connection),
            durable_file: None,
        };
        store.migrate()?;
        Ok(store)
    }

    fn require_production_profile(&self) -> Result<()> {
        self.durable_file
            .as_ref()
            .ok_or_else(|| {
                BrokerError::AuthorityUnavailable(
                    "production broker attempt storage must be durable SQLite".to_string(),
                )
            })?
            .validate()
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| BrokerError::Storage("attempt store lock is poisoned".to_string()))?;
        if let Some(durable_file) = self.durable_file.as_ref() {
            durable_file.validate()?;
        }
        Ok(connection)
    }

    fn validate_durable_binding(&self, path: &Path) -> Result<()> {
        self.durable_file
            .as_ref()
            .ok_or_else(|| {
                BrokerError::Invariant(
                    "durable attempt store is missing its retained database descriptor".to_string(),
                )
            })?
            .validate_path_binding(path)
    }

    fn migrate(&self) -> Result<()> {
        let connection = self.connection()?;
        connection
            .execute_batch(
                r#"
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = FULL;
                PRAGMA busy_timeout = 5000;
                PRAGMA foreign_keys = ON;
                "#,
            )
            .map_err(storage)?;
        migrate_registered_attempt_state(&connection)?;
        connection
            .execute_batch(
                r#"

                CREATE TABLE IF NOT EXISTS broker_attempts (
                    attempt_id TEXT PRIMARY KEY,
                    operation_id TEXT NOT NULL UNIQUE,
                    invocation_id TEXT NOT NULL,
                    parent_capability_id TEXT NOT NULL,
                    broker_capability_id TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    request_canonical_digest TEXT NOT NULL,
                    proof_digest TEXT NOT NULL,
                    proof_key_id TEXT NOT NULL,
                    proof_nonce TEXT NOT NULL,
                    nonce_expires_at INTEGER NOT NULL CHECK(nonce_expires_at >= 0),
                    hold_id TEXT NOT NULL UNIQUE,
                    authorize_event_id TEXT NOT NULL UNIQUE,
                    reverse_event_id TEXT NOT NULL UNIQUE,
                    capture_event_id TEXT NOT NULL UNIQUE,
                    quotas_json BLOB NOT NULL,
                    authority_metadata_digest TEXT NOT NULL,
                    revocation_authority_domain TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN (
                        'registered', 'prepared', 'held', 'captured', 'dispatch_committed',
                        'reversed', 'unknown_outcome', 'completed', 'failed'
                    )),
                    dispatch_claim_id TEXT,
                    revocation_set_digest TEXT,
                    budget_commit_index INTEGER,
                    revocation_commit_index INTEGER,
                    authority_commit_index INTEGER,
                    leader_epoch INTEGER,
                    response_digest TEXT,
                    updated_at INTEGER NOT NULL CHECK(updated_at >= 0)
                ) STRICT;

                CREATE TABLE IF NOT EXISTS broker_nonces (
                    proof_key_id TEXT NOT NULL,
                    proof_nonce TEXT NOT NULL,
                    attempt_id TEXT NOT NULL UNIQUE,
                    expires_at INTEGER NOT NULL CHECK(expires_at >= 0),
                    PRIMARY KEY (proof_key_id, proof_nonce),
                    FOREIGN KEY (attempt_id) REFERENCES broker_attempts(attempt_id)
                        ON DELETE RESTRICT
                ) STRICT;

                CREATE INDEX IF NOT EXISTS idx_broker_attempts_recovery
                    ON broker_attempts(state, updated_at, attempt_id);
                "#,
            )
            .map_err(storage)?;
        migrate_dispatch_claim_column(&connection)?;
        migrate_registration_binding_columns(&connection)
    }
}

impl ProductionSqliteAttemptStore {
    pub(crate) fn new(store: Arc<SqliteAttemptStore>) -> Result<Self> {
        store.require_production_profile()?;
        Ok(Self { store })
    }

    pub(crate) fn into_attempt_store(self) -> Result<Arc<dyn AttemptStore>> {
        self.store.require_production_profile()?;
        Ok(self.store)
    }
}

fn migrate_registered_attempt_state(connection: &Connection) -> Result<()> {
    let schema: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'broker_attempts'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(storage)?;
    let Some(schema) = schema else {
        return Ok(());
    };
    if schema.contains("'registered'") {
        return Ok(());
    }
    connection
        .execute_batch(
            r#"
            PRAGMA foreign_keys = OFF;
            BEGIN IMMEDIATE;

            ALTER TABLE broker_nonces RENAME TO broker_nonces_before_registration;
            ALTER TABLE broker_attempts RENAME TO broker_attempts_before_registration;

            CREATE TABLE broker_attempts (
                attempt_id TEXT PRIMARY KEY,
                operation_id TEXT NOT NULL UNIQUE,
                invocation_id TEXT NOT NULL,
                parent_capability_id TEXT NOT NULL,
                broker_capability_id TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                proof_digest TEXT NOT NULL,
                proof_key_id TEXT NOT NULL,
                proof_nonce TEXT NOT NULL,
                nonce_expires_at INTEGER NOT NULL CHECK(nonce_expires_at >= 0),
                hold_id TEXT NOT NULL UNIQUE,
                authorize_event_id TEXT NOT NULL UNIQUE,
                reverse_event_id TEXT NOT NULL UNIQUE,
                capture_event_id TEXT NOT NULL UNIQUE,
                quotas_json BLOB NOT NULL,
                authority_metadata_digest TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN (
                    'registered', 'prepared', 'held', 'captured', 'dispatch_committed',
                    'reversed', 'unknown_outcome', 'completed', 'failed'
                )),
                dispatch_claim_id TEXT,
                revocation_set_digest TEXT,
                budget_commit_index INTEGER,
                revocation_commit_index INTEGER,
                authority_commit_index INTEGER,
                leader_epoch INTEGER,
                response_digest TEXT,
                updated_at INTEGER NOT NULL CHECK(updated_at >= 0)
            ) STRICT;

            INSERT INTO broker_attempts (
                attempt_id, operation_id, invocation_id, parent_capability_id,
                broker_capability_id, request_digest, proof_digest, proof_key_id,
                proof_nonce, nonce_expires_at, hold_id, authorize_event_id,
                reverse_event_id, capture_event_id, quotas_json,
                authority_metadata_digest, state, revocation_set_digest,
                budget_commit_index, revocation_commit_index,
                authority_commit_index, leader_epoch, response_digest, updated_at
            )
            SELECT
                attempt_id, operation_id, invocation_id, parent_capability_id,
                broker_capability_id, request_digest, proof_digest, proof_key_id,
                proof_nonce, nonce_expires_at, hold_id, authorize_event_id,
                reverse_event_id, capture_event_id, quotas_json,
                authority_metadata_digest, state, revocation_set_digest,
                budget_commit_index, revocation_commit_index,
                authority_commit_index, leader_epoch, response_digest, updated_at
            FROM broker_attempts_before_registration;

            CREATE TABLE broker_nonces (
                proof_key_id TEXT NOT NULL,
                proof_nonce TEXT NOT NULL,
                attempt_id TEXT NOT NULL UNIQUE,
                expires_at INTEGER NOT NULL CHECK(expires_at >= 0),
                PRIMARY KEY (proof_key_id, proof_nonce),
                FOREIGN KEY (attempt_id) REFERENCES broker_attempts(attempt_id)
                    ON DELETE RESTRICT
            ) STRICT;

            INSERT INTO broker_nonces (proof_key_id, proof_nonce, attempt_id, expires_at)
            SELECT proof_key_id, proof_nonce, attempt_id, expires_at
            FROM broker_nonces_before_registration;

            DROP TABLE broker_nonces_before_registration;
            DROP TABLE broker_attempts_before_registration;
            CREATE INDEX idx_broker_attempts_recovery
                ON broker_attempts(state, updated_at, attempt_id);

            COMMIT;
            PRAGMA foreign_keys = ON;
            "#,
        )
        .map_err(storage)
}

fn migrate_dispatch_claim_column(connection: &Connection) -> Result<()> {
    let mut statement = connection
        .prepare("PRAGMA table_info(broker_attempts)")
        .map_err(storage)?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(storage)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(storage)?;
    drop(statement);
    if !columns.iter().any(|column| column == "dispatch_claim_id") {
        connection
            .execute(
                "ALTER TABLE broker_attempts ADD COLUMN dispatch_claim_id TEXT",
                [],
            )
            .map_err(storage)?;
    }
    Ok(())
}

fn migrate_registration_binding_columns(connection: &Connection) -> Result<()> {
    let mut statement = connection
        .prepare("PRAGMA table_info(broker_attempts)")
        .map_err(storage)?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(storage)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(storage)?;
    drop(statement);
    if !columns
        .iter()
        .any(|column| column == "request_canonical_digest")
    {
        connection
            .execute(
                "ALTER TABLE broker_attempts ADD COLUMN request_canonical_digest TEXT NOT NULL DEFAULT ''",
                [],
            )
            .map_err(storage)?;
    }
    if !columns
        .iter()
        .any(|column| column == "revocation_authority_domain")
    {
        connection
            .execute(
                "ALTER TABLE broker_attempts ADD COLUMN revocation_authority_domain TEXT NOT NULL DEFAULT ''",
                [],
            )
            .map_err(storage)?;
    }
    // Rows written before canonical request binding cannot be resumed safely.
    // Preserve them for audit, but terminalize them during the schema upgrade.
    connection
        .execute(
            r#"
            UPDATE broker_attempts
            SET request_canonical_digest = ?1,
                revocation_authority_domain = 'legacy-unbound',
                state = 'failed',
                dispatch_claim_id = NULL
            WHERE request_canonical_digest = ''
               OR revocation_authority_domain = ''
            "#,
            params!["0".repeat(64)],
        )
        .map_err(storage)?;
    Ok(())
}

impl DurableBrokerDatabaseFile {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        reject_volatile_attempt_database_path(path)?;
        #[cfg(unix)]
        {
            let parent = open_trusted_attempt_parent(path)?;
            let file = open_broker_database_at(&parent, path, true, true)?;
            validate_attempt_file_authority(&file, true)?;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|error| {
                    BrokerError::Storage(format!(
                        "broker database permission hardening failed: {error}"
                    ))
                })?;
            validate_attempt_file_authority(&file, true)?;
            file.sync_all().map_err(|error| {
                BrokerError::Storage(format!("broker database sync failed: {error}"))
            })?;
            parent.sync_all().map_err(|error| {
                BrokerError::Storage(format!("broker database parent sync failed: {error}"))
            })?;
            let metadata = file.metadata().map_err(|error| {
                BrokerError::Storage(format!("broker database metadata failed: {error}"))
            })?;
            let opened = Self {
                file,
                path: path.to_path_buf(),
                parent,
                device: metadata.dev(),
                inode: metadata.ino(),
            };
            opened.validate_path_binding(path)?;
            Ok(opened)
        }
        #[cfg(not(unix))]
        {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(path)
                .map_err(|error| {
                    BrokerError::Storage(format!("broker database creation failed: {error}"))
                })?;
            let opened = Self {
                file,
                path: path.to_path_buf(),
            };
            opened.validate_path_binding(path)?;
            Ok(opened)
        }
    }

    pub(crate) fn open_existing_read_only(path: &Path) -> Result<Self> {
        reject_volatile_attempt_database_path(path)?;
        #[cfg(unix)]
        {
            let parent = open_trusted_attempt_parent(path)?;
            let file = open_broker_database_at(&parent, path, false, false)?;
            validate_attempt_file_authority(&file, true)?;
            let metadata = file.metadata().map_err(|error| {
                BrokerError::Storage(format!("broker database metadata failed: {error}"))
            })?;
            let opened = Self {
                file,
                path: path.to_path_buf(),
                parent,
                device: metadata.dev(),
                inode: metadata.ino(),
            };
            opened.validate_path_binding(path)?;
            Ok(opened)
        }
        #[cfg(not(unix))]
        {
            let file = OpenOptions::new().read(true).open(path).map_err(|error| {
                BrokerError::Storage(format!("broker database open failed: {error}"))
            })?;
            let opened = Self {
                file,
                path: path.to_path_buf(),
            };
            opened.validate_path_binding(path)?;
            Ok(opened)
        }
    }

    pub(crate) fn try_clone_file(&self) -> Result<File> {
        self.file.try_clone().map_err(|error| {
            BrokerError::Storage(format!("broker database descriptor clone failed: {error}"))
        })
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.validate_path_binding(&self.path)
    }

    fn validate_path_binding(&self, path: &Path) -> Result<()> {
        #[cfg(unix)]
        {
            let current_parent = open_trusted_attempt_parent(path)?;
            let retained_parent = self.parent.metadata().map_err(|error| {
                BrokerError::Storage(format!(
                    "broker database retained parent metadata failed: {error}"
                ))
            })?;
            let current_parent_metadata = current_parent.metadata().map_err(|error| {
                BrokerError::Storage(format!(
                    "broker database current parent metadata failed: {error}"
                ))
            })?;
            if retained_parent.dev() != current_parent_metadata.dev()
                || retained_parent.ino() != current_parent_metadata.ino()
            {
                return Err(BrokerError::Storage(
                    "broker database parent identity changed".to_string(),
                ));
            }
            let current_file = open_broker_database_at(&current_parent, path, false, false)?;
            validate_attempt_file_authority(&self.file, true)?;
            validate_attempt_file_authority(&current_file, true)?;
            let retained_metadata = self.file.metadata().map_err(|error| {
                BrokerError::Storage(format!("broker database metadata failed: {error}"))
            })?;
            let current_metadata = current_file.metadata().map_err(|error| {
                BrokerError::Storage(format!("broker database path metadata failed: {error}"))
            })?;
            if retained_metadata.dev() != self.device
                || retained_metadata.ino() != self.inode
                || current_metadata.dev() != self.device
                || current_metadata.ino() != self.inode
            {
                return Err(BrokerError::Storage(
                    "broker database descriptor identity changed".to_string(),
                ));
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let path_metadata = fs::symlink_metadata(path).map_err(|error| {
                BrokerError::Storage(format!("broker database path metadata failed: {error}"))
            })?;
            let file_metadata = self.file.metadata().map_err(|error| {
                BrokerError::Storage(format!("broker database metadata failed: {error}"))
            })?;
            if path_metadata.file_type().is_symlink()
                || !path_metadata.file_type().is_file()
                || !file_metadata.file_type().is_file()
            {
                return Err(BrokerError::Storage(
                    "broker database path is not a stable regular file".to_string(),
                ));
            }
            Ok(())
        }
    }
}

fn reject_volatile_attempt_database_path(path: &Path) -> Result<()> {
    let text = path.to_string_lossy();
    if text == ":memory:" || text.to_ascii_lowercase().starts_with("file:") {
        return Err(BrokerError::Storage(
            "broker database must use a durable filesystem path".to_string(),
        ));
    }
    if !path.is_absolute() {
        return Err(BrokerError::Storage(
            "broker database path must be absolute".to_string(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn open_trusted_attempt_parent(path: &Path) -> Result<File> {
    let parent = path.parent().ok_or_else(|| {
        BrokerError::Storage("broker database path has no parent directory".to_string())
    })?;
    let mut names = Vec::new();
    for component in parent.components() {
        match component {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(name) => names.push(name.to_os_string()),
            std::path::Component::Prefix(_) => {
                return Err(BrokerError::Storage(
                    "broker database path has an unsupported prefix".to_string(),
                ));
            }
            std::path::Component::CurDir | std::path::Component::ParentDir => {
                return Err(BrokerError::Storage(
                    "broker database path contains a dot component".to_string(),
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
    .map_err(|error| BrokerError::Storage(format!("broker database root open failed: {error}")))?;
    let mut directory = File::from(root);
    validate_attempt_parent_descriptor(&directory, !names.is_empty())?;
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
            BrokerError::Storage(format!("broker database ancestor open failed: {error}"))
        })?;
        let next = File::from(descriptor);
        validate_attempt_parent_descriptor(&next, index + 1 != name_count)?;
        directory = next;
    }
    Ok(directory)
}

#[cfg(unix)]
fn validate_attempt_parent_descriptor(directory: &File, allow_sticky_write: bool) -> Result<()> {
    let metadata = directory.metadata().map_err(|error| {
        BrokerError::Storage(format!("broker database parent metadata failed: {error}"))
    })?;
    let effective_uid = rustix::process::geteuid().as_raw();
    let trusted_owner = metadata.uid() == effective_uid || metadata.uid() == 0;
    let group_or_world_writable = metadata.mode() & 0o022 != 0;
    let sticky = metadata.mode() & 0o1000 != 0;
    if !metadata.file_type().is_dir()
        || !trusted_owner
        || (group_or_world_writable && !(allow_sticky_write && sticky))
        || attempt_file_grants_extended_acl_authority(directory)?
    {
        return Err(BrokerError::Storage(
            "broker database parent chain grants untrusted write authority".to_string(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn open_broker_database_at(
    parent: &File,
    path: &Path,
    writable: bool,
    create: bool,
) -> Result<File> {
    let file_name = path
        .file_name()
        .ok_or_else(|| BrokerError::Storage("broker database path has no file name".to_string()))?;
    let mut flags = rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC;
    flags |= if writable {
        rustix::fs::OFlags::RDWR
    } else {
        rustix::fs::OFlags::RDONLY
    };
    if create {
        flags |= rustix::fs::OFlags::CREATE;
    }
    rustix::fs::openat(
        parent,
        file_name,
        flags,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .map(File::from)
    .map_err(|error| BrokerError::Storage(format!("broker database open failed: {error}")))
}

#[cfg(unix)]
fn validate_attempt_file_authority(file: &File, require_private_mode: bool) -> Result<()> {
    let metadata = file.metadata().map_err(|error| {
        BrokerError::Storage(format!("broker database metadata failed: {error}"))
    })?;
    let effective_uid = rustix::process::geteuid().as_raw();
    if !metadata.file_type().is_file()
        || (metadata.uid() != effective_uid && metadata.uid() != 0)
        || metadata.nlink() != 1
        || (require_private_mode && metadata.mode() & 0o077 != 0)
        || attempt_file_grants_extended_acl_authority(file)?
    {
        return Err(BrokerError::Storage(
            "broker database must have trusted ownership, mode 0600 or stricter, no authority-granting ACL, and one hard link"
                .to_string(),
        ));
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn attempt_file_grants_extended_acl_authority(file: &File) -> Result<bool> {
    for attribute in ["system.posix_acl_access", "system.posix_acl_default"] {
        let mut value = Vec::<u8>::with_capacity(1);
        match rustix::fs::fgetxattr(file, attribute, &mut value) {
            Ok(_) | Err(rustix::io::Errno::RANGE) => return Ok(true),
            Err(error) if error == rustix::io::Errno::NODATA => {}
            Err(error) if error == rustix::io::Errno::NOTSUP => {}
            Err(error) => {
                return Err(BrokerError::Storage(format!(
                    "broker database ACL inspection failed: {error}"
                )));
            }
        }
    }
    Ok(false)
}

#[cfg(target_vendor = "apple")]
fn attempt_file_grants_extended_acl_authority(file: &File) -> Result<bool> {
    chio_keyring::darwin_descriptor_grants_extended_acl_authority(file).map_err(|error| {
        BrokerError::Storage(format!("broker database ACL inspection failed: {error}"))
    })
}

#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android", target_vendor = "apple"))
))]
fn attempt_file_grants_extended_acl_authority(_file: &File) -> Result<bool> {
    Err(BrokerError::Storage(
        "broker database ACL inspection is unsupported on this platform".to_string(),
    ))
}

fn register_with_initial_state(
    store: &SqliteAttemptStore,
    registration: &AttemptRegistration,
    now_unix_seconds: u64,
    initial_state: AttemptState,
) -> Result<RegisterAttemptOutcome> {
    if !matches!(
        initial_state,
        AttemptState::Registered | AttemptState::Prepared
    ) {
        return Err(BrokerError::Invariant(
            "attempt registration initial state is invalid".to_string(),
        ));
    }
    registration.validate()?;
    if now_unix_seconds > registration.nonce_expires_at_unix_seconds {
        return Err(BrokerError::AuthorizationDenied(
            "request proof nonce is already expired".to_string(),
        ));
    }
    let mut connection = store.connection()?;
    let transaction = connection.transaction().map_err(storage)?;
    if let Some(existing) = load_attempt_in_transaction(&transaction, &registration.ids.attempt_id)?
    {
        if existing.registration != *registration {
            return Err(BrokerError::Conflict(
                "deterministic attempt ID was reused with different input".to_string(),
            ));
        }
        transaction.commit().map_err(storage)?;
        return Ok(RegisterAttemptOutcome::ExactRetry(existing));
    }

    let claimed_attempt: Option<String> = transaction
        .query_row(
            "SELECT attempt_id FROM broker_nonces WHERE proof_key_id = ?1 AND proof_nonce = ?2",
            params![registration.proof_key_id, registration.proof_nonce],
            |row| row.get(0),
        )
        .optional()
        .map_err(storage)?;
    if claimed_attempt.is_some() {
        return Err(BrokerError::AuthorizationDenied(
            "request proof nonce was already consumed".to_string(),
        ));
    }

    let quotas = canonical_json_bytes(&registration.quotas).map_err(|error| {
        BrokerError::Invariant(format!("attempt quota encoding failed: {error}"))
    })?;
    transaction
        .execute(
            r#"
            INSERT INTO broker_attempts (
                attempt_id, operation_id, invocation_id, parent_capability_id,
                broker_capability_id, request_digest, request_canonical_digest,
                proof_digest, proof_key_id,
                proof_nonce, nonce_expires_at, hold_id, authorize_event_id,
                reverse_event_id, capture_event_id, quotas_json,
                authority_metadata_digest, revocation_authority_domain, state, updated_at
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20
            )
            "#,
            params![
                registration.ids.attempt_id,
                registration.ids.operation_id,
                registration.invocation_id,
                registration.parent_capability_id,
                registration.broker_capability_id,
                registration.request_digest,
                registration.request_canonical_digest,
                registration.proof_digest,
                registration.proof_key_id,
                registration.proof_nonce,
                sqlite_u64(registration.nonce_expires_at_unix_seconds, "nonce expiry")?,
                registration.ids.hold_id,
                registration.ids.authorize_event_id,
                registration.ids.reverse_event_id,
                registration.ids.capture_event_id,
                quotas,
                registration.authority_metadata_digest,
                registration.revocation_authority_domain,
                initial_state.as_str(),
                sqlite_u64(now_unix_seconds, "attempt update time")?,
            ],
        )
        .map_err(storage)?;
    transaction
        .execute(
            r#"
            INSERT INTO broker_nonces (proof_key_id, proof_nonce, attempt_id, expires_at)
            VALUES (?1, ?2, ?3, ?4)
            "#,
            params![
                registration.proof_key_id,
                registration.proof_nonce,
                registration.ids.attempt_id,
                sqlite_u64(registration.nonce_expires_at_unix_seconds, "nonce expiry")?,
            ],
        )
        .map_err(storage)?;
    let record = load_attempt_in_transaction(&transaction, &registration.ids.attempt_id)?
        .ok_or_else(|| {
            BrokerError::Invariant("inserted attempt could not be reloaded".to_string())
        })?;
    transaction.commit().map_err(storage)?;
    Ok(RegisterAttemptOutcome::Inserted(record))
}

impl AttemptStore for SqliteAttemptStore {
    fn register_intent(
        &self,
        registration: &AttemptRegistration,
        now_unix_seconds: u64,
    ) -> Result<RegisterAttemptOutcome> {
        register_with_initial_state(
            self,
            registration,
            now_unix_seconds,
            AttemptState::Registered,
        )
    }

    fn claim_registered_attempt(&self, attempt_id: &str, now_unix_seconds: u64) -> Result<bool> {
        crate::validate_identifier(attempt_id, "attempt id", 512)?;
        let connection = self.connection()?;
        let changed = connection
            .execute(
                r#"
                UPDATE broker_attempts
                SET state = 'prepared', updated_at = ?1
                WHERE attempt_id = ?2 AND state = 'registered'
                "#,
                params![
                    sqlite_u64(now_unix_seconds, "attempt claim time")?,
                    attempt_id,
                ],
            )
            .map_err(storage)?;
        Ok(changed == 1)
    }

    fn register_attempt(
        &self,
        registration: &AttemptRegistration,
        now_unix_seconds: u64,
    ) -> Result<RegisterAttemptOutcome> {
        register_with_initial_state(self, registration, now_unix_seconds, AttemptState::Prepared)
    }

    fn load_attempt(&self, attempt_id: &str) -> Result<Option<AttemptRecord>> {
        let connection = self.connection()?;
        load_attempt_from_connection(&connection, attempt_id)
    }

    fn transition(
        &self,
        attempt_id: &str,
        expected: AttemptState,
        next: AttemptState,
        evidence: &AttemptTransitionEvidence,
        now_unix_seconds: u64,
    ) -> Result<AttemptRecord> {
        if !expected.permits(next) {
            return Err(BrokerError::Invariant(
                "requested attempt transition is not permitted".to_string(),
            ));
        }
        validate_transition_evidence(next, evidence)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction().map_err(storage)?;
        let current = load_attempt_in_transaction(&transaction, attempt_id)?
            .ok_or_else(|| BrokerError::Storage("broker attempt was not found".to_string()))?;
        if current.state == next && current.state != expected {
            validate_repeated_evidence(&current, evidence)?;
            transaction.commit().map_err(storage)?;
            return Ok(current);
        }
        if current.state != expected {
            return Err(BrokerError::Conflict(format!(
                "attempt transition expected {} but found {}",
                expected.as_str(),
                current.state.as_str()
            )));
        }
        validate_existing_evidence(&current, evidence)?;
        let changed = transaction
            .execute(
                r#"
                UPDATE broker_attempts
                SET state = ?1,
                    dispatch_claim_id = CASE
                        WHEN ?1 = 'captured' THEN dispatch_claim_id
                        ELSE NULL
                    END,
                    revocation_set_digest = COALESCE(?2, revocation_set_digest),
                    budget_commit_index = COALESCE(?3, budget_commit_index),
                    revocation_commit_index = COALESCE(?4, revocation_commit_index),
                    authority_commit_index = COALESCE(?5, authority_commit_index),
                    leader_epoch = COALESCE(?6, leader_epoch),
                    response_digest = COALESCE(?7, response_digest),
                    updated_at = ?8
                WHERE attempt_id = ?9 AND state = ?10
                "#,
                params![
                    next.as_str(),
                    evidence.revocation_set_digest,
                    evidence
                        .budget_commit_index
                        .map(|value| sqlite_u64(value, "budget index"))
                        .transpose()?,
                    evidence
                        .revocation_commit_index
                        .map(|value| sqlite_u64(value, "revocation index"))
                        .transpose()?,
                    evidence
                        .authority_commit_index
                        .map(|value| sqlite_u64(value, "authority index"))
                        .transpose()?,
                    evidence
                        .leader_epoch
                        .map(|value| sqlite_u64(value, "leader epoch"))
                        .transpose()?,
                    evidence.response_digest,
                    sqlite_u64(now_unix_seconds, "attempt update time")?,
                    attempt_id,
                    expected.as_str(),
                ],
            )
            .map_err(storage)?;
        if changed != 1 {
            return Err(BrokerError::Conflict(
                "attempt transition lost its compare-and-swap".to_string(),
            ));
        }
        let updated = load_attempt_in_transaction(&transaction, attempt_id)?
            .ok_or_else(|| BrokerError::Invariant("updated attempt disappeared".to_string()))?;
        transaction.commit().map_err(storage)?;
        Ok(updated)
    }

    fn claim_captured_attempt(
        &self,
        attempt_id: &str,
        dispatch_claim_id: &str,
        now_unix_seconds: u64,
    ) -> Result<bool> {
        crate::validate_identifier(attempt_id, "attempt id", 512)?;
        crate::validate_identifier(dispatch_claim_id, "dispatch claim id", 512)?;
        let connection = self.connection()?;
        let changed = connection
            .execute(
                r#"
                UPDATE broker_attempts
                SET dispatch_claim_id = ?1, updated_at = ?2
                WHERE attempt_id = ?3
                  AND state = 'captured'
                  AND dispatch_claim_id IS NULL
                "#,
                params![
                    dispatch_claim_id,
                    sqlite_u64(now_unix_seconds, "attempt claim time")?,
                    attempt_id,
                ],
            )
            .map_err(storage)?;
        Ok(changed == 1)
    }

    fn release_captured_attempt_claim(
        &self,
        attempt_id: &str,
        dispatch_claim_id: &str,
        now_unix_seconds: u64,
    ) -> Result<bool> {
        crate::validate_identifier(attempt_id, "attempt id", 512)?;
        crate::validate_identifier(dispatch_claim_id, "dispatch claim id", 512)?;
        let connection = self.connection()?;
        let changed = connection
            .execute(
                r#"
                UPDATE broker_attempts
                SET dispatch_claim_id = NULL, updated_at = ?1
                WHERE attempt_id = ?2
                  AND state = 'captured'
                  AND dispatch_claim_id = ?3
                "#,
                params![
                    sqlite_u64(now_unix_seconds, "attempt claim release time")?,
                    attempt_id,
                    dispatch_claim_id,
                ],
            )
            .map_err(storage)?;
        Ok(changed == 1)
    }

    fn commit_captured_attempt_dispatch(
        &self,
        attempt_id: &str,
        dispatch_claim_id: &str,
        evidence: &AttemptTransitionEvidence,
        now_unix_seconds: u64,
    ) -> Result<AttemptRecord> {
        crate::validate_identifier(attempt_id, "attempt id", 512)?;
        crate::validate_identifier(dispatch_claim_id, "dispatch claim id", 512)?;
        validate_transition_evidence(AttemptState::DispatchCommitted, evidence)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction().map_err(storage)?;
        let current = load_attempt_in_transaction(&transaction, attempt_id)?
            .ok_or_else(|| BrokerError::Storage("broker attempt was not found".to_string()))?;
        if current.state != AttemptState::Captured
            || current.dispatch_claim_id.as_deref() != Some(dispatch_claim_id)
        {
            return Err(BrokerError::Conflict(
                "captured attempt dispatch claim is absent or owned by another caller".to_string(),
            ));
        }
        validate_existing_evidence(&current, evidence)?;
        let changed = transaction
            .execute(
                r#"
                UPDATE broker_attempts
                SET state = 'dispatch_committed',
                    dispatch_claim_id = NULL,
                    revocation_set_digest = COALESCE(?1, revocation_set_digest),
                    budget_commit_index = COALESCE(?2, budget_commit_index),
                    revocation_commit_index = COALESCE(?3, revocation_commit_index),
                    authority_commit_index = COALESCE(?4, authority_commit_index),
                    leader_epoch = COALESCE(?5, leader_epoch),
                    updated_at = ?6
                WHERE attempt_id = ?7
                  AND state = 'captured'
                  AND dispatch_claim_id = ?8
                "#,
                params![
                    evidence.revocation_set_digest,
                    evidence
                        .budget_commit_index
                        .map(|value| sqlite_u64(value, "budget index"))
                        .transpose()?,
                    evidence
                        .revocation_commit_index
                        .map(|value| sqlite_u64(value, "revocation index"))
                        .transpose()?,
                    evidence
                        .authority_commit_index
                        .map(|value| sqlite_u64(value, "authority index"))
                        .transpose()?,
                    evidence
                        .leader_epoch
                        .map(|value| sqlite_u64(value, "leader epoch"))
                        .transpose()?,
                    sqlite_u64(now_unix_seconds, "dispatch commit time")?,
                    attempt_id,
                    dispatch_claim_id,
                ],
            )
            .map_err(storage)?;
        if changed != 1 {
            return Err(BrokerError::Conflict(
                "captured attempt dispatch claim was lost".to_string(),
            ));
        }
        let updated = load_attempt_in_transaction(&transaction, attempt_id)?
            .ok_or_else(|| BrokerError::Invariant("updated attempt disappeared".to_string()))?;
        transaction.commit().map_err(storage)?;
        Ok(updated)
    }

    fn clear_stale_captured_attempt_claim(
        &self,
        attempt_id: &str,
        now_unix_seconds: u64,
    ) -> Result<AttemptRecord> {
        crate::validate_identifier(attempt_id, "attempt id", 512)?;
        let connection = self.connection()?;
        connection
            .execute(
                r#"
                UPDATE broker_attempts
                SET dispatch_claim_id = NULL, updated_at = ?1
                WHERE attempt_id = ?2 AND state = 'captured'
                "#,
                params![
                    sqlite_u64(now_unix_seconds, "stale claim recovery time")?,
                    attempt_id,
                ],
            )
            .map_err(storage)?;
        load_attempt_from_connection(&connection, attempt_id)?
            .ok_or_else(|| BrokerError::Storage("broker attempt was not found".to_string()))
    }

    fn recoverable_attempts(
        &self,
        after_attempt_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AttemptRecord>> {
        if limit == 0 || limit > 1_000 {
            return Err(BrokerError::InvalidRequest(
                "recovery batch limit is invalid".to_string(),
            ));
        }
        if let Some(cursor) = after_attempt_id {
            crate::validate_identifier(cursor, "recovery attempt cursor", 512)?;
        }
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                r#"
                SELECT attempt_id
                FROM broker_attempts
                WHERE state IN ('registered', 'prepared', 'held', 'captured', 'dispatch_committed', 'unknown_outcome')
                  AND (?1 IS NULL OR attempt_id > ?1)
                ORDER BY attempt_id
                LIMIT ?2
                "#,
            )
            .map_err(storage)?;
        let attempt_ids = statement
            .query_map(
                params![
                    after_attempt_id,
                    i64::try_from(limit).map_err(|_| {
                        BrokerError::InvalidRequest(
                            "recovery limit exceeds SQLite range".to_string(),
                        )
                    })?,
                ],
                |row| row.get::<_, String>(0),
            )
            .map_err(storage)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(storage)?;
        let mut records = Vec::with_capacity(attempt_ids.len());
        for attempt_id in attempt_ids {
            records.push(
                load_attempt_from_connection(&connection, &attempt_id)?.ok_or_else(|| {
                    BrokerError::Invariant("recovery attempt disappeared".to_string())
                })?,
            );
        }
        Ok(records)
    }
}

fn load_attempt_in_transaction(
    transaction: &Transaction<'_>,
    attempt_id: &str,
) -> Result<Option<AttemptRecord>> {
    load_attempt_row(transaction, attempt_id)
}

fn load_attempt_from_connection(
    connection: &Connection,
    attempt_id: &str,
) -> Result<Option<AttemptRecord>> {
    load_attempt_row(connection, attempt_id)
}

fn load_attempt_row(connection: &Connection, attempt_id: &str) -> Result<Option<AttemptRecord>> {
    let row = connection
        .query_row(
            r#"
            SELECT attempt_id, operation_id, invocation_id, parent_capability_id,
                   broker_capability_id, request_digest, request_canonical_digest,
                   proof_digest, proof_key_id,
                   proof_nonce, nonce_expires_at, hold_id, authorize_event_id,
                   reverse_event_id, capture_event_id, quotas_json,
                   authority_metadata_digest, revocation_authority_domain,
                   state, revocation_set_digest,
                   budget_commit_index, revocation_commit_index, authority_commit_index,
                   leader_epoch, response_digest, dispatch_claim_id, updated_at
            FROM broker_attempts
            WHERE attempt_id = ?1
            "#,
            [attempt_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, String>(13)?,
                    row.get::<_, String>(14)?,
                    row.get::<_, Vec<u8>>(15)?,
                    row.get::<_, String>(16)?,
                    row.get::<_, String>(17)?,
                    row.get::<_, String>(18)?,
                    row.get::<_, Option<String>>(19)?,
                    row.get::<_, Option<i64>>(20)?,
                    row.get::<_, Option<i64>>(21)?,
                    row.get::<_, Option<i64>>(22)?,
                    row.get::<_, Option<i64>>(23)?,
                    row.get::<_, Option<String>>(24)?,
                    row.get::<_, Option<String>>(25)?,
                    row.get::<_, i64>(26)?,
                ))
            },
        )
        .optional()
        .map_err(storage)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let quotas: Vec<ExecutionQuota> = serde_json::from_slice(&row.15)
        .map_err(|error| BrokerError::Invariant(format!("stored quota set is invalid: {error}")))?;
    let record = AttemptRecord {
        registration: AttemptRegistration {
            ids: AttemptIds {
                attempt_id: row.0,
                operation_id: row.1,
                hold_id: row.11,
                authorize_event_id: row.12,
                reverse_event_id: row.13,
                capture_event_id: row.14,
            },
            invocation_id: row.2,
            parent_capability_id: row.3,
            broker_capability_id: row.4,
            request_digest: row.5,
            request_canonical_digest: row.6,
            proof_digest: row.7,
            proof_key_id: row.8,
            proof_nonce: row.9,
            nonce_expires_at_unix_seconds: nonnegative_u64(row.10, "nonce expiry")?,
            quotas,
            authority_metadata_digest: row.16,
            revocation_authority_domain: row.17,
        },
        state: AttemptState::parse(&row.18)?,
        dispatch_claim_id: row.25,
        revocation_set_digest: row.19,
        budget_commit_index: optional_u64(row.20, "budget commit index")?,
        revocation_commit_index: optional_u64(row.21, "revocation commit index")?,
        authority_commit_index: optional_u64(row.22, "authority commit index")?,
        leader_epoch: optional_u64(row.23, "leader epoch")?,
        response_digest: row.24,
        updated_at_unix_seconds: nonnegative_u64(row.26, "attempt update time")?,
    };
    record.registration.validate()?;
    validate_record_evidence(&record)?;
    Ok(Some(record))
}

fn validate_repeated_evidence(
    current: &AttemptRecord,
    evidence: &AttemptTransitionEvidence,
) -> Result<()> {
    validate_existing_evidence(current, evidence)?;
    for (incoming, stored, label) in [
        (
            evidence.revocation_set_digest.as_ref(),
            current.revocation_set_digest.as_ref(),
            "revocation-set digest",
        ),
        (
            evidence.response_digest.as_ref(),
            current.response_digest.as_ref(),
            "response digest",
        ),
    ] {
        if incoming.is_some() && incoming != stored {
            return Err(BrokerError::Conflict(format!(
                "repeated transition changed {label}"
            )));
        }
    }
    Ok(())
}

fn validate_existing_evidence(
    current: &AttemptRecord,
    evidence: &AttemptTransitionEvidence,
) -> Result<()> {
    for (incoming, stored, label) in [
        (
            evidence.revocation_set_digest.as_ref(),
            current.revocation_set_digest.as_ref(),
            "revocation-set digest",
        ),
        (
            evidence.response_digest.as_ref(),
            current.response_digest.as_ref(),
            "response digest",
        ),
    ] {
        if stored.is_some() && incoming.is_some() && incoming != stored {
            return Err(BrokerError::Conflict(format!(
                "attempt transition changed {label}"
            )));
        }
    }
    for (incoming, stored, label) in [
        (
            evidence.budget_commit_index,
            current.budget_commit_index,
            "budget commit index",
        ),
        (
            evidence.revocation_commit_index,
            current.revocation_commit_index,
            "revocation commit index",
        ),
        (
            evidence.authority_commit_index,
            current.authority_commit_index,
            "authority commit index",
        ),
        (evidence.leader_epoch, current.leader_epoch, "leader epoch"),
    ] {
        if stored.is_some() && incoming.is_some() && incoming != stored {
            return Err(BrokerError::Conflict(format!(
                "attempt transition changed {label}"
            )));
        }
    }
    Ok(())
}

fn validate_transition_evidence(
    next: AttemptState,
    evidence: &AttemptTransitionEvidence,
) -> Result<()> {
    if let Some(digest) = &evidence.revocation_set_digest {
        validate_digest(digest, "transition revocation-set digest")?;
    }
    if let Some(digest) = &evidence.response_digest {
        validate_digest(digest, "transition response digest")?;
    }
    if matches!(
        next,
        AttemptState::Captured | AttemptState::DispatchCommitted | AttemptState::Completed
    ) && (evidence.revocation_set_digest.is_none()
        || evidence.budget_commit_index.is_none()
        || evidence.revocation_commit_index.is_none()
        || evidence.authority_commit_index.is_none()
        || evidence.leader_epoch.is_none())
    {
        return Err(BrokerError::Invariant(
            "captured transition lacks atomic authority evidence".to_string(),
        ));
    }
    if next == AttemptState::Completed && evidence.response_digest.is_none() {
        return Err(BrokerError::Invariant(
            "completed transition lacks a response digest".to_string(),
        ));
    }
    Ok(())
}

fn validate_record_evidence(record: &AttemptRecord) -> Result<()> {
    if let Some(claim_id) = record.dispatch_claim_id.as_deref() {
        crate::validate_identifier(claim_id, "dispatch claim id", 512)?;
        if record.state != AttemptState::Captured {
            return Err(BrokerError::Invariant(
                "dispatch claim is attached to a non-captured attempt".to_string(),
            ));
        }
    }
    let evidence = AttemptTransitionEvidence {
        revocation_set_digest: record.revocation_set_digest.clone(),
        budget_commit_index: record.budget_commit_index,
        revocation_commit_index: record.revocation_commit_index,
        authority_commit_index: record.authority_commit_index,
        leader_epoch: record.leader_epoch,
        response_digest: record.response_digest.clone(),
    };
    validate_transition_evidence(record.state, &evidence)
}

fn storage(error: rusqlite::Error) -> BrokerError {
    BrokerError::Storage(format!("broker SQLite operation failed: {error}"))
}

fn sqlite_u64(value: u64, label: &str) -> Result<i64> {
    i64::try_from(value)
        .map_err(|_| BrokerError::InvalidRequest(format!("{label} exceeds SQLite range")))
}

fn nonnegative_u64(value: i64, label: &str) -> Result<u64> {
    u64::try_from(value).map_err(|_| BrokerError::Invariant(format!("stored {label} is negative")))
}

fn optional_u64(value: Option<i64>, label: &str) -> Result<Option<u64>> {
    value.map(|inner| nonnegative_u64(inner, label)).transpose()
}

#[cfg(test)]
mod tests {
    use chio_test_support::prelude::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    use super::*;
    use crate::store::derive_attempt_ids;

    fn registration(nonce: &str) -> AttemptRegistration {
        let request_digest = "a".repeat(64);
        AttemptRegistration {
            ids: derive_attempt_ids("broker-cap", "invocation", nonce, &request_digest)
                .test_expect("ids"),
            invocation_id: "invocation".to_string(),
            parent_capability_id: "parent-cap".to_string(),
            broker_capability_id: "broker-cap".to_string(),
            request_digest,
            request_canonical_digest: "d".repeat(64),
            proof_digest: "b".repeat(64),
            proof_key_id: "proof-key".to_string(),
            proof_nonce: nonce.to_string(),
            nonce_expires_at_unix_seconds: 100,
            quotas: vec![ExecutionQuota {
                key_id: "broker-quota".to_string(),
                maximum_executions: 1,
            }],
            authority_metadata_digest: "c".repeat(64),
            revocation_authority_domain: "combined-authority".to_string(),
        }
    }

    #[test]
    fn production_profile_rejects_in_memory_attempt_storage() {
        let store = Arc::new(SqliteAttemptStore::open_in_memory().test_expect("store"));
        let result = ProductionSqliteAttemptStore::new(store);
        assert!(matches!(
            result,
            Err(BrokerError::AuthorityUnavailable(message))
                if message == "production broker attempt storage must be durable SQLite"
        ));
    }

    #[test]
    fn nonce_and_prepared_intent_commit_atomically_and_retry_exactly() {
        let store = SqliteAttemptStore::open_in_memory().test_expect("store");
        let registration = registration("nonce-abcdefghijkl");
        assert!(matches!(
            store
                .register_attempt(&registration, 10)
                .test_expect("insert"),
            RegisterAttemptOutcome::Inserted(_)
        ));
        assert!(matches!(
            store
                .register_attempt(&registration, 11)
                .test_expect("retry"),
            RegisterAttemptOutcome::ExactRetry(_)
        ));
    }

    #[test]
    fn concurrent_replay_has_one_insert_and_exact_retries_only() {
        let directory = crate::private_tempdir().test_expect("temporary directory");
        let trusted_directory =
            std::fs::canonicalize(directory.path()).test_expect("canonicalize database directory");
        let path = trusted_directory.join("attempts.sqlite3");
        let store = Arc::new(SqliteAttemptStore::open(&path).test_expect("store"));
        let barrier = Arc::new(Barrier::new(8));
        let mut workers = Vec::new();
        for _ in 0..8 {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                barrier.wait();
                store.register_attempt(&registration("nonce-abcdefghijkl"), 10)
            }));
        }
        let mut inserted = 0;
        for worker in workers {
            match worker.join().test_expect("join").test_expect("register") {
                RegisterAttemptOutcome::Inserted(_) => inserted += 1,
                RegisterAttemptOutcome::ExactRetry(_) => {}
            }
        }
        assert_eq!(inserted, 1);
    }

    #[test]
    fn state_machine_refuses_dispatch_without_capture() {
        let store = SqliteAttemptStore::open_in_memory().test_expect("store");
        let registration = registration("nonce-abcdefghijkl");
        store
            .register_attempt(&registration, 10)
            .test_expect("insert");
        assert!(store
            .transition(
                &registration.ids.attempt_id,
                AttemptState::Prepared,
                AttemptState::DispatchCommitted,
                &AttemptTransitionEvidence::default(),
                11,
            )
            .is_err());
    }

    #[test]
    fn deterministic_attempt_reuse_with_changed_input_is_a_conflict() {
        let store = SqliteAttemptStore::open_in_memory().test_expect("store");
        let registration = registration("nonce-abcdefghijkl");
        store
            .register_attempt(&registration, 10)
            .test_expect("insert");

        let mut changed = registration;
        changed.proof_digest = "d".repeat(64);
        assert!(matches!(
            store.register_attempt(&changed, 11),
            Err(BrokerError::Conflict(_))
        ));
    }

    #[test]
    fn nonce_insert_failure_rolls_back_the_prepared_intent() {
        let store = SqliteAttemptStore::open_in_memory().test_expect("store");
        store
            .connection()
            .test_expect("connection")
            .execute("DROP TABLE broker_nonces", [])
            .test_expect("drop nonce table");

        assert!(matches!(
            store.register_attempt(&registration("nonce-abcdefghijkl"), 10),
            Err(BrokerError::Storage(_))
        ));
        let attempt_count: i64 = store
            .connection()
            .test_expect("connection")
            .query_row("SELECT COUNT(*) FROM broker_attempts", [], |row| row.get(0))
            .test_expect("attempt count");
        assert_eq!(attempt_count, 0);
    }
}
