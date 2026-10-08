use std::fs::{self, File};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use chio_core::crypto::{Keypair, PublicKey};
use chio_kernel::admission_operation::{DurableAdmissionMode, StoreMutationFence};
use chio_kernel::tool_outcome::QualifiedToolOutcomeStore;
use chio_kernel::{BudgetStore, ChioKernel, QualifiedAdmissionProjectionStore, RevocationStore};
use chio_store_sqlite::{
    RelocationImport, RelocationImportPhase, RelocationSeal, SqliteAuthorityStore,
    SqliteBudgetStore, SqliteRevocationStore,
};

use crate::{load_or_create_authority_keypair, CliError};

#[cfg(windows)]
#[path = "durable_admission/windows.rs"]
mod windows;

#[path = "durable_admission/payload_maintenance.rs"]
mod payload_maintenance;
pub use payload_maintenance::{
    LocalTerminalPayloadMaintenance, TerminalPayloadMaintenanceConfig,
    TerminalPayloadMaintenanceError, TerminalPayloadMaintenanceHealth,
    TerminalPayloadMaintenanceLifecycle,
};

#[cfg(test)]
#[path = "durable_admission/payload_maintenance_tests.rs"]
pub(crate) mod payload_maintenance_tests;

#[derive(Clone)]
pub struct DurableAdmissionRuntime {
    // Drop this shared owner before releasing any authority ports. Its worker
    // independently retains this same authority until stop and join complete.
    payload_maintenance: Arc<payload_maintenance::PayloadMaintenanceOwner>,
    operations: Arc<dyn QualifiedAdmissionProjectionStore>,
    outcomes: Arc<dyn QualifiedToolOutcomeStore>,
    budget: Arc<dyn BudgetStore>,
    revocations: Arc<dyn RevocationStore>,
    local_authority: Option<Arc<SqliteAuthorityStore>>,
    local_operations: Option<chio_store_sqlite::SqliteAdmissionOperationStore>,
    local_budget: Option<SqliteBudgetStore>,
    local_revocations: Option<SqliteRevocationStore>,
    fence: StoreMutationFence,
    kernel_keypair: Keypair,
}

impl DurableAdmissionRuntime {
    pub fn open(path: &Path) -> Result<Self, CliError> {
        Self::open_with_clock(path, Arc::new(chio_security_types::clock::SystemClock))
    }

    /// Use the service's authority clock for the complete joint durable store.
    pub fn open_with_clock(
        path: &Path,
        clock: Arc<dyn chio_security_types::clock::Clock>,
    ) -> Result<Self, CliError> {
        clock.read().map_err(std::io::Error::other)?;
        if path
            .to_str()
            .is_some_and(chio_store_sqlite::is_in_memory_sqlite_path)
        {
            return Err(CliError::cli_other_error(
                "refusing to attach an in-memory database as durable admission state".to_string(),
            ));
        }

        SqliteAuthorityStore::ensure_serving_supported()?;
        let lock_root = durable_admission_lock_root(path)?;
        create_private_directory(&lock_root)?;
        SqliteAuthorityStore::provision(path, &lock_root)?;
        let authority = Arc::new(SqliteAuthorityStore::open_serving_with_clock(
            path, &lock_root, clock,
        )?);
        let budget = authority.budget_store();
        let revocations = authority.revocation_store();
        let kernel_keypair =
            load_or_create_authority_keypair(&durable_admission_kernel_seed_path(path)?)?;
        bind_durable_admission_kernel_identity(path, &kernel_keypair.public_key())?;

        Ok(Self {
            payload_maintenance: Arc::new(payload_maintenance::PayloadMaintenanceOwner::default()),
            operations: Arc::new(authority.admission_operation_store()),
            outcomes: Arc::new(authority.tool_outcome_store()),
            budget: Arc::new(budget.clone()),
            revocations: Arc::new(revocations.clone()),
            local_authority: Some(authority.clone()),
            local_operations: Some(authority.admission_operation_store()),
            local_budget: Some(budget),
            local_revocations: Some(revocations),
            fence: authority.mutation_fence(),
            kernel_keypair,
        })
    }

    /// Retire the authority at `path` and seal it for import at another
    /// location. Requires a stopped store; see `SqliteAuthorityStore::export_for_relocation`.
    pub fn export_relocation(path: &Path) -> Result<RelocationSeal, CliError> {
        if path
            .to_str()
            .is_some_and(chio_store_sqlite::is_in_memory_sqlite_path)
        {
            return Err(CliError::cli_other_error(
                "an in-memory database cannot be relocated".to_string(),
            ));
        }
        SqliteAuthorityStore::ensure_serving_supported()?;
        let lock_root = durable_admission_lock_root(path)?;
        Ok(SqliteAuthorityStore::export_for_relocation(
            path, &lock_root,
        )?)
    }

    /// Import a manifest-verified export, or finish a committed import at the
    /// same location. Application files must be checked on every retry; the
    /// callback checks the original exported authority files before mutation.
    pub fn import_relocation_checked(
        path: &Path,
        expected: &RelocationSeal,
        verify_exported: impl FnOnce() -> Result<(), CliError>,
    ) -> Result<RelocationImport, CliError> {
        Self::import_relocation_checked_with_phase(path, expected, |phase| {
            if phase == RelocationImportPhase::Exported {
                verify_exported()?;
            }
            Ok(())
        })
    }

    /// Check relocated files against the owning store's verified import phase.
    /// A committed retry may retain its authority commit in WAL; only the store
    /// qualifies that state, before the callback or any recovery mutation.
    pub fn import_relocation_checked_with_phase(
        path: &Path,
        expected: &RelocationSeal,
        verify_files: impl FnOnce(RelocationImportPhase) -> Result<(), CliError>,
    ) -> Result<RelocationImport, CliError> {
        SqliteAuthorityStore::ensure_serving_supported()?;
        let lock_root = durable_admission_lock_root(path)?;
        create_private_directory(&lock_root)?;
        if !durable_admission_kernel_seed_path(path)?.is_file() {
            return Err(CliError::cli_other_error(
                "the durable admission kernel seed did not move with its database".to_string(),
            ));
        }
        Ok(SqliteAuthorityStore::import_relocated_checked_with_phase(
            path,
            &lock_root,
            expected,
            |phase| {
                verify_files(phase).map_err(|failure| {
                    chio_store_sqlite::SqliteServingOwnerError::Invalid(failure.to_string())
                })
            },
        )?)
    }

    /// Re-anchor an exported copy at `path` after validating local seed custody.
    /// This unchecked API does not authenticate an external relocation seal;
    /// callers requiring that guarantee must use `import_relocation_checked`.
    pub fn import_relocation(path: &Path) -> Result<RelocationImport, CliError> {
        if path
            .to_str()
            .is_some_and(chio_store_sqlite::is_in_memory_sqlite_path)
        {
            return Err(CliError::cli_other_error(
                "an in-memory database cannot be relocated".to_string(),
            ));
        }
        SqliteAuthorityStore::ensure_serving_supported()?;
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file() {
            return Err(CliError::cli_other_error(
                "relocated authority must be a regular file",
            ));
        }
        crate::load_existing_authority_keypair(&durable_admission_kernel_seed_path(path)?)?;
        let lock_root = durable_admission_lock_root(path)?;
        create_private_directory(&lock_root)?;
        let imported = SqliteAuthorityStore::import_relocated(path, &lock_root)?;
        Ok(imported)
    }

    pub fn open_remote(
        identity_path: &Path,
        control_url: &str,
        control_token: &str,
    ) -> Result<Self, CliError> {
        if identity_path
            .to_str()
            .is_some_and(chio_store_sqlite::is_in_memory_sqlite_path)
        {
            return Err(CliError::cli_other_error(
                "refusing to persist durable admission identity beside an in-memory database"
                    .to_owned(),
            ));
        }
        let kernel_keypair =
            load_or_create_authority_keypair(&durable_admission_kernel_seed_path(identity_path)?)?;
        bind_durable_admission_kernel_identity(identity_path, &kernel_keypair.public_key())?;
        let stores =
            crate::trust_control::service_runtime::remote_admission::build_remote_admission_stores(
                control_url,
                control_token,
                kernel_keypair.clone(),
            )?;
        let revocations = Arc::from(
            crate::trust_control::service_runtime::remote_stores::build_remote_revocation_store(
                control_url,
                control_token,
            )?,
        );
        Ok(Self {
            payload_maintenance: Arc::new(payload_maintenance::PayloadMaintenanceOwner::default()),
            operations: stores.operations,
            outcomes: stores.outcomes,
            budget: stores.budget,
            revocations,
            local_authority: None,
            local_operations: None,
            local_budget: None,
            local_revocations: None,
            fence: stores.fence,
            kernel_keypair,
        })
    }

    #[must_use]
    pub fn kernel_keypair(&self) -> Keypair {
        self.kernel_keypair.clone()
    }

    /// The existing local serving owner for native flow and broker composition.
    /// This shares the authority attached to the kernel without opening another
    /// store or creating another mutation fence. Remote profiles have no local port.
    #[must_use]
    pub fn local_authority_store(&self) -> Option<Arc<SqliteAuthorityStore>> {
        self.local_authority.clone()
    }

    #[must_use]
    pub fn local_budget_store(&self) -> Option<SqliteBudgetStore> {
        self.local_budget.clone()
    }

    #[must_use]
    pub fn local_revocation_store(&self) -> Option<SqliteRevocationStore> {
        self.local_revocations.clone()
    }

    /// The local participant and its existing fence, for sealing a runtime
    /// source before attaching a hook. Remote authorities have no local port.
    #[must_use]
    pub fn local_runtime_participant(
        &self,
    ) -> Option<(
        chio_store_sqlite::SqliteAdmissionOperationStore,
        StoreMutationFence,
    )> {
        self.local_operations
            .clone()
            .map(|store| (store, self.fence.clone()))
    }

    pub fn attach(&self, kernel: &mut ChioKernel) -> Result<(), CliError> {
        if kernel.public_key() != self.kernel_keypair.public_key() {
            return Err(CliError::cli_other_error(
                "kernel signing key does not match the durable admission authority".to_string(),
            ));
        }
        kernel.set_durable_admission_store(
            self.operations.clone(),
            self.outcomes.clone(),
            self.fence.clone(),
        )?;
        kernel.set_budget_store_handle(self.budget.clone());
        kernel.set_revocation_store_handle(self.revocations.clone());
        kernel.reconcile_durable_admission_startup()?;
        Ok(())
    }
}

pub fn validate_durable_admission_participant_paths(
    mode: DurableAdmissionMode,
    control_url: Option<&str>,
    revocation_database: Option<&Path>,
    budget_database: Option<&Path>,
) -> Result<(), CliError> {
    if mode == DurableAdmissionMode::Off
        || revocation_database.is_none() && budget_database.is_none()
    {
        return Ok(());
    }
    if control_url.is_some() {
        return Err(CliError::cli_other_error(
            "--control-url cannot be combined with --revocation-db or --budget-db when durable admission is enabled"
                .to_owned(),
        ));
    }
    Err(CliError::cli_other_error(
        "the durable admission authority owns revocation and budget state; remove --revocation-db and --budget-db so all admission participants share one fenced transaction coordinator"
            .to_owned(),
    ))
}

pub fn open_durable_admission_runtime(
    mode: DurableAdmissionMode,
    database_path: Option<&Path>,
) -> Result<Option<DurableAdmissionRuntime>, CliError> {
    if mode == DurableAdmissionMode::Off {
        return Ok(None);
    }
    let path = database_path.ok_or_else(|| {
        CliError::cli_other_error(
            "durable admission mode requires a database so operations and tool outcomes survive restart"
                .to_string(),
        )
    })?;
    DurableAdmissionRuntime::open(path).map(Some)
}

pub fn durable_admission_sidecar_path(session_database: &Path) -> Result<PathBuf, CliError> {
    sibling_path(session_database, ".admission", "session database")
}

pub fn validate_distinct_database_paths(paths: &[(&str, &Path)]) -> Result<(), CliError> {
    for (index, (left_label, left_path)) in paths.iter().enumerate() {
        for (right_label, right_path) in paths.iter().skip(index + 1) {
            if database_paths_alias(left_path, right_path)? {
                return Err(CliError::cli_other_error(format!(
                    "{left_label} must not alias {right_label}"
                )));
            }
        }
    }
    Ok(())
}

pub(crate) fn durable_admission_lock_root(path: &Path) -> Result<PathBuf, CliError> {
    sibling_path(path, ".locks", "durable admission database")
}

/// Durable admission directories are owned by the effective user and are not
/// writable by group or others.
#[cfg(unix)]
const PRIVATE_DIRECTORY_POLICY: chio_secure_fs::OwnerPolicy = chio_secure_fs::OwnerPolicy {
    owner: chio_secure_fs::Owner::EffectiveUser,
    forbidden_mode: 0o022,
    require_single_link: false,
    reject_acl: false,
};

pub(crate) fn create_private_directory(path: &Path) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        chio_secure_fs::PrivateDirectory::prepare_hardened(path, &PRIVATE_DIRECTORY_POLICY)?;
    }
    #[cfg(windows)]
    {
        let absolute = normalize_private_directory_path(path)?;
        windows::prepare_private_directory(&absolute)?;
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "secure private-directory creation is unavailable on this platform",
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn private_tempdir() -> Result<tempfile::TempDir, CliError> {
    let directory = tempfile::tempdir()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    }
    Ok(directory)
}

/// A private directory pinned by a platform directory handle.
///
/// Relative operations remain anchored to the validated directory even if its
/// pathname is renamed or replaced after preparation.
pub struct PreparedPrivateDirectory {
    #[cfg(not(unix))]
    path: PathBuf,
    #[cfg(unix)]
    directory: chio_secure_fs::PrivateDirectory,
    #[cfg(windows)]
    directory: windows::PreparedPrivateDirectory,
}

impl PreparedPrivateDirectory {
    /// Returns the resolved absolute path used to prepare this directory.
    /// Security-sensitive operations use the retained handle, not this
    /// pathname.
    #[must_use]
    pub fn path(&self) -> &Path {
        #[cfg(unix)]
        {
            self.directory.path()
        }
        #[cfg(not(unix))]
        {
            &self.path
        }
    }

    /// The descriptor-pinned directory, for custody operations beyond
    /// creating directories and new files.
    #[cfg(unix)]
    #[must_use]
    pub fn custody(&self) -> &chio_secure_fs::PrivateDirectory {
        &self.directory
    }

    /// Verifies that the prepared pathname still identifies the pinned
    /// directory.
    ///
    /// Relative operations remain safe when the pathname is replaced, but a
    /// caller must use this check before reporting that the pathname contains
    /// those operations' results.
    pub fn validate_path_identity(&self) -> Result<(), std::io::Error> {
        #[cfg(unix)]
        {
            self.directory.revalidate()
        }
        #[cfg(windows)]
        {
            self.directory.validate_path_identity(&self.path)
        }
        #[cfg(not(any(unix, windows)))]
        {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "secure private-directory identity validation is unavailable on this platform",
            ))
        }
    }

    /// Reports whether the pinned directory contains no entries.
    pub fn is_empty(&self) -> Result<bool, std::io::Error> {
        #[cfg(unix)]
        {
            self.directory.is_empty()
        }
        #[cfg(windows)]
        {
            self.directory.is_empty()
        }
        #[cfg(not(any(unix, windows)))]
        {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "secure private-directory inspection is unavailable on this platform",
            ))
        }
    }

    /// Creates every missing directory in a relative path without following
    /// symlinks or Windows reparse points.
    pub fn create_dir_all(&self, relative: &Path) -> Result<(), std::io::Error> {
        #[cfg(unix)]
        {
            self.directory.create_dir_all(relative, 0o755)
        }
        #[cfg(windows)]
        {
            self.directory.create_dir_all(relative)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = relative;
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "secure relative-directory creation is unavailable on this platform",
            ))
        }
    }

    /// Creates and durably writes a new relative file without overwriting an
    /// existing entry.
    pub fn write_new(&self, relative: &Path, contents: &[u8]) -> Result<(), std::io::Error> {
        #[cfg(unix)]
        {
            self.directory.write_new(relative, contents, 0o666)
        }
        #[cfg(windows)]
        {
            self.directory.write_new(relative, contents)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (relative, contents);
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "secure relative-file creation is unavailable on this platform",
            ))
        }
    }

    /// Creates a new owner-only secret file relative to the pinned directory.
    /// Unix creation uses mode 0600 from the first write and never follows
    /// symlinks or replaces an existing entry.
    #[cfg(unix)]
    pub fn write_new_secret(&self, relative: &Path, contents: &[u8]) -> Result<(), std::io::Error> {
        self.directory.write_new(relative, contents, 0o600)
    }
}

/// Creates a missing private directory or validates an existing one without
/// changing its permissions.
///
/// On Unix, the path is traversed relative to open directory descriptors so
/// symlinks cannot redirect validation or creation. A missing target is created
/// with mode `0700`. An existing target must be owned by the effective user and
/// must not be group or world writable.
pub fn ensure_private_directory(path: &Path) -> Result<(), std::io::Error> {
    prepare_private_directory(path).map(drop)
}

/// Creates or validates a private directory and retains a secure handle for
/// subsequent relative operations.
pub fn prepare_private_directory(path: &Path) -> Result<PreparedPrivateDirectory, std::io::Error> {
    #[cfg(unix)]
    {
        let directory = chio_secure_fs::PrivateDirectory::prepare(path, &PRIVATE_DIRECTORY_POLICY)?;
        Ok(PreparedPrivateDirectory { directory })
    }
    #[cfg(windows)]
    {
        let absolute = normalize_private_directory_path(path)?;
        let directory = windows::prepare_private_directory(&absolute)?;
        Ok(PreparedPrivateDirectory {
            path: absolute,
            directory,
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "secure private-directory creation is unavailable on this platform",
        ))
    }
}

#[cfg(windows)]
fn normalize_private_directory_path(path: &Path) -> Result<PathBuf, std::io::Error> {
    if path.is_absolute() {
        if path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "private directory path must not contain parent components after a named component",
            ));
        }
        return Ok(path
            .components()
            .filter(|component| !matches!(component, Component::CurDir))
            .collect());
    }

    let mut normalized = std::env::current_dir()?;
    let mut reached_named_component = false;
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir if !reached_named_component => {
                normalized.pop();
            }
            Component::ParentDir => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "private directory path must not contain parent components after a named component",
                ));
            }
            Component::Normal(name) => {
                normalized.push(name);
                reached_named_component = true;
            }
            Component::Prefix(_) | Component::RootDir => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "relative private directory path must not contain a platform prefix or root",
                ));
            }
        }
    }
    if !reached_named_component {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "private directory path must name a directory below the filesystem root",
        ));
    }
    Ok(normalized)
}

/// Authority seed and identity files are created at mode 0600. The staged
/// file is not checked further, so filesystems without Unix modes still accept
/// the write.
#[cfg(unix)]
const AUTHORITY_FILE_POLICY: chio_secure_fs::OwnerPolicy = chio_secure_fs::OwnerPolicy {
    owner: chio_secure_fs::Owner::Unchecked,
    forbidden_mode: 0,
    require_single_link: false,
    reject_acl: false,
};

pub(super) fn write_private_file_atomically(path: &Path, contents: &[u8]) -> Result<(), CliError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let file_name = path
        .file_name()
        .ok_or_else(|| CliError::cli_other_error("private file path must name a file"))?;
    #[cfg(unix)]
    {
        let directory = File::open(parent)?;
        chio_secure_fs::publish_at(
            &directory,
            file_name,
            contents,
            0o600,
            chio_secure_fs::Expect::Replace,
            &AUTHORITY_FILE_POLICY,
        )?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        use std::fs::OpenOptions;
        use std::io::Write;

        let temporary = parent.join(format!(
            ".{}.{}.tmp",
            file_name.to_string_lossy(),
            uuid::Uuid::now_v7()
        ));
        let mut staged = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        if let Err(error) = staged.write_all(contents).and_then(|()| staged.sync_all()) {
            drop(staged);
            let _ = fs::remove_file(&temporary);
            return Err(CliError::Io(error));
        }
        drop(staged);
        if let Err(error) = fs::rename(&temporary, path) {
            let _ = fs::remove_file(&temporary);
            return Err(CliError::Io(error));
        }
        File::open(parent)?.sync_all()?;
        Ok(())
    }
}

pub(super) fn durable_admission_kernel_seed_path(path: &Path) -> Result<PathBuf, CliError> {
    sibling_path(path, ".kernel.seed", "durable admission database")
}

fn durable_admission_kernel_identity_path(path: &Path) -> Result<PathBuf, CliError> {
    sibling_path(path, ".kernel.pub", "durable admission database")
}

fn sibling_path(path: &Path, suffix: &str, label: &str) -> Result<PathBuf, CliError> {
    let file_name = path
        .file_name()
        .ok_or_else(|| CliError::cli_other_error(format!("{label} path must name a file")))?;
    let mut sibling_name = file_name.to_os_string();
    sibling_name.push(suffix);
    Ok(path.with_file_name(sibling_name))
}

fn database_paths_alias(left: &Path, right: &Path) -> Result<bool, CliError> {
    if left == right {
        return Ok(true);
    }
    let left_metadata = optional_metadata(left)?;
    let right_metadata = optional_metadata(right)?;
    #[cfg(unix)]
    if let (Some(left), Some(right)) = (&left_metadata, &right_metadata) {
        use std::os::unix::fs::MetadataExt;

        if left.dev() == right.dev() && left.ino() == right.ino() {
            return Ok(true);
        }
    }
    #[cfg(not(unix))]
    let _ = (&left_metadata, &right_metadata);
    Ok(resolve_database_path(left)? == resolve_database_path(right)?)
}

fn optional_metadata(path: &Path) -> Result<Option<fs::Metadata>, CliError> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(CliError::Io(error)),
    }
}

fn resolve_database_path(path: &Path) -> Result<PathBuf, CliError> {
    resolve_database_path_inner(path, 0)
}

fn resolve_database_path_inner(path: &Path, symlink_depth: usize) -> Result<PathBuf, CliError> {
    const MAX_SYMLINK_DEPTH: usize = 40;

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let normalized = normalize_path(&absolute);
    let components = normalized.components().collect::<Vec<_>>();
    let mut resolved = PathBuf::new();

    for (index, component) in components.iter().enumerate() {
        match component {
            Component::Prefix(_) | Component::RootDir => resolved.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                resolved.pop();
            }
            Component::Normal(_) => {
                let candidate = resolved.join(component.as_os_str());
                match fs::symlink_metadata(&candidate) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        if symlink_depth >= MAX_SYMLINK_DEPTH {
                            return Err(CliError::cli_other_error(
                                "database path exceeds the supported symlink depth",
                            ));
                        }
                        let target = fs::read_link(&candidate)?;
                        let mut redirected = if target.is_absolute() {
                            target
                        } else {
                            resolved.join(target)
                        };
                        for remaining in components.iter().skip(index + 1) {
                            redirected.push(remaining.as_os_str());
                        }
                        return resolve_database_path_inner(&redirected, symlink_depth + 1);
                    }
                    Ok(_) => resolved.push(component.as_os_str()),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        resolved.push(component.as_os_str());
                        for remaining in components.iter().skip(index + 1) {
                            resolved.push(remaining.as_os_str());
                        }
                        return Ok(normalize_path(&resolved));
                    }
                    Err(error) => return Err(CliError::Io(error)),
                }
            }
        }
    }

    match fs::canonicalize(&resolved) {
        Ok(canonical) => Ok(canonical),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(resolved),
        Err(error) => Err(CliError::Io(error)),
    }
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

fn bind_durable_admission_kernel_identity(
    database_path: &Path,
    public_key: &PublicKey,
) -> Result<(), CliError> {
    let identity_path = durable_admission_kernel_identity_path(database_path)?;
    let expected = public_key.to_hex();
    match std::fs::read_to_string(&identity_path) {
        Ok(stored) if stored.trim() == expected => Ok(()),
        Ok(_) => Err(CliError::cli_other_error(
            "durable admission database is bound to a different kernel signing key".to_string(),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            write_durable_admission_kernel_identity(&identity_path, &expected)
        }
        Err(error) => Err(CliError::Io(error)),
    }
}

fn write_durable_admission_kernel_identity(path: &Path, public_key: &str) -> Result<(), CliError> {
    write_private_file_atomically(path, format!("{public_key}\n").as_bytes())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn unchecked_relocation_validates_seed_before_any_import_mutation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let temp = private_tempdir()?;
        let original = temp.path().join("original");
        fs::create_dir(&original)?;
        fs::set_permissions(&original, fs::Permissions::from_mode(0o700))?;
        let database = original.join("authority.db");
        drop(DurableAdmissionRuntime::open(&database)?);
        DurableAdmissionRuntime::export_relocation(&database)?;
        for variant in ["missing", "directory", "symlink", "broad", "malformed"] {
            let destination = temp.path().join(variant);
            fs::create_dir(&destination)?;
            fs::set_permissions(&destination, fs::Permissions::from_mode(0o700))?;
            let copied = destination.join("authority.db");
            fs::copy(&database, &copied)?;
            let seed = durable_admission_kernel_seed_path(&copied)?;
            match variant {
                "missing" => {}
                "directory" => fs::create_dir(&seed)?,
                "symlink" => symlink(durable_admission_kernel_seed_path(&database)?, &seed)?,
                "broad" | "malformed" => {
                    fs::copy(durable_admission_kernel_seed_path(&database)?, &seed)?;
                    if variant == "broad" {
                        fs::set_permissions(&seed, fs::Permissions::from_mode(0o644))?;
                    } else {
                        fs::write(&seed, b"bad seed")?;
                    }
                }
                _ => unreachable!(),
            }
            let before = fs::read(&copied)?;
            assert!(
                DurableAdmissionRuntime::import_relocation(&copied).is_err(),
                "{variant}"
            );
            assert!(fs::read(&copied)? == before, "{variant} mutated authority");
            assert!(
                !durable_admission_lock_root(&copied)?.exists(),
                "{variant} created locks"
            );
        }
        for variant in ["missing-database", "directory-database", "symlink-database"] {
            let destination = temp.path().join(variant);
            fs::create_dir(&destination)?;
            fs::set_permissions(&destination, fs::Permissions::from_mode(0o700))?;
            let copied = destination.join("authority.db");
            fs::copy(
                durable_admission_kernel_seed_path(&database)?,
                durable_admission_kernel_seed_path(&copied)?,
            )?;
            match variant {
                "missing-database" => {}
                "directory-database" => fs::create_dir(&copied)?,
                "symlink-database" => symlink(&database, &copied)?,
                _ => unreachable!(),
            }
            let original_bytes = fs::read(&database)?;
            assert!(DurableAdmissionRuntime::import_relocation(&copied).is_err());
            assert!(fs::read(&database)? == original_bytes);
            assert!(!durable_admission_lock_root(&copied)?.exists());
        }
        let destination = temp.path().join("valid");
        fs::create_dir(&destination)?;
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o700))?;
        let copied = destination.join("authority.db");
        fs::copy(&database, &copied)?;
        fs::copy(
            durable_admission_kernel_seed_path(&database)?,
            durable_admission_kernel_seed_path(&copied)?,
        )?;
        let imported = DurableAdmissionRuntime::import_relocation(&copied)?;
        assert_eq!(
            DurableAdmissionRuntime::import_relocation(&copied)?,
            imported
        );
        drop(DurableAdmissionRuntime::open(&copied)?);
        Ok(())
    }

    #[test]
    fn durable_admission_rejects_split_local_participant_databases() -> Result<(), CliError> {
        let revocations = Path::new("revocations.sqlite3");
        let budget = Path::new("budget.sqlite3");

        for (revocation_database, budget_database) in [
            (Some(revocations), None),
            (None, Some(budget)),
            (Some(revocations), Some(budget)),
        ] {
            let Err(error) = validate_durable_admission_participant_paths(
                DurableAdmissionMode::SideEffecting,
                None,
                revocation_database,
                budget_database,
            ) else {
                return Err(CliError::cli_other_error(
                    "split local participant databases were accepted",
                ));
            };
            assert!(error
                .to_string()
                .contains("durable admission authority owns revocation and budget state"));
        }
        Ok(())
    }

    #[test]
    fn durable_admission_rejects_local_participants_with_remote_authority() -> Result<(), CliError>
    {
        let Err(error) = validate_durable_admission_participant_paths(
            DurableAdmissionMode::Monetary,
            Some("http://127.0.0.1:8080"),
            Some(Path::new("revocations.sqlite3")),
            None,
        ) else {
            return Err(CliError::cli_other_error(
                "remote authority accepted a local participant database",
            ));
        };
        assert!(error
            .to_string()
            .contains("--control-url cannot be combined with --revocation-db or --budget-db"));
        Ok(())
    }

    #[test]
    fn participant_path_validation_is_inactive_when_durable_admission_is_off(
    ) -> Result<(), CliError> {
        validate_durable_admission_participant_paths(
            DurableAdmissionMode::Off,
            None,
            Some(Path::new("revocations.sqlite3")),
            Some(Path::new("budget.sqlite3")),
        )
    }

    #[test]
    fn database_path_validation_rejects_hard_link_aliases() -> Result<(), CliError> {
        let directory = private_tempdir()?;
        let first = directory.path().join("first.sqlite3");
        let second = directory.path().join("second.sqlite3");
        fs::write(&first, [])?;
        fs::hard_link(&first, &second)?;

        let Err(error) = validate_distinct_database_paths(&[
            ("first database", first.as_path()),
            ("second database", second.as_path()),
        ]) else {
            return Err(CliError::cli_other_error(
                "hard-linked databases were treated as distinct",
            ));
        };
        assert!(error
            .to_string()
            .contains("first database must not alias second database"));
        Ok(())
    }

    #[test]
    fn database_path_validation_rejects_dangling_symlink_aliases() -> Result<(), CliError> {
        use std::os::unix::fs::symlink;

        let directory = private_tempdir()?;
        let target = directory.path().join("target.sqlite3");
        let alias = directory.path().join("alias.sqlite3");
        symlink(&target, &alias)?;

        let Err(error) = validate_distinct_database_paths(&[
            ("target database", target.as_path()),
            ("alias database", alias.as_path()),
        ]) else {
            return Err(CliError::cli_other_error(
                "dangling database symlink was treated as distinct",
            ));
        };
        assert!(error
            .to_string()
            .contains("target database must not alias alias database"));
        Ok(())
    }

    #[test]
    fn database_path_validation_rejects_dangling_parent_symlink_aliases() -> Result<(), CliError> {
        use std::os::unix::fs::symlink;

        let directory = private_tempdir()?;
        let target_directory = directory.path().join("target");
        let alias_directory = directory.path().join("alias");
        symlink(&target_directory, &alias_directory)?;
        let target = target_directory.join("state.sqlite3");
        let alias = alias_directory.join("state.sqlite3");

        let Err(error) = validate_distinct_database_paths(&[
            ("target database", target.as_path()),
            ("alias database", alias.as_path()),
        ]) else {
            return Err(CliError::cli_other_error(
                "databases below a dangling symlink were treated as distinct",
            ));
        };
        assert!(error
            .to_string()
            .contains("target database must not alias alias database"));
        Ok(())
    }

    #[test]
    fn private_directory_rejects_symlink_without_chmod_target() -> Result<(), CliError> {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = tempfile::tempdir()?;
        let target = directory.path().join("attacker-selected");
        let alias = directory.path().join("authority.locks");
        fs::create_dir(&target)?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755))?;
        symlink(&target, &alias)?;

        let Err(error) = create_private_directory(&alias) else {
            return Err(CliError::cli_other_error(
                "a symlinked private-directory path was accepted",
            ));
        };
        assert_ne!(error.kind(), std::io::ErrorKind::NotFound);
        assert_eq!(fs::metadata(&target)?.permissions().mode() & 0o777, 0o755);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn private_directory_rejects_a_parent_writable_by_other_users() -> Result<(), CliError> {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir()?;
        let insecure_parent = directory.path().join("shared");
        fs::create_dir(&insecure_parent)?;
        fs::set_permissions(&insecure_parent, fs::Permissions::from_mode(0o777))?;

        let Err(error) = create_private_directory(&insecure_parent.join("authority.locks")) else {
            return Err(CliError::cli_other_error(
                "an attacker-writable parent was accepted",
            ));
        };
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(error
            .to_string()
            .contains("must not be group or world writable unless sticky"));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn private_directory_rejects_an_attacker_writable_ancestor() -> Result<(), CliError> {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir()?;
        let insecure_ancestor = directory.path().join("shared");
        let secure_parent = insecure_ancestor.join("victim");
        fs::create_dir(&insecure_ancestor)?;
        fs::set_permissions(&insecure_ancestor, fs::Permissions::from_mode(0o777))?;
        fs::create_dir(&secure_parent)?;
        fs::set_permissions(&secure_parent, fs::Permissions::from_mode(0o700))?;

        let Err(error) = create_private_directory(&secure_parent.join("authority.locks")) else {
            return Err(CliError::cli_other_error(
                "an attacker-writable ancestor was accepted",
            ));
        };
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(error
            .to_string()
            .contains("must not be group or world writable unless sticky"));
        Ok(())
    }

    fn private_directory_test_root() -> Result<tempfile::TempDir, CliError> {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        Ok(directory)
    }

    #[test]
    fn ensured_private_directory_is_created_with_private_permissions() -> Result<(), CliError> {
        use std::os::unix::fs::PermissionsExt;

        let directory = private_directory_test_root()?;
        let target = directory.path().join("project");

        ensure_private_directory(&target)?;

        assert_eq!(fs::metadata(&target)?.permissions().mode() & 0o777, 0o700);
        Ok(())
    }

    #[test]
    fn ensured_private_directory_preserves_safe_existing_permissions() -> Result<(), CliError> {
        use std::os::unix::fs::PermissionsExt;

        let directory = private_directory_test_root()?;
        let target = directory.path().join("project");
        fs::create_dir(&target)?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755))?;

        ensure_private_directory(&target)?;

        assert_eq!(fs::metadata(&target)?.permissions().mode() & 0o777, 0o755);
        Ok(())
    }

    #[test]
    fn ensured_private_directory_rejects_and_preserves_writable_target() -> Result<(), CliError> {
        use std::os::unix::fs::PermissionsExt;

        let directory = private_directory_test_root()?;
        let target = directory.path().join("project");
        fs::create_dir(&target)?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o775))?;

        let Err(error) = ensure_private_directory(&target) else {
            return Err(CliError::cli_other_error(
                "a group-writable private directory was accepted",
            ));
        };

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(error
            .to_string()
            .contains("must not be group or world writable"));
        assert_eq!(fs::metadata(&target)?.permissions().mode() & 0o777, 0o775);
        Ok(())
    }

    #[test]
    fn ensured_private_directory_rejects_final_symlink_with_trailing_slash() -> Result<(), CliError>
    {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = private_directory_test_root()?;
        let target = directory.path().join("attacker-selected");
        let alias = directory.path().join("project");
        fs::create_dir(&target)?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755))?;
        symlink(&target, &alias)?;
        let trailing_slash = PathBuf::from(format!("{}/", alias.display()));

        let Err(error) = ensure_private_directory(&trailing_slash) else {
            return Err(CliError::cli_other_error(
                "a trailing slash made a final symlink safe",
            ));
        };

        assert_ne!(error.kind(), std::io::ErrorKind::NotFound);
        assert_eq!(fs::metadata(&target)?.permissions().mode() & 0o777, 0o755);
        Ok(())
    }

    #[test]
    fn ensured_private_directory_resolves_parent_components() -> Result<(), CliError> {
        use std::os::unix::fs::PermissionsExt;

        // The lock root derived from a relative database path such as
        // `../state/session.sqlite3` keeps its parent component once joined
        // with the working directory.
        let directory = private_directory_test_root()?;
        let state = directory.path().join("state");
        let bin = directory.path().join("bin");
        fs::create_dir(&bin)?;
        fs::create_dir(&state)?;
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700))?;
        let traversed = durable_admission_lock_root(
            &directory
                .path()
                .join("bin")
                .join("..")
                .join("state")
                .join("session.sqlite3"),
        )?;

        ensure_private_directory(&traversed)?;

        let created = state.join("session.sqlite3.locks");
        assert!(created.is_dir(), "{} is not a directory", created.display());
        assert_eq!(fs::metadata(&created)?.permissions().mode() & 0o777, 0o700);
        Ok(())
    }

    /// Requires a platform with a traversal-only or search-only open mode for
    /// the descriptor-relative walk.
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "illumos",
        target_os = "solaris",
    ))]
    #[test]
    fn ensured_private_directory_traverses_execute_only_ancestors() -> Result<(), CliError> {
        use std::os::unix::fs::PermissionsExt;

        let directory = private_directory_test_root()?;
        let ancestor = directory.path().join("execute-only");
        let target = ancestor.join("project");
        fs::create_dir(&ancestor)?;
        fs::create_dir(&target)?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700))?;
        // Traversable but not readable: ordinary path resolution walks it.
        fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o311))?;

        let walked = ensure_private_directory(&target);
        fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o700))?;
        walked?;

        assert_eq!(fs::metadata(&target)?.permissions().mode() & 0o777, 0o700);
        Ok(())
    }

    #[test]
    fn ensured_private_directory_rejects_intermediate_symlink() -> Result<(), CliError> {
        use std::os::unix::fs::symlink;

        let directory = private_directory_test_root()?;
        let target_parent = directory.path().join("attacker-selected");
        let alias_parent = directory.path().join("alias");
        fs::create_dir(&target_parent)?;
        fs::create_dir(target_parent.join("project"))?;
        symlink(&target_parent, &alias_parent)?;

        if ensure_private_directory(&alias_parent.join("project")).is_ok() {
            return Err(CliError::cli_other_error(
                "an intermediate symlink was accepted",
            ));
        }
        Ok(())
    }

    #[test]
    fn ensured_private_directory_rejects_unsafe_ancestor() -> Result<(), CliError> {
        use std::os::unix::fs::PermissionsExt;

        let directory = private_directory_test_root()?;
        let insecure_ancestor = directory.path().join("shared");
        let target = insecure_ancestor.join("project");
        fs::create_dir(&insecure_ancestor)?;
        fs::set_permissions(&insecure_ancestor, fs::Permissions::from_mode(0o777))?;
        fs::create_dir(&target)?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755))?;

        let Err(error) = ensure_private_directory(&target) else {
            return Err(CliError::cli_other_error(
                "a nonsticky writable ancestor was accepted",
            ));
        };

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(error
            .to_string()
            .contains("must not be group or world writable unless sticky"));
        assert_eq!(fs::metadata(&target)?.permissions().mode() & 0o777, 0o755);
        Ok(())
    }

    #[test]
    fn prepared_directory_rejects_symlink_before_parent_component() -> Result<(), CliError> {
        use std::os::unix::fs::symlink;

        let directory = private_directory_test_root()?;
        let working = directory.path().join("working");
        let outside = directory.path().join("outside");
        fs::create_dir(&working)?;
        fs::create_dir(&outside)?;
        symlink(&outside, working.join("link"))?;
        let lexical_target = working.join("project");
        let redirected_target = directory.path().join("project");

        let error = prepare_private_directory(&working.join("link").join("..").join("project"))
            .err()
            .ok_or_else(|| {
                CliError::cli_other_error("private directory walk followed a symlink before ..")
            })?;

        assert_ne!(error.kind(), std::io::ErrorKind::NotFound);
        assert!(!lexical_target.exists());
        assert!(!redirected_target.exists());
        assert!(!outside.join("proof.txt").exists());
        Ok(())
    }

    #[test]
    fn prepared_directory_resolves_nested_parent_components() -> Result<(), CliError> {
        use std::os::unix::fs::PermissionsExt;

        let directory = private_directory_test_root()?;
        let first = directory.path().join("first");
        let second = first.join("second");
        let target = fs::canonicalize(directory.path())?.join("state");
        fs::create_dir(&first)?;
        fs::create_dir(&second)?;
        fs::set_permissions(&first, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(&second, fs::Permissions::from_mode(0o700))?;

        let prepared = prepare_private_directory(&second.join("..").join("..").join("state"))?;

        assert_eq!(prepared.path(), target);
        assert!(target.is_dir());
        assert_eq!(fs::metadata(&target)?.permissions().mode() & 0o777, 0o700);
        Ok(())
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "netbsd",
    ))]
    #[test]
    fn prepared_directory_traverses_search_only_ancestor() -> Result<(), CliError> {
        use std::os::unix::fs::PermissionsExt;

        let directory = private_directory_test_root()?;
        let search_only = directory.path().join("search-only");
        let target = search_only.join("project");
        fs::create_dir(&search_only)?;
        fs::create_dir(&target)?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755))?;
        fs::set_permissions(&search_only, fs::Permissions::from_mode(0o100))?;

        let prepared = prepare_private_directory(&target);
        fs::set_permissions(&search_only, fs::Permissions::from_mode(0o700))?;
        let prepared = prepared?;

        assert!(prepared.is_empty()?);
        Ok(())
    }

    #[test]
    fn prepared_directory_operations_remain_bound_after_path_replacement() -> Result<(), CliError> {
        use std::os::unix::fs::DirBuilderExt;
        use std::os::unix::fs::PermissionsExt;

        let directory = private_directory_test_root()?;
        let target = directory.path().join("project");
        let pinned = directory.path().join("pinned-project");
        let prepared = prepare_private_directory(&target)?;
        prepared.validate_path_identity()?;
        fs::rename(&target, &pinned)?;
        fs::create_dir(&target)?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700))?;

        let Err(identity_error) = prepared.validate_path_identity() else {
            return Err(CliError::cli_other_error(
                "replacement path retained the pinned directory identity",
            ));
        };
        assert_eq!(identity_error.kind(), std::io::ErrorKind::InvalidData);

        assert!(prepared.is_empty()?);
        prepared.create_dir_all(Path::new("src/bin"))?;
        prepared.write_new(Path::new("src/bin/demo.rs"), b"fn main() {}\n")?;
        prepared.write_new_secret(Path::new("worker.json"), b"private connection")?;
        assert_eq!(fs::read(pinned.join("worker.json"))?, b"private connection");
        assert_eq!(
            fs::metadata(pinned.join("worker.json"))?
                .permissions()
                .mode()
                & 0o077,
            0
        );
        let mut reference_builder = fs::DirBuilder::new();
        reference_builder.mode(0o755);
        reference_builder.create(pinned.join("reference"))?;

        assert_eq!(fs::read(pinned.join("src/bin/demo.rs"))?, b"fn main() {}\n");
        assert_eq!(
            fs::metadata(pinned.join("src"))?.permissions().mode() & 0o777,
            fs::metadata(pinned.join("reference"))?.permissions().mode() & 0o777,
            "guard-created scaffold directories must preserve ordinary 0755 creation modes"
        );
        assert!(fs::read_dir(&target)?.next().is_none());
        Ok(())
    }

    #[test]
    fn prepared_directory_write_new_never_overwrites_entries() -> Result<(), CliError> {
        use std::os::unix::fs::symlink;
        use std::os::unix::fs::PermissionsExt;

        let directory = private_directory_test_root()?;
        let target = directory.path().join("project");
        let outside = directory.path().join("outside.txt");
        let prepared = prepare_private_directory(&target)?;
        prepared.write_new(Path::new("Cargo.toml"), b"first")?;
        fs::write(target.join("reference.txt"), b"reference")?;

        assert_eq!(
            fs::metadata(target.join("Cargo.toml"))?
                .permissions()
                .mode()
                & 0o777,
            fs::metadata(target.join("reference.txt"))?
                .permissions()
                .mode()
                & 0o777,
            "guard writes must preserve normal fs::write creation permissions"
        );

        let overwrite = prepared.write_new(Path::new("Cargo.toml"), b"second");
        assert!(overwrite.is_err());
        assert_eq!(fs::read(target.join("Cargo.toml"))?, b"first");

        fs::write(&outside, b"outside")?;
        symlink(&outside, target.join("README.md"))?;
        let redirected = prepared.write_new(Path::new("README.md"), b"redirected");
        assert!(redirected.is_err());
        assert!(prepared
            .write_new_secret(Path::new("README.md"), b"secret")
            .is_err());
        assert_eq!(fs::read(&outside)?, b"outside");
        Ok(())
    }

    #[test]
    fn authority_files_replace_entries_without_following_or_leaving_temporaries(
    ) -> Result<(), CliError> {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = private_directory_test_root()?;
        let outside = directory.path().join("outside");
        let state = directory.path().join("state");
        let seed = state.join("authority.seed");
        fs::write(&outside, b"outside")?;
        write_private_file_atomically(&seed, b"first\n")?;
        fs::remove_file(&seed)?;
        symlink(&outside, &seed)?;

        write_private_file_atomically(&seed, b"second\n")?;

        assert_eq!(fs::read(&seed)?, b"second\n");
        assert_eq!(fs::read(&outside)?, b"outside");
        assert!(fs::symlink_metadata(&seed)?.file_type().is_file());
        assert_eq!(fs::metadata(&seed)?.permissions().mode() & 0o777, 0o600);
        let entries = fs::read_dir(&state)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(entries, [std::ffi::OsString::from("authority.seed")]);
        Ok(())
    }

    #[test]
    fn private_directory_owner_must_match_effective_user() -> Result<(), CliError> {
        use std::os::unix::fs::MetadataExt;

        // Root owns /etc, so only another user observes the owner refusal.
        let foreign = Path::new("/etc");
        if fs::metadata(foreign)?.uid() == chio_secure_fs::effective_uid() {
            return Ok(());
        }

        let Err(error) = ensure_private_directory(foreign) else {
            return Err(CliError::cli_other_error(
                "foreign private-directory ownership was accepted",
            ));
        };

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(error
            .to_string()
            .contains("must be owned by the effective user"));
        Ok(())
    }
}

#[cfg(all(test, windows))]
mod windows_authority_tests {
    use super::*;

    #[test]
    fn durable_admission_rejects_windows_without_creating_state() -> Result<(), CliError> {
        let directory = tempfile::tempdir()?;
        let state_parent = directory.path().join("state");
        let database = state_parent.join("admission.sqlite3");
        let lock_root = durable_admission_lock_root(&database)?;
        let kernel_seed = durable_admission_kernel_seed_path(&database)?;
        let kernel_identity = durable_admission_kernel_identity_path(&database)?;

        let Err(error) = DurableAdmissionRuntime::open(&database) else {
            return Err(CliError::cli_other_error(
                "Windows durable admission unexpectedly opened",
            ));
        };

        assert!(error
            .to_string()
            .contains("sqlite authority serving requires Unix file identity and positioned I/O"));
        assert!(!state_parent.exists());
        assert!(!database.exists());
        assert!(!lock_root.exists());
        assert!(!kernel_seed.exists());
        assert!(!kernel_identity.exists());
        Ok(())
    }
}
