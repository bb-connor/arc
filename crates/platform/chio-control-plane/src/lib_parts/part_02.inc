pub fn compose_ordinary_admission_runtime(
    mut kernel: ChioKernel,
    config: OrdinaryAdmissionRuntimeConfig<'_>,
) -> Result<ChioKernel, CliError> {
    let threshold_approvals = kernel.threshold_approval_requirement_resolver().is_some();
    let durable_admission_required =
        config.enable_aggregate_invocation_admission || threshold_approvals;

    if threshold_approvals && config.control_url.is_some() {
        return Err(CliError::cli_other_error(
            "threshold approvals require one local durable authority composition; remote admission-operation and approval authorities are unavailable"
                .to_string(),
        ));
    }
    if config.enable_aggregate_invocation_admission && config.control_url.is_some() {
        return Err(CliError::cli_other_error(
            "aggregate admission requires one local durable authority composition; remote admission-operation authority is unavailable"
                .to_string(),
        ));
    }

    if !durable_admission_required {
        if config.admission_operation_db_path.is_some() {
            return Err(CliError::cli_other_error(
                "--admission-operation-db requires aggregate invocation admission or a threshold approval policy"
                    .to_string(),
            ));
        }
        if config.approval_db_path.is_some() {
            return Err(CliError::cli_other_error(
                "--approval-db requires a threshold approval policy".to_string(),
            ));
        }
        configure_budget_store(
            &mut kernel,
            config.budget_db_path,
            config.control_url,
            config.control_token,
        )?;
        return Ok(kernel);
    }

    let operation_path = config.admission_operation_db_path.ok_or_else(|| {
        CliError::cli_other_error(
            "aggregate and threshold admission require --admission-operation-db".to_string(),
        )
    })?;
    let budget_path = config.budget_db_path.ok_or_else(|| {
        CliError::cli_other_error(
            "aggregate and threshold admission require --budget-db".to_string(),
        )
    })?;
    let approval_path = if threshold_approvals {
        Some(config.approval_db_path.ok_or_else(|| {
            CliError::cli_other_error("threshold approvals require --approval-db".to_string())
        })?)
    } else {
        if config.approval_db_path.is_some() {
            return Err(CliError::cli_other_error(
                "--approval-db requires a threshold approval policy".to_string(),
            ));
        }
        None
    };

    // Open every authority before mutating the kernel. The consuming API then
    // drops the kernel on any subsequent installation or activation failure.
    let operation_store: Arc<dyn chio_kernel::admission_operation::AdmissionOperationStore> =
        Arc::new(
            chio_store_sqlite::SqliteAdmissionOperationStore::open(operation_path).map_err(
                |error| {
                    CliError::cli_other_error(format!(
                        "failed to open durable admission-operation store: {error}"
                    ))
                },
            )?,
        );
    let approval_store: Option<Arc<dyn chio_kernel::approval::ApprovalStore>> = approval_path
        .map(|path| {
            chio_store_sqlite::SqliteApprovalStore::open(path)
                .map(|store| Arc::new(store) as Arc<dyn chio_kernel::approval::ApprovalStore>)
                .map_err(|error| {
                    CliError::cli_other_error(format!(
                        "failed to open durable approval store: {error}"
                    ))
                })
        })
        .transpose()?;
    let budget_store: Arc<dyn chio_kernel::BudgetStore> = Arc::new(
        chio_store_sqlite::SqliteBudgetStore::open(budget_path).map_err(|error| {
            CliError::cli_other_error(format!("failed to open durable budget store: {error}"))
        })?,
    );

    kernel.set_admission_operation_store_handle(operation_store)?;
    if let Some(approval_store) = approval_store {
        kernel.set_approval_store_handle(approval_store)?;
    }
    kernel.set_budget_store_handle(budget_store)?;
    if threshold_approvals {
        kernel.enable_threshold_governed_approvals()?;
    }
    if config.enable_aggregate_invocation_admission {
        kernel.enable_aggregate_invocation_admission()?;
    }
    Ok(kernel)
}

pub fn require_control_token(control_token: Option<&str>) -> Result<&str, CliError> {
    control_token.ok_or_else(|| {
        CliError::cli_other_error(
            "--control-url requires --control-token so trust-service authentication is explicit"
                .to_string(),
        )
    })
}

pub fn authority_public_key_from_seed_file(
    path: &Path,
) -> Result<Option<chio_core::PublicKey>, CliError> {
    match read_private_file(path, 256) {
        Ok((bytes, _)) => {
            let seed_hex = std::str::from_utf8(&bytes).map_err(|_| {
                CliError::cli_other_error("authority seed is not valid UTF-8".to_string())
            })?;
            Ok(Some(Keypair::from_seed_hex(seed_hex.trim())?.public_key()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(CliError::Io(error)),
    }
}

pub fn rotate_authority_keypair(path: &Path) -> Result<chio_core::PublicKey, CliError> {
    let keypair = Keypair::generate();
    write_authority_seed_file(path, &keypair)?;
    Ok(keypair.public_key())
}

pub fn load_or_create_authority_keypair(path: &Path) -> Result<Keypair, CliError> {
    match load_existing_authority_keypair(path) {
        Ok(keypair) => Ok(keypair),
        Err(CliError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            let keypair = Keypair::generate();
            write_authority_seed_file(path, &keypair)?;
            Ok(keypair)
        }
        Err(error) => Err(error),
    }
}

/// Load existing seed-file signing custody without creating or repairing it.
pub fn load_existing_authority_keypair(path: &Path) -> Result<Keypair, CliError> {
    load_existing_authority_keypair_with_identity(path).map(|(keypair, _)| keypair)
}

fn load_existing_authority_keypair_with_identity(
    path: &Path,
) -> Result<(Keypair, PrivateFileIdentity), CliError> {
    let (bytes, identity) = read_private_file(path, 256)?;
    let seed_hex = std::str::from_utf8(&bytes)
        .map_err(|_| CliError::cli_other_error("authority seed is not valid UTF-8".to_string()))?;
    Keypair::from_seed_hex(seed_hex.trim())
        .map_err(CliError::from)
        .map(|keypair| (keypair, identity))
}

pub fn keyring_pending_authority_seed_path(active_seed_path: &Path) -> PathBuf {
    let mut value = active_seed_path.as_os_str().to_os_string();
    value.push(".chio-keyring-pending");
    PathBuf::from(value)
}

pub fn persist_authority_keypair(path: &Path, keypair: &Keypair) -> Result<(), CliError> {
    write_authority_seed_file(path, keypair)
}

pub fn load_keyring_runtime_from_authority_seed(
    config_path: &Path,
    active_seed_path: &Path,
) -> Result<(Keypair, KeyringRuntimeComposition), CliError> {
    let (active, active_identity) =
        load_existing_authority_keypair_with_identity(active_seed_path)?;
    match load_keyring_runtime_composition(&active, config_path) {
        Ok(composition) => {
            cleanup_completed_authority_seed_handoff(active_seed_path, &active, &composition)?;
            Ok((active, composition))
        }
        Err(active_error) => {
            let pending_path = keyring_pending_authority_seed_path(active_seed_path);
            let (handoff, recovered, pending_identity) =
                match load_optional_authority_seed_handoff(&pending_path)? {
                    Some(value) => value,
                    None => return Err(active_error),
                };
            handoff.validate_keypair(&recovered)?;
            match load_keyring_runtime_composition(&recovered, config_path) {
                Ok(composition) => {
                    composition.require_key_log_verification()?;
                    let state = composition
                        .store
                        .load_state()
                        .map_err(|error| CliError::cli_other_error(error.to_string()))?
                        .ok_or_else(|| {
                            CliError::cli_other_error(
                                "keyring operator log is not initialized".to_string(),
                            )
                        })?;
                    if state.pending_event_id().is_some()
                        || state.signing_epoch() != handoff.target_epoch
                        || state
                            .active_signing_key()
                            .map_err(|error| CliError::cli_other_error(error.to_string()))?
                            .key_id
                            .to_string()
                            != handoff.key_id
                    {
                        return Err(active_error);
                    }
                    composition.require_key_log_verification()?;
                    write_authority_seed_file_bound(
                        active_seed_path,
                        &recovered,
                        Some(&active_identity),
                    )?;
                    composition.require_key_log_verification()?;
                    remove_authority_seed_handoff(&pending_path, &handoff, &pending_identity)?;
                    Ok((recovered, composition))
                }
                Err(_) => Err(active_error),
            }
        }
    }
}

pub fn issue_default_capabilities(
    kernel: &ChioKernel,
    agent_pk: &chio_core::PublicKey,
    default_capabilities: &[policy::DefaultCapability],
) -> Result<Vec<chio_core::capability::token::CapabilityToken>, CliError> {
    default_capabilities
        .iter()
        .cloned()
        .map(|default_capability| {
            kernel
                .issue_capability(agent_pk, default_capability.scope, default_capability.ttl)
                .map_err(|error| {
                    CliError::cli_other_error(format!(
                        "failed to issue initial capability: {error}"
                    ))
                })
        })
        .collect()
}

pub fn issue_default_capabilities_with_security_context(
    kernel: &ChioKernel,
    agent_pk: &chio_core::PublicKey,
    default_capabilities: &[policy::DefaultCapability],
    security_context: &chio_kernel::SecurityInvocationContext,
) -> Result<Vec<chio_core::capability::token::CapabilityToken>, CliError> {
    default_capabilities
        .iter()
        .cloned()
        .map(|default_capability| {
            kernel
                .issue_capability_with_security_context(
                    agent_pk,
                    default_capability.scope,
                    default_capability.ttl,
                    security_context,
                )
                .map_err(|error| {
                    CliError::cli_other_error(format!(
                        "failed to issue initial capability with authoritative context: {error}"
                    ))
                })
        })
        .collect()
}

const AUTHORITY_SEED_HANDOFF_SCHEMA: &str = "chio.authority-seed-handoff.v1";
static AUTHORITY_SEED_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Eq, PartialEq)]
struct PrivateFileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    length: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct AuthoritySeedHandoff {
    schema: String,
    key_id: String,
    base_epoch: u64,
    target_epoch: u64,
    seed_hex: String,
}

impl AuthoritySeedHandoff {
    fn new(keypair: &Keypair, base_epoch: u64, target_epoch: u64) -> Result<Self, CliError> {
        if target_epoch
            != base_epoch.checked_add(1).ok_or_else(|| {
                CliError::cli_other_error("authority signing epoch overflow".to_string())
            })?
        {
            return Err(CliError::cli_other_error(
                "authority seed handoff target epoch is not contiguous".to_string(),
            ));
        }
        let public_key = keypair.public_key();
        let key_id = chio_keyring::derive_key_id(public_key.algorithm(), &public_key)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        Ok(Self {
            schema: AUTHORITY_SEED_HANDOFF_SCHEMA.to_string(),
            key_id: key_id.to_string(),
            base_epoch,
            target_epoch,
            seed_hex: keypair.seed_hex(),
        })
    }

    fn validate_keypair(&self, keypair: &Keypair) -> Result<(), CliError> {
        let expected_target = self.base_epoch.checked_add(1).ok_or_else(|| {
            CliError::cli_other_error("authority signing epoch overflow".to_string())
        })?;
        let public_key = keypair.public_key();
        let key_id = chio_keyring::derive_key_id(public_key.algorithm(), &public_key)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        if self.schema != AUTHORITY_SEED_HANDOFF_SCHEMA
            || self.target_epoch != expected_target
            || self.key_id != key_id.to_string()
            || self.seed_hex != keypair.seed_hex()
        {
            return Err(CliError::cli_other_error(
                "authority seed handoff identity or epoch binding is invalid".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QuiescentAuthoritySeedHandoff {
    Completed,
    Resumable { target_epoch: u64 },
}

fn classify_quiescent_authority_seed_handoff(
    handoff: &AuthoritySeedHandoff,
    active_epoch: u64,
    active_key_id: &str,
) -> Result<QuiescentAuthoritySeedHandoff, CliError> {
    if handoff.target_epoch == active_epoch && handoff.key_id == active_key_id {
        return Ok(QuiescentAuthoritySeedHandoff::Completed);
    }
    let target_epoch = active_epoch
        .checked_add(1)
        .ok_or_else(|| CliError::cli_other_error("authority signing epoch overflow".to_string()))?;
    if handoff.base_epoch == active_epoch && handoff.target_epoch == target_epoch {
        return Ok(QuiescentAuthoritySeedHandoff::Resumable { target_epoch });
    }
    Err(CliError::cli_other_error(
        "stale pending authority seed is not bound to the active epoch".to_string(),
    ))
}

fn persist_authority_seed_handoff(
    path: &Path,
    handoff: &AuthoritySeedHandoff,
) -> Result<PrivateFileIdentity, CliError> {
    let bytes = chio_core::canonical::canonical_json_bytes(handoff)?;
    atomic_write_private_file(path, &bytes, None).map_err(CliError::Io)
}

fn load_authority_seed_handoff(
    path: &Path,
) -> Result<(AuthoritySeedHandoff, Keypair, PrivateFileIdentity), CliError> {
    let (bytes, identity) = read_private_file(path, 1_024)?;
    let handoff: AuthoritySeedHandoff = serde_json::from_slice(&bytes)?;
    let keypair = Keypair::from_seed_hex(&handoff.seed_hex)?;
    handoff.validate_keypair(&keypair)?;
    Ok((handoff, keypair, identity))
}

fn load_optional_authority_seed_handoff(
    path: &Path,
) -> Result<Option<(AuthoritySeedHandoff, Keypair, PrivateFileIdentity)>, CliError> {
    match load_authority_seed_handoff(path) {
        Ok(value) => Ok(Some(value)),
        Err(CliError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn cleanup_completed_authority_seed_handoff(
    active_seed_path: &Path,
    active_keypair: &Keypair,
    composition: &KeyringRuntimeComposition,
) -> Result<(), CliError> {
    composition.require_key_log_verification()?;
    let pending_path = keyring_pending_authority_seed_path(active_seed_path);
    let Some((handoff, pending_keypair, identity)) =
        load_optional_authority_seed_handoff(&pending_path)?
    else {
        return Ok(());
    };
    let state = composition
        .store
        .load_state()
        .map_err(|error| CliError::cli_other_error(error.to_string()))?
        .ok_or_else(|| {
            CliError::cli_other_error("keyring operator log is not initialized".to_string())
        })?;
    if state.pending_event_id().is_some() {
        let pending = state.pending_rotation_key().ok_or_else(|| {
            CliError::cli_other_error("pending rotation is missing its key".to_string())
        })?;
        if handoff.base_epoch != state.signing_epoch()
            || handoff.target_epoch
                != state.signing_epoch().checked_add(1).ok_or_else(|| {
                    CliError::cli_other_error("authority signing epoch overflow".to_string())
                })?
            || handoff.key_id != pending.key_id.to_string()
        {
            return Err(CliError::cli_other_error(
                "pending authority seed does not match the durable rotation".to_string(),
            ));
        }
        return Ok(());
    }
    let active_public_key = active_keypair.public_key();
    let active_key_id =
        chio_keyring::derive_key_id(active_public_key.algorithm(), &active_public_key)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    match classify_quiescent_authority_seed_handoff(
        &handoff,
        state.signing_epoch(),
        &active_key_id.to_string(),
    )? {
        QuiescentAuthoritySeedHandoff::Completed => {
            if pending_keypair.public_key() != active_public_key {
                return Err(CliError::cli_other_error(
                    "completed authority seed handoff does not match the active key".to_string(),
                ));
            }
            composition.require_key_log_verification()?;
            remove_authority_seed_handoff(&pending_path, &handoff, &identity)
        }
        QuiescentAuthoritySeedHandoff::Resumable { .. } => Ok(()),
    }
}

fn remove_authority_seed_handoff(
    path: &Path,
    expected: &AuthoritySeedHandoff,
    expected_identity: &PrivateFileIdentity,
) -> Result<(), CliError> {
    let (current, _, identity) = load_authority_seed_handoff(path)?;
    if &current != expected || &identity != expected_identity {
        return Err(CliError::cli_other_error(
            "pending authority seed changed before cleanup".to_string(),
        ));
    }
    fs::remove_file(path)?;
    sync_parent_directory(path)?;
    Ok(())
}

fn write_authority_seed_file_bound(
    path: &Path,
    keypair: &Keypair,
    expected_identity: Option<&PrivateFileIdentity>,
) -> Result<PrivateFileIdentity, CliError> {
    atomic_write_private_file(
        path,
        format!("{}\n", keypair.seed_hex()).as_bytes(),
        expected_identity,
    )
    .map_err(CliError::Io)
}

fn read_private_file(
    path: &Path,
    maximum_bytes: usize,
) -> Result<(Vec<u8>, PrivateFileIdentity), std::io::Error> {
    let path_metadata = fs::symlink_metadata(path)?;
    validate_private_file_metadata(&path_metadata)?;
    #[cfg(unix)]
    let mut file = {
        use rustix::fs::{open, Mode, OFlags};

        let descriptor = open(
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| std::io::Error::from_raw_os_error(error.raw_os_error()))?;
        File::from(descriptor)
    };
    #[cfg(not(unix))]
    let mut file = OpenOptions::new().read(true).open(path)?;
    let opened_metadata = file.metadata()?;
    validate_private_file_metadata(&opened_metadata)?;
    let expected_identity = identity_from_metadata(&path_metadata);
    if identity_from_metadata(&opened_metadata) != expected_identity {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "private file changed while it was opened",
        ));
    }
    let limit = u64::try_from(maximum_bytes)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "file limit"))?
        .checked_add(1)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "file limit"))?;
    let mut bytes = Vec::with_capacity(maximum_bytes);
    Read::by_ref(&mut file)
        .take(limit)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "private file exceeds its byte limit",
        ));
    }
    let final_path_metadata = fs::symlink_metadata(path)?;
    validate_private_file_metadata(&final_path_metadata)?;
    if identity_from_metadata(&final_path_metadata) != expected_identity
        || identity_from_metadata(&file.metadata()?) != expected_identity
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "private file identity changed while it was read",
        ));
    }
    Ok((bytes, expected_identity))
}

fn load_private_seed_backend(path: &Path) -> Result<chio_core::crypto::Ed25519Backend, CliError> {
    let (mut bytes, _) = read_private_file(path, 32)?;
    if bytes.len() != 32 {
        bytes.fill(0);
        return Err(CliError::cli_other_error(
            "signing seed must contain exactly 32 bytes".to_string(),
        ));
    }
    let mut seed = [0_u8; 32];
    seed.copy_from_slice(&bytes);
    bytes.fill(0);
    let keypair = Keypair::from_seed(&seed);
    seed.fill(0);
    Ok(chio_core::crypto::Ed25519Backend::new(keypair))
}

fn private_file_identity(path: &Path) -> Result<PrivateFileIdentity, std::io::Error> {
    let metadata = fs::symlink_metadata(path)?;
    validate_private_file_metadata(&metadata)?;
    Ok(identity_from_metadata(&metadata))
}

fn validate_private_file_metadata(metadata: &fs::Metadata) -> Result<(), std::io::Error> {
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "private key material must be a regular file",
        ));
    }
    #[cfg(unix)]
    if metadata.nlink() != 1 || metadata.mode() & 0o177 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "private key material must be singly linked with mode 0600 or stricter",
        ));
    }
    Ok(())
}

fn identity_from_metadata(metadata: &fs::Metadata) -> PrivateFileIdentity {
    PrivateFileIdentity {
        #[cfg(unix)]
        device: metadata.dev(),
        #[cfg(unix)]
        inode: metadata.ino(),
        length: metadata.len(),
    }
}

fn atomic_write_private_file(
    path: &Path,
    bytes: &[u8],
    expected_identity: Option<&PrivateFileIdentity>,
) -> Result<PrivateFileIdentity, std::io::Error> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    if !parent_metadata.file_type().is_dir() || parent_metadata.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "private key parent must be a regular directory",
        ));
    }
    validate_destination_identity(path, expected_identity)?;
    let mut temp_path = None;
    let mut temp_file = None;
    for _ in 0..128 {
        let counter = AUTHORITY_SEED_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut name = path.file_name().unwrap_or_default().to_os_string();
        name.push(format!(".{}.{}.tmp", std::process::id(), counter));
        let candidate = parent.join(name);
        #[cfg(unix)]
        let opened = {
            use rustix::fs::{open, Mode, OFlags};

            open(
                &candidate,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::RUSR | Mode::WUSR,
            )
            .map(File::from)
            .map_err(|error| std::io::Error::from_raw_os_error(error.raw_os_error()))
        };
        #[cfg(not(unix))]
        let opened = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate);
        match opened {
            Ok(file) => {
                temp_path = Some(candidate);
                temp_file = Some(file);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    let temp_path = temp_path.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "unable to allocate a unique private-key temp file",
        )
    })?;
    let result = (|| {
        let mut file =
            temp_file.ok_or_else(|| std::io::Error::other("private temp file missing"))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        validate_private_file_metadata(&file.metadata()?)?;
        validate_destination_identity(path, expected_identity)?;
        fs::rename(&temp_path, path)?;
        sync_parent_directory(path)?;
        private_file_identity(path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn validate_destination_identity(
    path: &Path,
    expected_identity: Option<&PrivateFileIdentity>,
) -> Result<(), std::io::Error> {
    match (private_file_identity(path), expected_identity) {
        (Ok(actual), Some(expected)) if &actual == expected => Ok(()),
        (Ok(_), Some(_)) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "private key destination identity changed",
        )),
        (Err(error), None) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        (Ok(_), None) => Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "private key destination already exists",
        )),
        (Err(error), _) => Err(error),
    }
}

fn sync_parent_directory(path: &Path) -> Result<(), std::io::Error> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    File::open(parent)?.sync_all()
}

fn write_authority_seed_file(path: &Path, keypair: &Keypair) -> Result<(), CliError> {
    let expected = match private_file_identity(path) {
        Ok(identity) => Some(identity),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(CliError::Io(error)),
    };
    write_authority_seed_file_bound(path, keypair, expected.as_ref())?;
    Ok(())
}
