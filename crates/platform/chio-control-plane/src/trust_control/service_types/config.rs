use super::super::cluster_replay::{
    cluster_replay_path_aliases, ensure_secure_cluster_replay_platform,
};
use super::super::report_validation::normalize_cluster_config_url;
use super::*;

pub(crate) fn load_strict_cluster_node_keypair(path: &Path) -> Result<Keypair, CliError> {
    load_strict_cluster_node_keypair_with_hook(path, || {})
}

fn load_strict_cluster_node_keypair_with_hook(
    path: &Path,
    after_open: impl FnOnce(),
) -> Result<Keypair, CliError> {
    let bytes = read_strict_cluster_node_seed(path, after_open)?;
    let seed_bytes = match bytes.as_slice() {
        bytes if bytes.len() == 64 => bytes,
        bytes if bytes.len() == 65 && bytes.last() == Some(&b'\n') => &bytes[..64],
        _ => {
            return Err(CliError::cli_other_error(
                "cluster node seed must contain exactly 64 lowercase hex characters and at most one trailing newline"
                    .to_string(),
            ));
        }
    };
    if !seed_bytes
        .iter()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(CliError::cli_other_error(
            "cluster node seed must contain exactly 64 lowercase hex characters".to_string(),
        ));
    }
    let seed_hex = std::str::from_utf8(seed_bytes).map_err(|_| {
        CliError::cli_other_error("cluster node seed is not valid UTF-8".to_string())
    })?;
    Keypair::from_seed_hex(seed_hex).map_err(CliError::from)
}

#[cfg(unix)]
fn read_strict_cluster_node_seed(
    path: &Path,
    after_open: impl FnOnce(),
) -> Result<Vec<u8>, CliError> {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;

    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(CliError::cli_other_error(
            "cluster node seed path must be absolute and contain no dot components".to_string(),
        ));
    }
    let parent_path = path.parent().ok_or_else(|| {
        CliError::cli_other_error("cluster node seed path has no parent".to_string())
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        CliError::cli_other_error("cluster node seed path has no file name".to_string())
    })?;
    let parent = open_trusted_cluster_seed_directory_chain(parent_path)?;
    let parent_metadata = parent.metadata().map_err(CliError::Io)?;
    let descriptor = rustix::fs::openat(
        &parent,
        file_name,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| CliError::Io(error.into()))?;
    let mut file = std::fs::File::from(descriptor);
    let metadata = file.metadata().map_err(CliError::Io)?;
    validate_cluster_seed_file_descriptor(&file, &metadata)?;
    after_open();

    let mut bytes = Vec::with_capacity(65);
    Read::by_ref(&mut file)
        .take(66)
        .read_to_end(&mut bytes)
        .map_err(CliError::Io)?;
    if bytes.len() > 65 {
        return Err(CliError::cli_other_error(
            "cluster node seed exceeds its byte limit".to_string(),
        ));
    }

    let current_parent = open_trusted_cluster_seed_directory_chain(parent_path)?;
    let current_parent_metadata = current_parent.metadata().map_err(CliError::Io)?;
    if current_parent_metadata.dev() != parent_metadata.dev()
        || current_parent_metadata.ino() != parent_metadata.ino()
    {
        return Err(CliError::cli_other_error(
            "cluster node seed ancestor identity changed while custody was read".to_string(),
        ));
    }
    let current_descriptor = rustix::fs::openat(
        &parent,
        file_name,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| CliError::Io(error.into()))?;
    let current_file = std::fs::File::from(current_descriptor);
    let current_metadata = current_file.metadata().map_err(CliError::Io)?;
    validate_cluster_seed_file_descriptor(&current_file, &current_metadata)?;
    let retained_metadata = file.metadata().map_err(CliError::Io)?;
    if current_metadata.dev() != metadata.dev()
        || current_metadata.ino() != metadata.ino()
        || retained_metadata.dev() != metadata.dev()
        || retained_metadata.ino() != metadata.ino()
    {
        return Err(CliError::cli_other_error(
            "cluster node seed file identity changed while custody was read".to_string(),
        ));
    }
    Ok(bytes)
}

#[cfg(not(unix))]
fn read_strict_cluster_node_seed(
    _path: &Path,
    _after_open: impl FnOnce(),
) -> Result<Vec<u8>, CliError> {
    Err(CliError::cli_other_error(
        "strict cluster node seed custody is unsupported on this platform".to_string(),
    ))
}

#[cfg(unix)]
fn open_trusted_cluster_seed_directory_chain(path: &Path) -> Result<std::fs::File, CliError> {
    let mut names = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(name) => names.push(name.to_os_string()),
            std::path::Component::Prefix(_) => {
                return Err(CliError::cli_other_error(
                    "cluster node seed path has an unsupported prefix".to_string(),
                ));
            }
            std::path::Component::CurDir | std::path::Component::ParentDir => {
                return Err(CliError::cli_other_error(
                    "cluster node seed path must not contain dot components".to_string(),
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
    .map_err(|error| CliError::Io(error.into()))?;
    let mut directory = std::fs::File::from(root);
    validate_cluster_seed_directory_descriptor(&directory, !names.is_empty())?;
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
        .map_err(|error| CliError::Io(error.into()))?;
        let next = std::fs::File::from(descriptor);
        validate_cluster_seed_directory_descriptor(&next, index + 1 != name_count)?;
        directory = next;
    }
    Ok(directory)
}

#[cfg(unix)]
fn validate_cluster_seed_directory_descriptor(
    directory: &std::fs::File,
    allow_sticky_write: bool,
) -> Result<(), CliError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = directory.metadata().map_err(CliError::Io)?;
    let effective_uid = rustix::process::geteuid().as_raw();
    let trusted_owner = metadata.uid() == effective_uid || metadata.uid() == 0;
    let group_or_world_writable = metadata.mode() & 0o022 != 0;
    let sticky = metadata.mode() & 0o1000 != 0;
    if !metadata.file_type().is_dir()
        || !trusted_owner
        || (group_or_world_writable && !(allow_sticky_write && sticky))
        || cluster_seed_descriptor_grants_extended_acl_authority(directory)?
    {
        return Err(CliError::cli_other_error(
            "cluster node seed ancestor chain grants untrusted write authority".to_string(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_cluster_seed_file_descriptor(
    file: &std::fs::File,
    metadata: &std::fs::Metadata,
) -> Result<(), CliError> {
    use std::os::unix::fs::MetadataExt;

    let effective_uid = rustix::process::geteuid().as_raw();
    if !metadata.file_type().is_file()
        || (metadata.uid() != effective_uid && metadata.uid() != 0)
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
        || cluster_seed_descriptor_grants_extended_acl_authority(file)?
    {
        return Err(CliError::cli_other_error(
            "cluster node seed must have trusted ownership, mode 0600 or stricter, no authority-granting ACL, and one hard link"
                .to_string(),
        ));
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn cluster_seed_descriptor_grants_extended_acl_authority(
    file: &std::fs::File,
) -> Result<bool, CliError> {
    for attribute in ["system.posix_acl_access", "system.posix_acl_default"] {
        let mut value = Vec::<u8>::with_capacity(1);
        match rustix::fs::fgetxattr(file, attribute, &mut value) {
            Ok(_) | Err(rustix::io::Errno::RANGE) => return Ok(true),
            Err(error) if error == rustix::io::Errno::NODATA => {}
            Err(error) if error == rustix::io::Errno::NOTSUP => {}
            Err(error) => return Err(CliError::Io(error.into())),
        }
    }
    Ok(false)
}

#[cfg(target_vendor = "apple")]
fn cluster_seed_descriptor_grants_extended_acl_authority(
    file: &std::fs::File,
) -> Result<bool, CliError> {
    chio_keyring::darwin_descriptor_grants_extended_acl_authority(file)
        .map_err(|error| CliError::cli_other_error(error.to_string()))
}

#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android", target_vendor = "apple"))
))]
fn cluster_seed_descriptor_grants_extended_acl_authority(
    _file: &std::fs::File,
) -> Result<bool, CliError> {
    Err(CliError::cli_other_error(
        "cluster node seed ACL inspection is unsupported on this platform".to_string(),
    ))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClusterMemberIdentity {
    pub node_url: String,
    pub public_key: PublicKey,
}

#[derive(Clone)]
pub struct AuthorityWorkloadPolicy {
    pub credential_token: String,
    pub tenant_id: String,
    pub workload_id: String,
    pub server_id: String,
    pub signer_public_key: PublicKey,
    pub session_admission_public_key: PublicKey,
    pub allowed_capabilities: Vec<crate::policy::DefaultCapability>,
}

impl AuthorityWorkloadPolicy {
    pub(crate) fn derive_capability(
        &self,
        requested_scope: &ChioScope,
        requested_ttl: u64,
    ) -> Result<(ChioScope, u64), String> {
        let requested = canonical_json_bytes(requested_scope).map_err(|error| error.to_string())?;
        let mut matched_ttl = None;
        let mut matched_scope = None;
        for capability in &self.allowed_capabilities {
            let mut allowed_scope = capability.scope.clone();
            for grant in &mut allowed_scope.grants {
                if grant.server_id == "*" {
                    grant.server_id.clone_from(&self.server_id);
                }
            }
            let canonical =
                canonical_json_bytes(&allowed_scope).map_err(|error| error.to_string())?;
            if canonical == requested {
                matched_ttl =
                    Some(matched_ttl.map_or(capability.ttl, |ttl: u64| ttl.min(capability.ttl)));
                matched_scope = Some(allowed_scope);
            }
        }
        let scope = matched_scope.ok_or_else(|| {
            "requested capability scope is not an exact workload-policy grant".to_string()
        })?;
        let ttl = requested_ttl.min(matched_ttl.unwrap_or_default());
        if ttl == 0 {
            return Err("derived capability TTL is zero".to_string());
        }
        Ok((scope, ttl))
    }
}

#[derive(Clone)]
pub struct TrustServiceConfig {
    pub listen: SocketAddr,
    pub service_token: String,
    pub dashboard_read_token: Option<String>,
    pub dashboard_report_origin: Option<String>,
    pub dashboard_report_token: Option<String>,
    pub dashboard_allow_insecure_report_origin: bool,
    pub authority_admin_token: Option<String>,
    pub authority_workloads: Vec<AuthorityWorkloadPolicy>,
    pub tenant_read_tokens: BTreeMap<String, String>,
    pub receipt_db_path: Option<PathBuf>,
    pub revocation_db_path: Option<PathBuf>,
    pub authority_seed_path: Option<PathBuf>,
    pub authority_db_path: Option<PathBuf>,
    pub authority_keyring_config_path: Option<PathBuf>,
    pub budget_db_path: Option<PathBuf>,
    pub partition_escrow_authority:
        Option<Arc<super::super::service_runtime::budget::SealedPartitionEscrowRemoteAuthority>>,
    pub enterprise_providers_file: Option<PathBuf>,
    pub federation_policies_file: Option<PathBuf>,
    pub scim_lifecycle_file: Option<PathBuf>,
    pub verifier_policies_file: Option<PathBuf>,
    pub verifier_challenge_db_path: Option<PathBuf>,
    pub passport_statuses_file: Option<PathBuf>,
    pub passport_issuance_offers_file: Option<PathBuf>,
    pub certification_registry_file: Option<PathBuf>,
    pub certification_discovery_file: Option<PathBuf>,
    pub issuance_policy: Option<crate::policy::ReputationIssuancePolicy>,
    pub runtime_assurance_policy: Option<crate::policy::RuntimeAssuranceIssuancePolicy>,
    pub advertise_url: Option<String>,
    pub allow_local_peer_urls: bool,
    pub certification_public_metadata_ttl_seconds: u64,
    pub peer_urls: Vec<String>,
    pub cluster_node_seed_path: Option<PathBuf>,
    pub cluster_replay_db_path: Option<PathBuf>,
    pub cluster_members: Vec<ClusterMemberIdentity>,
    pub cluster_sync_interval: Duration,
    pub roster_policy: Option<RosterPolicy>,
    /// Process memory budget for the trust control service. Its
    /// `admission_key_cap` bounds the federation admission rate limiter, so
    /// lowering it here actually tightens that guard rather than being silently
    /// overridden by the compiled-in default.
    pub memory_budget: chio_kernel::MemoryBudgetConfig,
}

impl TrustServiceConfig {
    pub fn validate(&self) -> Result<(), CliError> {
        validate_control_secret(&self.service_token, "control service token")?;
        self.validate_dashboard_report_bridge()?;
        if let Some(dashboard_token) = self.dashboard_read_token.as_deref() {
            validate_control_secret(dashboard_token, "dashboard read token")?;
            if dashboard_token.len() > super::super::dashboard_auth::DASHBOARD_READ_TOKEN_MAX_BYTES
            {
                return Err(CliError::cli_other_error(
                    "dashboard read token exceeds its byte limit".to_string(),
                ));
            }
            let reused = dashboard_token == self.service_token
                || self
                    .authority_admin_token
                    .as_deref()
                    .is_some_and(|token| token == dashboard_token)
                || self
                    .authority_workloads
                    .iter()
                    .any(|workload| workload.credential_token == dashboard_token)
                || self
                    .tenant_read_tokens
                    .values()
                    .any(|token| token == dashboard_token)
                || self
                    .dashboard_report_token
                    .as_deref()
                    .is_some_and(|token| token == dashboard_token);
            if reused {
                return Err(CliError::cli_other_error(
                    "dashboard read token must be distinct from every service, authority, workload, and tenant credential"
                        .to_string(),
                ));
            }
        }
        if self.authority_seed_path.is_some() && self.authority_db_path.is_some() {
            return Err(CliError::cli_other_error(
                "use either --authority-seed-file or --authority-db, not both".to_string(),
            ));
        }
        if !self.peer_urls.is_empty()
            && (self.authority_seed_path.is_some() || self.authority_db_path.is_some())
        {
            return Err(CliError::cli_other_error(
                "clustered capability-authority custody and issuance are unsupported until a shared authority write and selector protocol is configured; authority snapshots are observational only"
                    .to_string(),
            ));
        }
        if !self.peer_urls.is_empty() {
            match (
                self.budget_db_path.as_deref(),
                self.revocation_db_path.as_deref(),
            ) {
                (None, None) => {}
                (Some(budget_path), Some(revocation_path)) => {
                    if !cluster_replay_path_aliases(budget_path, revocation_path)? {
                        return Err(CliError::cli_other_error(
                            "HA admission consensus requires budget and revocation state to use one SQLite database"
                                .to_string(),
                        ));
                    }
                }
                _ => {
                    return Err(CliError::cli_other_error(
                        "HA admission consensus requires budget and revocation databases together"
                            .to_string(),
                    ));
                }
            }
        }
        if let (Some(receipt_path), Some(authority_path)) = (
            self.receipt_db_path.as_deref(),
            self.authority_db_path.as_deref(),
        ) {
            if cluster_replay_path_aliases(receipt_path, authority_path)? {
                return Err(CliError::cli_other_error(
                    "authority database must be distinct from the receipt and security-state database"
                        .to_string(),
                ));
            }
        }
        if self.authority_seed_path.is_some() || self.authority_db_path.is_some() {
            let admin_token = self.authority_admin_token.as_ref().ok_or_else(|| {
                CliError::cli_other_error(
                    "configured authority custody requires a dedicated authority admin token"
                        .to_string(),
                )
            })?;
            validate_control_secret(admin_token, "authority admin token")?;
            if admin_token == &self.service_token {
                return Err(CliError::cli_other_error(
                    "authority admin token must not equal the control service token".to_string(),
                ));
            }
            let mut workload_tokens = BTreeSet::new();
            let mut workload_keys = BTreeSet::new();
            let mut session_admission_keys = BTreeSet::new();
            let mut workload_identities = BTreeSet::new();
            for workload in &self.authority_workloads {
                validate_control_secret(
                    &workload.credential_token,
                    "authority workload credential token",
                )?;
                if workload.credential_token == self.service_token
                    || workload.credential_token == *admin_token
                {
                    return Err(CliError::cli_other_error(
                        "authority workload credential must be distinct from service and authority admin tokens"
                            .to_string(),
                    ));
                }
                if !workload_tokens.insert(workload.credential_token.clone()) {
                    return Err(CliError::cli_other_error(
                        "authority workload credential tokens must be unique".to_string(),
                    ));
                }
                if !workload_keys.insert(workload.signer_public_key.to_hex()) {
                    return Err(CliError::cli_other_error(
                        "authority workload signer public keys must be unique".to_string(),
                    ));
                }
                if workload.session_admission_public_key == workload.signer_public_key {
                    return Err(CliError::cli_other_error(
                        "authority session-admission signer must be distinct from the workload request signer"
                            .to_string(),
                    ));
                }
                if !session_admission_keys.insert(workload.session_admission_public_key.to_hex()) {
                    return Err(CliError::cli_other_error(
                        "authority session-admission signer public keys must be unique".to_string(),
                    ));
                }
                if !workload_identities.insert((
                    workload.tenant_id.clone(),
                    workload.workload_id.clone(),
                    workload.server_id.clone(),
                )) {
                    return Err(CliError::cli_other_error(
                        "authority workload tenant, workload, and server identities must be unique"
                            .to_string(),
                    ));
                }
                for (label, value) in [
                    ("tenant", workload.tenant_id.as_str()),
                    ("workload", workload.workload_id.as_str()),
                    ("server", workload.server_id.as_str()),
                ] {
                    if value.is_empty()
                        || value.trim() != value
                        || value.chars().any(char::is_control)
                    {
                        return Err(CliError::cli_other_error(format!(
                            "authority workload {label} identity is invalid"
                        )));
                    }
                }
                if workload.allowed_capabilities.is_empty() {
                    return Err(CliError::cli_other_error(
                        "authority workload policy requires at least one allowed capability"
                            .to_string(),
                    ));
                }
                for capability in &workload.allowed_capabilities {
                    if capability.ttl == 0 {
                        return Err(CliError::cli_other_error(
                            "authority workload policy capability TTL must be non-zero".to_string(),
                        ));
                    }
                    if capability.scope.grants.iter().any(|grant| {
                        grant.server_id != "*" && grant.server_id != workload.server_id
                    }) {
                        return Err(CliError::cli_other_error(
                            "authority workload policy contains a tool grant for another server"
                                .to_string(),
                        ));
                    }
                }
            }
            if !workload_keys.is_disjoint(&session_admission_keys) {
                return Err(CliError::cli_other_error(
                    "authority workload and session-admission signer roles must use disjoint keys"
                        .to_string(),
                ));
            }
            for (tenant_id, token) in &self.tenant_read_tokens {
                if token == admin_token || workload_tokens.contains(token) {
                    return Err(CliError::cli_other_error(format!(
                        "tenant read token for `{tenant_id}` must be distinct from every authority credential"
                    )));
                }
            }
            if !self.authority_workloads.is_empty() {
                if self.authority_seed_path.is_none()
                    || self.authority_db_path.is_some()
                    || self.authority_keyring_config_path.is_none()
                {
                    return Err(CliError::cli_other_error(
                        "authority workload issuance requires --authority-seed-file plus --authority-keyring-config and forbids --authority-db"
                            .to_string(),
                    ));
                }
                if !self.peer_urls.is_empty() {
                    return Err(CliError::cli_other_error(
                        "clustered keyring capability issuance is unsupported until selector leases are integrated with cluster consensus"
                            .to_string(),
                    ));
                }
            } else if self.authority_keyring_config_path.is_some() {
                return Err(CliError::cli_other_error(
                    "authority keyring configuration requires at least one pinned authority workload"
                        .to_string(),
                ));
            }
        } else if self.authority_admin_token.is_some()
            || !self.authority_workloads.is_empty()
            || self.authority_keyring_config_path.is_some()
        {
            return Err(CliError::cli_other_error(
                "authority credentials require configured authority custody".to_string(),
            ));
        }
        let mut tenant_read_secret_set = BTreeSet::new();
        for (tenant_id, token) in &self.tenant_read_tokens {
            if tenant_id.trim().is_empty() {
                return Err(CliError::cli_other_error(
                    "tenant read token id must be non-empty".to_string(),
                ));
            }
            if tenant_id.trim() != tenant_id {
                return Err(CliError::cli_other_error(
                    "tenant read token id must not contain surrounding whitespace".to_string(),
                ));
            }
            if tenant_id.chars().any(char::is_control) {
                return Err(CliError::cli_other_error(
                    "tenant read token id must not contain control characters".to_string(),
                ));
            }
            let token_label = format!("tenant read token for `{tenant_id}`");
            validate_control_secret(token, &token_label)?;
            if token == &self.service_token {
                return Err(CliError::cli_other_error(
                    "control tenant read token must not equal service token".to_string(),
                ));
            }
            if !tenant_read_secret_set.insert(token.clone()) {
                return Err(CliError::cli_other_error(
                    "tenant read tokens must be unique across tenants".to_string(),
                ));
            }
        }
        if self.cluster_sync_interval.is_zero() {
            return Err(CliError::cli_other_error(
                "cluster sync interval must be non-zero".to_string(),
            ));
        }
        self.validate_cluster_membership()?;
        self.validate_partition_escrow_authority()?;
        if self.certification_public_metadata_ttl_seconds == 0 {
            return Err(CliError::cli_other_error(
                "certification public metadata TTL must be non-zero".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_partition_escrow_authority(&self) -> Result<(), CliError> {
        let Some(authority) = self.partition_escrow_authority.as_deref() else {
            return Ok(());
        };
        if self.peer_urls.is_empty()
            || self.budget_db_path.is_none()
            || self.revocation_db_path.is_none()
            || self.cluster_members.is_empty()
        {
            return Err(CliError::cli_other_error(
                "partition escrow service authority requires HA admission consensus and a shared budget/revocation database"
                    .to_string(),
            ));
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "partition escrow authority clock is before the Unix epoch: {error}"
                ))
            })?
            .as_secs();
        authority
            .verify_current(now)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        let mut normalized_members = self
            .cluster_members
            .iter()
            .map(|member| {
                Ok(ClusterMemberIdentity {
                    node_url: normalize_cluster_config_url(
                        &member.node_url,
                        self.allow_local_peer_urls,
                    )?,
                    public_key: member.public_key.clone(),
                })
            })
            .collect::<Result<Vec<_>, CliError>>()?;
        normalized_members
            .sort_by(|left, right| left.node_url.as_bytes().cmp(right.node_url.as_bytes()));
        authority.validate_cluster_members(&normalized_members)?;
        let endpoints = normalized_members
            .iter()
            .map(|member| member.node_url.clone())
            .collect::<Vec<_>>();
        authority.validate_service_endpoints(&endpoints)?;
        super::super::cluster::validate_partition_escrow_admission_membership(self, authority)
    }

    fn validate_dashboard_report_bridge(&self) -> Result<(), CliError> {
        let (origin, token) = match (
            self.dashboard_report_origin.as_deref(),
            self.dashboard_report_token.as_deref(),
        ) {
            (None, None) => {
                if self.dashboard_allow_insecure_report_origin {
                    return Err(CliError::cli_other_error(
                        "insecure dashboard report origin mode requires a configured report origin and token"
                            .to_string(),
                    ));
                }
                return Ok(());
            }
            (Some(origin), Some(token)) => (origin, token),
            _ => {
                return Err(CliError::cli_other_error(
                    "dashboard report origin and server-side read token must be configured together"
                        .to_string(),
                ));
            }
        };
        validate_control_secret(token, "dashboard report read token")?;
        if token.len() > super::super::dashboard_auth::DASHBOARD_READ_TOKEN_MAX_BYTES {
            return Err(CliError::cli_other_error(
                "dashboard report read token exceeds its byte limit".to_string(),
            ));
        }
        let reused = token == self.service_token
            || self
                .dashboard_read_token
                .as_deref()
                .is_some_and(|credential| credential == token)
            || self
                .authority_admin_token
                .as_deref()
                .is_some_and(|credential| credential == token)
            || self
                .authority_workloads
                .iter()
                .any(|workload| workload.credential_token == token)
            || self
                .tenant_read_tokens
                .values()
                .any(|credential| credential == token);
        if reused {
            return Err(CliError::cli_other_error(
                "dashboard report read token must be distinct from every dashboard, service, authority, workload, and tenant credential"
                    .to_string(),
            ));
        }

        if origin.trim() != origin || origin.chars().any(char::is_control) {
            return Err(CliError::cli_other_error(
                "dashboard report origin must not contain whitespace or control characters"
                    .to_string(),
            ));
        }
        let parsed = url::Url::parse(origin).map_err(|_| {
            CliError::cli_other_error("dashboard report origin is not a valid URL".to_string())
        })?;
        if !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.path() != "/"
        {
            return Err(CliError::cli_other_error(
                "dashboard report origin must be an origin URL without credentials, path, query, or fragment"
                    .to_string(),
            ));
        }
        let insecure_loopback = parsed.scheme() == "http"
            && self.dashboard_allow_insecure_report_origin
            && parsed.host_str().is_some_and(|host| {
                host.eq_ignore_ascii_case("localhost")
                    || host
                        .parse::<IpAddr>()
                        .is_ok_and(|address| address.is_loopback())
            });
        if parsed.scheme() != "https" && !insecure_loopback {
            return Err(CliError::cli_other_error(
                "dashboard report origin must use HTTPS; HTTP is restricted to explicit loopback test mode"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn validate_cluster_membership(&self) -> Result<(), CliError> {
        if self.peer_urls.is_empty() {
            if self.cluster_node_seed_path.is_some()
                || self.cluster_replay_db_path.is_some()
                || !self.cluster_members.is_empty()
            {
                return Err(CliError::cli_other_error(
                    "cluster membership identity requires at least one configured peer URL"
                        .to_string(),
                ));
            }
            return Ok(());
        }
        ensure_secure_cluster_replay_platform()?;

        let advertise_url = self.advertise_url.as_deref().ok_or_else(|| {
            CliError::cli_other_error(
                "clustered trust control requires an explicit --advertise-url".to_string(),
            )
        })?;
        let self_url = normalize_cluster_config_url(advertise_url, self.allow_local_peer_urls)?;
        let seed_path = self.cluster_node_seed_path.as_deref().ok_or_else(|| {
            CliError::cli_other_error(
                "clustered trust control requires --cluster-node-seed-file".to_string(),
            )
        })?;
        let replay_db_path = self.cluster_replay_db_path.as_deref().ok_or_else(|| {
            CliError::cli_other_error(
                "clustered trust control requires --cluster-replay-db".to_string(),
            )
        })?;
        for (label, store_path) in [
            ("receipt database", self.receipt_db_path.as_deref()),
            ("revocation database", self.revocation_db_path.as_deref()),
            ("authority database", self.authority_db_path.as_deref()),
            (
                "authority keyring configuration",
                self.authority_keyring_config_path.as_deref(),
            ),
            ("budget database", self.budget_db_path.as_deref()),
            (
                "verifier challenge database",
                self.verifier_challenge_db_path.as_deref(),
            ),
            (
                "enterprise provider registry",
                self.enterprise_providers_file.as_deref(),
            ),
            (
                "federation policy registry",
                self.federation_policies_file.as_deref(),
            ),
            (
                "SCIM lifecycle registry",
                self.scim_lifecycle_file.as_deref(),
            ),
            (
                "verifier policy registry",
                self.verifier_policies_file.as_deref(),
            ),
            (
                "passport status registry",
                self.passport_statuses_file.as_deref(),
            ),
            (
                "passport issuance registry",
                self.passport_issuance_offers_file.as_deref(),
            ),
            (
                "certification registry",
                self.certification_registry_file.as_deref(),
            ),
            (
                "certification discovery registry",
                self.certification_discovery_file.as_deref(),
            ),
        ] {
            if store_path
                .map(|path| cluster_replay_path_aliases(replay_db_path, path))
                .transpose()?
                .unwrap_or(false)
            {
                return Err(CliError::cli_other_error(format!(
                    "cluster replay database must be distinct from the {label}"
                )));
            }
        }
        if cluster_replay_path_aliases(replay_db_path, seed_path)? {
            return Err(CliError::cli_other_error(
                "cluster replay database must be distinct from the node identity seed".to_string(),
            ));
        }
        if self
            .authority_seed_path
            .as_deref()
            .map(|path| cluster_replay_path_aliases(seed_path, path))
            .transpose()?
            .unwrap_or(false)
        {
            return Err(CliError::cli_other_error(
                "cluster node identity seed must be distinct from authority custody".to_string(),
            ));
        }
        let node_keypair = load_strict_cluster_node_keypair(seed_path).map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to load strict cluster node identity seed: {error}"
            ))
        })?;
        let node_public_key = node_keypair.public_key();
        let node_seed_hex = node_keypair.seed_hex();
        let cluster_secret_reused_as_bearer = std::iter::once(self.service_token.as_str())
            .chain(self.dashboard_read_token.iter().map(String::as_str))
            .chain(self.dashboard_report_token.iter().map(String::as_str))
            .chain(self.authority_admin_token.iter().map(String::as_str))
            .chain(
                self.authority_workloads
                    .iter()
                    .map(|workload| workload.credential_token.as_str()),
            )
            .chain(self.tenant_read_tokens.values().map(String::as_str))
            .any(|credential| {
                credential
                    .strip_prefix("0x")
                    .unwrap_or(credential)
                    .eq_ignore_ascii_case(&node_seed_hex)
            });
        if cluster_secret_reused_as_bearer {
            return Err(CliError::cli_other_error(
                "cluster node identity seed must not be reused as any bearer credential"
                    .to_string(),
            ));
        }
        if self.authority_workloads.iter().any(|workload| {
            workload.signer_public_key == node_public_key
                || workload.session_admission_public_key == node_public_key
        }) {
            return Err(CliError::cli_other_error(
                "cluster node identity key must be distinct from every authority workload and session-admission identity"
                    .to_string(),
            ));
        }
        if let Some(authority_seed_path) = self.authority_seed_path.as_deref() {
            let authority_key = load_existing_authority_keypair(authority_seed_path)?;
            if authority_key.public_key() == node_public_key {
                return Err(CliError::cli_other_error(
                    "cluster node identity key must be distinct from authority custody".to_string(),
                ));
            }
        }
        if let Some(authority_db_path) = self
            .authority_db_path
            .as_deref()
            .filter(|path| path.exists())
        {
            let authority = SqliteCapabilityAuthority::open_existing(authority_db_path)?;
            if authority
                .status()?
                .trusted_public_keys
                .iter()
                .any(|trusted_key| trusted_key == &node_public_key)
            {
                return Err(CliError::cli_other_error(
                    "cluster node identity key must be distinct from current and historical authority custody"
                        .to_string(),
                ));
            }
        }

        let mut expected_urls = BTreeSet::from([self_url.clone()]);
        for peer_url in &self.peer_urls {
            let peer_url = normalize_cluster_config_url(peer_url, self.allow_local_peer_urls)?;
            if peer_url == self_url {
                return Err(CliError::cli_other_error(
                    "cluster peer URL must not repeat this node's advertise URL".to_string(),
                ));
            }
            if !expected_urls.insert(peer_url.clone()) {
                return Err(CliError::cli_other_error(format!(
                    "duplicate normalized cluster peer URL `{peer_url}`"
                )));
            }
        }

        let mut pinned_urls = BTreeSet::new();
        let mut pinned_keys = BTreeSet::new();
        let mut pinned_self_key = None;
        for member in &self.cluster_members {
            let member_url =
                normalize_cluster_config_url(&member.node_url, self.allow_local_peer_urls)?;
            if !pinned_urls.insert(member_url.clone()) {
                return Err(CliError::cli_other_error(format!(
                    "duplicate normalized cluster membership URL `{member_url}`"
                )));
            }
            let public_key_hex = member.public_key.to_hex();
            if public_key_hex.len() != 64
                || !public_key_hex
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            {
                return Err(CliError::cli_other_error(
                    "cluster membership keys must be bare Ed25519 public keys".to_string(),
                ));
            }
            if !pinned_keys.insert(public_key_hex) {
                return Err(CliError::cli_other_error(
                    "one cluster membership key must not identify multiple node URLs".to_string(),
                ));
            }
            if member_url == self_url {
                pinned_self_key = Some(member.public_key.clone());
            }
        }
        if pinned_urls != expected_urls {
            return Err(CliError::cli_other_error(
                "cluster membership must pin exactly the advertise URL and every peer URL"
                    .to_string(),
            ));
        }
        if pinned_self_key.as_ref() != Some(&node_public_key) {
            return Err(CliError::cli_other_error(
                "cluster node identity seed does not match the public key pinned for advertise URL"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

pub(crate) fn validate_control_secret(secret: &str, label: &str) -> Result<(), CliError> {
    if secret.trim().is_empty() {
        return Err(CliError::cli_other_error(format!(
            "{label} must be non-empty"
        )));
    }
    if secret.trim() != secret {
        return Err(CliError::cli_other_error(format!(
            "{label} must not contain surrounding whitespace"
        )));
    }
    if secret.chars().any(char::is_control) {
        return Err(CliError::cli_other_error(format!(
            "{label} must not contain control characters"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod service_config_tests {
    use super::*;
    use chio_test_support::prelude::*;

    fn base_config() -> TrustServiceConfig {
        let listen = match "127.0.0.1:0".parse() {
            Ok(addr) => addr,
            Err(error) => panic!("test listen address should parse: {error}"),
        };
        TrustServiceConfig {
            listen,
            service_token: "token".to_string(),
            dashboard_read_token: None,
            dashboard_report_origin: None,
            dashboard_report_token: None,
            dashboard_allow_insecure_report_origin: false,
            authority_admin_token: None,
            authority_workloads: Vec::new(),
            tenant_read_tokens: BTreeMap::new(),
            receipt_db_path: None,
            revocation_db_path: None,
            authority_seed_path: None,
            authority_db_path: None,
            authority_keyring_config_path: None,
            budget_db_path: None,
            partition_escrow_authority: None,
            enterprise_providers_file: None,
            federation_policies_file: None,
            scim_lifecycle_file: None,
            verifier_policies_file: None,
            verifier_challenge_db_path: None,
            passport_statuses_file: None,
            passport_issuance_offers_file: None,
            certification_registry_file: None,
            certification_discovery_file: None,
            issuance_policy: None,
            runtime_assurance_policy: None,
            advertise_url: None,
            allow_local_peer_urls: true,
            certification_public_metadata_ttl_seconds: PUBLIC_DISCOVERY_TTL_SECS,
            peer_urls: Vec::new(),
            cluster_node_seed_path: None,
            cluster_replay_db_path: None,
            cluster_members: Vec::new(),
            cluster_sync_interval: Duration::from_millis(25),
            roster_policy: None,
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        }
    }

    #[test]
    fn trust_service_config_rejects_dashboard_credential_reuse() {
        let mut config = base_config();
        config.dashboard_read_token = Some("token".to_string());
        let error = config.validate().test_unwrap_err();
        assert!(error
            .to_string()
            .contains("dashboard read token must be distinct"));

        let mut config = base_config();
        config
            .tenant_read_tokens
            .insert("tenant-a".to_string(), "tenant-secret".to_string());
        config.dashboard_read_token = Some("tenant-secret".to_string());
        let error = config.validate().test_unwrap_err();
        assert!(error
            .to_string()
            .contains("dashboard read token must be distinct"));
    }

    #[test]
    fn trust_service_config_accepts_a_distinct_dashboard_read_credential() {
        let mut config = base_config();
        config.dashboard_read_token = Some("dashboard-secret".to_string());
        config.validate().test_unwrap();
    }

    #[test]
    fn trust_service_config_rejects_partial_dashboard_report_bridge_configuration() {
        let mut origin_only = base_config();
        origin_only.dashboard_report_origin = Some("https://relay.example/".to_string());
        assert!(origin_only
            .validate()
            .test_unwrap_err()
            .to_string()
            .contains("must be configured together"));

        let mut token_only = base_config();
        token_only.dashboard_report_token = Some("relay-read-secret".to_string());
        assert!(token_only
            .validate()
            .test_unwrap_err()
            .to_string()
            .contains("must be configured together"));
    }

    #[test]
    fn trust_service_config_restricts_insecure_report_origins_to_explicit_loopback_mode() {
        let mut config = base_config();
        config.dashboard_report_origin = Some("http://127.0.0.1:43199/".to_string());
        config.dashboard_report_token = Some("relay-read-secret".to_string());
        assert!(config
            .validate()
            .test_unwrap_err()
            .to_string()
            .contains("must use HTTPS"));

        config.dashboard_allow_insecure_report_origin = true;
        config.validate().test_unwrap();

        config.dashboard_report_origin = Some("http://relay.example/".to_string());
        assert!(config.validate().is_err());
    }

    #[test]
    fn trust_service_config_requires_a_distinct_dashboard_report_credential() {
        let mut config = base_config();
        config.dashboard_read_token = Some("dashboard-secret".to_string());
        config.dashboard_report_origin = Some("https://relay.example/".to_string());
        config.dashboard_report_token = Some("dashboard-secret".to_string());
        assert!(config
            .validate()
            .test_unwrap_err()
            .to_string()
            .contains("report read token must be distinct"));

        config.dashboard_report_token = Some("relay-read-secret".to_string());
        config.validate().test_unwrap();
    }

    #[test]
    fn trust_service_config_rejects_padded_service_token_at_startup() {
        for token in [" token", "token "] {
            let mut config = base_config();
            config.service_token = token.to_string();

            let error = match config.validate() {
                Ok(()) => panic!("padded service token should fail closed at startup"),
                Err(error) => error,
            };

            assert!(
                error
                    .to_string()
                    .contains("control service token must not contain surrounding whitespace"),
                "unexpected error for token `{token:?}`: {error}",
            );
        }
    }

    #[test]
    fn trust_service_config_rejects_padded_tenant_read_tokens_at_startup() {
        for token in [" tenant-token", "tenant-token "] {
            let mut config = base_config();
            config
                .tenant_read_tokens
                .insert("tenant-a".to_string(), token.to_string());

            let error = match config.validate() {
                Ok(()) => panic!("padded tenant read token should fail closed at startup"),
                Err(error) => error,
            };

            assert!(
                error.to_string().contains(
                    "tenant read token for `tenant-a` must not contain surrounding whitespace"
                ),
                "unexpected error for token `{token:?}`: {error}",
            );
        }
    }

    #[test]
    fn trust_service_config_rejects_padded_tenant_read_token_ids_at_startup() {
        for tenant_id in [" tenant-a", "tenant-a "] {
            let mut config = base_config();
            config
                .tenant_read_tokens
                .insert(tenant_id.to_string(), "tenant-token".to_string());

            let error = match config.validate() {
                Ok(()) => panic!("padded tenant read token id should fail closed at startup"),
                Err(error) => error,
            };

            assert!(
                error
                    .to_string()
                    .contains("tenant read token id must not contain surrounding whitespace"),
                "unexpected error for tenant id `{tenant_id:?}`: {error}",
            );
        }
    }

    #[test]
    fn trust_service_config_rejects_control_bearing_tenant_read_tokens_at_startup() {
        for (tenant_id, token) in [
            ("tenant-\na", "tenant-token"),
            ("tenant-a", "tenant\u{7f}token"),
        ] {
            let mut config = base_config();
            config
                .tenant_read_tokens
                .insert(tenant_id.to_string(), token.to_string());

            let error = match config.validate() {
                Ok(()) => panic!("control-bearing tenant read token should fail closed at startup"),
                Err(error) => error,
            };

            assert!(
                error.to_string().contains("control characters"),
                "unexpected error for tenant token mapping `{tenant_id:?}`: {error}",
            );
        }
    }

    #[test]
    fn trust_service_config_rejects_zero_public_certification_metadata_ttl() {
        let mut config = base_config();
        config.certification_public_metadata_ttl_seconds = 0;

        let error = config.validate().test_unwrap_err();

        assert!(
            error
                .to_string()
                .contains("certification public metadata TTL must be non-zero"),
            "unexpected zero TTL error: {error}",
        );
    }

    #[test]
    fn trust_service_config_rejects_clustered_seed_file_authority_at_startup() {
        let mut config = base_config();
        config.authority_seed_path = Some(PathBuf::from("authority.seed"));
        config.peer_urls = vec!["https://peer.example".to_string()];

        let error = config.validate().test_unwrap_err();

        assert!(error
            .to_string()
            .contains("shared authority write and selector protocol"));
    }

    #[test]
    fn trust_service_config_rejects_seed_and_database_authority_custody() {
        for keyring in [None, Some(PathBuf::from("authority-keyring.yaml"))] {
            let mut config = base_config();
            config.authority_seed_path = Some(PathBuf::from("authority.seed"));
            config.authority_db_path = Some(PathBuf::from("authority.sqlite3"));
            config.authority_keyring_config_path = keyring;

            let error = config.validate().test_unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("use either --authority-seed-file or --authority-db, not both"),
                "unexpected mixed authority custody error: {error}"
            );
        }
    }

    #[test]
    fn trust_service_config_rejects_clustered_authority_database() {
        let mut config = base_config();
        config.authority_db_path = Some(PathBuf::from("authority.sqlite3"));
        config.peer_urls = vec!["https://peer.example".to_string()];

        let error = config.validate().test_unwrap_err();
        assert!(
            error
                .to_string()
                .contains("shared authority write and selector protocol"),
            "unexpected clustered authority database error: {error}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn clustered_admission_requires_one_ca_free_budget_revocation_database() {
        let (temp, mut config, _self_key, _peer_key) = valid_cluster_config();
        let admission_path = temp.path().join("admission.sqlite3");
        drop(SqliteBudgetStore::open(&admission_path).test_unwrap());
        drop(SqliteRevocationStore::open(&admission_path).test_unwrap());
        config.budget_db_path = Some(admission_path.clone());
        config.revocation_db_path = Some(admission_path);

        config.validate().test_unwrap();
        assert!(config.authority_seed_path.is_none());
        assert!(config.authority_db_path.is_none());

        let separate_revocations = temp.path().join("revocations.sqlite3");
        drop(SqliteRevocationStore::open(&separate_revocations).test_unwrap());
        config.revocation_db_path = Some(separate_revocations);
        assert!(config
            .validate()
            .test_unwrap_err()
            .to_string()
            .contains("one SQLite database"));

        config.revocation_db_path = None;
        assert!(config
            .validate()
            .test_unwrap_err()
            .to_string()
            .contains("budget and revocation databases together"));
    }

    #[cfg(not(target_os = "macos"))]
    fn valid_cluster_config() -> (tempfile::TempDir, TrustServiceConfig, Keypair, Keypair) {
        let temp = tempfile::tempdir().test_unwrap();
        let self_key = Keypair::from_seed(&[0x91; 32]);
        let peer_key = Keypair::from_seed(&[0x92; 32]);
        let seed_path = temp.path().join("cluster-node.seed");
        crate::persist_authority_keypair(&seed_path, &self_key).test_unwrap();
        let mut config = base_config();
        config.advertise_url = Some("http://127.0.0.1:41001".to_string());
        config.peer_urls = vec!["http://127.0.0.1:41002".to_string()];
        config.cluster_node_seed_path = Some(seed_path);
        config.cluster_replay_db_path = Some(temp.path().join("cluster-replay.sqlite3"));
        config.cluster_members = vec![
            ClusterMemberIdentity {
                node_url: "http://127.0.0.1:41001".to_string(),
                public_key: self_key.public_key(),
            },
            ClusterMemberIdentity {
                node_url: "http://127.0.0.1:41002".to_string(),
                public_key: peer_key.public_key(),
            },
        ];
        (temp, config, self_key, peer_key)
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn clustered_startup_requires_complete_dedicated_membership_configuration() {
        let (_temp, config, _self_key, _peer_key) = valid_cluster_config();
        config.validate().test_unwrap();

        let mut missing_seed = config.clone();
        missing_seed.cluster_node_seed_path = None;
        assert!(missing_seed
            .validate()
            .test_unwrap_err()
            .to_string()
            .contains("requires --cluster-node-seed-file"));

        let mut missing_replay_db = config.clone();
        missing_replay_db.cluster_replay_db_path = None;
        assert!(missing_replay_db
            .validate()
            .test_unwrap_err()
            .to_string()
            .contains("requires --cluster-replay-db"));

        let mut missing_member = config.clone();
        missing_member.cluster_members.pop();
        assert!(missing_member
            .validate()
            .test_unwrap_err()
            .to_string()
            .contains("must pin exactly"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn clustered_startup_rejects_duplicate_urls_keys_and_seed_mismatch() {
        let (_temp, config, _self_key, peer_key) = valid_cluster_config();

        let mut duplicate_peer = config.clone();
        duplicate_peer
            .peer_urls
            .push("http://127.0.0.1:41002/".to_string());
        assert!(duplicate_peer
            .validate()
            .test_unwrap_err()
            .to_string()
            .contains("duplicate normalized cluster peer URL"));

        let mut duplicate_key = config.clone();
        duplicate_key.cluster_members[0].public_key = peer_key.public_key();
        assert!(duplicate_key
            .validate()
            .test_unwrap_err()
            .to_string()
            .contains("must not identify multiple node URLs"));

        let mut mismatched_seed = config;
        mismatched_seed.cluster_members[0].public_key =
            Keypair::from_seed(&[0x93; 32]).public_key();
        assert!(mismatched_seed
            .validate()
            .test_unwrap_err()
            .to_string()
            .contains("does not match the public key pinned"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn cluster_identity_rotation_requires_seed_and_pin_to_move_together() {
        let (temp, mut config, _self_key, _peer_key) = valid_cluster_config();
        let rotated = Keypair::from_seed(&[0x94; 32]);
        let rotated_seed_path = temp.path().join("cluster-node-rotated.seed");
        crate::persist_authority_keypair(&rotated_seed_path, &rotated).test_unwrap();
        config.cluster_node_seed_path = Some(rotated_seed_path);

        assert!(config
            .validate()
            .test_unwrap_err()
            .to_string()
            .contains("does not match the public key pinned"));
        config.cluster_members[0].public_key = rotated.public_key();
        config.validate().test_unwrap();
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn cluster_private_seed_cannot_be_reused_as_a_bearer_credential() {
        let (_temp, mut config, self_key, _peer_key) = valid_cluster_config();
        config.service_token = self_key.seed_hex();
        assert!(config
            .validate()
            .test_unwrap_err()
            .to_string()
            .contains("must not be reused as any bearer credential"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn cluster_node_key_cannot_equal_session_admission_identity() {
        let (_temp, mut config, self_key, peer_key) = valid_cluster_config();
        config.authority_workloads.push(AuthorityWorkloadPolicy {
            credential_token: "workload-credential".to_string(),
            tenant_id: "tenant-a".to_string(),
            workload_id: "workload-a".to_string(),
            server_id: "server-a".to_string(),
            signer_public_key: peer_key.public_key(),
            session_admission_public_key: self_key.public_key(),
            allowed_capabilities: Vec::new(),
        });

        let error = config.validate_cluster_membership().test_unwrap_err();
        assert!(
            error.to_string().contains("session-admission identity"),
            "unexpected session-admission collision error: {error}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn cluster_node_key_cannot_equal_retired_authority_key() {
        let (temp, mut config, _self_key, _peer_key) = valid_cluster_config();
        let authority_path = temp.path().join("authority.sqlite3");
        let authority = SqliteCapabilityAuthority::open(&authority_path).test_unwrap();
        let retired_keypair = authority.local_keypair().test_unwrap();
        authority.rotate().test_unwrap();
        assert_ne!(
            authority.status().test_unwrap().public_key,
            retired_keypair.public_key()
        );

        let node_seed_path = temp.path().join("retired-authority-node.seed");
        crate::persist_authority_keypair(&node_seed_path, &retired_keypair).test_unwrap();
        config.cluster_node_seed_path = Some(node_seed_path);
        config.cluster_members[0].public_key = retired_keypair.public_key();
        config.authority_db_path = Some(authority_path);

        let error = config.validate_cluster_membership().test_unwrap_err();
        assert!(
            error
                .to_string()
                .contains("current and historical authority custody"),
            "unexpected retired authority collision error: {error}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn cluster_node_seed_rejects_noncanonical_hex_and_extra_whitespace() {
        let (_temp, config, self_key, _peer_key) = valid_cluster_config();
        let seed_path = config.cluster_node_seed_path.as_deref().test_unwrap();
        std::fs::write(
            seed_path,
            format!("{}\n", self_key.seed_hex().to_uppercase()),
        )
        .test_unwrap();
        assert!(config
            .validate()
            .test_unwrap_err()
            .to_string()
            .contains("lowercase hex"));

        std::fs::write(seed_path, format!("{}\n\n", self_key.seed_hex())).test_unwrap();
        assert!(config.validate().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn cluster_node_seed_rejects_unsafe_and_symlinked_ancestor_chains() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let temp = tempfile::tempdir().test_unwrap();
        let keypair = Keypair::from_seed(&[0xa1; 32]);
        let unsafe_parent = temp.path().join("unsafe-parent");
        std::fs::create_dir(&unsafe_parent).test_unwrap();
        let unsafe_seed = unsafe_parent.join("cluster-node.seed");
        crate::persist_authority_keypair(&unsafe_seed, &keypair).test_unwrap();
        std::fs::set_permissions(&unsafe_parent, std::fs::Permissions::from_mode(0o777))
            .test_unwrap();
        assert!(load_strict_cluster_node_keypair(&unsafe_seed).is_err());

        let real_parent = temp.path().join("real-parent");
        std::fs::create_dir(&real_parent).test_unwrap();
        let real_seed = real_parent.join("cluster-node.seed");
        crate::persist_authority_keypair(&real_seed, &keypair).test_unwrap();
        let alias_parent = temp.path().join("alias-parent");
        symlink(&real_parent, &alias_parent).test_unwrap();
        assert!(load_strict_cluster_node_keypair(&alias_parent.join("cluster-node.seed")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn cluster_node_seed_detects_parent_replacement_after_open() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().test_unwrap();
        let keypair = Keypair::from_seed(&[0xa2; 32]);
        let parent = temp.path().join("seed-parent");
        let moved_parent = temp.path().join("seed-parent-moved");
        std::fs::create_dir(&parent).test_unwrap();
        let seed_path = parent.join("cluster-node.seed");
        crate::persist_authority_keypair(&seed_path, &keypair).test_unwrap();

        let error = load_strict_cluster_node_keypair_with_hook(&seed_path, || {
            std::fs::rename(&parent, &moved_parent).test_unwrap();
            std::fs::create_dir(&parent).test_unwrap();
            std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).test_unwrap();
        })
        .test_unwrap_err();
        assert!(
            error.to_string().contains("ancestor identity changed"),
            "unexpected parent replacement error: {error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn cluster_node_seed_rejects_hardlinks_and_final_symlinks() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().test_unwrap();
        let keypair = Keypair::from_seed(&[0xa3; 32]);
        let seed_path = temp.path().join("cluster-node.seed");
        crate::persist_authority_keypair(&seed_path, &keypair).test_unwrap();
        let hardlink = temp.path().join("cluster-node-hardlink.seed");
        std::fs::hard_link(&seed_path, &hardlink).test_unwrap();
        assert!(load_strict_cluster_node_keypair(&seed_path).is_err());
        std::fs::remove_file(&hardlink).test_unwrap();

        let symlink_path = temp.path().join("cluster-node-symlink.seed");
        symlink(&seed_path, &symlink_path).test_unwrap();
        assert!(load_strict_cluster_node_keypair(&symlink_path).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cluster_replay_database_rejects_aliases_of_other_cluster_storage() {
        use std::os::unix::fs::symlink;

        let (temp, mut config, _self_key, _peer_key) = valid_cluster_config();
        let alias = temp.path().join("storage-alias");
        symlink(temp.path(), &alias).test_unwrap();
        config.receipt_db_path = Some(alias.join("cluster-replay.sqlite3"));

        assert!(config
            .validate()
            .test_unwrap_err()
            .to_string()
            .contains("distinct from the receipt database"));
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn clustered_startup_rejects_platforms_without_descriptor_anchored_sqlite() {
        let (_temp, config, _self_key, _peer_key) = valid_cluster_config();
        let error = config.validate().test_unwrap_err();
        assert!(
            error
                .to_string()
                .contains("SQLite cannot be opened through a retained directory descriptor"),
            "unexpected unsupported cluster platform error: {error}"
        );
    }
}
