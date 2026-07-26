#[cfg(unix)]
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chio_core_types::{canonical_json_bytes, Ed25519Backend, PublicKey, SigningBackend};
use chio_security_types::ports::RecordId;
use chio_security_types::{
    EnterpriseMigrationControl, EnterpriseMigrationKey, EnterpriseMigrationMinimumHead,
    EnterpriseMigrationScopeKind, EnterpriseMigrationStage, EnterpriseMigrationStateStore,
};
use chio_store_sqlite::{SqliteEnterpriseMigrationOpenPolicy, SqliteEnterpriseMigrationStateStore};
use serde::{Deserialize, Serialize};

#[cfg(unix)]
use crate::audit::{
    verify_broker_audit_runner_authorization, BrokerAuditReferenceRequest, BrokerAuditRunnerTrust,
    CompletedBrokerAuditComparison, SignedBrokerAuditComparison,
    SignedBrokerAuditRunnerAuthorization,
};
use crate::authority_ipc::{
    AuthorityRpcClient, AuthorityRpcClientConfig, BrokerAdmissionAuthority,
};
use crate::budget::BrokerExecutionBudget;
use crate::daemon::{BrokerDaemonHandler, DaemonClock, SystemDaemonClock};
use crate::generic_https::GenericHttpsExecutor;
use crate::migration::{BrokerMigrationEnforcer, ProductionBrokerMigrationEnforcer};
#[cfg(unix)]
use crate::privileged_audit::{
    BrokerPrivilegedAuditEndpoint, BrokerPrivilegedAuditEndpointConfig,
    BrokerPrivilegedAuditHandler,
};
#[cfg(unix)]
use crate::protocol::BrokerExecuteRequest;
use crate::provider::{CredentialPlacement, GenericCredentialProvider};
#[cfg(unix)]
use crate::provision::AdminAuthorization;
use crate::provision::{GovernedAdminAuthorizer, GovernedAdminPolicy, SystemAdminClock};
use crate::receipt::SqliteBrokerReceiptSink;
use crate::reconcile::{
    reconcile_durable_completions, reconcile_durable_failures, reconcile_pending,
};
use crate::revocation::{BrokerRevocations, CapabilityLiveness};
#[cfg(unix)]
use crate::service::UnixBrokerEndpoint;
use crate::service::{
    BrokerIpcDeadlines, BrokerIpcHandler, BrokerService, BrokerServiceAuthorityBundle,
    BrokerServiceConfig,
};
use crate::sqlite::{DurableBrokerDatabaseFile, ProductionSqliteAttemptStore, SqliteAttemptStore};
use crate::{
    validate_identifier, BrokerError, EncryptedBlobSecretBackend, Result, SealedKeyFd,
    SealedSigningKeyFd,
};

pub const BROKER_DAEMON_CONFIG_SCHEMA: &str = "chio.secret-brokerd.runtime-config.v5";
const MAX_CONFIG_BYTES: u64 = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderPlacementConfig {
    BearerAuthorization,
    ApiKeyHeader,
}

impl ProviderPlacementConfig {
    fn into_placement(self) -> CredentialPlacement {
        match self {
            Self::BearerAuthorization => CredentialPlacement::BearerAuthorization,
            Self::ApiKeyHeader => CredentialPlacement::ApiKeyHeader,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrokerDaemonDatabaseConfig {
    pub secret_database_path: PathBuf,
    pub attempt_database_path: PathBuf,
    pub admin_replay_database_path: PathBuf,
    pub receipt_database_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrokerDaemonAdminConfig {
    pub trusted_approvers: Vec<PublicKey>,
    pub subject: PublicKey,
    pub threshold: usize,
    pub maximum_token_lifetime_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrokerDaemonPrivilegedAuditConfig {
    pub socket_path: PathBuf,
    pub authorized_runner_uid: u32,
    pub authorized_runner_gid: u32,
    pub read_timeout_ms: u64,
    pub write_timeout_ms: u64,
    pub authorization_lifetime_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrokerDaemonMigrationConfig {
    pub state_database_path: PathBuf,
    pub deployment_id: RecordId,
    pub credential_provider: RecordId,
    pub trusted_transition_signers: Vec<PublicKey>,
    pub minimum_heads: Vec<EnterpriseMigrationMinimumHead>,
    pub credential_custody_stage: EnterpriseMigrationStage,
    pub quota_enforcement_stage: EnterpriseMigrationStage,
}

impl BrokerDaemonMigrationConfig {
    fn validate_for_deployment(&self, deployment_id: &RecordId) -> Result<()> {
        validate_database_path(&self.state_database_path)?;
        if &self.deployment_id != deployment_id {
            return Err(BrokerError::InvalidRequest(
                "daemon enterprise migration deployment does not match the broker deployment"
                    .to_string(),
            ));
        }
        if self.trusted_transition_signers.is_empty()
            || self.trusted_transition_signers.len() > 16
            || self
                .trusted_transition_signers
                .windows(2)
                .any(|pair| pair[0].to_hex() >= pair[1].to_hex())
            || !self
                .credential_custody_stage
                .operational_failure_must_deny()
            || !self.quota_enforcement_stage.operational_failure_must_deny()
        {
            return Err(BrokerError::InvalidRequest(
                "daemon enterprise migration signers must be bounded, sorted, and unique, and both controls must deny on failure"
                    .to_string(),
            ));
        }
        let expected = [
            (
                EnterpriseMigrationKey {
                    deployment_id: self.deployment_id.clone(),
                    scope_kind: EnterpriseMigrationScopeKind::Provider,
                    scope_id: self.credential_provider.clone(),
                    control: EnterpriseMigrationControl::BrokerCredentialCustody,
                },
                self.credential_custody_stage,
            ),
            (
                EnterpriseMigrationKey {
                    deployment_id: self.deployment_id.clone(),
                    scope_kind: EnterpriseMigrationScopeKind::Provider,
                    scope_id: self.credential_provider.clone(),
                    control: EnterpriseMigrationControl::BrokerQuotaEnforcement,
                },
                self.quota_enforcement_stage,
            ),
        ];
        if self.minimum_heads.len() != expected.len()
            || self
                .minimum_heads
                .windows(2)
                .any(|pair| pair[0].key >= pair[1].key)
        {
            return Err(BrokerError::InvalidRequest(
                "daemon enterprise migration anchors must contain the exact sorted broker controls"
                    .to_string(),
            ));
        }
        for (head, (expected_key, expected_stage)) in self.minimum_heads.iter().zip(expected.iter())
        {
            if !head.is_valid()
                || &head.key != expected_key
                || head.minimum_generation != expected_stage.generation()
            {
                return Err(BrokerError::InvalidRequest(
                    "daemon enterprise migration anchor is misbound to its provider, control, or stage"
                        .to_string(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrokerDaemonConfig {
    pub schema: String,
    pub deployment_id: String,
    pub broker_instance_id: String,
    pub tenant_scope: String,
    pub audit_runner_id: String,
    pub trusted_audit_runner: PublicKey,
    pub ipc_socket_path: PathBuf,
    pub authority_socket_path: PathBuf,
    pub trusted_capability_issuer: PublicKey,
    pub trusted_authority: PublicKey,
    pub broker_identity: PublicKey,
    pub broker_audience: String,
    pub parent_audience: String,
    pub provider_adapter_id: String,
    pub provider_adapter_version: u32,
    pub provider_placement: ProviderPlacementConfig,
    pub trusted_service_uid: u32,
    pub authorized_client_uid: u32,
    pub ipc_read_timeout_ms: u64,
    pub ipc_write_timeout_ms: u64,
    pub authority_timeout_ms: u64,
    pub maximum_clock_skew_seconds: u64,
    pub maximum_liveness_snapshot_age_seconds: u64,
    pub maximum_revocation_snapshot_age_seconds: u64,
    pub databases: BrokerDaemonDatabaseConfig,
    pub enterprise_migration: BrokerDaemonMigrationConfig,
    pub admin: BrokerDaemonAdminConfig,
    pub privileged_audit: BrokerDaemonPrivilegedAuditConfig,
}

impl BrokerDaemonConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let retained_config = DurableBrokerDatabaseFile::open_existing_read_only(path)?;
        let mut file = retained_config.try_clone_file()?;
        let metadata = file.metadata().map_err(|error| {
            BrokerError::Storage(format!("daemon config descriptor metadata failed: {error}"))
        })?;
        if !metadata.file_type().is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_CONFIG_BYTES
        {
            return Err(BrokerError::Storage(
                "daemon config is not a bounded regular file".to_string(),
            ));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.by_ref()
            .take(MAX_CONFIG_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| BrokerError::Storage(format!("daemon config read failed: {error}")))?;
        if bytes.len() as u64 != metadata.len() {
            return Err(BrokerError::Storage(
                "daemon config changed while it was read".to_string(),
            ));
        }
        retained_config.validate()?;
        let config: Self = serde_json::from_slice(&bytes).map_err(|error| {
            BrokerError::InvalidRequest(format!("daemon config decoding failed: {error}"))
        })?;
        let canonical = canonical_json_bytes(&config).map_err(|error| {
            BrokerError::InvalidRequest(format!("daemon config encoding failed: {error}"))
        })?;
        if canonical != bytes {
            return Err(BrokerError::InvalidRequest(
                "daemon config is not canonical JSON".to_string(),
            ));
        }
        #[cfg(unix)]
        if metadata.uid() != config.trusted_service_uid {
            return Err(BrokerError::Custody(
                "daemon config owner does not match the trusted service UID".to_string(),
            ));
        }
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != BROKER_DAEMON_CONFIG_SCHEMA {
            return Err(BrokerError::InvalidRequest(
                "daemon config schema is invalid".to_string(),
            ));
        }
        for (value, label) in [
            (&self.deployment_id, "daemon deployment id"),
            (&self.broker_instance_id, "daemon broker instance id"),
            (&self.tenant_scope, "daemon tenant scope"),
            (&self.audit_runner_id, "daemon audit runner id"),
            (&self.broker_audience, "broker audience"),
            (&self.parent_audience, "parent audience"),
            (&self.provider_adapter_id, "provider adapter id"),
        ] {
            validate_identifier(value, label, 512)?;
        }
        let migration_deployment_id =
            RecordId::new(self.deployment_id.clone()).map_err(|error| {
                BrokerError::InvalidRequest(format!(
                    "daemon deployment id is invalid for enterprise migration: {error}"
                ))
            })?;
        self.enterprise_migration
            .validate_for_deployment(&migration_deployment_id)?;
        if self.provider_adapter_version == 0
            || self.authority_timeout_ms == 0
            || self.authority_timeout_ms > 30_000
            || self.maximum_clock_skew_seconds == 0
            || self.maximum_clock_skew_seconds > 30
            || self.maximum_liveness_snapshot_age_seconds == 0
            || self.maximum_liveness_snapshot_age_seconds > 60
            || self.maximum_revocation_snapshot_age_seconds == 0
            || self.maximum_revocation_snapshot_age_seconds > 60
        {
            return Err(BrokerError::InvalidRequest(
                "daemon provider or authority limits are invalid".to_string(),
            ));
        }
        if self.trusted_audit_runner == self.broker_identity
            || self.trusted_audit_runner == self.trusted_capability_issuer
            || self.trusted_audit_runner == self.trusted_authority
            || self.trusted_audit_runner == self.admin.subject
            || self
                .admin
                .trusted_approvers
                .contains(&self.trusted_audit_runner)
        {
            return Err(BrokerError::InvalidRequest(
                "daemon audit runner key must be independent of broker and operator keys"
                    .to_string(),
            ));
        }
        BrokerIpcDeadlines::from_millis(self.ipc_read_timeout_ms, self.ipc_write_timeout_ms)?;
        let effective_uid = current_effective_uid()?;
        if self.trusted_service_uid != effective_uid {
            return Err(BrokerError::Custody(
                "effective service UID does not match the trusted daemon configuration".to_string(),
            ));
        }
        validate_socket_path(&self.ipc_socket_path, "broker IPC socket")?;
        validate_socket_path(&self.authority_socket_path, "authority IPC socket")?;
        #[cfg(unix)]
        BrokerPrivilegedAuditEndpointConfig {
            socket_path: self.privileged_audit.socket_path.clone(),
            trusted_service_uid: self.trusted_service_uid,
            authorized_runner_uid: self.privileged_audit.authorized_runner_uid,
            authorized_runner_gid: self.privileged_audit.authorized_runner_gid,
            read_timeout_ms: self.privileged_audit.read_timeout_ms,
            write_timeout_ms: self.privileged_audit.write_timeout_ms,
            authorization_lifetime_seconds: self.privileged_audit.authorization_lifetime_seconds,
            deployment_id: self.deployment_id.clone(),
            broker_instance_id: self.broker_instance_id.clone(),
            tenant_scope: self.tenant_scope.clone(),
            runner_id: self.audit_runner_id.clone(),
        }
        .validate()?;
        let socket_paths = [
            self.ipc_socket_path.as_path(),
            self.authority_socket_path.as_path(),
            self.privileged_audit.socket_path.as_path(),
        ];
        if socket_paths[0] == socket_paths[1]
            || socket_paths[0] == socket_paths[2]
            || socket_paths[1] == socket_paths[2]
        {
            return Err(BrokerError::InvalidRequest(
                "broker, authority, and privileged audit sockets must be distinct".to_string(),
            ));
        }
        if self.ipc_socket_path.parent() == self.privileged_audit.socket_path.parent()
            || self.authority_socket_path.parent() == self.privileged_audit.socket_path.parent()
        {
            return Err(BrokerError::InvalidRequest(
                "privileged audit socket must use a dedicated parent directory".to_string(),
            ));
        }
        let database_paths = [
            self.databases.secret_database_path.as_path(),
            self.databases.attempt_database_path.as_path(),
            self.databases.admin_replay_database_path.as_path(),
            self.databases.receipt_database_path.as_path(),
            self.enterprise_migration.state_database_path.as_path(),
        ];
        for path in database_paths {
            validate_database_path(path)?;
            if socket_paths.contains(&path) {
                return Err(BrokerError::InvalidRequest(
                    "daemon database and socket paths must be distinct".to_string(),
                ));
            }
        }
        for (index, path) in database_paths.iter().enumerate() {
            if database_paths[index + 1..].contains(path) {
                return Err(BrokerError::InvalidRequest(
                    "daemon database paths must be distinct".to_string(),
                ));
            }
        }
        GovernedAdminPolicy {
            trusted_approvers: self.admin.trusted_approvers.clone(),
            subject: self.admin.subject.clone(),
            threshold: self.admin.threshold,
            maximum_token_lifetime_seconds: self.admin.maximum_token_lifetime_seconds,
        }
        .validate_for_runtime()?;
        Ok(())
    }
}

#[cfg(unix)]
pub struct BrokerDaemonRuntime {
    endpoint: UnixBrokerEndpoint,
    privileged_audit_endpoint: BrokerPrivilegedAuditEndpoint,
    audit: Arc<BrokerDaemonAuditContext>,
    _database_owner_locks: Vec<File>,
    _database_identity_files: Vec<DurableBrokerDatabaseFile>,
}

#[cfg(unix)]
struct BrokerDaemonAuditContext {
    audit_service: Arc<BrokerService>,
    audit_admin: Arc<GovernedAdminAuthorizer>,
    audit_clock: Arc<dyn DaemonClock>,
    audit_deployment_id: String,
    audit_broker_instance_id: String,
    audit_tenant_scope: String,
    audit_runner_id: String,
    trusted_audit_runner: PublicKey,
}

#[cfg(not(unix))]
pub struct BrokerDaemonRuntime;

#[cfg(unix)]
fn run_daemon_serving_worker<F>(
    label: &'static str,
    failure_sender: std::sync::mpsc::SyncSender<BrokerError>,
    worker: F,
) where
    F: FnOnce() -> Result<()>,
{
    // Unwinding profiles publish one typed terminal failure so the peer worker
    // is stopped and joined. Abort profiles terminate the entire broker
    // process at the panic site, which is already terminal and cannot deadlock
    // this in-process supervisor.
    #[cfg(panic = "unwind")]
    let failure = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(worker)) {
        Ok(Ok(())) => BrokerError::Invariant(format!(
            "{label} serving worker terminated without a terminal error"
        )),
        Ok(Err(error)) => error,
        Err(_) => BrokerError::Invariant(format!("{label} serving worker panicked")),
    };
    #[cfg(panic = "abort")]
    let failure = match worker() {
        Ok(()) => BrokerError::Invariant(format!(
            "{label} serving worker terminated without a terminal error"
        )),
        Err(error) => error,
    };
    let _send_result = failure_sender.send(failure);
}

impl BrokerDaemonRuntime {
    #[cfg(unix)]
    pub fn build(
        config: BrokerDaemonConfig,
        master_key_file: File,
        signing_key_file: File,
    ) -> Result<Self> {
        Self::build_with_https_override(config, master_key_file, signing_key_file, None)
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn build_for_process_boundary_test(
        config: BrokerDaemonConfig,
        master_key_file: File,
        signing_key_file: File,
        https: Arc<GenericHttpsExecutor>,
    ) -> Result<Self> {
        Self::build_with_https_override(config, master_key_file, signing_key_file, Some(https))
    }

    #[cfg(unix)]
    fn build_with_https_override(
        config: BrokerDaemonConfig,
        master_key_file: File,
        signing_key_file: File,
        https_override: Option<Arc<GenericHttpsExecutor>>,
    ) -> Result<Self> {
        config.validate()?;
        validate_key_file_identity(&master_key_file, config.trusted_service_uid, "master key")?;
        validate_key_file_identity(&signing_key_file, config.trusted_service_uid, "signing key")?;
        validate_distinct_key_files(&master_key_file, &signing_key_file)?;
        validate_private_service_file(
            &config.enterprise_migration.state_database_path,
            config.trusted_service_uid,
            "enterprise migration state database",
        )?;
        validate_sqlite_sidecars(
            &config.enterprise_migration.state_database_path,
            config.trusted_service_uid,
            "enterprise migration state database",
        )?;
        let migration_policy = SqliteEnterpriseMigrationOpenPolicy::new(
            config
                .enterprise_migration
                .trusted_transition_signers
                .clone(),
            config.enterprise_migration.minimum_heads.clone(),
        )
        .map_err(|error| {
            BrokerError::InvalidRequest(format!(
                "daemon enterprise migration open policy failed: {error}"
            ))
        })?;
        let migration_store = Arc::new(
            SqliteEnterpriseMigrationStateStore::open(
                &config.enterprise_migration.state_database_path,
                migration_policy,
            )
            .map_err(|error| {
                BrokerError::Storage(format!(
                    "daemon enterprise migration state database failed: {error}"
                ))
            })?,
        );
        validate_private_service_file(
            &config.enterprise_migration.state_database_path,
            config.trusted_service_uid,
            "enterprise migration state database",
        )?;
        validate_sqlite_sidecars(
            &config.enterprise_migration.state_database_path,
            config.trusted_service_uid,
            "enterprise migration state database",
        )?;
        let migration_store: Arc<dyn EnterpriseMigrationStateStore> = migration_store;
        let migration_enforcer: Arc<dyn BrokerMigrationEnforcer> =
            Arc::new(ProductionBrokerMigrationEnforcer::load(
                &migration_store,
                &config.enterprise_migration.deployment_id,
                &config.enterprise_migration.credential_provider,
                config.enterprise_migration.credential_custody_stage,
                config.enterprise_migration.quota_enforcement_stage,
            )?);
        prepare_socket_parent(&config.ipc_socket_path, config.trusted_service_uid)?;
        let database_files: [(&Path, &str); 4] = [
            (&config.databases.secret_database_path, "secret database"),
            (&config.databases.attempt_database_path, "attempt database"),
            (
                &config.databases.admin_replay_database_path,
                "admin replay database",
            ),
            (&config.databases.receipt_database_path, "receipt database"),
        ];
        let mut database_identity_files = Vec::with_capacity(database_files.len());
        for &(path, label) in &database_files {
            let retained = DurableBrokerDatabaseFile::open(path)?;
            validate_sqlite_sidecars(path, config.trusted_service_uid, label)?;
            database_identity_files.push(retained);
        }
        let all_database_files: [(&Path, &str); 5] = [
            database_files[0],
            database_files[1],
            database_files[2],
            database_files[3],
            (
                &config.enterprise_migration.state_database_path,
                "enterprise migration state database",
            ),
        ];
        validate_distinct_database_files(&all_database_files)?;
        let database_owner_locks =
            acquire_database_owner_locks(&database_files, config.trusted_service_uid)?;
        let signing_key =
            SealedSigningKeyFd::from_inherited_file(signing_key_file, config.trusted_service_uid)
                .into_keypair()?;
        if signing_key.public_key() != config.broker_identity {
            return Err(BrokerError::Custody(
                "sealed signing key does not match the configured broker identity".to_string(),
            ));
        }
        let signing_backend: Arc<dyn SigningBackend> =
            Arc::new(Ed25519Backend::new(signing_key.clone()));
        let backend = Arc::new(EncryptedBlobSecretBackend::open(
            &config.databases.secret_database_path,
            config.tenant_scope.clone(),
            SealedKeyFd::from_inherited_file(master_key_file, config.trusted_service_uid),
        )?);
        let attempts = Arc::new(SqliteAttemptStore::open(
            &config.databases.attempt_database_path,
        )?);
        let receipt_sink = Arc::new(SqliteBrokerReceiptSink::open(
            &config.databases.receipt_database_path,
            signing_key.public_key(),
        )?);
        let admin = Arc::new(GovernedAdminAuthorizer::open(
            &config.databases.admin_replay_database_path,
            GovernedAdminPolicy {
                trusted_approvers: config.admin.trusted_approvers.clone(),
                subject: config.admin.subject.clone(),
                threshold: config.admin.threshold,
                maximum_token_lifetime_seconds: config.admin.maximum_token_lifetime_seconds,
            },
            signing_key.public_key(),
            Arc::new(SystemAdminClock),
        )?);
        for &(path, label) in &database_files {
            validate_private_service_file(path, config.trusted_service_uid, label)?;
            validate_sqlite_sidecars(path, config.trusted_service_uid, label)?;
        }
        for retained in &database_identity_files {
            retained.validate()?;
        }
        validate_distinct_database_files(&all_database_files)?;
        let daemon_clock: Arc<dyn DaemonClock> = Arc::new(SystemDaemonClock);
        reconcile_durable_failures(
            attempts.as_ref(),
            receipt_sink.as_ref(),
            &signing_key.public_key(),
            256,
            daemon_clock.now_unix_seconds()?,
        )?;
        reconcile_durable_completions(
            attempts.as_ref(),
            receipt_sink.as_ref(),
            &signing_key.public_key(),
            256,
            daemon_clock.now_unix_seconds()?,
        )?;
        let authority = Arc::new(AuthorityRpcClient::connect(
            AuthorityRpcClientConfig {
                socket_path: config.authority_socket_path.clone(),
                trusted_authority: config.trusted_authority.clone(),
                timeout_ms: config.authority_timeout_ms,
                maximum_clock_skew_seconds: config.maximum_clock_skew_seconds,
            },
            Arc::clone(&signing_backend),
        )?);
        reconcile_pending(
            attempts.as_ref(),
            authority.as_ref(),
            256,
            daemon_clock.now_unix_seconds()?,
        )?;
        let provider = Arc::new(GenericCredentialProvider::new(
            config.provider_adapter_id.clone(),
            config.provider_adapter_version,
            config.provider_placement.into_placement(),
        )?);
        let https = match https_override {
            Some(https) => https,
            None => Arc::new(GenericHttpsExecutor::production()?),
        };
        let budget: Arc<dyn BrokerExecutionBudget> = authority.clone();
        let liveness: Arc<dyn CapabilityLiveness> = authority.clone();
        let revocations: Arc<dyn BrokerRevocations> = authority.clone();
        let service = Arc::new(BrokerService::new_production(
            BrokerServiceConfig {
                audience: config.broker_audience.clone(),
                parent_audience: config.parent_audience.clone(),
                maximum_clock_skew_seconds: config.maximum_clock_skew_seconds,
                maximum_liveness_snapshot_age_seconds: config.maximum_liveness_snapshot_age_seconds,
                maximum_revocation_snapshot_age_seconds: config
                    .maximum_revocation_snapshot_age_seconds,
            },
            ProductionSqliteAttemptStore::new(attempts)?,
            BrokerServiceAuthorityBundle {
                trusted_issuer: config.trusted_capability_issuer.clone(),
                backend: Arc::clone(&backend),
                provider,
                https,
                budget,
                liveness,
                revocations,
                receipt_sink,
                receipt_signer: Arc::clone(&signing_backend),
                migration_enforcer: Arc::clone(&migration_enforcer),
            },
        )?);
        let admission: Arc<dyn BrokerAdmissionAuthority> = authority;
        let ipc_deadlines = BrokerIpcDeadlines::from_millis(
            config.ipc_read_timeout_ms,
            config.ipc_write_timeout_ms,
        )?;
        let handler: Arc<dyn BrokerIpcHandler> = Arc::new(BrokerDaemonHandler::new(
            config.tenant_scope.clone(),
            config.broker_audience.clone(),
            config.trusted_capability_issuer.clone(),
            config.trusted_authority.clone(),
            config.maximum_clock_skew_seconds,
            Arc::clone(&service),
            admission,
            Arc::clone(&admin),
            Arc::clone(&signing_backend),
            backend,
            Arc::clone(&daemon_clock),
        )?);
        migration_enforcer.ensure_ready()?;
        let endpoint = UnixBrokerEndpoint::bind_with_deadlines(
            &config.ipc_socket_path,
            handler,
            config.trusted_service_uid,
            config.authorized_client_uid,
            ipc_deadlines,
        )?;
        let audit = Arc::new(BrokerDaemonAuditContext {
            audit_service: service,
            audit_admin: admin,
            audit_clock: daemon_clock,
            audit_deployment_id: config.deployment_id.clone(),
            audit_broker_instance_id: config.broker_instance_id.clone(),
            audit_tenant_scope: config.tenant_scope.clone(),
            audit_runner_id: config.audit_runner_id.clone(),
            trusted_audit_runner: config.trusted_audit_runner.clone(),
        });
        let privileged_audit_handler: Arc<dyn BrokerPrivilegedAuditHandler> = audit.clone();
        migration_enforcer.ensure_ready()?;
        let privileged_audit_endpoint = BrokerPrivilegedAuditEndpoint::bind(
            BrokerPrivilegedAuditEndpointConfig {
                socket_path: config.privileged_audit.socket_path,
                trusted_service_uid: config.trusted_service_uid,
                authorized_runner_uid: config.privileged_audit.authorized_runner_uid,
                authorized_runner_gid: config.privileged_audit.authorized_runner_gid,
                read_timeout_ms: config.privileged_audit.read_timeout_ms,
                write_timeout_ms: config.privileged_audit.write_timeout_ms,
                authorization_lifetime_seconds: config
                    .privileged_audit
                    .authorization_lifetime_seconds,
                deployment_id: config.deployment_id,
                broker_instance_id: config.broker_instance_id,
                tenant_scope: config.tenant_scope,
                runner_id: config.audit_runner_id,
            },
            signing_backend,
            privileged_audit_handler,
        )?;
        Ok(Self {
            endpoint,
            privileged_audit_endpoint,
            audit,
            _database_owner_locks: database_owner_locks,
            _database_identity_files: database_identity_files,
        })
    }

    #[cfg(not(unix))]
    pub fn build(
        _config: BrokerDaemonConfig,
        _master_key_file: File,
        _signing_key_file: File,
    ) -> Result<Self> {
        Err(BrokerError::AuthorityUnavailable(
            "secret broker daemon requires Unix process isolation".to_string(),
        ))
    }

    #[cfg(unix)]
    pub fn audit_compare_outbound_request(
        &self,
        request: &BrokerExecuteRequest,
        reference: BrokerAuditReferenceRequest,
        runner_authorization: &SignedBrokerAuditRunnerAuthorization,
        admin_authorization: &AdminAuthorization,
    ) -> Result<SignedBrokerAuditComparison> {
        self.audit
            .compare(
                request,
                reference,
                runner_authorization,
                admin_authorization,
            )
            .map(|completed| completed.comparison)
    }

    #[cfg(unix)]
    pub fn serve(&self) -> Result<()> {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::mpsc;
        use std::time::Duration;

        self.endpoint.set_nonblocking(true)?;
        self.privileged_audit_endpoint.set_nonblocking(true)?;
        let stop = AtomicBool::new(false);
        let (failure_sender, failure_receiver) = mpsc::sync_channel::<BrokerError>(2);
        std::thread::scope(|scope| {
            let normal_sender = failure_sender.clone();
            let normal_stop = &stop;
            let normal_endpoint = &self.endpoint;
            scope.spawn(move || {
                run_daemon_serving_worker("normal IPC", normal_sender, || {
                    while !normal_stop.load(Ordering::Acquire) {
                        match normal_endpoint.try_serve_one() {
                            Ok(Some(_)) => {}
                            Ok(None) => std::thread::sleep(Duration::from_millis(2)),
                            Err(error) => return Err(error),
                        }
                    }
                    Ok(())
                });
            });
            let audit_sender = failure_sender.clone();
            let audit_stop = &stop;
            let audit_endpoint = &self.privileged_audit_endpoint;
            scope.spawn(move || {
                run_daemon_serving_worker("privileged audit", audit_sender, || {
                    while !audit_stop.load(Ordering::Acquire) {
                        match audit_endpoint.try_serve_one() {
                            Ok(Some(_)) => {}
                            Ok(None) => std::thread::sleep(Duration::from_millis(2)),
                            Err(error) => return Err(error),
                        }
                    }
                    Ok(())
                });
            });
            drop(failure_sender);
            let failure = failure_receiver.recv().unwrap_or_else(|_| {
                BrokerError::Invariant("broker daemon serving thread terminated".to_string())
            });
            stop.store(true, Ordering::Release);
            Err(failure)
        })
    }

    #[cfg(not(unix))]
    pub fn serve(&self) -> Result<()> {
        Err(BrokerError::AuthorityUnavailable(
            "secret broker daemon requires Unix process isolation".to_string(),
        ))
    }
}

#[cfg(unix)]
impl BrokerDaemonAuditContext {
    fn compare(
        &self,
        request: &BrokerExecuteRequest,
        reference: BrokerAuditReferenceRequest,
        runner_authorization: &SignedBrokerAuditRunnerAuthorization,
        admin_authorization: &AdminAuthorization,
    ) -> Result<CompletedBrokerAuditComparison> {
        let now_unix_seconds = self.audit_clock.now_unix_seconds()?;
        let verified_runner = verify_broker_audit_runner_authorization(
            runner_authorization,
            request,
            &reference,
            BrokerAuditRunnerTrust {
                deployment_id: &self.audit_deployment_id,
                broker_instance_id: &self.audit_broker_instance_id,
                tenant_scope: &self.audit_tenant_scope,
                runner_id: &self.audit_runner_id,
                trusted_runner: &self.trusted_audit_runner,
            },
            now_unix_seconds,
        )?;
        self.audit_service.audit_compare_outbound_request(
            request,
            reference,
            verified_runner,
            admin_authorization,
            self.audit_admin.as_ref(),
            now_unix_seconds,
        )
    }
}

#[cfg(unix)]
impl BrokerPrivilegedAuditHandler for BrokerDaemonAuditContext {
    fn now_unix_seconds(&self) -> Result<u64> {
        self.audit_clock.now_unix_seconds()
    }

    fn compare(
        &self,
        request: &BrokerExecuteRequest,
        reference: BrokerAuditReferenceRequest,
        runner_authorization: &SignedBrokerAuditRunnerAuthorization,
        admin_authorization: &AdminAuthorization,
    ) -> Result<CompletedBrokerAuditComparison> {
        BrokerDaemonAuditContext::compare(
            self,
            request,
            reference,
            runner_authorization,
            admin_authorization,
        )
    }
}

#[cfg(unix)]
fn validate_distinct_key_files(master_key: &File, signing_key: &File) -> Result<()> {
    let master = master_key
        .metadata()
        .map_err(|error| BrokerError::Custody(format!("master key metadata failed: {error}")))?;
    let signing = signing_key
        .metadata()
        .map_err(|error| BrokerError::Custody(format!("signing key metadata failed: {error}")))?;
    if master.dev() == signing.dev() && master.ino() == signing.ino() {
        return Err(BrokerError::Custody(
            "master and signing keys must use distinct sealed descriptors".to_string(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_key_file_identity(file: &File, trusted_service_uid: u32, label: &str) -> Result<()> {
    let metadata = file
        .metadata()
        .map_err(|error| BrokerError::Custody(format!("{label} metadata failed: {error}")))?;
    if !metadata.file_type().is_file() || metadata.uid() != trusted_service_uid {
        return Err(BrokerError::Custody(format!(
            "{label} is not owned by the trusted service UID"
        )));
    }
    Ok(())
}

/// Validate one already-owned inherited key descriptor and prevent later exec
/// transitions from inheriting it.
pub fn secure_inherited_key_file(file: File, label: &str) -> Result<File> {
    #[cfg(unix)]
    {
        use rustix::io::{fcntl_getfd, fcntl_setfd, FdFlags};

        let raw_fd = file.as_raw_fd();
        if !(3..=65_535).contains(&raw_fd) {
            return Err(BrokerError::Custody(format!(
                "{label} inherited descriptor number is invalid"
            )));
        }
        let _ = u32::try_from(raw_fd).map_err(|_| {
            BrokerError::Custody(format!("{label} inherited descriptor number is invalid"))
        })?;
        let flags = fcntl_getfd(&file).map_err(|error| {
            BrokerError::Custody(format!(
                "{label} inherited descriptor flags failed: {error}"
            ))
        })?;
        fcntl_setfd(&file, flags | FdFlags::CLOEXEC).map_err(|error| {
            BrokerError::Custody(format!(
                "{label} inherited descriptor CLOEXEC setup failed: {error}"
            ))
        })?;
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        let _ = (file, label);
        Err(BrokerError::Custody(
            "inherited key descriptors require Unix descriptor custody".to_string(),
        ))
    }
}

#[cfg(target_os = "linux")]
pub fn harden_broker_process_custody() -> Result<()> {
    use rustix::process::{dumpable_behavior, set_dumpable_behavior, DumpableBehavior};

    set_dumpable_behavior(DumpableBehavior::NotDumpable).map_err(|error| {
        BrokerError::Custody(format!(
            "broker process dump protection could not be enabled: {error}"
        ))
    })?;
    if dumpable_behavior().map_err(|error| {
        BrokerError::Custody(format!(
            "broker process dump protection could not be verified: {error}"
        ))
    })? != DumpableBehavior::NotDumpable
    {
        return Err(BrokerError::Custody(
            "broker process dump protection was not retained".to_string(),
        ));
    }
    Ok(())
}

fn validate_socket_path(path: &Path, label: &str) -> Result<()> {
    if !path.is_absolute()
        || path.as_os_str().as_encoded_bytes().is_empty()
        || path.as_os_str().as_encoded_bytes().len() > 100
    {
        return Err(BrokerError::InvalidRequest(format!(
            "{label} path is not absolute or exceeds the Unix socket limit"
        )));
    }
    Ok(())
}

fn validate_database_path(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path.as_os_str().as_encoded_bytes().is_empty()
        || path.to_string_lossy().starts_with("file:")
        || path.to_string_lossy() == ":memory:"
    {
        return Err(BrokerError::InvalidRequest(
            "daemon database path must be an absolute filesystem path".to_string(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn prepare_socket_parent(path: &Path, trusted_service_uid: u32) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        BrokerError::Storage("broker IPC socket has no parent directory".to_string())
    })?;
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder
        .create(parent)
        .map_err(|error| BrokerError::Storage(format!("IPC directory creation failed: {error}")))?;
    let metadata = fs::symlink_metadata(parent)
        .map_err(|error| BrokerError::Storage(format!("IPC directory metadata failed: {error}")))?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.uid() != trusted_service_uid
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(BrokerError::Storage(
            "IPC directory is not a service-private regular directory".to_string(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn prepare_private_service_database(
    path: &Path,
    trusted_service_uid: u32,
    label: &str,
) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        BrokerError::Storage(format!("{label} has no service-owned parent directory"))
    })?;
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder.create(parent).map_err(|error| {
        BrokerError::Storage(format!("{label} parent directory creation failed: {error}"))
    })?;

    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(true).mode(0o600);
            let flags = rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW;
            let flags = i32::try_from(flags.bits()).map_err(|_| {
                BrokerError::Storage(format!("{label} secure creation flags are invalid"))
            })?;
            options.custom_flags(flags);
            drop(options.open(path).map_err(|open_error| {
                BrokerError::Storage(format!("{label} secure creation failed: {open_error}"))
            })?);
        }
        Err(error) => {
            return Err(BrokerError::Storage(format!(
                "{label} metadata failed: {error}"
            )))
        }
    }
    validate_private_service_file(path, trusted_service_uid, label)
}

#[cfg(unix)]
fn acquire_database_owner_locks(
    database_files: &[(&Path, &str)],
    trusted_service_uid: u32,
) -> Result<Vec<File>> {
    let mut ordered = Vec::with_capacity(database_files.len());
    for &(path, label) in database_files {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| BrokerError::Storage(format!("{label} metadata failed: {error}")))?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err(BrokerError::Custody(format!(
                "{label} has no stable database identity"
            )));
        }
        ordered.push((metadata.dev(), metadata.ino(), path, label));
    }
    ordered.sort_by(|left, right| {
        (left.0, left.1, left.2.as_os_str()).cmp(&(right.0, right.1, right.2.as_os_str()))
    });
    if ordered
        .windows(2)
        .any(|pair| (pair[0].0, pair[0].1) == (pair[1].0, pair[1].1))
    {
        return Err(BrokerError::Custody(
            "daemon databases must have distinct owner-lock identities".to_string(),
        ));
    }
    let mut locks = Vec::with_capacity(ordered.len());
    for (_, _, path, label) in ordered {
        locks.push(acquire_database_owner_lock(
            path,
            label,
            trusted_service_uid,
        )?);
    }
    Ok(locks)
}

#[cfg(unix)]
fn acquire_database_owner_lock(
    database_path: &Path,
    database_label: &str,
    trusted_service_uid: u32,
) -> Result<File> {
    let mut lock_path = database_path.as_os_str().to_os_string();
    lock_path.push(".owner.lock");
    let lock_path = PathBuf::from(lock_path);
    let lock_label = format!("{database_label} owner lock");
    prepare_private_service_database(&lock_path, trusted_service_uid, &lock_label)?;
    let path_metadata = fs::symlink_metadata(&lock_path)
        .map_err(|error| BrokerError::Storage(format!("{lock_label} metadata failed: {error}")))?;
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    let flags = rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW;
    let flags = i32::try_from(flags.bits())
        .map_err(|_| BrokerError::Storage(format!("{lock_label} flags are invalid")))?;
    options.custom_flags(flags);
    let file = options
        .open(&lock_path)
        .map_err(|error| BrokerError::Storage(format!("{lock_label} open failed: {error}")))?;
    let descriptor_metadata = file.metadata().map_err(|error| {
        BrokerError::Storage(format!("{lock_label} descriptor metadata failed: {error}"))
    })?;
    if path_metadata.dev() != descriptor_metadata.dev()
        || path_metadata.ino() != descriptor_metadata.ino()
        || !descriptor_metadata.file_type().is_file()
    {
        return Err(BrokerError::Custody(format!(
            "{lock_label} changed during secure open"
        )));
    }
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).map_err(
        |error| {
            BrokerError::AuthorityUnavailable(format!(
                "{database_label} is already owned by another broker daemon: {error}"
            ))
        },
    )?;
    validate_private_service_file(&lock_path, trusted_service_uid, &lock_label)?;
    Ok(file)
}

#[cfg(unix)]
fn validate_private_service_file(path: &Path, trusted_service_uid: u32, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| BrokerError::Storage(format!("{label} metadata failed: {error}")))?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.uid() != trusted_service_uid
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(BrokerError::Custody(format!(
            "{label} ownership or permissions do not match the trusted service UID"
        )));
    }
    let parent = path.parent().ok_or_else(|| {
        BrokerError::Custody(format!("{label} has no service-owned parent directory"))
    })?;
    let parent_metadata = fs::symlink_metadata(parent).map_err(|error| {
        BrokerError::Storage(format!("{label} parent metadata failed: {error}"))
    })?;
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.file_type().is_dir()
        || parent_metadata.uid() != trusted_service_uid
        || parent_metadata.permissions().mode() & 0o022 != 0
    {
        return Err(BrokerError::Custody(format!(
            "{label} parent is not controlled by the trusted service UID"
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_distinct_database_files(paths: &[(&Path, &str)]) -> Result<()> {
    let mut identities = BTreeSet::new();
    for &(path, label) in paths {
        let path_metadata = fs::symlink_metadata(path)
            .map_err(|error| BrokerError::Storage(format!("{label} metadata failed: {error}")))?;
        let mut options = OpenOptions::new();
        options.read(true);
        let flags = rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW;
        let flags = i32::try_from(flags.bits())
            .map_err(|_| BrokerError::Storage(format!("{label} secure open flags are invalid")))?;
        options.custom_flags(flags);
        let file = options.open(path).map_err(|error| {
            BrokerError::Storage(format!("{label} secure open failed: {error}"))
        })?;
        let metadata = file.metadata().map_err(|error| {
            BrokerError::Storage(format!("{label} descriptor metadata failed: {error}"))
        })?;
        if path_metadata.file_type().is_symlink()
            || !path_metadata.file_type().is_file()
            || !metadata.file_type().is_file()
            || path_metadata.dev() != metadata.dev()
            || path_metadata.ino() != metadata.ino()
            || metadata.nlink() != 1
        {
            return Err(BrokerError::Custody(format!(
                "{label} does not have a stable single-link identity"
            )));
        }
        if !identities.insert((metadata.dev(), metadata.ino())) {
            return Err(BrokerError::Custody(
                "daemon databases must have distinct descriptor identities".to_string(),
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_sqlite_sidecars(path: &Path, trusted_service_uid: u32, label: &str) -> Result<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        let sidecar = PathBuf::from(sidecar);
        match fs::symlink_metadata(&sidecar) {
            Ok(_) => {
                let retained = DurableBrokerDatabaseFile::open_existing_read_only(&sidecar)?;
                validate_private_service_file(&sidecar, trusted_service_uid, label)?;
                retained.validate()?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(BrokerError::Storage(format!(
                    "{label} sidecar metadata failed: {error}"
                )))
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn current_effective_uid() -> Result<u32> {
    Ok(rustix::process::geteuid().as_raw())
}

#[cfg(not(unix))]
fn current_effective_uid() -> Result<u32> {
    Err(BrokerError::Custody(
        "kernel-observed broker service UID requires Unix".to_string(),
    ))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use chio_test_support::prelude::*;

    #[cfg(panic = "unwind")]
    #[test]
    fn serving_worker_panics_publish_failure_while_peer_sender_is_live() {
        for label in ["normal IPC", "privileged audit"] {
            let (sender, receiver) = std::sync::mpsc::sync_channel(2);
            let peer_sender = sender.clone();
            run_daemon_serving_worker(label, sender, || {
                panic!("deterministic serving worker panic")
            });

            let failure = receiver
                .try_recv()
                .test_expect("panicking serving worker must publish a failure");
            assert!(matches!(
                failure,
                BrokerError::Invariant(message)
                    if message == format!("{label} serving worker panicked")
            ));
            drop(peer_sender);
        }
    }

    #[test]
    fn key_custody_requires_distinct_underlying_files() {
        let master = tempfile::NamedTempFile::new().test_expect("master fixture");
        let duplicate = File::open(master.path()).test_expect("duplicate fixture");
        assert!(validate_distinct_key_files(master.as_file(), &duplicate).is_err());

        let signing = tempfile::NamedTempFile::new().test_expect("signing fixture");
        validate_distinct_key_files(master.as_file(), signing.as_file())
            .test_expect("distinct key files");
    }

    #[test]
    fn key_custody_owner_is_bound_to_the_effective_service_uid() {
        let key = tempfile::NamedTempFile::new().test_expect("key fixture");
        let service_uid = current_effective_uid().test_expect("effective UID");
        validate_key_file_identity(key.as_file(), service_uid, "test key")
            .test_expect("service-owned key");
        assert!(
            validate_key_file_identity(key.as_file(), service_uid.wrapping_add(1), "test key")
                .is_err()
        );
    }

    #[test]
    fn database_identity_rejects_hard_link_aliases() {
        let directory = tempfile::tempdir().test_expect("database directory");
        let primary = directory.path().join("primary.sqlite3");
        let alias = directory.path().join("alias.sqlite3");
        File::create(&primary).test_expect("create primary database");
        fs::hard_link(&primary, &alias).test_expect("create database hard link");

        let error = validate_distinct_database_files(&[
            (&primary, "primary database"),
            (&alias, "alias database"),
        ])
        .test_expect_err("hard-linked database paths must fail closed");
        assert!(error.to_string().contains("single-link identity"));
    }

    #[test]
    fn database_owner_locks_reject_shared_receipt_with_distinct_attempt_database() {
        let directory = tempfile::tempdir().test_expect("database directory");
        let service_uid = current_effective_uid().test_expect("effective UID");
        let first_secret = directory.path().join("first-secret.sqlite3");
        let first_attempt = directory.path().join("first-attempt.sqlite3");
        let first_admin = directory.path().join("first-admin.sqlite3");
        let second_secret = directory.path().join("second-secret.sqlite3");
        let second_attempt = directory.path().join("second-attempt.sqlite3");
        let second_admin = directory.path().join("second-admin.sqlite3");
        let shared_receipt = directory.path().join("shared-receipt.sqlite3");
        let first = [
            (first_secret.as_path(), "first secret database"),
            (first_attempt.as_path(), "first attempt database"),
            (first_admin.as_path(), "first admin database"),
            (shared_receipt.as_path(), "shared receipt database"),
        ];
        let second = [
            (second_secret.as_path(), "second secret database"),
            (second_attempt.as_path(), "second attempt database"),
            (second_admin.as_path(), "second admin database"),
            (shared_receipt.as_path(), "shared receipt database"),
        ];
        for &(path, label) in first.iter().chain(second.iter()) {
            prepare_private_service_database(path, service_uid, label)
                .test_expect("prepare database fixture");
        }

        let first_locks =
            acquire_database_owner_locks(&first, service_uid).test_expect("acquire first lock set");
        assert_eq!(first_locks.len(), 4);
        let error = acquire_database_owner_locks(&second, service_uid)
            .test_expect_err("a shared receipt identity must prevent a second daemon owner");
        assert!(matches!(error, BrokerError::AuthorityUnavailable(_)));
        assert!(error.to_string().contains("shared receipt database"));
    }
}
