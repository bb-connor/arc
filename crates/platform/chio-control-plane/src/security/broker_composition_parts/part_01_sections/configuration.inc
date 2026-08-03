use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;
#[cfg(unix)]
use std::os::fd::{FromRawFd, OwnedFd};
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chio_core::canonical::canonical_json_bytes;
use chio_core::capability::scope::Operation;
use chio_core::capability::token::CapabilityToken;
#[cfg(test)]
use chio_core::crypto::Keypair;
use chio_core::crypto::{sha256_hex, Ed25519Backend, PublicKey};
use chio_core::SigningBackend;
use chio_kernel::supplemental_quota::SupplementalQuotaDestination;
use chio_kernel::{ChioKernel, ReceiptStore};
use chio_manifest::{
    load_existing_verified_manifest_registry, RuntimeToolTopology, SignedManifest,
    VerifiedManifestRegistry,
};
use chio_secret_broker::authority_ipc::AuthorityControlRequest;
use chio_secret_broker::capability::{issue_capability, verify_capability};
use chio_secret_broker::daemon::{
    daemon_admin_intent_digest, CapabilityControlCommand, CapabilityStatusResponse,
    IssueCapabilityCommand, CAPABILITY_CONTROL_SCHEMA, CAPABILITY_STATUS_SCHEMA,
    ISSUE_CAPABILITY_SCHEMA,
};
use chio_secret_broker::daemon_runtime::secure_inherited_key_file;
use chio_secret_broker::ipc_client::{BrokerIpcClient, BrokerIpcClientConfig};
use chio_secret_broker::protocol::{BrokerCapabilityBody, SignedBrokerCapability};
use chio_secret_broker::provision::{
    AdminAuthorization, GovernedAdminAuthorizer, GovernedAdminPolicy, SystemAdminClock,
};
use chio_secret_broker::receipt::SqliteBrokerReceiptSink;
use chio_secret_broker::revocation::{
    BrokerRevocations, CapabilityLiveness, CapabilityLivenessRequest,
};
use chio_secret_broker::service::IpcOperation;
use chio_secret_broker::{BrokerError, Result as BrokerResult, SealedSigningKeyFd};
use chio_security_types::ports::{Digest32, LeaseOwnerId, ProducerId, RecordId, TenantId};
use chio_security_types::{
    EnterpriseMigrationControl, EnterpriseMigrationKey, EnterpriseMigrationMinimumHead,
    EnterpriseMigrationScopeKind, EnterpriseMigrationStage, EnterpriseMigrationStateStore,
};
use chio_store_sqlite::{
    SqliteAdmissionCaptureAuthority, SqliteEnterpriseMigrationOpenPolicy,
    SqliteEnterpriseMigrationStateStore, SqliteReceiptStore,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::broker::{
    AuthoritativeBrokerExecutionAdapter, AuthoritativeBrokerExecutionConfig,
    BrokerAttemptRegistrationPort, BrokerControlAuthority, BrokerIntegrationError,
    BrokerIntegrationRuntimeParts, BrokerMigrationEnforcer, BrokerSupplementalQuotaVerifier,
};
#[cfg(test)]
use super::broker::TestBrokerMigrationEnforcer;
use super::broker_runtime::{
    CombinedAuthorityBrokerRevocations, ProductionBrokerAuthorityBinding,
    ProductionBrokerAuthorityHandle, ProductionBrokerReceiptBinding, ProductionBrokerRuntime,
    ProductionBrokerRuntimeConfig, ReceiptStoreCapabilityLiveness,
};
use super::active_response_authority::{
    ProductionActiveResponseAuthorityClient, ProductionActiveResponseAuthorityFileConfig,
};
use super::event_consumer::{
    AttestedFindingResponsePolicyPlanner, AttestedFindingResponseRecoveryLimits,
    TrustedSecurityEventProducer,
};
use super::migration::EnterpriseMigrationRuntimeBinding;
use super::orchestration::{ProductionActiveDefenseConfig, ProductionActiveDefenseHost};
#[cfg(test)]
use super::production_runtime::{
    ProductionClassificationRuleConfig, ProductionTrustedWatermarkKeyConfig,
    ProductionWatermarkSourceContextConfig,
};
use super::production_runtime::{
    decode_runtime_policy_digest, ProductionSecurityRuntimeFactory,
    ProductionSecurityRuntimeFactoryConfig,
    ProductionSecurityRuntimeFileConfig,
};
use super::scheduler_worker::{
    ActiveDefenseServiceRegistry, ProductionResponseSchedulerConfig,
    ProductionResponseWorkerLoopConfig,
};

const MAX_PRODUCTION_DATABASE_PATH_BYTES: usize = 4_096;
const MAX_PRODUCTION_SELECTED_PROVIDERS: usize = 64;
const MAX_PRODUCTION_PRODUCT_CONFIG_BYTES: u64 = 65_536;

pub const PRODUCTION_BROKER_PRODUCT_CONFIG_SCHEMA: &str = "chio.broker-product.runtime-config.v5";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductionBrokerKeyCustodyConfig {
    pub expected_owner_uid: u32,
    pub capability_issuer_signing_key_fd: u32,
    pub release_receipt_signing_key_fd: u32,
    pub active_defense_executor_signing_key_fd: u32,
    pub decoy_registry_master_key_fd: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductionBrokerMigrationConfig {
    pub state_database_path: PathBuf,
    pub deployment_id: RecordId,
    pub trusted_transition_signers: Vec<PublicKey>,
    pub minimum_heads: Vec<EnterpriseMigrationMinimumHead>,
    pub providers: Vec<ProductionBrokerProviderMigrationPosture>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductionBrokerProviderMigrationPosture {
    pub credential_provider: RecordId,
    pub credential_custody_stage: EnterpriseMigrationStage,
    pub quota_enforcement_stage: EnterpriseMigrationStage,
}

impl ProductionBrokerMigrationConfig {
    fn validate(&self) -> Result<(), BrokerIntegrationError> {
        validate_database_path(
            &self.state_database_path,
            "enterprise migration state database",
            false,
        )?;
        if self.trusted_transition_signers.is_empty()
            || self.trusted_transition_signers.len() > 16
            || self
                .trusted_transition_signers
                .windows(2)
                .any(|pair| pair[0].to_hex() >= pair[1].to_hex())
            || self.providers.is_empty()
            || self.providers.len() > MAX_PRODUCTION_SELECTED_PROVIDERS
            || self
                .providers
                .windows(2)
                .any(|pair| pair[0].credential_provider >= pair[1].credential_provider)
        {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "production broker migration signers and providers must be nonempty, bounded, sorted, and unique"
                    .to_string(),
            ));
        }
        let mut expected = BTreeMap::new();
        for provider in &self.providers {
            if !provider
                .credential_custody_stage
                .operational_failure_must_deny()
                || !provider
                    .quota_enforcement_stage
                    .operational_failure_must_deny()
            {
                return Err(BrokerIntegrationError::InvalidConfiguration(
                    "production broker migration controls must be durably enforced".to_string(),
                ));
            }
            for (control, stage) in [
                (
                    EnterpriseMigrationControl::BrokerCredentialCustody,
                    provider.credential_custody_stage,
                ),
                (
                    EnterpriseMigrationControl::BrokerQuotaEnforcement,
                    provider.quota_enforcement_stage,
                ),
            ] {
                expected.insert(
                    EnterpriseMigrationKey {
                        deployment_id: self.deployment_id.clone(),
                        scope_kind: EnterpriseMigrationScopeKind::Provider,
                        scope_id: provider.credential_provider.clone(),
                        control,
                    },
                    stage,
                );
            }
        }
        if self.minimum_heads.len() != expected.len()
            || self
                .minimum_heads
                .windows(2)
                .any(|pair| pair[0].key >= pair[1].key)
        {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "production broker migration anchors must be complete, sorted, and unique"
                    .to_string(),
            ));
        }
        for head in &self.minimum_heads {
            let Some(stage) = expected.get(&head.key) else {
                return Err(BrokerIntegrationError::InvalidConfiguration(
                    "production broker migration anchor has an unknown provider or control"
                        .to_string(),
                ));
            };
            if !head.is_valid() || head.minimum_generation != stage.generation() {
                return Err(BrokerIntegrationError::InvalidConfiguration(
                    "production broker migration anchor does not match its configured stage"
                        .to_string(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductionBrokerClientFileConfig {
    pub socket_path: PathBuf,
    pub tenant_scope: String,
    pub timeout_ms: u64,
    pub expected_peer: chio_secret_broker::ipc_client::BrokerPeerIdentity,
    pub trusted_receipt_signer: PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductionBrokerAdminFileConfig {
    pub trusted_approvers: Vec<PublicKey>,
    pub subject: PublicKey,
    pub threshold: usize,
    pub maximum_token_lifetime_seconds: u64,
}

/// Policy-independent process bounds for the broker-owned active-defense
/// service. The actual temporal rules and their runtime hash come from the
/// separately loaded Chio policy, while response decisions and authorization
/// artifacts come from the pinned external authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductionBrokerActiveDefenseFileConfig {
    pub response_authority: ProductionActiveResponseAuthorityFileConfig,
    pub correlation_bounded_lateness_ms: u64,
    pub correlation_max_scan_events: u32,
    pub correlation_cas_retries: u8,
    pub correlation_allow_verified_receipts: bool,
    pub scheduler_lease_owner_id: String,
    pub scheduler_lease_duration_ms: u64,
    pub scheduler_base_backoff_ms: u64,
    pub scheduler_max_backoff_ms: u64,
    pub scheduler_operator_page_threshold_ms: u64,
    pub scheduler_max_claims: u32,
    pub scheduler_renewal_margin_ms: u64,
    pub worker_tick_interval_ms: u64,
    pub recovery_max_records_per_pass: u32,
    pub recovery_max_startup_records: u64,
    pub recovery_max_startup_wall_clock_ms: u64,
}

impl ProductionBrokerActiveDefenseFileConfig {
    fn validate(&self) -> Result<(), BrokerIntegrationError> {
        self.response_authority.validate().map_err(|error| {
            BrokerIntegrationError::InvalidConfiguration(format!(
                "active-response authority configuration failed: {error}"
            ))
        })?;
        if self.correlation_allow_verified_receipts {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "receipt-backed active-defense events require explicitly configured trusted receipt producers"
                    .to_string(),
            ));
        }
        chio_quarantine::CorrelationPolicy::new(
            self.correlation_bounded_lateness_ms,
            self.correlation_max_scan_events,
            self.correlation_cas_retries,
            self.correlation_allow_verified_receipts,
        )
        .map_err(|error| {
            BrokerIntegrationError::InvalidConfiguration(format!(
                "active-defense correlation policy is invalid: {error}"
            ))
        })?;
        chio_quarantine::SchedulerPolicy {
            lease_duration_ms: self.scheduler_lease_duration_ms,
            base_backoff_ms: self.scheduler_base_backoff_ms,
            max_backoff_ms: self.scheduler_max_backoff_ms,
            operator_page_threshold_ms: self.scheduler_operator_page_threshold_ms,
            max_claims: self.scheduler_max_claims,
        }
        .validate()
        .map_err(|error| {
            BrokerIntegrationError::InvalidConfiguration(format!(
                "active-defense scheduler policy is invalid: {error}"
            ))
        })?;
        LeaseOwnerId::new(self.scheduler_lease_owner_id.clone()).map_err(|error| {
            BrokerIntegrationError::InvalidConfiguration(format!(
                "active-defense scheduler owner is invalid: {error}"
            ))
        })?;
        if self.scheduler_renewal_margin_ms == 0
            || self.scheduler_renewal_margin_ms >= self.scheduler_lease_duration_ms
            || self.worker_tick_interval_ms == 0
            || self.worker_tick_interval_ms > 30_000
        {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "active-defense renewal, worker, or recovery bounds are invalid".to_string(),
            ));
        }
        AttestedFindingResponseRecoveryLimits::new(
            self.recovery_max_records_per_pass,
            self.recovery_max_startup_records,
            self.recovery_max_startup_wall_clock_ms,
        )
        .map_err(|error| {
            BrokerIntegrationError::InvalidConfiguration(format!(
                "active-response recovery bounds are invalid: {error}"
            ))
        })?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductionBrokerProductConfig {
    pub schema: String,
    pub authority_socket_path: PathBuf,
    pub authority_maximum_clock_skew_seconds: u64,
    pub broker_client: ProductionBrokerClientFileConfig,
    pub authority_public_key: PublicKey,
    pub trusted_broker: PublicKey,
    pub trusted_capability_issuer: PublicKey,
    pub trusted_release_receipt_signer: PublicKey,
    pub active_defense_executor_public_key: PublicKey,
    pub broker_server_id: String,
    pub broker_tool_name: String,
    pub selected_provider_adapter_ids: BTreeSet<String>,
    pub broker_audience: String,
    pub parent_audience: String,
    pub supplemental_verifier_id: String,
    pub revocation_authority_domain: String,
    pub maximum_pending_admissions: usize,
    pub execution_authority_database_path: PathBuf,
    pub governed_admin_database_path: PathBuf,
    pub broker_receipt_database_path: PathBuf,
    pub issuance_database_path: PathBuf,
    pub native_receipt_database_path: PathBuf,
    pub kernel_admission_operation_database_path: PathBuf,
    pub active_defense: ProductionBrokerActiveDefenseFileConfig,
    pub security_runtime: ProductionSecurityRuntimeFileConfig,
    pub receipt_tenant_id: String,
    pub broker_manifest_path: PathBuf,
    pub broker_manifest_public_key: PublicKey,
    pub admin: ProductionBrokerAdminFileConfig,
    pub key_custody: ProductionBrokerKeyCustodyConfig,
    pub enterprise_migration: ProductionBrokerMigrationConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionBrokerHostDatabasePaths {
    pub receipt_database_path: PathBuf,
    pub revocation_database_path: PathBuf,
    pub budget_database_path: PathBuf,
    pub admission_operation_database_path: PathBuf,
    pub approval_database_path: PathBuf,
}

#[derive(Debug)]
struct ProductionBrokerHostDatabaseIdentities {
    receipt_database: RetainedDatabaseFileIdentity,
    revocation_database: RetainedDatabaseFileIdentity,
    budget_database: RetainedDatabaseFileIdentity,
    admission_operation_database: RetainedDatabaseFileIdentity,
    approval_database: RetainedDatabaseFileIdentity,
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct DatabaseFileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Debug)]
struct RetainedDatabaseFileIdentity {
    file: File,
    parent: File,
    identity: DatabaseFileIdentity,
}

#[derive(Debug)]
pub(super) struct RetainedSecurityStateLifecycleLease {
    retained: RetainedDatabaseFileIdentity,
    path: PathBuf,
    #[cfg(target_os = "macos")]
    lifecycle_lock: RetainedDatabaseFileIdentity,
    #[cfg(target_os = "macos")]
    lifecycle_lock_path: PathBuf,
    acquisition_pid: rustix::process::Pid,
}

impl RetainedSecurityStateLifecycleLease {
    pub(super) fn acquire(path: &Path) -> Result<Self, BrokerIntegrationError> {
        const LABEL: &str = "security state database lifecycle lease";

        prepare_private_database(path, LABEL)?;
        let retained = RetainedDatabaseFileIdentity::open(path, LABEL)?;
        #[cfg(target_os = "macos")]
        let lifecycle_lock_path = security_state_lifecycle_lock_path(path)?;
        #[cfg(target_os = "macos")]
        prepare_private_database(&lifecycle_lock_path, LABEL)?;
        #[cfg(target_os = "macos")]
        let lifecycle_lock = RetainedDatabaseFileIdentity::open(&lifecycle_lock_path, LABEL)?;
        #[cfg(target_os = "macos")]
        rustix::fs::flock(
            &lifecycle_lock.file,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .map_err(|error| {
            BrokerIntegrationError::Conflict(format!(
                "security state database is already owned by another production runtime: {error}"
            ))
        })?;
        #[cfg(not(target_os = "macos"))]
        rustix::fs::flock(
            &retained.file,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .map_err(|error| {
            BrokerIntegrationError::Conflict(format!(
                "security state database is already owned by another production runtime: {error}"
            ))
        })?;
        retained.validate_path_binding(path, LABEL)?;
        #[cfg(target_os = "macos")]
        lifecycle_lock.validate_path_binding(&lifecycle_lock_path, LABEL)?;
        Ok(Self {
            retained,
            path: path.to_path_buf(),
            #[cfg(target_os = "macos")]
            lifecycle_lock,
            #[cfg(target_os = "macos")]
            lifecycle_lock_path,
            acquisition_pid: rustix::process::getpid(),
        })
    }

    pub(super) fn ensure_owned(&self) -> Result<(), BrokerIntegrationError> {
        let current_process = rustix::process::getpid();
        if !self.acquired_by_current_process() {
            return Err(BrokerIntegrationError::Conflict(format!(
                "security state database lifecycle lease belongs to process {}; inherited process {} must acquire an independent lease",
                self.acquisition_pid, current_process
            )));
        }
        self.retained
            .validate_path_binding(&self.path, "security state database lifecycle lease")?;
        #[cfg(target_os = "macos")]
        {
            rustix::fs::flock(
                &self.lifecycle_lock.file,
                rustix::fs::FlockOperation::NonBlockingLockExclusive,
            )
            .map_err(|error| {
                BrokerIntegrationError::Conflict(format!(
                    "security state database lifecycle lock is no longer owned: {error}"
                ))
            })?;
            self.lifecycle_lock.validate_path_binding(
                &self.lifecycle_lock_path,
                "security state database lifecycle lease",
            )?;
        }
        Ok(())
    }

    fn acquired_by_current_process(&self) -> bool {
        rustix::process::getpid() == self.acquisition_pid
    }

    pub(super) fn try_clone_locked_file(&self) -> Result<File, BrokerIntegrationError> {
        self.ensure_owned()?;
        let cloned = File::from(
            rustix::io::fcntl_dupfd_cloexec(&self.retained.file, 0).map_err(|error| {
                BrokerIntegrationError::InvalidConfiguration(format!(
                    "security state database lifecycle descriptor clone failed: {error}"
                ))
            })?,
        );
        validate_private_file_descriptor(&cloned, "security state database lifecycle lease")?;
        if database_file_identity(&cloned, "security state database lifecycle lease")?
            != self.retained.identity
        {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "security state database lifecycle descriptor identity changed during clone"
                    .to_string(),
            ));
        }
        self.ensure_owned()?;
        Ok(cloned)
    }

    #[cfg(target_os = "macos")]
    pub(super) fn try_clone_lifecycle_lock_file(&self) -> Result<File, BrokerIntegrationError> {
        self.ensure_owned()?;
        let cloned = File::from(
            rustix::io::fcntl_dupfd_cloexec(&self.lifecycle_lock.file, 0).map_err(|error| {
                BrokerIntegrationError::InvalidConfiguration(format!(
                    "security state lifecycle lock descriptor clone failed: {error}"
                ))
            })?,
        );
        validate_private_file_descriptor(&cloned, "security state database lifecycle lease")?;
        if database_file_identity(&cloned, "security state database lifecycle lease")?
            != self.lifecycle_lock.identity
        {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "security state lifecycle lock descriptor identity changed during clone"
                    .to_string(),
            ));
        }
        self.ensure_owned()?;
        Ok(cloned)
    }
}

#[cfg(target_os = "macos")]
fn security_state_lifecycle_lock_path(
    path: &Path,
) -> Result<PathBuf, BrokerIntegrationError> {
    let file_name = path.file_name().ok_or_else(|| {
        BrokerIntegrationError::InvalidConfiguration(
            "security state database lifecycle lease path has no file name".to_string(),
        )
    })?;
    let mut lock_name = file_name.to_os_string();
    lock_name.push(".lifecycle.lock");
    Ok(path.with_file_name(lock_name))
}

impl RetainedDatabaseFileIdentity {
    fn open(path: &Path, label: &str) -> Result<Self, BrokerIntegrationError> {
        let parent = open_trusted_parent_directory(path, label)?;
        let file = open_private_file_at(&parent, path, false, false, label)?;
        validate_private_file_descriptor(&file, label)?;
        let identity = database_file_identity(&file, label)?;
        let retained = Self {
            file,
            parent,
            identity,
        };
        retained.validate_path_binding(path, label)?;
        Ok(retained)
    }

    fn validate_path_binding(
        &self,
        path: &Path,
        label: &str,
    ) -> Result<(), BrokerIntegrationError> {
        let current_parent = open_trusted_parent_directory(path, label)?;
        let retained_parent = database_file_identity(&self.parent, label)?;
        let current_parent_identity = database_file_identity(&current_parent, label)?;
        if retained_parent != current_parent_identity {
            return Err(BrokerIntegrationError::InvalidConfiguration(format!(
                "{label} parent descriptor identity changed"
            )));
        }
        let current_file = open_private_file_at(&current_parent, path, false, false, label)?;
        validate_private_file_descriptor(&current_file, label)?;
        if database_file_identity(&self.file, label)? != self.identity
            || database_file_identity(&current_file, label)? != self.identity
        {
            return Err(BrokerIntegrationError::InvalidConfiguration(format!(
                "{label} descriptor identity changed after it was retained"
            )));
        }
        Ok(())
    }
}

/// Policy-owned inputs for the broker product's asynchronous active-defense
/// start phase. Durable authorities are deliberately absent: the product
/// derives those from its already validated production factory.
#[derive(Clone)]
struct ProductionBrokerActiveDefenseStartConfig {
    response_policy_planner: Arc<dyn AttestedFindingResponsePolicyPlanner>,
    active_defense: ProductionActiveDefenseConfig,
    worker_loop: ProductionResponseWorkerLoopConfig,
}

#[derive(Debug, Clone)]
pub(super) struct ProductionBrokerCompositionConfig {
    pub authority_socket_path: PathBuf,
    pub authority_maximum_clock_skew_seconds: u64,
    pub broker_client: BrokerIpcClientConfig,
    pub response_authority_socket_path: PathBuf,
    pub response_authority_expected_peer: chio_secret_broker::ipc_client::BrokerPeerIdentity,
    pub authority_public_key: PublicKey,
    pub trusted_broker: PublicKey,
    pub trusted_capability_issuer: PublicKey,
    pub trusted_release_receipt_signer: PublicKey,
    pub trusted_response_authority: PublicKey,
    pub broker_server_id: String,
    pub broker_tool_name: String,
    pub selected_provider_adapter_ids: BTreeSet<String>,
    pub broker_audience: String,
    pub parent_audience: String,
    pub supplemental_verifier_id: String,
    pub revocation_authority_domain: String,
    pub maximum_pending_admissions: usize,
    pub enterprise_migration_state_database_path: PathBuf,
    pub execution_authority_database_path: PathBuf,
    pub kernel_admission_operation_database_path: PathBuf,
    pub governed_admin_database_path: PathBuf,
    pub broker_receipt_database_path: PathBuf,
    pub issuance_database_path: PathBuf,
    pub native_receipt_database_path: PathBuf,
    pub receipt_tenant_id: String,
    pub admin_policy: GovernedAdminPolicy,
}

#[cfg_attr(test, derive(Clone))]
pub(super) struct ProductionBrokerKeys {
    pub authority_signer: Arc<dyn SigningBackend>,
    pub capability_issuer_signer: Arc<dyn SigningBackend>,
    pub release_receipt_signer: Arc<dyn SigningBackend>,
}

type LoadedProductionBrokerKeys = (
    ProductionBrokerKeys,
    Arc<dyn SigningBackend>,
    [u8; 32],
);

impl ProductionBrokerProductConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, BrokerIntegrationError> {
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "broker product config path must be absolute".to_string(),
            ));
        }
        let retained = RetainedDatabaseFileIdentity::open(path, "broker product config")?;
        let mut file = retained.file.try_clone().map_err(|error| {
            BrokerIntegrationError::InvalidConfiguration(format!(
                "broker product config descriptor clone failed: {error}"
            ))
        })?;
        let metadata = file.metadata().map_err(|error| {
            BrokerIntegrationError::InvalidConfiguration(format!(
                "broker product config metadata failed: {error}"
            ))
        })?;
        if !metadata.file_type().is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_PRODUCTION_PRODUCT_CONFIG_BYTES
        {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "broker product config is not a bounded regular file".to_string(),
            ));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.by_ref()
            .take(MAX_PRODUCTION_PRODUCT_CONFIG_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                BrokerIntegrationError::InvalidConfiguration(format!(
                    "broker product config read failed: {error}"
                ))
            })?;
        if bytes.len() as u64 != metadata.len() {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "broker product config changed while it was read".to_string(),
            ));
        }
        retained.validate_path_binding(path, "broker product config")?;
        let config: Self = serde_json::from_slice(&bytes).map_err(|error| {
            BrokerIntegrationError::InvalidConfiguration(format!(
                "broker product config decoding failed: {error}"
            ))
        })?;
        let canonical = canonical_json_bytes(&config).map_err(|error| {
            BrokerIntegrationError::InvalidConfiguration(format!(
                "broker product config encoding failed: {error}"
            ))
        })?;
        if canonical != bytes {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "broker product config is not canonical JSON".to_string(),
            ));
        }
        let effective_uid = rustix::process::geteuid().as_raw();
        if metadata.uid() != effective_uid || config.key_custody.expected_owner_uid != effective_uid
        {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "broker product config and signing-key custody must match the effective service identity"
                    .to_string(),
            ));
        }
        config.validate_wire_contract()?;
        Ok(config)
    }

    fn validate_wire_contract(&self) -> Result<(), BrokerIntegrationError> {
        if self.schema != PRODUCTION_BROKER_PRODUCT_CONFIG_SCHEMA {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "broker product config schema is invalid".to_string(),
            ));
        }
        let custody_fds = [
            self.key_custody.capability_issuer_signing_key_fd,
            self.key_custody.release_receipt_signing_key_fd,
            self.key_custody.active_defense_executor_signing_key_fd,
            self.key_custody.decoy_registry_master_key_fd,
        ];
        if custody_fds
            .iter()
            .any(|descriptor| !(3..=65_535).contains(descriptor))
            || custody_fds.into_iter().collect::<BTreeSet<_>>().len() != 4
        {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "broker product custody requires four distinct inherited descriptors".to_string(),
            ));
        }
        if !self.broker_manifest_path.is_absolute() {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "broker manifest path must be absolute".to_string(),
            ));
        }
        validate_database_path(
            &self.kernel_admission_operation_database_path,
            "kernel admission operation database",
            false,
        )?;
        self.enterprise_migration.validate()?;
        self.active_defense.validate()?;
        let executor_lease_owner_id = LeaseOwnerId::new(
            self.security_runtime
                .active_response_executor_lease_owner_id
                .clone(),
        )
        .map_err(|error| {
            BrokerIntegrationError::InvalidConfiguration(format!(
                "active-response executor lease owner is invalid: {error}"
            ))
        })?;
        if executor_lease_owner_id.as_str()
            == self.active_defense.scheduler_lease_owner_id.as_str()
        {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "active-response executor and scheduler workers require distinct lease owner identities"
                    .to_string(),
            ));
        }
        let composition = self.composition_config();
        composition.validate_contract()?;
        let product_database_paths = [
            (
                &composition.execution_authority_database_path,
                "execution authority database",
            ),
            (
                &composition.governed_admin_database_path,
                "governed admin database",
            ),
            (
                &composition.broker_receipt_database_path,
                "broker receipt database",
            ),
            (&composition.issuance_database_path, "issuance database"),
            (
                &composition.native_receipt_database_path,
                "native receipt database",
            ),
            (
                &self.kernel_admission_operation_database_path,
                "kernel admission operation database",
            ),
            (
                &self.security_runtime.security_state_database_path,
                "security state database",
            ),
            (
                &self.security_runtime.decoy_registry_database_path,
                "decoy registry database",
            ),
            (
                &self.security_runtime.approval_database_path,
                "security approval database",
            ),
            (
                &self.security_runtime.alert_outbox_database_path,
                "security alert outbox database",
            ),
            (
                &self.security_runtime.alert_archive_path,
                "security alert archive",
            ),
            (
                &self.enterprise_migration.state_database_path,
                "enterprise migration state database",
            ),
        ];
        let mut product_database_identities = BTreeSet::new();
        for (path, label) in product_database_paths {
            validate_database_path(path, label, false)?;
            if !product_database_identities.insert(normalized_path_identity(path, label)?) {
                return Err(BrokerIntegrationError::InvalidConfiguration(
                    "broker product databases must use distinct files except for the explicitly shared combined authority"
                        .to_string(),
                ));
            }
        }
        let mut product_socket_identities = BTreeSet::new();
        for (socket_path, label) in [
            (&self.authority_socket_path, "authority socket"),
            (&self.broker_client.socket_path, "broker socket"),
            (
                &self.active_defense.response_authority.socket_path,
                "active-response authority socket",
            ),
        ] {
            validate_socket_path(socket_path, label)?;
            if !product_socket_identities.insert(normalized_path_identity(socket_path, label)?) {
                return Err(BrokerIntegrationError::InvalidConfiguration(
                    "production broker authority sockets must use distinct normalized paths"
                        .to_string(),
                ));
            }
        }
        if !product_database_identities.is_disjoint(&product_socket_identities) {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "production broker sockets and databases must use distinct normalized paths"
                    .to_string(),
            ));
        }
        let security_role_keys = [
            &self.authority_public_key,
            &self.trusted_broker,
            &self.trusted_capability_issuer,
            &self.trusted_release_receipt_signer,
            &self.active_defense.response_authority.trusted_authority,
            &self.active_defense_executor_public_key,
        ]
        .into_iter()
        .map(PublicKey::to_hex)
        .collect::<BTreeSet<_>>();
        if security_role_keys.len() != 6
            || self.broker_client.trusted_receipt_signer != self.trusted_broker
            || security_role_keys.contains(&self.broker_manifest_public_key.to_hex())
            || security_role_keys.contains(&self.admin.subject.to_hex())
            || self
                .admin
                .trusted_approvers
                .iter()
                .any(|approver| security_role_keys.contains(&approver.to_hex()))
        {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "broker product trust roots do not preserve independent signing roles, including the response authority and active-defense executor"
                    .to_string(),
            ));
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

    fn composition_config(&self) -> ProductionBrokerCompositionConfig {
        ProductionBrokerCompositionConfig {
            authority_socket_path: self.authority_socket_path.clone(),
            authority_maximum_clock_skew_seconds: self.authority_maximum_clock_skew_seconds,
            broker_client: BrokerIpcClientConfig {
                socket_path: self.broker_client.socket_path.clone(),
                tenant_scope: self.broker_client.tenant_scope.clone(),
                timeout_ms: self.broker_client.timeout_ms,
                expected_peer: self.broker_client.expected_peer,
                trusted_receipt_signer: self.broker_client.trusted_receipt_signer.clone(),
            },
            response_authority_socket_path: self
                .active_defense
                .response_authority
                .socket_path
                .clone(),
            response_authority_expected_peer: self
                .active_defense
                .response_authority
                .expected_peer,
            authority_public_key: self.authority_public_key.clone(),
            trusted_broker: self.trusted_broker.clone(),
            trusted_capability_issuer: self.trusted_capability_issuer.clone(),
            trusted_release_receipt_signer: self.trusted_release_receipt_signer.clone(),
            trusted_response_authority: self
                .active_defense
                .response_authority
                .trusted_authority
                .clone(),
            broker_server_id: self.broker_server_id.clone(),
            broker_tool_name: self.broker_tool_name.clone(),
            selected_provider_adapter_ids: self.selected_provider_adapter_ids.clone(),
            broker_audience: self.broker_audience.clone(),
            parent_audience: self.parent_audience.clone(),
            supplemental_verifier_id: self.supplemental_verifier_id.clone(),
            revocation_authority_domain: self.revocation_authority_domain.clone(),
            maximum_pending_admissions: self.maximum_pending_admissions,
            enterprise_migration_state_database_path: self
                .enterprise_migration
                .state_database_path
                .clone(),
            execution_authority_database_path: self.execution_authority_database_path.clone(),
            kernel_admission_operation_database_path: self
                .kernel_admission_operation_database_path
                .clone(),
            governed_admin_database_path: self.governed_admin_database_path.clone(),
            broker_receipt_database_path: self.broker_receipt_database_path.clone(),
            issuance_database_path: self.issuance_database_path.clone(),
            native_receipt_database_path: self.native_receipt_database_path.clone(),
            receipt_tenant_id: self.receipt_tenant_id.clone(),
            admin_policy: GovernedAdminPolicy {
                trusted_approvers: self.admin.trusted_approvers.clone(),
                subject: self.admin.subject.clone(),
                threshold: self.admin.threshold,
                maximum_token_lifetime_seconds: self.admin.maximum_token_lifetime_seconds,
            },
        }
    }

    fn load_keys(
        &self,
        authority_signer: Arc<dyn SigningBackend>,
    ) -> Result<LoadedProductionBrokerKeys, BrokerIntegrationError> {
        let owner = self.key_custody.expected_owner_uid;
        let capability_issuer_signer = SealedSigningKeyFd::from_inherited_file(
            take_production_inherited_key_file(
                self.key_custody.capability_issuer_signing_key_fd,
                "broker capability issuer signing key",
            )?,
            owner,
        )
        .into_keypair()?;
        let release_receipt_signer = SealedSigningKeyFd::from_inherited_file(
            take_production_inherited_key_file(
                self.key_custody.release_receipt_signing_key_fd,
                "broker release receipt signing key",
            )?,
            owner,
        )
        .into_keypair()?;
        let active_defense_executor_signer = SealedSigningKeyFd::from_inherited_file(
            take_production_inherited_key_file(
                self.key_custody.active_defense_executor_signing_key_fd,
                "active-defense executor signing key",
            )?,
            owner,
        )
        .into_keypair()?;
        let active_defense_executor_signer: Arc<dyn SigningBackend> =
            Arc::new(Ed25519Backend::new(active_defense_executor_signer));
        ensure_active_defense_executor_signer_matches_configured_key(
            &active_defense_executor_signer,
            &self.active_defense_executor_public_key,
        )?;
        let decoy_registry_master_key =
            read_decoy_registry_master_key(take_production_inherited_key_file(
                self.key_custody.decoy_registry_master_key_fd,
                "decoy registry master key",
            )?)?;
        Ok((
            ProductionBrokerKeys {
                authority_signer,
                capability_issuer_signer: Arc::new(Ed25519Backend::new(capability_issuer_signer)),
                release_receipt_signer: Arc::new(Ed25519Backend::new(release_receipt_signer)),
            },
            active_defense_executor_signer,
            decoy_registry_master_key,
        ))
    }
}

fn take_production_inherited_key_file(
    fd: u32,
    label: &str,
) -> Result<File, BrokerIntegrationError> {
    if !(3..=65_535).contains(&fd) {
        return Err(BrokerError::Custody(format!(
            "{label} inherited descriptor number is invalid"
        ))
        .into());
    }
    #[cfg(unix)]
    {
        let raw_fd = i32::try_from(fd).map_err(|_| {
            BrokerError::Custody(format!("{label} inherited descriptor number is invalid"))
        })?;
        // SAFETY: raw fcntl accepts an integer descriptor and reports EBADF for
        // a closed number without first requiring a Rust descriptor borrow.
        let duplicated = unsafe { libc::fcntl(raw_fd, libc::F_DUPFD_CLOEXEC, 3) };
        if duplicated < 0 {
            return Err(BrokerError::Custody(format!(
                "{label} inherited descriptor duplication failed: {}",
                std::io::Error::last_os_error()
            ))
            .into());
        }
        // SAFETY: successful F_DUPFD_CLOEXEC returns a new live descriptor
        // uniquely owned by this function with CLOEXEC set atomically.
        let descriptor = unsafe { OwnedFd::from_raw_fd(duplicated) };
        // SAFETY: production composition requires exclusive ownership transfer
        // of every configured descriptor. Duplication established liveness, and
        // the transfer contract requires retiring the inherited original.
        if unsafe { libc::close(raw_fd) } != 0 {
            return Err(BrokerError::Custody(format!(
                "{label} inherited descriptor retirement failed: {}",
                std::io::Error::last_os_error()
            ))
            .into());
        }
        secure_inherited_key_file(File::from(descriptor), label).map_err(Into::into)
    }
    #[cfg(not(unix))]
    {
        let _ = label;
        Err(BrokerError::Custody(
            "inherited key descriptors require Unix descriptor custody".to_string(),
        )
        .into())
    }
}

pub struct ProductionBrokerProductRuntime {
    authority: Option<ProductionBrokerAuthorityHandle>,
    composition: ProductionBrokerComposition,
    broker_manifest: SignedManifest,
    broker_manifest_public_key: PublicKey,
    broker_server_id: String,
    broker_tool_name: String,
    contract_digest: String,
    host_database_paths: ProductionBrokerHostDatabasePaths,
    host_database_identities: ProductionBrokerHostDatabaseIdentities,
    reserved_database_paths: Vec<(PathBuf, &'static str)>,
    security_runtime_factory: ProductionSecurityRuntimeFactory,
    active_defense_config: ProductionBrokerActiveDefenseFileConfig,
    active_defense_tenant_id: String,
    active_defense_producer_id: String,
    active_defense_producer_key_id: String,
    active_defense_policy_version: String,
    active_defense_max_event_age_ms: u64,
    active_defense_max_future_skew_ms: u64,
    active_defense_disallowed_signer_keys: BTreeSet<String>,
    active_defense_executor_signer: Arc<dyn SigningBackend>,
    active_defense_host: Option<ProductionActiveDefenseHost>,
    canonical_active_defense_signer: Option<Arc<dyn SigningBackend>>,
    migration_bindings: Arc<ProductionBrokerMigrationBindings>,
}

struct ProductionBrokerProviderMigrationBindings {
    credential_custody: EnterpriseMigrationRuntimeBinding,
    quota_enforcement: EnterpriseMigrationRuntimeBinding,
}

pub(super) struct ProductionBrokerMigrationBindings {
    providers: BTreeMap<String, ProductionBrokerProviderMigrationBindings>,
}

impl ProductionBrokerMigrationBindings {
    fn ensure_fail_closed(&self) -> Result<(), BrokerIntegrationError> {
        for provider in self.providers.keys() {
            self.require_provider_enforced(provider)?;
        }
        Ok(())
    }

    fn require_provider_enforced(
        &self,
        credential_provider: &str,
    ) -> Result<(), BrokerIntegrationError> {
        validate_identifier(credential_provider, "broker credential provider")?;
        let bindings = self.providers.get(credential_provider).ok_or_else(|| {
            BrokerIntegrationError::Broker(BrokerError::AuthorizationDenied(
                "credential provider has no enforced enterprise migration binding".to_string(),
            ))
        })?;
        for (binding, label) in [
            (&bindings.credential_custody, "broker credential custody"),
            (&bindings.quota_enforcement, "broker quota enforcement"),
        ] {
            binding.require_enforced().map_err(|error| {
                BrokerIntegrationError::Broker(BrokerError::AuthorizationDenied(format!(
                    "{label} migration enforcement denied: {error}"
                )))
            })?;
        }
        Ok(())
    }
}

impl BrokerMigrationEnforcer for ProductionBrokerMigrationBindings {
    fn require_provider_enforced(&self, credential_provider: &str) -> BrokerResult<()> {
        ProductionBrokerMigrationBindings::require_provider_enforced(
            self,
            credential_provider,
        )
        .map_err(|error| match error {
            BrokerIntegrationError::Broker(error) => error,
            other => BrokerError::AuthorizationDenied(format!(
                "enterprise migration enforcement denied: {other}"
            )),
        })
    }
}

#[derive(Clone)]
pub struct ProductionBrokerManifestRegistry {
    registry: Arc<VerifiedManifestRegistry>,
    broker_contract_digest: String,
}

fn exact_active_defense_signer_matches(
    active: Option<&Arc<dyn SigningBackend>>,
    candidate: &Arc<dyn SigningBackend>,
) -> bool {
    active.is_some_and(|signer| Arc::ptr_eq(signer, candidate))
}

fn retain_exact_active_defense_signer(
    canonical: &mut Option<Arc<dyn SigningBackend>>,
    candidate: &Arc<dyn SigningBackend>,
) -> Result<Arc<dyn SigningBackend>, BrokerIntegrationError> {
    if let Some(existing) = canonical.as_ref() {
        if !Arc::ptr_eq(existing, candidate) {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "production active-defense signer changed after its evidence authority was retained"
                    .to_string(),
            ));
        }
        return Ok(Arc::clone(existing));
    }
    let retained = Arc::clone(candidate);
    *canonical = Some(Arc::clone(&retained));
    Ok(retained)
}

fn install_active_response_submission_authority_before_publication(
    kernel: &mut ChioKernel,
    authority: &PublicKey,
) -> Result<(), BrokerIntegrationError> {
    kernel
        .set_active_response_submission_authority(authority.clone())
        .map_err(|error| {
            BrokerIntegrationError::InvalidConfiguration(format!(
                "active-response submission authority installation failed: {error}"
            ))
        })
}

fn ensure_active_response_submission_authority_is_pinned(
    kernel: &ChioKernel,
    authority: &PublicKey,
) -> Result<(), BrokerIntegrationError> {
    kernel
        .ensure_active_response_submission_authority_matches(authority)
        .map_err(|error| {
            BrokerIntegrationError::InvalidConfiguration(format!(
                "active-response submission authority validation failed: {error}"
            ))
        })
}

fn ensure_active_defense_signer_role_separation(
    signer: &PublicKey,
    disallowed_role_keys: &BTreeSet<String>,
) -> Result<(), BrokerIntegrationError> {
    if disallowed_role_keys.contains(&signer.to_hex()) {
        return Err(BrokerIntegrationError::InvalidConfiguration(
            "active-defense client and executor signer must be distinct from every configured authority, manifest, and governed admin signing role"
                .to_string(),
        ));
    }
    Ok(())
}

fn ensure_active_defense_executor_signer_matches_configured_key(
    signer: &Arc<dyn SigningBackend>,
    configured_key: &PublicKey,
) -> Result<(), BrokerIntegrationError> {
    if &signer.public_key() != configured_key
        || signer.algorithm() != configured_key.algorithm()
    {
        return Err(BrokerIntegrationError::InvalidConfiguration(
            "active-defense executor signing key does not match its configured public key"
                .to_string(),
        ));
    }
    Ok(())
}

impl ProductionBrokerManifestRegistry {
    #[must_use]
    pub fn registry(&self) -> &Arc<VerifiedManifestRegistry> {
        &self.registry
    }
}

fn load_production_broker_migration_bindings(
    config: &ProductionBrokerMigrationConfig,
) -> Result<ProductionBrokerMigrationBindings, BrokerIntegrationError> {
    config.validate()?;
    prepare_private_database(
        &config.state_database_path,
        "enterprise migration state database",
    )?;
    let policy = SqliteEnterpriseMigrationOpenPolicy::new(
        config.trusted_transition_signers.clone(),
        config.minimum_heads.clone(),
    )
    .map_err(|error| {
        BrokerIntegrationError::InvalidConfiguration(format!(
            "enterprise migration open policy failed: {error}"
        ))
    })?;
    let concrete = Arc::new(
        SqliteEnterpriseMigrationStateStore::open(&config.state_database_path, policy).map_err(
            |error| {
                BrokerIntegrationError::InvalidConfiguration(format!(
                    "enterprise migration state database failed: {error}"
                ))
            },
        )?,
    );
    let store: Arc<dyn EnterpriseMigrationStateStore> = concrete;
    let mut providers = BTreeMap::new();
    for provider in &config.providers {
        let key = |control| EnterpriseMigrationKey {
            deployment_id: config.deployment_id.clone(),
            scope_kind: EnterpriseMigrationScopeKind::Provider,
            scope_id: provider.credential_provider.clone(),
            control,
        };
        let credential_key = key(EnterpriseMigrationControl::BrokerCredentialCustody);
        let quota_key = key(EnterpriseMigrationControl::BrokerQuotaEnforcement);
        let credential_posture = production_broker_migration_posture_digest(
            &config.deployment_id,
            &provider.credential_provider,
            credential_key.control,
            provider.credential_custody_stage,
        )?;
        let quota_posture = production_broker_migration_posture_digest(
            &config.deployment_id,
            &provider.credential_provider,
            quota_key.control,
            provider.quota_enforcement_stage,
        )?;
        let bindings = ProductionBrokerProviderMigrationBindings {
            credential_custody: EnterpriseMigrationRuntimeBinding::load(
                &store,
                &credential_key,
                provider.credential_custody_stage,
                credential_posture,
            )
            .map_err(|error| {
                BrokerIntegrationError::InvalidConfiguration(format!(
                    "broker credential-custody migration binding failed: {error}"
                ))
            })?,
            quota_enforcement: EnterpriseMigrationRuntimeBinding::load(
                &store,
                &quota_key,
                provider.quota_enforcement_stage,
                quota_posture,
            )
            .map_err(|error| {
                BrokerIntegrationError::InvalidConfiguration(format!(
                    "broker quota-enforcement migration binding failed: {error}"
                ))
            })?,
        };
        if providers
            .insert(provider.credential_provider.as_str().to_string(), bindings)
            .is_some()
        {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "duplicate production broker migration provider".to_string(),
            ));
        }
    }
    let bindings = ProductionBrokerMigrationBindings { providers };
    bindings.ensure_fail_closed()?;
    Ok(bindings)
}

fn production_broker_migration_posture_digest(
    deployment_id: &RecordId,
    credential_provider: &RecordId,
    control: EnterpriseMigrationControl,
    stage: EnterpriseMigrationStage,
) -> Result<Digest32, BrokerIntegrationError> {
    chio_secret_broker::migration::production_broker_migration_posture_digest(
        deployment_id,
        credential_provider,
        control,
        stage,
    )
    .map_err(BrokerIntegrationError::Broker)
}
