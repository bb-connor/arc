use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::{sha256_hex, PublicKey};
use chio_kernel::budget_store::{
    BudgetAdmissionOperationBinding, BudgetAuthorizeHoldDecision, BudgetCaptureInvocationRequest,
    BudgetEventAuthority, BudgetInvocationQuota, BudgetInvocationReservationState,
    BudgetQuotaProfile, BudgetStore,
};
use chio_kernel::supplemental_quota::{
    CanonicalRevocationSet, OpaqueSignedSupplementalQuota, SupplementalAdmissionAuthorization,
    SupplementalAdmissionPlan, SupplementalAdmissionPrepareRequest, SupplementalAdmissionRegistrar,
    SupplementalQuotaDestination, SupplementalQuotaError, SupplementalQuotaVerificationContext,
    SupplementalQuotaVerifier, VerifiedSupplementalQuotaClaimBody,
};
#[cfg(test)]
use chio_kernel::AdmissionOperationCompareAndSwap;
use chio_kernel::{
    AdmissionCaptureAuthority, AdmissionCaptureDecision, AdmissionCaptureError,
    AdmissionCaptureRequest, AdmissionCaptureRequestInput, AdmissionDispatchState,
    AdmissionOperation, AdmissionOperationError, AdmissionOperationKind, AdmissionOperationState,
    AdmissionOperationStore, BudgetStoreError, RevocationStore,
};
use chio_secret_broker::authority_ipc::{
    AuthorityControlRequest, AuthorityOperation, AuthorityResult, BrokerAuthorityHandler,
};
use chio_secret_broker::budget::{
    canonicalize_quotas, AuthorizeExecutionHoldRequest, BrokerExecutionBudget,
    CaptureExecutionHoldRequest, CombinedCaptureCommit, ExecutionAuthorityCapabilities,
    ExecutionAuthorityProfile, ExecutionHoldState, ExecutionQuota, QueryExecutionHoldRequest,
    ReverseExecutionHoldRequest,
};
use chio_secret_broker::capability::{capability_digest, verify_capability};
use chio_secret_broker::ipc_client::BrokerIpcClient;
use chio_secret_broker::proof::proof_digest;
use chio_secret_broker::protocol::{BrokerExecuteRequest, SignedBrokerCapability};
use chio_secret_broker::provision::GovernedAdminAuthorizer;
use chio_secret_broker::receipt::SqliteBrokerReceiptSink;
use chio_secret_broker::registration::{
    broker_execute_request_registration_digest, prepared_dispatch_id,
    PrepareDispatchAcknowledgement, RegisterAttemptAcknowledgement, ReleaseAttemptAcknowledgement,
};
use chio_secret_broker::revocation::{BrokerRevocations, CapabilityLiveness};
use chio_secret_broker::service::{broker_request_digest, TrustedExecutionContext};
use chio_secret_broker::store::{
    derive_attempt_ids, derive_attempt_ids_for_operation, AttemptIds, AttemptRegistration,
};
use chio_secret_broker::{BrokerError, Result as BrokerResult};
use chio_store_sqlite::budget_store::{
    SqliteAggregateFamilyEvidence, SqliteCompositeAuthorizeInput,
};
use chio_store_sqlite::{
    SqliteAdmissionCaptureAuthority, SqliteAdmissionOperationStore, SqliteBudgetStore,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};

const BROKER_CONSTRAINT_DIGEST_DOMAIN: &[u8] = b"chio.broker-request-constraints.v1\0";
const BROKER_AUTHORITY_METADATA_DOMAIN: &[u8] = b"chio.broker-authority-metadata.v1\0";
const KERNEL_QUOTA_ID_DOMAIN: &[u8] = b"chio.broker-kernel-quota-id.v1\0";

#[derive(Debug, thiserror::Error)]
pub enum BrokerIntegrationError {
    #[error("invalid broker integration configuration: {0}")]
    InvalidConfiguration(String),
    #[error("missing required broker runtime component: {0}")]
    MissingComponent(&'static str),
    #[error("broker integration state conflict: {0}")]
    Conflict(String),
    #[error(transparent)]
    Broker(#[from] BrokerError),
    #[error(transparent)]
    Budget(#[from] BudgetStoreError),
    #[error(transparent)]
    Capture(#[from] AdmissionCaptureError),
    #[error(transparent)]
    AdmissionOperation(#[from] AdmissionOperationError),
    #[error("durable broker admission registry failed: {0}")]
    Registry(String),
    #[error("kernel admission composition failed: {0}")]
    Kernel(#[from] chio_kernel::KernelError),
}

/// Security-module-owned migration gate. Production construction supplies the
/// signed, externally anchored ledger implementation; unit tests use the
/// test-only implementation in this module.
pub(super) trait BrokerMigrationEnforcer: Send + Sync {
    fn require_provider_enforced(&self, credential_provider: &str) -> BrokerResult<()>;
}

#[cfg(test)]
pub(super) struct TestBrokerMigrationEnforcer {
    providers: std::collections::BTreeSet<String>,
}

#[cfg(test)]
impl TestBrokerMigrationEnforcer {
    pub(super) fn new(providers: impl IntoIterator<Item = String>) -> Arc<Self> {
        Arc::new(Self {
            providers: providers.into_iter().collect(),
        })
    }
}

#[cfg(test)]
impl BrokerMigrationEnforcer for TestBrokerMigrationEnforcer {
    fn require_provider_enforced(&self, credential_provider: &str) -> BrokerResult<()> {
        if self.providers.contains(credential_provider) {
            Ok(())
        } else {
            Err(BrokerError::AuthorizationDenied(
                "credential provider has no test migration binding".to_string(),
            ))
        }
    }
}

#[derive(Debug, Clone)]
pub struct BrokerSupplementalQuotaVerifier {
    trusted_issuer: PublicKey,
    audience: String,
    broker_destination: SupplementalQuotaDestination,
    production: bool,
    verifier_id: String,
}

impl BrokerSupplementalQuotaVerifier {
    pub fn new(
        trusted_issuer: PublicKey,
        audience: String,
        broker_destination: SupplementalQuotaDestination,
        production: bool,
        verifier_id: String,
    ) -> Result<Self, BrokerIntegrationError> {
        validate_identifier(&audience, "broker audience")?;
        validate_identifier(&verifier_id, "supplemental verifier id")?;
        if production && verifier_id.contains("test") {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "production supplemental verifier ID cannot identify a test verifier".to_string(),
            ));
        }
        Ok(Self {
            trusted_issuer,
            audience,
            broker_destination,
            production,
            verifier_id,
        })
    }

    pub fn verifier_id(&self) -> &str {
        &self.verifier_id
    }

    pub fn broker_destination(&self) -> &SupplementalQuotaDestination {
        &self.broker_destination
    }

    fn decode_and_verify(
        &self,
        artifact: &OpaqueSignedSupplementalQuota,
        context: &SupplementalQuotaVerificationContext,
    ) -> Result<SignedBrokerCapability, SupplementalQuotaError> {
        let capability: SignedBrokerCapability = serde_json::from_slice(artifact.as_bytes())
            .map_err(|error| {
                SupplementalQuotaError::Verification(format!(
                    "broker capability decoding failed: {error}"
                ))
            })?;
        let canonical = canonical_json_bytes(&capability).map_err(|error| {
            SupplementalQuotaError::Canonicalization(format!(
                "broker capability encoding failed: {error}"
            ))
        })?;
        if canonical != artifact.as_bytes() {
            return Err(SupplementalQuotaError::Verification(
                "broker capability artifact is not canonical JSON".to_string(),
            ));
        }
        verify_capability(
            &capability,
            &self.trusted_issuer,
            &self.audience,
            context.now,
            self.production,
        )
        .map_err(|error| SupplementalQuotaError::Verification(error.to_string()))?;
        if capability.body.parent_capability_id != context.capability_id
            || capability.body.subject != context.subject
            || context.destination != self.broker_destination
        {
            return Err(SupplementalQuotaError::ContextMismatch(
                "broker parent, subject, or mediated destination".to_string(),
            ));
        }
        Ok(capability)
    }
}

impl SupplementalQuotaVerifier for BrokerSupplementalQuotaVerifier {
    fn verifier_id(&self) -> &str {
        &self.verifier_id
    }

    fn verify(
        &self,
        artifact: &OpaqueSignedSupplementalQuota,
        context: &SupplementalQuotaVerificationContext,
    ) -> Result<VerifiedSupplementalQuotaClaimBody, SupplementalQuotaError> {
        let capability = self.decode_and_verify(artifact, context)?;
        let request_constraint_digest = broker_constraint_digest(&capability)?;
        let negotiated_features_digest = sha256_hex(
            &canonical_json_bytes(&context.negotiated_features).map_err(|error| {
                SupplementalQuotaError::Canonicalization(format!(
                    "negotiated feature encoding failed: {error}"
                ))
            })?,
        );
        let mut supplemental_revocation_ids = vec![
            capability.body.capability_id.clone(),
            capability.body.revocation_id.clone(),
        ];
        supplemental_revocation_ids
            .sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        Ok(VerifiedSupplementalQuotaClaimBody {
            capability_id: context.capability_id.clone(),
            capability_digest: context.capability_digest.clone(),
            subject: context.subject.clone(),
            request_id: context.request_id.clone(),
            destination: context.destination.clone(),
            arguments_digest: context.arguments_digest.clone(),
            request_binding_hash: context.request_binding_hash.clone(),
            not_before: capability.body.not_before_unix_seconds,
            expires_at: capability.body.expires_at_unix_seconds,
            broker_capability_id: capability.body.capability_id,
            issuer: capability.body.issuer,
            request_constraint_digest,
            max_invocations: capability.body.maximum_executions,
            supplemental_revocation_ids,
            artifact_digest: artifact.digest(),
            negotiated_features_digest,
            profile: BudgetQuotaProfile::SupplementalBrokerExecution,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BrokerConstraintDigestBody<'a> {
    credential: &'a chio_secret_broker::protocol::CredentialRef,
    provider_adapter_id: &'a str,
    provider_adapter_version: u32,
    destination: &'a chio_secret_broker::protocol::BrokerDestination,
    constraints: &'a chio_secret_broker::protocol::RequestConstraints,
    proof: &'a chio_secret_broker::protocol::ProofBinding,
    consumption: chio_secret_broker::protocol::AttemptConsumption,
}

fn broker_constraint_digest(
    capability: &SignedBrokerCapability,
) -> Result<String, SupplementalQuotaError> {
    let canonical = canonical_json_bytes(&BrokerConstraintDigestBody {
        credential: &capability.body.credential,
        provider_adapter_id: &capability.body.provider_adapter_id,
        provider_adapter_version: capability.body.provider_adapter_version,
        destination: &capability.body.destination,
        constraints: &capability.body.constraints,
        proof: &capability.body.proof,
        consumption: capability.body.consumption,
    })
    .map_err(|error| {
        SupplementalQuotaError::Canonicalization(format!(
            "broker request constraint encoding failed: {error}"
        ))
    })?;
    let mut bytes = Vec::with_capacity(BROKER_CONSTRAINT_DIGEST_DOMAIN.len() + canonical.len());
    bytes.extend_from_slice(BROKER_CONSTRAINT_DIGEST_DOMAIN);
    bytes.extend_from_slice(&canonical);
    Ok(sha256_hex(&bytes))
}

#[derive(Debug, Clone)]
pub struct AuthoritativeBrokerExecutionConfig {
    pub revocation_authority_domain: String,
    pub supplemental_verifier_id: String,
    pub maximum_pending_admissions: usize,
}

impl AuthoritativeBrokerExecutionConfig {
    fn validate(&self) -> Result<(), BrokerIntegrationError> {
        validate_identifier(
            &self.revocation_authority_domain,
            "revocation authority domain",
        )?;
        validate_identifier(&self.supplemental_verifier_id, "supplemental verifier id")?;
        if self.maximum_pending_admissions == 0 || self.maximum_pending_admissions > 65_536 {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "pending broker admission capacity is invalid".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PreparedBrokerAdmission {
    registration_digest: String,
    ids: AttemptIds,
    admission_operation_id: String,
    broker_capability_id: String,
    invocation_id: String,
    authorization: SqliteCompositeAuthorizeInput,
    aggregate_family_evidence: Option<SqliteAggregateFamilyEvidence>,
    trusted_context: TrustedExecutionContext,
    reverse_event_id: String,
    capture_event_id: String,
    last_observed_revocation_index: Option<u64>,
    registration: AttemptRegistration,
    request: BrokerExecuteRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DurablePreparedBrokerAdmission {
    schema: String,
    registration_digest: String,
    trusted_context: TrustedExecutionContext,
    last_observed_revocation_index: Option<u64>,
    registration: AttemptRegistration,
    request: BrokerExecuteRequest,
}

impl PreparedBrokerAdmission {
    fn durable(&self) -> DurablePreparedBrokerAdmission {
        DurablePreparedBrokerAdmission {
            schema: "chio.broker-pending-admission.v1".to_string(),
            registration_digest: self.registration_digest.clone(),
            trusted_context: self.trusted_context.clone(),
            last_observed_revocation_index: self.last_observed_revocation_index,
            registration: self.registration.clone(),
            request: self.request.clone(),
        }
    }
}

struct BrokerPendingAdmissionRegistry {
    connection: Mutex<Connection>,
}

impl BrokerPendingAdmissionRegistry {
    fn open(path: &Path) -> Result<Self, BrokerIntegrationError> {
        let connection = Connection::open(path).map_err(registry_error)?;
        connection
            .execute_batch(
                r#"
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = FULL;
                PRAGMA busy_timeout = 5000;

                CREATE TABLE IF NOT EXISTS broker_pending_admissions (
                    operation_id TEXT PRIMARY KEY,
                    attempt_id TEXT NOT NULL UNIQUE,
                    canonical_body BLOB NOT NULL,
                    body_sha256 TEXT NOT NULL
                );
                "#,
            )
            .map_err(registry_error)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>, BrokerIntegrationError> {
        self.connection.lock().map_err(|_| {
            BrokerIntegrationError::Registry(
                "pending admission registry lock is poisoned".to_string(),
            )
        })
    }

    fn insert(
        &self,
        admission: &DurablePreparedBrokerAdmission,
        capacity: usize,
    ) -> Result<(), BrokerIntegrationError> {
        validate_durable_admission(admission)?;
        let canonical = canonical_json_bytes(admission).map_err(|error| {
            BrokerIntegrationError::Registry(format!("pending admission encoding failed: {error}"))
        })?;
        let digest = sha256_hex(&canonical);
        let operation_id = admission.registration.ids.operation_id.as_str();
        let attempt_id = admission.registration.ids.attempt_id.as_str();
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(registry_error)?;
        if let Some(existing) = load_registry_admission_by_operation(&transaction, operation_id)? {
            transaction.rollback().map_err(registry_error)?;
            if existing == *admission {
                return Ok(());
            }
            return Err(BrokerIntegrationError::Conflict(
                "kernel admission operation ID was reused for different broker input".to_string(),
            ));
        }
        if load_registry_admission_by_attempt(&transaction, attempt_id)?.is_some() {
            transaction.rollback().map_err(registry_error)?;
            return Err(BrokerIntegrationError::Conflict(
                "broker attempt ID was reused by a different kernel operation".to_string(),
            ));
        }
        let count: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM broker_pending_admissions",
                [],
                |row| row.get(0),
            )
            .map_err(registry_error)?;
        let count = usize::try_from(count).map_err(|_| {
            BrokerIntegrationError::Registry(
                "pending admission registry returned a negative row count".to_string(),
            )
        })?;
        if count >= capacity {
            transaction.rollback().map_err(registry_error)?;
            return Err(BrokerIntegrationError::Conflict(
                "pending broker admission registry is at capacity".to_string(),
            ));
        }
        transaction
            .execute(
                r#"
                INSERT INTO broker_pending_admissions (
                    operation_id, attempt_id, canonical_body, body_sha256
                ) VALUES (?1, ?2, ?3, ?4)
                "#,
                params![operation_id, attempt_id, canonical, digest],
            )
            .map_err(registry_error)?;
        transaction.commit().map_err(registry_error)?;
        Ok(())
    }

    fn load_by_operation(
        &self,
        operation_id: &str,
    ) -> Result<Option<DurablePreparedBrokerAdmission>, BrokerIntegrationError> {
        let connection = self.connection()?;
        load_registry_admission_by_operation(&connection, operation_id)
    }

    fn load_by_attempt(
        &self,
        attempt_id: &str,
    ) -> Result<Option<DurablePreparedBrokerAdmission>, BrokerIntegrationError> {
        let connection = self.connection()?;
        load_registry_admission_by_attempt(&connection, attempt_id)
    }

    fn operation_ids(&self) -> Result<Vec<String>, BrokerIntegrationError> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare("SELECT operation_id FROM broker_pending_admissions ORDER BY operation_id")
            .map_err(registry_error)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(registry_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(registry_error)
    }

    fn remove(&self, operation_id: &str) -> Result<bool, BrokerIntegrationError> {
        let connection = self.connection()?;
        let removed = connection
            .execute(
                "DELETE FROM broker_pending_admissions WHERE operation_id = ?1",
                params![operation_id],
            )
            .map_err(registry_error)?;
        Ok(removed == 1)
    }
}

fn load_registry_admission_by_operation(
    connection: &Connection,
    operation_id: &str,
) -> Result<Option<DurablePreparedBrokerAdmission>, BrokerIntegrationError> {
    connection
        .query_row(
            r#"
            SELECT operation_id, attempt_id, canonical_body, body_sha256
            FROM broker_pending_admissions
            WHERE operation_id = ?1
            "#,
            params![operation_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()
        .map_err(registry_error)?
        .map(|row| decode_registry_admission(row.0, row.1, row.2, row.3))
        .transpose()
}

fn load_registry_admission_by_attempt(
    connection: &Connection,
    attempt_id: &str,
) -> Result<Option<DurablePreparedBrokerAdmission>, BrokerIntegrationError> {
    connection
        .query_row(
            r#"
            SELECT operation_id, attempt_id, canonical_body, body_sha256
            FROM broker_pending_admissions
            WHERE attempt_id = ?1
            "#,
            params![attempt_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()
        .map_err(registry_error)?
        .map(|row| decode_registry_admission(row.0, row.1, row.2, row.3))
        .transpose()
}

fn decode_registry_admission(
    operation_id: String,
    attempt_id: String,
    canonical: Vec<u8>,
    digest: String,
) -> Result<DurablePreparedBrokerAdmission, BrokerIntegrationError> {
    if sha256_hex(&canonical) != digest {
        return Err(BrokerIntegrationError::Registry(
            "pending admission body digest does not match durable bytes".to_string(),
        ));
    }
    let admission: DurablePreparedBrokerAdmission =
        serde_json::from_slice(&canonical).map_err(|error| {
            BrokerIntegrationError::Registry(format!("pending admission decoding failed: {error}"))
        })?;
    let recanonical = canonical_json_bytes(&admission).map_err(|error| {
        BrokerIntegrationError::Registry(format!(
            "pending admission canonicalization failed: {error}"
        ))
    })?;
    if recanonical != canonical
        || admission.registration.ids.operation_id != operation_id
        || admission.registration.ids.attempt_id != attempt_id
    {
        return Err(BrokerIntegrationError::Registry(
            "pending admission row keys or canonical body are inconsistent".to_string(),
        ));
    }
    validate_durable_admission(&admission)?;
    Ok(admission)
}

fn validate_durable_admission(
    admission: &DurablePreparedBrokerAdmission,
) -> Result<(), BrokerIntegrationError> {
    if admission.schema != "chio.broker-pending-admission.v1" {
        return Err(BrokerIntegrationError::Registry(
            "pending admission schema is unsupported".to_string(),
        ));
    }
    validate_sha256_digest(
        &admission.registration_digest,
        "pending admission registration digest",
    )?;
    admission.registration.validate()?;
    admission.request.validate_bounds()?;
    let canonical_request = canonical_json_bytes(&admission.request).map_err(|error| {
        BrokerIntegrationError::Registry(format!(
            "pending admission request encoding failed: {error}"
        ))
    })?;
    if admission.registration_digest != sha256_hex(&canonical_request) {
        return Err(BrokerIntegrationError::Registry(
            "pending admission registration digest does not bind its canonical request".to_string(),
        ));
    }
    if admission.registration.request_canonical_digest
        != broker_execute_request_registration_digest(&admission.request)?
    {
        return Err(BrokerIntegrationError::Registry(
            "pending admission registration does not bind its canonical broker request".to_string(),
        ));
    }
    if admission.trusted_context.admission_operation_id != admission.registration.ids.operation_id
        || admission.trusted_context.quotas != admission.registration.quotas
        || admission.trusted_context.authority_metadata_digest
            != admission.registration.authority_metadata_digest
        || admission.trusted_context.revocation_authority_domain
            != admission.registration.revocation_authority_domain
        || admission.trusted_context.prepared_dispatch_id
            != prepared_dispatch_id(&admission.registration, &admission.request)?
    {
        return Err(BrokerIntegrationError::Registry(
            "pending admission trusted context diverges from its durable registration".to_string(),
        ));
    }
    Ok(())
}

fn validate_sha256_digest(value: &str, label: &str) -> Result<(), BrokerIntegrationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(BrokerIntegrationError::Registry(format!(
            "{label} must be lowercase SHA-256 hex"
        )));
    }
    Ok(())
}

fn registry_error(error: rusqlite::Error) -> BrokerIntegrationError {
    BrokerIntegrationError::Registry(error.to_string())
}

fn orphaned_pending_admission(operation_id: &str) -> BrokerIntegrationError {
    BrokerIntegrationError::Registry(format!(
        "orphaned pending broker admission has no durable kernel operation: {operation_id}"
    ))
}

pub trait BrokerAttemptRegistrationPort: Send + Sync {
    fn register_attempt(
        &self,
        registration: &AttemptRegistration,
        request: &BrokerExecuteRequest,
    ) -> BrokerResult<RegisterAttemptAcknowledgement>;

    fn prepare_dispatch(
        &self,
        registration: &AttemptRegistration,
        request: &BrokerExecuteRequest,
    ) -> BrokerResult<PrepareDispatchAcknowledgement>;

    fn release_attempt(
        &self,
        registration: &AttemptRegistration,
        request: &BrokerExecuteRequest,
    ) -> BrokerResult<ReleaseAttemptAcknowledgement>;
}

impl BrokerAttemptRegistrationPort for BrokerIpcClient {
    fn register_attempt(
        &self,
        registration: &AttemptRegistration,
        request: &BrokerExecuteRequest,
    ) -> BrokerResult<RegisterAttemptAcknowledgement> {
        BrokerIpcClient::register_attempt(self, registration, request)
    }

    fn prepare_dispatch(
        &self,
        registration: &AttemptRegistration,
        request: &BrokerExecuteRequest,
    ) -> BrokerResult<PrepareDispatchAcknowledgement> {
        BrokerIpcClient::prepare_dispatch(self, registration, request)
    }

    fn release_attempt(
        &self,
        registration: &AttemptRegistration,
        request: &BrokerExecuteRequest,
    ) -> BrokerResult<ReleaseAttemptAcknowledgement> {
        BrokerIpcClient::release_attempt(self, registration, request)
    }
}

pub struct AuthoritativeBrokerExecutionAdapter {
    budget: Arc<SqliteBudgetStore>,
    capture: Arc<SqliteAdmissionCaptureAuthority>,
    admission_operations: Arc<dyn AdmissionOperationStore>,
    attempt_registration: Arc<dyn BrokerAttemptRegistrationPort>,
    migration: Arc<dyn BrokerMigrationEnforcer>,
    config: AuthoritativeBrokerExecutionConfig,
    registry: BrokerPendingAdmissionRegistry,
}

impl AuthoritativeBrokerExecutionAdapter {
    pub(super) fn open(
        database_path: impl AsRef<Path>,
        admission_operation_database_path: impl AsRef<Path>,
        config: AuthoritativeBrokerExecutionConfig,
        attempt_registration: Arc<dyn BrokerAttemptRegistrationPort>,
        migration: Arc<dyn BrokerMigrationEnforcer>,
    ) -> Result<Self, BrokerIntegrationError> {
        config.validate()?;
        let database_path = database_path.as_ref();
        let budget = Arc::new(SqliteBudgetStore::open(database_path)?);
        let capture = Arc::new(SqliteAdmissionCaptureAuthority::open(database_path)?);
        let admission_operations = Arc::new(SqliteAdmissionOperationStore::open(
            admission_operation_database_path,
        )?);
        let registry = BrokerPendingAdmissionRegistry::open(database_path)?;
        let adapter = Self {
            budget,
            capture,
            admission_operations,
            attempt_registration,
            migration,
            config,
            registry,
        };
        adapter.prune_completed_registry()?;
        Ok(adapter)
    }

    fn prune_completed_registry(&self) -> Result<(), BrokerIntegrationError> {
        for operation_id in self.registry.operation_ids()? {
            let operation = self
                .admission_operations
                .load(&operation_id)?
                .ok_or_else(|| orphaned_pending_admission(&operation_id))?;
            if operation.state() == AdmissionOperationState::Completed {
                let _ = self.registry.remove(&operation_id)?;
            }
        }
        Ok(())
    }

    pub fn supplemental_verifier_id(&self) -> &str {
        &self.config.supplemental_verifier_id
    }

    pub fn budget_store(&self) -> Arc<dyn BudgetStore> {
        Arc::clone(&self.budget) as Arc<dyn BudgetStore>
    }

    pub fn admission_capture_authority(&self) -> Arc<dyn AdmissionCaptureAuthority> {
        Arc::clone(&self.capture) as Arc<dyn AdmissionCaptureAuthority>
    }

    pub fn revocation_store(&self) -> Arc<dyn RevocationStore> {
        Arc::clone(&self.capture) as Arc<dyn RevocationStore>
    }

    pub fn combined_authority(&self) -> Arc<SqliteAdmissionCaptureAuthority> {
        Arc::clone(&self.capture)
    }

    pub fn register_admission(
        &self,
        request: &BrokerExecuteRequest,
        admission_operation_id: &str,
        authorization: SqliteCompositeAuthorizeInput,
        aggregate_family_evidence: Option<SqliteAggregateFamilyEvidence>,
        source_receipt_ids: Vec<String>,
        last_observed_revocation_index: Option<u64>,
    ) -> Result<TrustedExecutionContext, BrokerIntegrationError> {
        self.require_migration_for_request(request)?;
        let prepared = self.prepare_admission(
            request,
            admission_operation_id,
            authorization,
            aggregate_family_evidence,
            source_receipt_ids,
            last_observed_revocation_index,
        )?;
        self.validate_operation_binding(&prepared, false)?;
        self.registry
            .insert(&prepared.durable(), self.config.maximum_pending_admissions)?;
        let acknowledgement = match self
            .attempt_registration
            .register_attempt(&prepared.registration, &prepared.request)
        {
            Ok(acknowledgement) => acknowledgement,
            // The registry row is the durable release outbox if broker
            // registration committed but its acknowledgement was lost. The
            // The kernel must first enter CompensationPending with its signed
            // terminal receipt staged; only then may release_admission
            // tombstone the broker attempt.
            Err(error) => return Err(BrokerIntegrationError::Broker(error)),
        };
        acknowledgement.validate_for(&prepared.registration)?;
        Ok(prepared.trusted_context)
    }

    pub fn prepare_dispatch(&self, operation_id: &str) -> Result<(), BrokerIntegrationError> {
        validate_identifier(operation_id, "broker operation id")?;
        let admission = self
            .registry
            .load_by_operation(operation_id)?
            .ok_or_else(|| {
                BrokerIntegrationError::Conflict(
                    "pre-dispatch broker preparation has no durable registration".to_string(),
                )
            })?;
        let operation = self
            .admission_operations
            .load(operation_id)?
            .ok_or_else(|| {
                BrokerIntegrationError::Conflict(
                    "pre-dispatch broker preparation has no durable kernel operation".to_string(),
                )
            })?;
        if operation.state() != AdmissionOperationState::ReadyToDispatch
            || operation.dispatch_state() != AdmissionDispatchState::NotStarted
            || operation.broker_attempt_id() != Some(admission.registration.ids.attempt_id.as_str())
        {
            return Err(BrokerIntegrationError::Conflict(
                "broker preparation requires the exact durable ReadyToDispatch operation"
                    .to_string(),
            ));
        }
        self.require_migration_for_request(&admission.request)?;
        let acknowledgement = self
            .attempt_registration
            .prepare_dispatch(&admission.registration, &admission.request)?;
        acknowledgement.validate_for(&admission.registration, &admission.request)?;
        if acknowledgement.prepared_dispatch_id != admission.trusted_context.prepared_dispatch_id {
            return Err(BrokerIntegrationError::Conflict(
                "broker preparation acknowledgement diverges from the durable operation binding"
                    .to_string(),
            ));
        }
        Ok(())
    }


    /// Drain only after the caller has authenticated live broker IPC. Opening
    /// the authority remains dial-free so broker-first and authority-first
    /// process startup cannot deadlock each other.
    pub fn drain_compensated_release_outbox(&self) -> Result<usize, BrokerIntegrationError> {
        let mut drained = 0usize;
        for operation_id in self.registry.operation_ids()? {
            let operation = self
                .admission_operations
                .load(&operation_id)?
                .ok_or_else(|| orphaned_pending_admission(&operation_id))?;
            match operation.state() {
                AdmissionOperationState::Completed => {
                    if self.registry.remove(&operation_id)? {
                        drained += 1;
                    }
                }
                AdmissionOperationState::CompensationPending
                | AdmissionOperationState::CompensatedBeforeDispatch => {
                    if self.release_admission(&operation_id)? {
                        drained += 1;
                    }
                }
                _ => {}
            }
        }
        Ok(drained)
    }

    pub fn finalize_admission(&self, operation_id: &str) -> Result<bool, BrokerIntegrationError> {
        validate_identifier(operation_id, "broker operation id")?;
        self.registry.remove(operation_id)
    }

    pub fn trusted_context_for(
        &self,
        request: &BrokerExecuteRequest,
    ) -> Result<TrustedExecutionContext, BrokerIntegrationError> {
        self.require_migration_for_request(request)?;
        request.validate_bounds()?;
        let request_digest = broker_request_digest(request)?;
        let provisional_ids = derive_attempt_ids(
            &request.capability.body.capability_id,
            &request.invocation_id,
            &request.proof.body.nonce,
            &request_digest,
        )?;
        let admission = self
            .registry
            .load_by_attempt(&provisional_ids.attempt_id)?
            .ok_or_else(|| {
                BrokerIntegrationError::Conflict(
                    "broker execution was not registered before authority RPC preparation"
                        .to_string(),
                )
            })?;
        let stored_authorization = self
            .budget
            .query_composite_authorization_input(&admission.registration.ids.authorize_event_id)?
            .ok_or_else(|| {
                BrokerIntegrationError::Conflict(
                    "broker execution has no durable kernel budget authorization".to_string(),
                )
            })?;
        let prepared = self.prepare_admission(
            request,
            &admission.registration.ids.operation_id,
            stored_authorization.authorization,
            stored_authorization.aggregate_family_evidence,
            admission.trusted_context.source_receipt_ids.clone(),
            admission.last_observed_revocation_index,
        )?;
        if prepared.durable() != admission {
            return Err(BrokerIntegrationError::Conflict(
                "broker authority preparation does not match the registered execution".to_string(),
            ));
        }
        self.validate_operation_binding(&prepared, true)?;
        let capture_request = Self::capture_request(&prepared)?;
        let decision = self
            .capture
            .query_admission_capture(&capture_request)?
            .ok_or_else(|| {
                BrokerIntegrationError::Conflict(
                    "dispatch-committed broker execution has no durable capture".to_string(),
                )
            })?;
        if !matches!(
            self.map_capture(&prepared, decision)?,
            ExecutionHoldState::Captured(_)
        ) {
            return Err(BrokerIntegrationError::Conflict(
                "dispatch-committed broker execution was not captured".to_string(),
            ));
        }
        Ok(prepared.trusted_context)
    }

    fn rehydrate_prepared(
        &self,
        admission: DurablePreparedBrokerAdmission,
    ) -> Result<Option<PreparedBrokerAdmission>, BrokerIntegrationError> {
        let Some(stored_authorization) = self
            .budget
            .query_composite_authorization_input(&admission.registration.ids.authorize_event_id)?
        else {
            return Ok(None);
        };
        let authorization = stored_authorization.authorization;
        let aggregate_family_evidence = stored_authorization.aggregate_family_evidence;
        if authorization.operation_id != admission.registration.ids.operation_id
            || authorization.capability_id != admission.registration.parent_capability_id
            || authorization.hold_id != admission.registration.ids.hold_id
            || authorization.event_id != admission.registration.ids.authorize_event_id
            || authorization.authority.is_none()
            || admission.trusted_context.admission_operation_id
                != admission.registration.ids.operation_id
            || admission.trusted_context.quotas != admission.registration.quotas
            || admission.trusted_context.authority_metadata_digest
                != admission.registration.authority_metadata_digest
            || admission.trusted_context.revocation_authority_domain
                != admission.registration.revocation_authority_domain
            || admission.trusted_context.prepared_dispatch_id
                != prepared_dispatch_id(&admission.registration, &admission.request)?
        {
            return Err(BrokerIntegrationError::Conflict(
                "durable broker registration diverges from kernel authorization".to_string(),
            ));
        }
        validate_internal_quotas(&authorization.invocation_quotas)?;
        validate_aggregate_family_evidence(
            &authorization.invocation_quotas,
            &authorization.revocation_set,
            aggregate_family_evidence.as_ref(),
        )?;
        authorization.revocation_set.validate().map_err(|error| {
            BrokerIntegrationError::InvalidConfiguration(format!(
                "persisted broker revocation set is invalid: {error}"
            ))
        })?;
        let expected_authority_digest = authority_metadata_digest(
            authorization.authority.as_ref().ok_or_else(|| {
                BrokerIntegrationError::Conflict(
                    "durable broker authorization omits its fenced authority".to_string(),
                )
            })?,
            &self.config,
            self.budget.as_ref(),
        )?;
        if expected_authority_digest != admission.trusted_context.authority_metadata_digest {
            return Err(BrokerIntegrationError::Conflict(
                "durable broker authority metadata changed across recovery".to_string(),
            ));
        }
        let ids = admission.registration.ids.clone();
        Ok(Some(PreparedBrokerAdmission {
            registration_digest: admission.registration_digest,
            ids: ids.clone(),
            admission_operation_id: ids.operation_id.clone(),
            broker_capability_id: admission.registration.broker_capability_id.clone(),
            invocation_id: admission.registration.invocation_id.clone(),
            authorization,
            aggregate_family_evidence,
            trusted_context: admission.trusted_context,
            reverse_event_id: ids.reverse_event_id.clone(),
            capture_event_id: ids.capture_event_id.clone(),
            last_observed_revocation_index: admission.last_observed_revocation_index,
            registration: admission.registration,
            request: admission.request,
        }))
    }

    fn validate_operation_binding(
        &self,
        prepared: &PreparedBrokerAdmission,
        require_dispatch_committed: bool,
    ) -> Result<AdmissionOperation, BrokerIntegrationError> {
        let operation = self
            .admission_operations
            .load(&prepared.admission_operation_id)?
            .ok_or_else(|| {
                BrokerIntegrationError::Conflict(
                    "broker registration has no durable kernel admission operation".to_string(),
                )
            })?;
        if operation.kind() != AdmissionOperationKind::ToolDispatch
            || operation.operation_id() != prepared.admission_operation_id
            || operation.broker_attempt_id() != Some(prepared.ids.attempt_id.as_str())
            || operation.budget_hold_id() != Some(prepared.authorization.hold_id.as_str())
            || operation.capability_id() != prepared.authorization.capability_id
            || operation.request_binding_hash() != prepared.authorization.request_binding_hash
        {
            return Err(BrokerIntegrationError::Conflict(
                "broker registration diverges from its durable kernel admission operation"
                    .to_string(),
            ));
        }
        if require_dispatch_committed
            && (operation.state() != AdmissionOperationState::DispatchCommitted
                || operation.dispatch_state() != AdmissionDispatchState::Committed)
        {
            return Err(BrokerIntegrationError::Conflict(format!(
                "broker network dispatch requires kernel DispatchCommitted, found {}",
                operation.state().as_str()
            )));
        }
        Ok(operation)
    }

    fn prepare_admission(
        &self,
        request: &BrokerExecuteRequest,
        admission_operation_id: &str,
        authorization: SqliteCompositeAuthorizeInput,
        aggregate_family_evidence: Option<SqliteAggregateFamilyEvidence>,
        source_receipt_ids: Vec<String>,
        last_observed_revocation_index: Option<u64>,
    ) -> Result<PreparedBrokerAdmission, BrokerIntegrationError> {
        self.require_migration_for_request(request)?;
        request.validate_bounds()?;
        validate_identifier(admission_operation_id, "admission operation id")?;
        BudgetAdmissionOperationBinding::new(
            authorization.operation_id.clone(),
            authorization.request_binding_hash.clone(),
        )
        .map_err(|error| BrokerIntegrationError::InvalidConfiguration(error.to_string()))?;
        request.capability.body.validate(true)?;
        let request_digest = broker_request_digest(request)?;
        let ids = derive_attempt_ids_for_operation(
            &request.capability.body.capability_id,
            &request.invocation_id,
            &request.proof.body.nonce,
            &request_digest,
            admission_operation_id,
        )?;
        if authorization.capability_id != request.capability.body.parent_capability_id
            || authorization.operation_id != admission_operation_id
            || authorization.hold_id != ids.hold_id
            || authorization.event_id != ids.authorize_event_id
            || authorization.authority.is_none()
        {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "prepared budget authorization does not match broker parent or deterministic IDs"
                    .to_string(),
            ));
        }
        validate_internal_quotas(&authorization.invocation_quotas)?;
        validate_aggregate_family_evidence(
            &authorization.invocation_quotas,
            &authorization.revocation_set,
            aggregate_family_evidence.as_ref(),
        )?;
        authorization.revocation_set.validate().map_err(|error| {
            BrokerIntegrationError::InvalidConfiguration(format!(
                "prepared revocation set is invalid: {error}"
            ))
        })?;
        for required in [
            &request.capability.body.parent_capability_id,
            &request.capability.body.capability_id,
            &request.capability.body.revocation_id,
        ] {
            if !authorization
                .revocation_set
                .ids()
                .iter()
                .any(|member| member == required)
            {
                return Err(BrokerIntegrationError::InvalidConfiguration(
                    "prepared revocation set omits a parent or broker authority member".to_string(),
                ));
            }
        }
        let artifact_digest = capability_digest(&request.capability)?;
        if authorization.authorization_artifact_digests != [artifact_digest.clone()] {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "prepared budget authorization is not bound to the broker capability artifact"
                    .to_string(),
            ));
        }
        let quotas = broker_quota_projection(
            &authorization.invocation_quotas,
            &request.capability.body.broker_quota_key_id,
            request.capability.body.maximum_executions,
        )?;
        let authority_metadata_digest = authority_metadata_digest(
            authorization.authority.as_ref().ok_or_else(|| {
                BrokerIntegrationError::InvalidConfiguration(
                    "prepared budget authorization omits its fenced authority".to_string(),
                )
            })?,
            &self.config,
            self.budget.as_ref(),
        )?;
        let registration_digest = sha256_hex(&canonical_json_bytes(request).map_err(|error| {
            BrokerIntegrationError::InvalidConfiguration(format!(
                "broker registration encoding failed: {error}"
            ))
        })?);
        let registration = Self::attempt_registration(
            request,
            &ids,
            &quotas,
            &authority_metadata_digest,
            &self.config.revocation_authority_domain,
        )?;
        let trusted_context = TrustedExecutionContext {
            admission_operation_id: admission_operation_id.to_string(),
            prepared_dispatch_id: prepared_dispatch_id(&registration, request)?,
            quotas,
            authority_metadata_digest,
            revocation_authority_domain: self.config.revocation_authority_domain.clone(),
            source_receipt_ids,
        };
        trusted_context.validate_for(request)?;
        Ok(PreparedBrokerAdmission {
            registration_digest,
            ids: ids.clone(),
            admission_operation_id: admission_operation_id.to_string(),
            broker_capability_id: request.capability.body.capability_id.clone(),
            invocation_id: request.invocation_id.clone(),
            authorization,
            aggregate_family_evidence,
            trusted_context,
            reverse_event_id: ids.reverse_event_id,
            capture_event_id: ids.capture_event_id,
            last_observed_revocation_index,
            registration,
            request: request.clone(),
        })
    }

    fn require_migration_for_request(
        &self,
        request: &BrokerExecuteRequest,
    ) -> Result<(), BrokerIntegrationError> {
        self.migration
            .require_provider_enforced(&request.capability.body.credential.provider)
            .map_err(BrokerIntegrationError::Broker)
    }

    fn attempt_registration(
        request: &BrokerExecuteRequest,
        ids: &AttemptIds,
        quotas: &[ExecutionQuota],
        authority_metadata_digest: &str,
        revocation_authority_domain: &str,
    ) -> Result<AttemptRegistration, BrokerIntegrationError> {
        let nonce_expires_at_unix_seconds = request
            .proof
            .body
            .issued_at_unix_seconds
            .checked_add(request.capability.body.proof.nonce_ttl_seconds)
            .ok_or_else(|| {
                BrokerIntegrationError::InvalidConfiguration(
                    "broker proof nonce expiry overflowed".to_string(),
                )
            })?;
        Ok(AttemptRegistration {
            ids: ids.clone(),
            invocation_id: request.invocation_id.clone(),
            parent_capability_id: request.capability.body.parent_capability_id.clone(),
            broker_capability_id: request.capability.body.capability_id.clone(),
            request_digest: broker_request_digest(request)?,
            request_canonical_digest: broker_execute_request_registration_digest(request)?,
            proof_digest: proof_digest(&request.proof)?,
            proof_key_id: request.proof.body.authority_key.to_hex(),
            proof_nonce: request.proof.body.nonce.clone(),
            nonce_expires_at_unix_seconds,
            quotas: quotas.to_vec(),
            authority_metadata_digest: authority_metadata_digest.to_string(),
            revocation_authority_domain: revocation_authority_domain.to_string(),
        })
    }

    fn prepared_for_authorize(
        &self,
        request: &AuthorizeExecutionHoldRequest,
    ) -> BrokerResult<Option<PreparedBrokerAdmission>> {
        request.validate()?;
        let admission = self
            .registry
            .load_by_operation(&request.operation_id)
            .map_err(integration_as_broker)?
            .ok_or_else(|| {
                BrokerError::AuthorityUnavailable(
                    "broker budget admission was not registered by the trusted kernel flow"
                        .to_string(),
                )
            })?;
        if request.invocation_id != admission.registration.invocation_id
            || request.parent_capability_id != admission.registration.parent_capability_id
            || request.broker_capability_id != admission.registration.broker_capability_id
            || request.hold_id != admission.registration.ids.hold_id
            || request.authorize_event_id != admission.registration.ids.authorize_event_id
            || request.quotas != admission.trusted_context.quotas
            || request.authority_metadata_digest
                != admission.trusted_context.authority_metadata_digest
        {
            return Err(BrokerError::AuthorizationDenied(
                "broker hold authorization does not match the trusted prepared admission"
                    .to_string(),
            ));
        }
        self.rehydrate_prepared(admission)
            .map_err(integration_as_broker)
    }

    fn prepared_for_query(
        &self,
        request: &QueryExecutionHoldRequest,
    ) -> BrokerResult<Option<PreparedBrokerAdmission>> {
        request.validate()?;
        let admission = self
            .registry
            .load_by_operation(&request.operation_id)
            .map_err(integration_as_broker)?
            .ok_or_else(|| {
                BrokerError::AuthorityUnavailable(
                    "broker budget query has no trusted prepared admission".to_string(),
                )
            })?;
        if request.invocation_id != admission.registration.invocation_id
            || request.parent_capability_id != admission.registration.parent_capability_id
            || request.broker_capability_id != admission.registration.broker_capability_id
            || request.hold_id != admission.registration.ids.hold_id
            || request.authorize_event_id != admission.registration.ids.authorize_event_id
            || request.reverse_event_id != admission.registration.ids.reverse_event_id
            || request.capture_event_id != admission.registration.ids.capture_event_id
        {
            return Err(BrokerError::AuthorizationDenied(
                "broker hold query does not match the trusted prepared admission".to_string(),
            ));
        }
        self.rehydrate_prepared(admission)
            .map_err(integration_as_broker)
    }

    fn capture_request(
        prepared: &PreparedBrokerAdmission,
    ) -> BrokerResult<AdmissionCaptureRequest> {
        AdmissionCaptureRequest::new(AdmissionCaptureRequestInput {
            operation_id: prepared.admission_operation_id.clone(),
            budget: BudgetCaptureInvocationRequest {
                admission_operation: Some(
                    BudgetAdmissionOperationBinding::new(
                        prepared.admission_operation_id.clone(),
                        prepared.authorization.request_binding_hash.clone(),
                    )
                    .map_err(budget_as_broker)?,
                ),
                capability_id: prepared.authorization.capability_id.clone(),
                grant_index: prepared.authorization.grant_index,
                hold_id: Some(prepared.authorization.hold_id.clone()),
                event_id: Some(prepared.capture_event_id.clone()),
                authority: prepared.authorization.authority.clone(),
            },
            revocation_set: prepared.authorization.revocation_set.clone(),
            bound_revocation_set_digest: prepared
                .authorization
                .revocation_set
                .digest()
                .to_string(),
            authorization_artifact_digests: prepared
                .authorization
                .authorization_artifact_digests
                .clone(),
            aggregate_root_capability_id: prepared
                .aggregate_family_evidence
                .as_ref()
                .map(|evidence| evidence.root_capability_id.clone()),
            aggregate_root_binding_digest: prepared
                .aggregate_family_evidence
                .as_ref()
                .map(|evidence| evidence.root_binding_digest.clone()),
            last_observed_revocation_index: prepared.last_observed_revocation_index,
        })
        .map_err(|error| {
            BrokerError::Invariant(format!("admission capture request failed: {error}"))
        })
    }

    fn map_authorization(
        &self,
        prepared: &PreparedBrokerAdmission,
        decision: BudgetAuthorizeHoldDecision,
    ) -> BrokerResult<ExecutionHoldState> {
        let (allowed, hold_id, invocation_state, revocation_set, metadata, usages) = match decision
        {
            BudgetAuthorizeHoldDecision::Authorized(authorized) => (
                true,
                authorized.hold_id,
                authorized.invocation_state,
                authorized.revocation_set,
                authorized.metadata,
                authorized.invocation_counts_after,
            ),
            BudgetAuthorizeHoldDecision::Denied(denied) => (
                false,
                denied.hold_id,
                denied.invocation_state,
                denied.revocation_set,
                denied.metadata,
                denied.invocation_counts_after,
            ),
        };
        if hold_id.as_deref() != Some(prepared.authorization.hold_id.as_str())
            || metadata.event_id.as_deref() != Some(prepared.authorization.event_id.as_str())
            || metadata.authority != prepared.authorization.authority
            || revocation_set.as_ref() != Some(&prepared.authorization.revocation_set)
            || usages
                .iter()
                .map(|usage| &usage.quota)
                .ne(prepared.authorization.invocation_quotas.iter())
            || (allowed && invocation_state != BudgetInvocationReservationState::Authorized)
            || (!allowed && invocation_state != BudgetInvocationReservationState::Denied)
        {
            return Err(BrokerError::Invariant(
                "persisted composite authorization diverges from the prepared admission"
                    .to_string(),
            ));
        }
        Ok(if allowed {
            ExecutionHoldState::Held
        } else {
            ExecutionHoldState::Denied
        })
    }

    fn map_capture(
        &self,
        prepared: &PreparedBrokerAdmission,
        decision: AdmissionCaptureDecision,
    ) -> BrokerResult<ExecutionHoldState> {
        match decision {
            AdmissionCaptureDecision::Denied(denial) => {
                if denial.metadata().operation_id() != prepared.admission_operation_id
                    || denial.metadata().checked_revocation_set_digest()
                        != prepared.authorization.revocation_set.digest()
                {
                    return Err(BrokerError::Invariant(
                        "revoked capture denial diverges from the prepared admission".to_string(),
                    ));
                }
                Ok(ExecutionHoldState::Denied)
            }
            AdmissionCaptureDecision::Captured { budget, metadata } => {
                let budget_commit_index =
                    metadata
                        .budget_commit()
                        .budget_commit_index
                        .ok_or_else(|| {
                            BrokerError::Invariant(
                                "combined capture omitted its budget commit index".to_string(),
                            )
                        })?;
                let leader_epoch = metadata
                    .budget_commit()
                    .authority
                    .as_ref()
                    .map(|authority| authority.lease_epoch)
                    .ok_or_else(|| {
                        BrokerError::Invariant(
                            "combined capture omitted its fenced authority".to_string(),
                        )
                    })?;
                if metadata.operation_id() != prepared.admission_operation_id
                    || metadata.checked_revocation_set_digest()
                        != prepared.authorization.revocation_set.digest()
                    || budget.hold_id.as_deref() != Some(prepared.authorization.hold_id.as_str())
                    || budget.invocation_state != BudgetInvocationReservationState::Captured
                    || budget.revocation_set.as_ref()
                        != Some(&prepared.authorization.revocation_set)
                    || budget.metadata.event_id.as_deref()
                        != Some(prepared.capture_event_id.as_str())
                    || budget.metadata.authority != prepared.authorization.authority
                {
                    return Err(BrokerError::Invariant(
                        "combined capture diverges from the prepared admission".to_string(),
                    ));
                }
                Ok(ExecutionHoldState::Captured(CombinedCaptureCommit {
                    checked_revocation_set_digest: metadata
                        .checked_revocation_set_digest()
                        .to_string(),
                    budget_commit_index,
                    revocation_commit_index: metadata.revocation_commit_index(),
                    authority_commit_index: metadata.authority_commit_index(),
                    leader_epoch,
                }))
            }
        }
    }
}

impl SupplementalAdmissionRegistrar for AuthoritativeBrokerExecutionAdapter {
    fn prepare_admission(
        &self,
        request: SupplementalAdmissionPrepareRequest<'_>,
    ) -> Result<SupplementalAdmissionPlan, SupplementalQuotaError> {
        let broker_request: BrokerExecuteRequest =
            serde_json::from_value(request.arguments.clone()).map_err(|error| {
                SupplementalQuotaError::Verification(format!(
                    "broker execution request decoding failed: {error}"
                ))
            })?;
        broker_request
            .validate_bounds()
            .map_err(|error| SupplementalQuotaError::Verification(error.to_string()))?;
        self.migration
            .require_provider_enforced(&broker_request.capability.body.credential.provider)
            .map_err(|error| SupplementalQuotaError::Verification(error.to_string()))?;
        if broker_request.capability.body.parent_capability_id != request.capability_id {
            return Err(SupplementalQuotaError::ContextMismatch(
                "broker parent capability".to_string(),
            ));
        }
        let canonical_capability = canonical_json_bytes(&broker_request.capability)
            .map_err(|error| SupplementalQuotaError::Canonicalization(error.to_string()))?;
        if canonical_capability != request.authorization_artifact.as_bytes() {
            return Err(SupplementalQuotaError::ContextMismatch(
                "broker capability artifact".to_string(),
            ));
        }
        let request_digest = broker_request_digest(&broker_request)
            .map_err(|error| SupplementalQuotaError::Verification(error.to_string()))?;
        let ids = derive_attempt_ids(
            &broker_request.capability.body.capability_id,
            &broker_request.invocation_id,
            &broker_request.proof.body.nonce,
            &request_digest,
        )
        .map_err(|error| SupplementalQuotaError::Verification(error.to_string()))?;
        let registration_payload = canonical_json_bytes(&broker_request)
            .map_err(|error| SupplementalQuotaError::Canonicalization(error.to_string()))?;
        SupplementalAdmissionPlan::new(
            ids.attempt_id,
            ids.hold_id,
            ids.authorize_event_id,
            ids.reverse_event_id,
            ids.capture_event_id,
            registration_payload,
        )
    }

    fn register_admission(
        &self,
        plan: &SupplementalAdmissionPlan,
        authorization: SupplementalAdmissionAuthorization<'_>,
    ) -> Result<(), SupplementalQuotaError> {
        let broker_request: BrokerExecuteRequest =
            serde_json::from_slice(plan.registration_payload()).map_err(|error| {
                SupplementalQuotaError::Verification(format!(
                    "broker registration payload decoding failed: {error}"
                ))
            })?;
        let budget = authorization.budget_request();
        let evidence = budget.invocation_admission_evidence().ok_or_else(|| {
            SupplementalQuotaError::Verification(
                "kernel registration omitted verified invocation admission".to_string(),
            )
        })?;
        let artifact_digest = evidence.supplemental_artifact_digest().ok_or_else(|| {
            SupplementalQuotaError::Verification(
                "kernel registration omitted supplemental artifact binding".to_string(),
            )
        })?;
        let aggregate_family_evidence = match (
            evidence.aggregate_root_capability_id(),
            evidence.aggregate_binding_digest(),
        ) {
            (Some(root_capability_id), Some(root_binding_digest)) => {
                Some(SqliteAggregateFamilyEvidence {
                    root_capability_id: root_capability_id.to_string(),
                    root_binding_digest: root_binding_digest.to_string(),
                })
            }
            (None, None) => None,
            _ => {
                return Err(SupplementalQuotaError::Verification(
                    "kernel registration supplied incomplete aggregate family evidence".to_string(),
                ));
            }
        };
        let revocation_set = budget.revocation_set().cloned().ok_or_else(|| {
            SupplementalQuotaError::Verification(
                "kernel registration omitted canonical revocation set".to_string(),
            )
        })?;
        let admission_operation = budget.admission_operation.as_ref().ok_or_else(|| {
            SupplementalQuotaError::Verification(
                "kernel registration omitted admission operation ownership".to_string(),
            )
        })?;
        let prepared = SqliteCompositeAuthorizeInput {
            operation_id: admission_operation.operation_id().to_string(),
            request_binding_hash: admission_operation.request_binding_hash().to_string(),
            capability_id: budget.capability_id.clone(),
            grant_index: budget.grant_index,
            requested_exposure_units: budget.requested_exposure_units,
            max_cost_per_invocation: budget.max_cost_per_invocation,
            max_total_cost_units: budget.max_total_cost_units,
            hold_id: budget.hold_id.clone().ok_or_else(|| {
                SupplementalQuotaError::Verification(
                    "kernel registration omitted hold id".to_string(),
                )
            })?,
            event_id: budget.event_id.clone().ok_or_else(|| {
                SupplementalQuotaError::Verification(
                    "kernel registration omitted authorize event id".to_string(),
                )
            })?,
            authority: budget.authority.clone(),
            invocation_quotas: budget.invocation_quotas().to_vec(),
            revocation_set,
            authorization_artifact_digests: vec![artifact_digest.to_string()],
            partition_escrow_evidence: None,
        };
        if prepared.hold_id != plan.hold_id() || prepared.event_id != plan.authorize_event_id() {
            return Err(SupplementalQuotaError::ContextMismatch(
                "broker deterministic budget identifiers".to_string(),
            ));
        }
        AuthoritativeBrokerExecutionAdapter::register_admission(
            self,
            &broker_request,
            authorization.admission_operation_id(),
            prepared,
            aggregate_family_evidence,
            Vec::new(),
            None,
        )
        .map(|_| ())
        .map_err(|error| SupplementalQuotaError::Verification(error.to_string()))
    }

    fn release_admission(
        &self,
        admission_operation_id: &str,
    ) -> Result<(), SupplementalQuotaError> {
        AuthoritativeBrokerExecutionAdapter::release_admission(self, admission_operation_id)
            .map(|_| ())
            .map_err(|error| SupplementalQuotaError::Verification(error.to_string()))
    }

    fn prepare_dispatch(&self, admission_operation_id: &str) -> Result<(), SupplementalQuotaError> {
        AuthoritativeBrokerExecutionAdapter::prepare_dispatch(self, admission_operation_id)
            .map_err(|error| SupplementalQuotaError::Verification(error.to_string()))
    }

    fn finalize_admission(
        &self,
        admission_operation_id: &str,
    ) -> Result<(), SupplementalQuotaError> {
        AuthoritativeBrokerExecutionAdapter::finalize_admission(self, admission_operation_id)
            .map(|_| ())
            .map_err(|error| SupplementalQuotaError::Verification(error.to_string()))
    }
}
