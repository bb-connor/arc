use std::fs::File;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::io::{Seek, SeekFrom, Write};
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::fd::AsRawFd;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::unix::fs::MetadataExt;

use chio_core_types::{sha256, Ed25519Backend, Keypair};
use chio_kernel::budget_store::{
    BudgetAdmissionOperationBinding, BudgetAuthorizeHoldDecision, BudgetCaptureInvocationRequest,
    BudgetInvocationQuota, BudgetInvocationReservationState, BudgetQuotaKey, BudgetQuotaProfile,
    BudgetReverseHoldRequest,
};
use chio_kernel::supplemental_quota::CanonicalRevocationSet;
use chio_kernel::{
    AdmissionCaptureAuthority, AdmissionCaptureDecision, AdmissionCaptureRequest,
    AdmissionCaptureRequestInput, BudgetStore,
};
use chio_store_sqlite::budget_store::{SqliteBudgetStore, SqliteCompositeAuthorizeInput};
use chio_store_sqlite::SqliteAdmissionCaptureAuthority;
use rusqlite::{params, Connection};

use crate::backend::SecretBackend;
use crate::budget::{
    canonicalize_quotas, AuthorizeExecutionHoldRequest, BrokerExecutionBudget,
    CaptureExecutionHoldRequest, CombinedCaptureCommit, ExecutionAuthorityCapabilities,
    ExecutionAuthorityProfile, ExecutionHoldState, ExecutionQuota, QueryExecutionHoldRequest,
    ReverseExecutionHoldRequest,
};
use crate::capability::{capability_digest, issue_capability};
use crate::encrypted_blob_backend::EncryptedBlobSecretBackend;
use crate::generic_https::{
    DestinationResolver, GenericHttpsExecutor, NetworkPolicy, PinnedHttpsRequest,
    PinnedHttpsTransport, RawHttpsResponse,
};
use crate::proof::{body_digest, issue_request_proof, proof_digest};
use crate::protocol::{
    AttemptConsumption, BrokerCapabilityBody, BrokerDestination, BrokerExecuteRequest,
    BrokerRequest, CallerOptions, CredentialRef, HeaderField, ProofBinding, ProofMode,
    RedirectPolicy, RequestConstraints, BROKER_CAPABILITY_SCHEMA, BROKER_EXECUTE_SCHEMA,
};
use crate::provider::{CredentialPlacement, GenericCredentialProvider};
use crate::receipt::{verify_execution_receipt, verify_failure_receipt, SqliteBrokerReceiptSink};
use crate::registration::{broker_execute_request_registration_digest, prepared_dispatch_id};
use crate::revocation::{
    BrokerRevocationRequest, BrokerRevocationSnapshot, BrokerRevocations,
    CanonicalBrokerRevocationSet, CapabilityLiveness, CapabilityLivenessRequest,
    LiveParentCapability,
};
use crate::service::{
    broker_request_digest, BrokerExecuteOutcome, BrokerService, TrustedExecutionContext,
};
use crate::sqlite::{ProductionSqliteAttemptStore, SqliteAttemptStore};
use crate::store::{derive_attempt_ids_for_operation, AttemptRegistration};
use crate::{BrokerError, Result, SealedKeyFd};

const BROKER_AUDIENCE: &str = "native-conformance-broker";
const PARENT_AUDIENCE: &str = "native-conformance-parent";
const AUTHORITY_DOMAIN: &str = "native-conformance-combined-authority";
const BROKER_QUOTA_KEY: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const PARENT_QUOTA_KEY: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn require(condition: bool, reason: &'static str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(BrokerError::Invariant(reason.to_string()))
    }
}

fn credential(version: u64) -> CredentialRef {
    CredentialRef {
        provider: "generic-https".to_string(),
        credential_id: "native-conformance-credential".to_string(),
        version,
    }
}

fn provision(
    backend: &EncryptedBlobSecretBackend,
    credential: &CredentialRef,
    secret: &[u8],
    operation_id: &str,
    mutation_byte: char,
) -> Result<()> {
    let operation_id = sha256(operation_id.as_bytes()).to_hex();
    backend.provision_once(
        credential,
        secret,
        &operation_id,
        &mutation_byte.to_string().repeat(64),
    )?;
    Ok(())
}

fn materializes_as(
    backend: &EncryptedBlobSecretBackend,
    credential: &CredentialRef,
    expected: &[u8],
) -> Result<bool> {
    let material = <EncryptedBlobSecretBackend as SecretBackend>::materialize(backend, credential)?;
    Ok(material.as_bytes() == expected)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn sealed_read_only_key(name: &str, seed: [u8; 32]) -> Result<(File, u32)> {
    use rustix::fs::{fcntl_add_seals, memfd_create, MemfdFlags, SealFlags};

    let descriptor = memfd_create(name, MemfdFlags::ALLOW_SEALING)
        .map_err(|error| BrokerError::Custody(format!("create sealed key descriptor: {error}")))?;
    let mut writable = File::from(descriptor);
    writable
        .write_all(&seed)
        .map_err(|error| BrokerError::Custody(format!("write sealed key descriptor: {error}")))?;
    writable
        .seek(SeekFrom::Start(0))
        .map_err(|error| BrokerError::Custody(format!("rewind sealed key descriptor: {error}")))?;
    fcntl_add_seals(
        &writable,
        SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE,
    )
    .map_err(|error| BrokerError::Custody(format!("seal key descriptor: {error}")))?;
    let read_only = File::open(format!("/proc/self/fd/{}", writable.as_raw_fd()))
        .map_err(|error| BrokerError::Custody(format!("reopen sealed key descriptor: {error}")))?;
    let owner = read_only
        .metadata()
        .map_err(|error| BrokerError::Custody(format!("inspect sealed key descriptor: {error}")))?
        .uid();
    Ok((read_only, owner))
}

fn open_backend(
    path: &Path,
    tenant_scope: &str,
    seed: [u8; 32],
    descriptor_name: &str,
) -> Result<EncryptedBlobSecretBackend> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let (file, owner) = sealed_read_only_key(descriptor_name, seed)?;
        return EncryptedBlobSecretBackend::open(
            path,
            tenant_scope.to_string(),
            SealedKeyFd::from_inherited_file(file, owner),
        );
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = descriptor_name;
        EncryptedBlobSecretBackend::open_with_tenant_key(
            path,
            tenant_scope.to_string(),
            chio_store_sqlite::TenantKey::from_bytes(seed),
        )
    }
}

pub fn encrypted_credential_custody(directory: &Path) -> Result<()> {
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let unsupported_path = directory.join("broker-unsupported-key.bin");
        std::fs::write(&unsupported_path, [40_u8; 32]).map_err(|error| {
            BrokerError::Custody(format!("write unsupported custody fixture: {error}"))
        })?;
        let unsupported = File::open(&unsupported_path).map_err(|error| {
            BrokerError::Custody(format!("open unsupported custody fixture: {error}"))
        })?;
        require(
            matches!(
                EncryptedBlobSecretBackend::open(
                    directory.join("broker-unsupported.sqlite"),
                    "native-conformance-unsupported".to_string(),
                    SealedKeyFd::from_inherited_file(unsupported, 0),
                ),
                Err(BrokerError::Custody(message))
                    if message == "sealed master-key descriptors are unsupported on this platform"
            ),
            "unsupported target did not reject sealed-descriptor custody explicitly",
        )?;
    }

    let path = directory.join("broker-custody.sqlite");
    let tenant_a = open_backend(
        &path,
        "native-conformance-tenant-a",
        [41; 32],
        "native-conformance-tenant-a-key",
    )?;
    let version_one = credential(1);
    let version_two = credential(2);
    provision(
        &tenant_a,
        &version_one,
        b"native-conformance-version-one",
        "native-conformance-provision-a-v1",
        '1',
    )?;
    provision(
        &tenant_a,
        &version_two,
        b"native-conformance-version-two",
        "native-conformance-provision-a-v2",
        '2',
    )?;
    require(
        materializes_as(&tenant_a, &version_one, b"native-conformance-version-one")?
            && materializes_as(&tenant_a, &version_two, b"native-conformance-version-two")?,
        "versioned credential references did not materialize their exact secret",
    )?;

    let tenant_b = open_backend(
        &path,
        "native-conformance-tenant-b",
        [41; 32],
        "native-conformance-tenant-b-key",
    )?;
    require(
        <EncryptedBlobSecretBackend as SecretBackend>::materialize(&tenant_b, &version_one)
            .is_err(),
        "credential reference crossed tenant scope before provisioning",
    )?;
    provision(
        &tenant_b,
        &version_one,
        b"native-conformance-tenant-b-version-one",
        "native-conformance-provision-b-v1",
        '3',
    )?;
    require(
        materializes_as(
            &tenant_b,
            &version_one,
            b"native-conformance-tenant-b-version-one",
        )? && materializes_as(&tenant_a, &version_two, b"native-conformance-version-two")?,
        "tenant-scoped credential references aliased another tenant or version",
    )?;

    let disable_operation_id = sha256(b"native-conformance-disable-a-v1").to_hex();
    tenant_a.disable_once(&version_one, &disable_operation_id, &"4".repeat(64))?;
    require(
        <EncryptedBlobSecretBackend as SecretBackend>::materialize(&tenant_a, &version_one)
            .is_err()
            && materializes_as(&tenant_a, &version_two, b"native-conformance-version-two")?,
        "disabling one credential version changed another version",
    )?;

    let wrong_key = open_backend(
        &path,
        "native-conformance-tenant-a",
        [42; 32],
        "native-conformance-wrong-key",
    )?;
    require(
        <EncryptedBlobSecretBackend as SecretBackend>::materialize(&wrong_key, &version_two)
            .is_err(),
        "credential materialized under a different tenant key",
    )?;

    let unsealed_path = directory.join("broker-unsealed-key.bin");
    std::fs::write(&unsealed_path, [43_u8; 32]).map_err(|error| {
        BrokerError::Custody(format!("write unsealed custody fixture: {error}"))
    })?;
    let unsealed = File::open(&unsealed_path)
        .map_err(|error| BrokerError::Custody(format!("open unsealed custody fixture: {error}")))?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let unsealed_owner = unsealed
        .metadata()
        .map_err(|error| BrokerError::Custody(format!("inspect unsealed key: {error}")))?
        .uid();
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let unsealed_owner = 0;
    let ordinary = EncryptedBlobSecretBackend::open(
        directory.join("broker-unsealed.sqlite"),
        "native-conformance-unsealed".to_string(),
        SealedKeyFd::from_inherited_file(unsealed, unsealed_owner),
    );
    #[cfg(any(target_os = "linux", target_os = "android"))]
    return require(
        ordinary.is_err(),
        "broker accepted an ordinary unsealed custody descriptor",
    );
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        require(
            matches!(
                ordinary,
                Err(BrokerError::Custody(message))
                    if message == "sealed master-key descriptors are unsupported on this platform"
            ),
            "unsupported target did not preserve its explicit custody rejection",
        )
    }
}

struct ConformanceBudget {
    budget_store: SqliteBudgetStore,
    capture_authority: SqliteAdmissionCaptureAuthority,
    database_path: PathBuf,
    revocation_set: CanonicalRevocationSet,
    authorization_artifact_digest: String,
    request_binding_hash: String,
    authorize_calls: AtomicU64,
    capture_calls: AtomicU64,
}

impl ConformanceBudget {
    fn open(
        database_path: PathBuf,
        revocation_set: &CanonicalBrokerRevocationSet,
        authorization_artifact_digest: String,
        request_binding_hash: String,
    ) -> Result<Self> {
        let revocation_set = CanonicalRevocationSet::from_persisted_parts(
            revocation_set.ids().to_vec(),
            revocation_set.digest().to_string(),
        )
        .map_err(|error| {
            BrokerError::Invariant(format!("translate canonical revocation set: {error}"))
        })?;
        let capture_authority = SqliteAdmissionCaptureAuthority::open(&database_path)
            .map_err(|error| BrokerError::AuthorityUnavailable(error.to_string()))?;
        let budget_store = SqliteBudgetStore::open(&database_path)
            .map_err(|error| BrokerError::AuthorityUnavailable(error.to_string()))?;
        Ok(Self {
            budget_store,
            capture_authority,
            database_path,
            revocation_set,
            authorization_artifact_digest,
            request_binding_hash,
            authorize_calls: AtomicU64::new(0),
            capture_calls: AtomicU64::new(0),
        })
    }

    fn admission_binding(&self, operation_id: &str) -> Result<BudgetAdmissionOperationBinding> {
        BudgetAdmissionOperationBinding::new(
            operation_id.to_string(),
            self.request_binding_hash.clone(),
        )
        .map_err(|error| BrokerError::AuthorityUnavailable(error.to_string()))
    }

    fn capture_request(
        &self,
        operation_id: &str,
        broker_capability_id: &str,
        hold_id: &str,
        capture_event_id: &str,
    ) -> Result<AdmissionCaptureRequest> {
        AdmissionCaptureRequest::new(AdmissionCaptureRequestInput {
            operation_id: operation_id.to_string(),
            budget: BudgetCaptureInvocationRequest {
                capability_id: broker_capability_id.to_string(),
                grant_index: 0,
                hold_id: Some(hold_id.to_string()),
                event_id: Some(capture_event_id.to_string()),
                authority: None,
                admission_operation: Some(self.admission_binding(operation_id)?),
            },
            revocation_set: self.revocation_set.clone(),
            bound_revocation_set_digest: self.revocation_set.digest().to_string(),
            authorization_artifact_digests: vec![self.authorization_artifact_digest.clone()],
            aggregate_root_capability_id: None,
            aggregate_root_binding_digest: None,
            last_observed_revocation_index: None,
        })
        .map_err(|error| BrokerError::AuthorityUnavailable(error.to_string()))
    }

    fn map_authorization(decision: BudgetAuthorizeHoldDecision) -> Result<ExecutionHoldState> {
        match decision {
            BudgetAuthorizeHoldDecision::Authorized(authorized)
                if authorized.invocation_state == BudgetInvocationReservationState::Authorized =>
            {
                Ok(ExecutionHoldState::Held)
            }
            BudgetAuthorizeHoldDecision::Denied(_) => Ok(ExecutionHoldState::Denied),
            _ => Err(BrokerError::Invariant(
                "durable authority returned an invalid authorization state".to_string(),
            )),
        }
    }

    fn map_capture(decision: AdmissionCaptureDecision) -> Result<ExecutionHoldState> {
        match decision {
            AdmissionCaptureDecision::Captured { budget, metadata } => {
                if budget.invocation_state != BudgetInvocationReservationState::Captured {
                    return Err(BrokerError::Invariant(
                        "combined authority returned uncaptured budget state".to_string(),
                    ));
                }
                let budget_commit_index =
                    metadata
                        .budget_commit()
                        .budget_commit_index
                        .ok_or_else(|| {
                            BrokerError::Invariant(
                                "combined authority omitted its budget commit index".to_string(),
                            )
                        })?;
                Ok(ExecutionHoldState::Captured(CombinedCaptureCommit {
                    checked_revocation_set_digest: metadata
                        .checked_revocation_set_digest()
                        .to_string(),
                    budget_commit_index,
                    revocation_commit_index: metadata.revocation_commit_index(),
                    authority_commit_index: metadata.authority_commit_index(),
                    leader_epoch: metadata.leader_epoch().unwrap_or(0),
                }))
            }
            AdmissionCaptureDecision::Denied(_) => Ok(ExecutionHoldState::Denied),
        }
    }

    fn verify_single_charge(&self) -> Result<()> {
        require(
            self.authorize_calls.load(Ordering::SeqCst) == 1
                && self.capture_calls.load(Ordering::SeqCst) == 2,
            "broker service reauthorized or skipped its exact capture retry",
        )?;
        let connection = Connection::open(&self.database_path)
            .map_err(|error| BrokerError::Storage(error.to_string()))?;
        for (profile, owner_id) in [
            (
                BudgetQuotaProfile::AggregateCapabilityInvocation,
                PARENT_QUOTA_KEY,
            ),
            (
                BudgetQuotaProfile::SupplementalBrokerExecution,
                BROKER_QUOTA_KEY,
            ),
        ] {
            let counts = connection
                .query_row(
                    r#"
                    SELECT max_invocations, reserved_invocations, captured_invocations
                    FROM budget_invocation_quota_usage
                    WHERE profile = ?1 AND owner_id = ?2
                    "#,
                    params![profile.as_str(), owner_id],
                    |row| {
                        Ok((
                            row.get::<_, u32>(0)?,
                            row.get::<_, u32>(1)?,
                            row.get::<_, u32>(2)?,
                        ))
                    },
                )
                .map_err(|error| BrokerError::Storage(error.to_string()))?;
            require(
                counts == (2, 0, 1),
                "durable parent or broker quota row was not captured exactly once",
            )?;
        }
        Ok(())
    }
}

impl BrokerExecutionBudget for ConformanceBudget {
    fn capabilities(&self) -> ExecutionAuthorityCapabilities {
        ExecutionAuthorityCapabilities {
            profile: ExecutionAuthorityProfile::AuthoritativeHoldEvent,
            atomic_multi_key_holds: true,
            combined_capture_and_revocation: true,
            query_by_id: true,
            shared_revocation_write_domain: true,
        }
    }

    fn query_execution_hold(
        &self,
        request: &QueryExecutionHoldRequest,
    ) -> Result<ExecutionHoldState> {
        request.validate()?;
        let capture = self.capture_request(
            &request.operation_id,
            &request.broker_capability_id,
            &request.hold_id,
            &request.capture_event_id,
        )?;
        if let Some(decision) = self
            .capture_authority
            .query_admission_capture(&capture)
            .map_err(|error| BrokerError::AuthorityUnavailable(error.to_string()))?
        {
            return Self::map_capture(decision);
        }
        if let Some(reverse) = self
            .budget_store
            .query_composite_hold_mutation(&request.reverse_event_id)
            .map_err(|error| BrokerError::AuthorityUnavailable(error.to_string()))?
        {
            return if reverse.invocation_state == BudgetInvocationReservationState::Reversed {
                Ok(ExecutionHoldState::Reversed)
            } else {
                Err(BrokerError::Invariant(
                    "durable reverse event has the wrong reservation state".to_string(),
                ))
            };
        }
        self.budget_store
            .query_composite_authorization(&request.authorize_event_id)
            .map_err(|error| BrokerError::AuthorityUnavailable(error.to_string()))?
            .map(Self::map_authorization)
            .transpose()
            .map(|state| state.unwrap_or(ExecutionHoldState::Unknown))
    }

    fn authorize_execution_hold(
        &self,
        request: &AuthorizeExecutionHoldRequest,
    ) -> Result<ExecutionHoldState> {
        request.validate()?;
        if request.authority_metadata_digest != self.request_binding_hash {
            return Err(BrokerError::Conflict(
                "authorization changed its authority binding".to_string(),
            ));
        }
        self.authorize_calls.fetch_add(1, Ordering::SeqCst);
        let broker_maximum = request
            .quotas
            .iter()
            .find(|quota| quota.key_id == BROKER_QUOTA_KEY)
            .map(|quota| quota.maximum_executions)
            .ok_or_else(|| BrokerError::Invariant("broker quota is missing".to_string()))?;
        let mut quotas = vec![BudgetInvocationQuota::from_persisted_parts(
            BudgetQuotaKey::grant(request.broker_capability_id.clone(), 0)
                .map_err(|error| BrokerError::AuthorityUnavailable(error.to_string()))?,
            broker_maximum,
        )
        .map_err(|error| BrokerError::AuthorityUnavailable(error.to_string()))?];
        for quota in &request.quotas {
            let profile = match quota.key_id.as_str() {
                BROKER_QUOTA_KEY => BudgetQuotaProfile::SupplementalBrokerExecution,
                PARENT_QUOTA_KEY => BudgetQuotaProfile::AggregateCapabilityInvocation,
                _ => {
                    return Err(BrokerError::Invariant(
                        "broker authorization contains an unmapped quota key".to_string(),
                    ))
                }
            };
            let key = BudgetQuotaKey::from_persisted_parts(profile, quota.key_id.clone(), None)
                .map_err(|error| BrokerError::AuthorityUnavailable(error.to_string()))?;
            quotas.push(
                BudgetInvocationQuota::from_persisted_parts(key, quota.maximum_executions)
                    .map_err(|error| BrokerError::AuthorityUnavailable(error.to_string()))?,
            );
        }
        quotas.sort_unstable_by(|left, right| left.key().cmp(right.key()));
        let decision = self
            .budget_store
            .authorize_composite_hold(SqliteCompositeAuthorizeInput {
                operation_id: request.operation_id.clone(),
                request_binding_hash: self.request_binding_hash.clone(),
                capability_id: request.broker_capability_id.clone(),
                grant_index: 0,
                requested_exposure_units: 0,
                max_cost_per_invocation: None,
                max_total_cost_units: None,
                hold_id: request.hold_id.clone(),
                event_id: request.authorize_event_id.clone(),
                authority: None,
                invocation_quotas: quotas,
                revocation_set: self.revocation_set.clone(),
                authorization_artifact_digests: vec![self.authorization_artifact_digest.clone()],
            })
            .map_err(|error| BrokerError::AuthorityUnavailable(error.to_string()))?;
        Self::map_authorization(decision)
    }

    fn reverse_execution_hold(
        &self,
        request: &ReverseExecutionHoldRequest,
    ) -> Result<ExecutionHoldState> {
        request.validate()?;
        let reversed = self
            .budget_store
            .reverse_budget_hold(BudgetReverseHoldRequest {
                capability_id: request.broker_capability_id.clone(),
                grant_index: 0,
                reversed_exposure_units: 0,
                hold_id: Some(request.hold_id.clone()),
                event_id: Some(request.reverse_event_id.clone()),
                authority: None,
                admission_operation: Some(self.admission_binding(&request.operation_id)?),
            })
            .map_err(|error| BrokerError::AuthorityUnavailable(error.to_string()))?;
        if reversed.invocation_state == BudgetInvocationReservationState::Reversed {
            Ok(ExecutionHoldState::Reversed)
        } else {
            Err(BrokerError::Invariant(
                "durable authority did not reverse the hold".to_string(),
            ))
        }
    }

    fn capture_execution_hold(
        &self,
        request: &CaptureExecutionHoldRequest,
    ) -> Result<ExecutionHoldState> {
        request.validate()?;
        if request.authority_metadata_digest != self.request_binding_hash
            || request.authorization_artifact_digest != self.authorization_artifact_digest
        {
            return Err(BrokerError::Conflict(
                "capture changed its authorization binding".to_string(),
            ));
        }
        let supplied_set = CanonicalRevocationSet::from_persisted_parts(
            request.revocation_ids.clone(),
            request.revocation_set_digest.clone(),
        )
        .map_err(|error| BrokerError::AuthorityUnavailable(error.to_string()))?;
        if supplied_set != self.revocation_set {
            return Err(BrokerError::Conflict(
                "capture changed its canonical revocation set".to_string(),
            ));
        }
        self.capture_calls.fetch_add(1, Ordering::SeqCst);
        let capture = self.capture_request(
            &request.operation_id,
            &request.broker_capability_id,
            &request.hold_id,
            &request.capture_event_id,
        )?;
        let decision = self
            .capture_authority
            .capture_admission(capture)
            .map_err(|error| BrokerError::AuthorityUnavailable(error.to_string()))?;
        Self::map_capture(decision)
    }
}

struct ConformanceLiveness;

impl CapabilityLiveness for ConformanceLiveness {
    fn verify_live_parent(
        &self,
        request: &CapabilityLivenessRequest,
    ) -> Result<LiveParentCapability> {
        Ok(LiveParentCapability {
            capability_id: request.parent_capability_id.clone(),
            subject: request.expected_subject.clone(),
            audience: request.expected_audience.clone(),
            delegation_ancestor_ids: vec!["native-conformance-ancestor".to_string()],
            expires_at_unix_seconds: 100,
            verified_at_unix_seconds: request.now_unix_seconds,
            authority_snapshot_digest: "a".repeat(64),
        })
    }
}

struct ConformanceRevocations;

impl BrokerRevocations for ConformanceRevocations {
    fn check_broker_revocation(
        &self,
        request: &BrokerRevocationRequest,
    ) -> Result<BrokerRevocationSnapshot> {
        Ok(BrokerRevocationSnapshot {
            revoked: false,
            observed_at_unix_seconds: request.now_unix_seconds,
            commit_index: 1,
            authority_domain: AUTHORITY_DOMAIN.to_string(),
        })
    }
}

struct ConformanceResolver;

impl DestinationResolver for ConformanceResolver {
    fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>> {
        Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
    }
}

struct ConformanceTransport {
    dispatches: Arc<AtomicU64>,
}

impl PinnedHttpsTransport for ConformanceTransport {
    fn dispatch(&self, _request: PinnedHttpsRequest) -> Result<RawHttpsResponse> {
        self.dispatches.fetch_add(1, Ordering::SeqCst);
        let body = b"native-conformance-response".to_vec();
        let content_length = body.len().to_string();
        let header = HeaderField::normalized("content-length", content_length.as_bytes())?;
        Ok(RawHttpsResponse {
            status: 200,
            headers: vec![header],
            decoded_body_chunks: vec![body],
            response_head_bytes: format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {content_length}\r\n\r\n"
            )
            .len(),
            connected_address: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            tls_server_name: "example.com".to_string(),
            redirected: false,
        })
    }
}

struct ConformanceExecution {
    request: BrokerExecuteRequest,
    trusted: TrustedExecutionContext,
    registration: AttemptRegistration,
    authorization: AuthorizeExecutionHoldRequest,
}

fn conformance_execution(issuer: &Keypair, caller: &Keypair) -> Result<ConformanceExecution> {
    let destination = BrokerDestination::parse("https://example.com/v1", "POST", false)?;
    let request = BrokerRequest {
        destination: destination.clone(),
        headers: Vec::new(),
        body: b"native-conformance-request".to_vec(),
        approved_preview_sha256: None,
        options: CallerOptions {
            timeout_ms: 1_000,
            streaming: false,
            response_limit_bytes: 1_024,
        },
    };
    let capability = issue_capability(
        BrokerCapabilityBody {
            schema: BROKER_CAPABILITY_SCHEMA.to_string(),
            issuer: issuer.public_key(),
            capability_id: "native-conformance-broker-capability".to_string(),
            parent_capability_id: "native-conformance-parent-capability".to_string(),
            subject: caller.public_key(),
            audience: BROKER_AUDIENCE.to_string(),
            issued_at_unix_seconds: 10,
            not_before_unix_seconds: 10,
            expires_at_unix_seconds: 100,
            credential: credential(1),
            provider_adapter_id: "generic-bearer".to_string(),
            provider_adapter_version: 1,
            destination,
            constraints: RequestConstraints {
                allowed_caller_headers: Vec::new(),
                provider_owned_headers: vec!["authorization".to_string()],
                maximum_body_bytes: 1_024,
                required_body_sha256: body_digest(&request.body),
                required_preview_sha256: None,
                redirect_policy: RedirectPolicy::Disabled,
                maximum_response_bytes: 1_024,
                streaming_allowed: false,
                maximum_timeout_ms: 1_000,
            },
            broker_quota_key_id: BROKER_QUOTA_KEY.to_string(),
            maximum_executions: 2,
            consumption: AttemptConsumption::CaptureBeforeDispatch,
            revocation_id: "native-conformance-broker-revocation".to_string(),
            proof: ProofBinding {
                mode: ProofMode::PublicKey,
                caller_public_key: caller.public_key(),
                nonce_ttl_seconds: 30,
            },
        },
        &Ed25519Backend::new(issuer.clone()),
        true,
    )?;
    let proof = issue_request_proof(
        &capability,
        &request,
        "native-conformance-nonce-0001".to_string(),
        20,
        caller,
    )?;
    let execute = BrokerExecuteRequest {
        schema: BROKER_EXECUTE_SCHEMA.to_string(),
        invocation_id: "native-conformance-invocation".to_string(),
        capability,
        proof,
        request,
    };
    let operation_id = "native-conformance-admission-operation".to_string();
    let quotas = canonicalize_quotas(vec![
        ExecutionQuota {
            key_id: BROKER_QUOTA_KEY.to_string(),
            maximum_executions: 2,
        },
        ExecutionQuota {
            key_id: PARENT_QUOTA_KEY.to_string(),
            maximum_executions: 2,
        },
    ])?;
    let request_digest = broker_request_digest(&execute)?;
    let ids = derive_attempt_ids_for_operation(
        &execute.capability.body.capability_id,
        &execute.invocation_id,
        &execute.proof.body.nonce,
        &request_digest,
        &operation_id,
    )?;
    let nonce_expires_at_unix_seconds = execute
        .proof
        .body
        .issued_at_unix_seconds
        .checked_add(execute.capability.body.proof.nonce_ttl_seconds)
        .ok_or_else(|| BrokerError::Invariant("proof nonce expiry overflowed".to_string()))?;
    let registration = AttemptRegistration {
        ids: ids.clone(),
        invocation_id: execute.invocation_id.clone(),
        parent_capability_id: execute.capability.body.parent_capability_id.clone(),
        broker_capability_id: execute.capability.body.capability_id.clone(),
        request_digest,
        request_canonical_digest: broker_execute_request_registration_digest(&execute)?,
        proof_digest: proof_digest(&execute.proof)?,
        proof_key_id: execute.proof.body.authority_key.to_hex(),
        proof_nonce: execute.proof.body.nonce.clone(),
        nonce_expires_at_unix_seconds,
        quotas: quotas.clone(),
        authority_metadata_digest: "e".repeat(64),
        revocation_authority_domain: AUTHORITY_DOMAIN.to_string(),
    };
    let trusted = TrustedExecutionContext {
        admission_operation_id: operation_id.clone(),
        prepared_dispatch_id: prepared_dispatch_id(&registration, &execute)?,
        quotas: quotas.clone(),
        authority_metadata_digest: "e".repeat(64),
        revocation_authority_domain: AUTHORITY_DOMAIN.to_string(),
        source_receipt_ids: vec!["native-conformance-parent-receipt".to_string()],
    };
    let authorization = AuthorizeExecutionHoldRequest {
        operation_id,
        invocation_id: execute.invocation_id.clone(),
        parent_capability_id: execute.capability.body.parent_capability_id.clone(),
        broker_capability_id: execute.capability.body.capability_id.clone(),
        hold_id: ids.hold_id,
        authorize_event_id: ids.authorize_event_id,
        quotas,
        authority_metadata_digest: "e".repeat(64),
    };
    Ok(ConformanceExecution {
        request: execute,
        trusted,
        registration,
        authorization,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnterpriseBrokerConformanceMode {
    Execute,
    RejectReversedAdmission,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnterpriseBrokerConformanceExecution {
    pub request: BrokerExecuteRequest,
    pub outcome: BrokerExecuteOutcome,
    pub trusted_receipt_signer: chio_core_types::PublicKey,
    pub dispatch_count: u64,
}

pub struct PreparedEnterpriseBrokerConformance {
    service: BrokerService,
    execution: ConformanceExecution,
    budget: Arc<ConformanceBudget>,
    receipt_sink: Arc<SqliteBrokerReceiptSink>,
    receipt_signer: Keypair,
    dispatches: Arc<AtomicU64>,
}

impl PreparedEnterpriseBrokerConformance {
    #[must_use]
    pub fn request(&self) -> &BrokerExecuteRequest {
        &self.execution.request
    }

    #[must_use]
    pub fn attempt_id(&self) -> &str {
        &self.execution.registration.ids.attempt_id
    }

    #[must_use]
    pub fn dispatch_count(&self) -> u64 {
        self.dispatches.load(Ordering::SeqCst)
    }

    pub fn reverse_admission(&self) -> Result<()> {
        require(
            self.budget
                .reverse_execution_hold(&ReverseExecutionHoldRequest {
                    operation_id: self.execution.registration.ids.operation_id.clone(),
                    invocation_id: self.execution.registration.invocation_id.clone(),
                    parent_capability_id: self.execution.registration.parent_capability_id.clone(),
                    broker_capability_id: self.execution.registration.broker_capability_id.clone(),
                    hold_id: self.execution.registration.ids.hold_id.clone(),
                    reverse_event_id: self.execution.registration.ids.reverse_event_id.clone(),
                    proof_dispatch_did_not_begin: true,
                })?
                == ExecutionHoldState::Reversed,
            "broker mutation did not reverse its admission before dispatch",
        )
    }

    pub fn execute_evidenced(
        &self,
        now_unix_seconds: u64,
    ) -> Result<EnterpriseBrokerConformanceExecution> {
        let outcome = self.service.execute_evidenced(
            &self.execution.request,
            &self.execution.trusted,
            now_unix_seconds,
        )?;
        match &outcome {
            BrokerExecuteOutcome::Success(response) => {
                let response = response.as_ref();
                verify_execution_receipt(&response.receipt, &self.receipt_signer.public_key())?;
                require(
                    self.receipt_sink.load(&response.receipt.body.receipt_id)?
                        == Some(response.receipt.clone()),
                    "broker success receipt was not durably queryable",
                )?;
            }
            BrokerExecuteOutcome::Failure(failure) => {
                let failure = failure.as_ref();
                verify_failure_receipt(&failure.receipt, &self.receipt_signer.public_key())?;
                require(
                    self.receipt_sink
                        .load_failure(&failure.receipt.body.receipt_id)?
                        == Some(failure.receipt.clone()),
                    "broker failure receipt was not durably queryable",
                )?;
            }
        }
        Ok(EnterpriseBrokerConformanceExecution {
            request: self.execution.request.clone(),
            outcome,
            trusted_receipt_signer: self.receipt_signer.public_key(),
            dispatch_count: self.dispatch_count(),
        })
    }
}

pub fn prepare_enterprise_broker_composition(
    directory: &Path,
) -> Result<PreparedEnterpriseBrokerConformance> {
    let issuer = Keypair::from_seed(&[61; 32]);
    let caller = Keypair::from_seed(&[62; 32]);
    let execution = conformance_execution(&issuer, &caller)?;
    let revocation_set = CanonicalBrokerRevocationSet::new(
        &execution.request.capability.body.parent_capability_id,
        &["native-conformance-ancestor".to_string()],
        &execution.request.capability.body.capability_id,
        &execution.request.capability.body.revocation_id,
    )?;
    let budget = Arc::new(ConformanceBudget::open(
        directory.join("broker-service-authority.sqlite"),
        &revocation_set,
        capability_digest(&execution.request.capability)?,
        execution.trusted.authority_metadata_digest.clone(),
    )?);
    let backend = Arc::new(open_backend(
        &directory.join("broker-service-credentials.sqlite"),
        "native-conformance-service-tenant",
        [51; 32],
        "native-conformance-service-key",
    )?);
    provision(
        &backend,
        &credential(1),
        b"native-conformance-service-secret",
        "native-conformance-service-provision",
        '5',
    )?;
    let attempts = Arc::new(SqliteAttemptStore::open(
        directory.join("broker-service-attempts.sqlite"),
    )?);
    let production_attempts = ProductionSqliteAttemptStore::new(attempts)?;
    let receipt_signer = Keypair::from_seed(&[63; 32]);
    let receipt_sink = Arc::new(SqliteBrokerReceiptSink::open(
        directory.join("broker-service-receipts.sqlite"),
        receipt_signer.public_key(),
    )?);
    let provider = Arc::new(GenericCredentialProvider::new(
        "generic-bearer".to_string(),
        1,
        CredentialPlacement::BearerAuthorization,
    )?);
    let dispatches = Arc::new(AtomicU64::new(0));
    let https = Arc::new(GenericHttpsExecutor::new(
        Arc::new(ConformanceResolver),
        Arc::new(ConformanceTransport {
            dispatches: Arc::clone(&dispatches),
        }),
        NetworkPolicy::production(),
    ));
    let service = BrokerService::new_production(
        crate::service::BrokerServiceConfig {
            audience: BROKER_AUDIENCE.to_string(),
            parent_audience: PARENT_AUDIENCE.to_string(),
            maximum_clock_skew_seconds: 2,
            maximum_liveness_snapshot_age_seconds: 5,
            maximum_revocation_snapshot_age_seconds: 5,
        },
        production_attempts,
        crate::service::BrokerServiceAuthorityBundle {
            trusted_issuer: issuer.public_key(),
            backend,
            provider,
            https,
            budget: budget.clone(),
            liveness: Arc::new(ConformanceLiveness),
            revocations: Arc::new(ConformanceRevocations),
            receipt_sink: receipt_sink.clone(),
            receipt_signer: Arc::new(Ed25519Backend::new(receipt_signer.clone())),
            migration_enforcer: crate::migration::TestBrokerMigrationEnforcer::new(vec![
                "generic-https".to_string(),
            ]),
        },
    )?;
    service.register_attempt(&execution.registration, &execution.request, 20)?;
    require(
        budget.authorize_execution_hold(&execution.authorization)? == ExecutionHoldState::Held,
        "runtime did not authorize the combined hold",
    )?;
    service.prepare_dispatch(&execution.registration, &execution.request, 20)?;
    Ok(PreparedEnterpriseBrokerConformance {
        service,
        execution,
        budget,
        receipt_sink,
        receipt_signer,
        dispatches,
    })
}

pub fn enterprise_broker_composition(
    directory: &Path,
    mode: EnterpriseBrokerConformanceMode,
) -> Result<EnterpriseBrokerConformanceExecution> {
    let prepared = prepare_enterprise_broker_composition(directory)?;
    if mode == EnterpriseBrokerConformanceMode::RejectReversedAdmission {
        prepared.reverse_admission()?;
    }
    let first = prepared.execute_evidenced(21)?;
    let replay = prepared.execute_evidenced(22)?;
    require(
        replay.outcome == first.outcome && replay.dispatch_count == first.dispatch_count,
        "broker retry changed its signed terminal outcome",
    )?;
    match &first.outcome {
        BrokerExecuteOutcome::Success(response) => {
            let response = response.as_ref();
            require(
                mode == EnterpriseBrokerConformanceMode::Execute
                    && response.evidence.hold_id == prepared.execution.authorization.hold_id
                    && first.dispatch_count == 1,
                "broker success was misbound or redispatched",
            )?;
            prepared.budget.verify_single_charge()?;
        }
        BrokerExecuteOutcome::Failure(failure) => {
            let failure = failure.as_ref();
            require(
                mode == EnterpriseBrokerConformanceMode::RejectReversedAdmission
                    && first.dispatch_count == 0
                    && failure.diagnostic_code == "chio.broker.authorization_denied",
                "broker admission mutation did not fail closed before dispatch",
            )?;
        }
    }
    Ok(first)
}

pub fn combined_quota_no_double_charge(directory: &Path) -> Result<()> {
    let execution =
        enterprise_broker_composition(directory, EnterpriseBrokerConformanceMode::Execute)?;
    require(
        matches!(execution.outcome, BrokerExecuteOutcome::Success(_)),
        "combined broker conformance did not produce a successful execution",
    )
}
