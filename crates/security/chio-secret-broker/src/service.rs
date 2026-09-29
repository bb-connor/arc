use std::collections::BTreeMap;
#[cfg(unix)]
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
#[cfg(unix)]
use std::time::Instant;

use chio_core_types::{canonical_json_bytes, PublicKey, SigningBackend};
#[cfg(test)]
use chio_core_types::{Ed25519Backend, Keypair};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::backend::{SecretBackend, SecretMaterial};
use crate::budget::{
    canonicalize_quotas, BrokerExecutionBudget, CaptureExecutionHoldRequest, ExecutionHoldState,
    ExecutionQuota, QueryExecutionHoldRequest,
};
#[cfg(test)]
use crate::budget::{AuthorizeExecutionHoldRequest, ReverseExecutionHoldRequest};
use crate::capability::{capability_digest, verify_capability};
use crate::encrypted_blob_backend::EncryptedBlobSecretBackend;
use crate::generic_https::{
    response_digest, GenericHttpsExecutor, HttpsDispatchFailure, PreparedHttpsDispatch,
};
use crate::migration::BrokerMigrationEnforcer;
use crate::proof::{proof_digest, verify_request_proof};
#[cfg(unix)]
use crate::protocol::is_well_formed_broker_execute_diagnostic_code;
use crate::protocol::{
    BrokerExecuteFailure, BrokerExecuteRequest, BrokerExecuteResponse, BrokerExecutionEvidence,
    BROKER_EVIDENCE_SCHEMA, MAX_WIRE_BYTES,
};
use crate::provider::{GenericCredentialProvider, ProviderAdapter};
use crate::provision::{AdminAuthorization, GovernedAdminAuthorizer};
use crate::receipt::{
    credential_reference_hash, failure_receipt_digest, receipt_digest, sign_execution_receipt,
    sign_failure_receipt, verify_execution_receipt, verify_failure_receipt,
    BrokerDispatchKnowledge, BrokerExecutionOutcome, BrokerFailureOutcome,
    BrokerFailureReceiptBody, BrokerFailureStage, BrokerReceiptBody, BrokerReceiptSink,
    BROKER_FAILURE_RECEIPT_SCHEMA, BROKER_RECEIPT_SCHEMA,
};
use crate::registration::{
    broker_execute_request_registration_digest, prepared_dispatch_id,
    PrepareDispatchAcknowledgement, RegisterAttemptAcknowledgement, ReleaseAttemptAcknowledgement,
};
use crate::revocation::{
    validate_parent_liveness, validate_revocation_snapshot, BrokerRevocationRequest,
    BrokerRevocations, CanonicalBrokerRevocationSet, CapabilityLiveness, CapabilityLivenessRequest,
};
use crate::sqlite::ProductionSqliteAttemptStore;
use crate::store::{
    derive_attempt_ids, derive_attempt_ids_for_operation, AttemptRecord, AttemptRegistration,
    AttemptState, AttemptStore, AttemptTransitionEvidence, RegisterAttemptOutcome,
};
use crate::{validate_digest, validate_identifier, BrokerError, Result};
const MAX_RETAINED_PREPARED_DISPATCHES: usize = 4_096;
const ATTEMPT_OPERATION_GATE_COUNT: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustedExecutionContext {
    pub admission_operation_id: String,
    pub prepared_dispatch_id: String,
    pub quotas: Vec<ExecutionQuota>,
    pub authority_metadata_digest: String,
    pub revocation_authority_domain: String,
    pub source_receipt_ids: Vec<String>,
}

impl TrustedExecutionContext {
    pub fn validate_for(&self, request: &BrokerExecuteRequest) -> Result<()> {
        validate_identifier(&self.admission_operation_id, "admission operation id", 512)?;
        validate_identifier(&self.prepared_dispatch_id, "prepared dispatch id", 512)?;
        validate_digest(&self.authority_metadata_digest, "authority metadata digest")?;
        validate_identifier(
            &self.revocation_authority_domain,
            "revocation authority domain",
            512,
        )?;
        if canonicalize_quotas(self.quotas.clone())? != self.quotas {
            return Err(BrokerError::InvalidRequest(
                "trusted quota set is not canonical".to_string(),
            ));
        }
        let broker_quota = self
            .quotas
            .iter()
            .find(|quota| quota.key_id == request.capability.body.broker_quota_key_id);
        if !broker_quota.is_some_and(|quota| {
            quota.maximum_executions == request.capability.body.maximum_executions
        }) {
            return Err(BrokerError::AuthorizationDenied(
                "authoritative hold omits the signed broker quota".to_string(),
            ));
        }
        if self.quotas.len() < 2 {
            return Err(BrokerError::AuthorizationDenied(
                "authoritative hold omits the parent grant quota".to_string(),
            ));
        }
        if self.source_receipt_ids.len() > 64
            || self
                .source_receipt_ids
                .array_windows::<2>()
                .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
        {
            return Err(BrokerError::AuthorizationDenied(
                "trusted source receipt lineage is oversized or noncanonical".to_string(),
            ));
        }
        for receipt_id in &self.source_receipt_ids {
            validate_identifier(receipt_id, "trusted source receipt id", 512)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct BrokerServiceConfig {
    pub(crate) audience: String,
    pub(crate) parent_audience: String,
    pub(crate) maximum_clock_skew_seconds: u64,
    pub(crate) maximum_liveness_snapshot_age_seconds: u64,
    pub(crate) maximum_revocation_snapshot_age_seconds: u64,
}

impl BrokerServiceConfig {
    fn validate(&self) -> Result<()> {
        validate_identifier(&self.audience, "broker audience", 512)?;
        validate_identifier(&self.parent_audience, "parent audience", 512)?;
        if self.maximum_clock_skew_seconds > 60
            || self.maximum_liveness_snapshot_age_seconds == 0
            || self.maximum_liveness_snapshot_age_seconds > 60
            || self.maximum_revocation_snapshot_age_seconds == 0
            || self.maximum_revocation_snapshot_age_seconds > 60
        {
            return Err(BrokerError::InvalidRequest(
                "broker authority freshness configuration is invalid".to_string(),
            ));
        }
        Ok(())
    }
}

pub(crate) struct BrokerServiceAuthorityBundle {
    pub(crate) trusted_issuer: PublicKey,
    pub(crate) backend: Arc<EncryptedBlobSecretBackend>,
    pub(crate) provider: Arc<GenericCredentialProvider>,
    pub(crate) https: Arc<GenericHttpsExecutor>,
    pub(crate) budget: Arc<dyn BrokerExecutionBudget>,
    pub(crate) liveness: Arc<dyn CapabilityLiveness>,
    pub(crate) revocations: Arc<dyn BrokerRevocations>,
    pub(crate) receipt_sink: Arc<dyn BrokerReceiptSink>,
    pub(crate) receipt_signer: Arc<dyn SigningBackend>,
    pub(crate) migration_enforcer: Arc<dyn BrokerMigrationEnforcer>,
}

impl BrokerServiceAuthorityBundle {
    fn validate_for_production(&self) -> Result<()> {
        self.budget.capabilities().require_production()?;
        self.migration_enforcer.ensure_ready()?;
        if !self.receipt_sink.supports_failure_receipts() {
            return Err(BrokerError::AuthorityUnavailable(
                "production broker receipt sink does not support failure receipts".to_string(),
            ));
        }
        if !self.receipt_sink.supports_completed_replay() {
            return Err(BrokerError::AuthorityUnavailable(
                "production broker receipt sink does not support completed-response replay"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

pub struct BrokerService {
    authority_clock: Option<Arc<dyn crate::daemon::Clock>>,
    config: BrokerServiceConfig,
    trusted_issuer: PublicKey,
    backend: Arc<EncryptedBlobSecretBackend>,
    provider: Arc<GenericCredentialProvider>,
    https: Arc<GenericHttpsExecutor>,
    attempts: Arc<dyn AttemptStore>,
    budget: Arc<dyn BrokerExecutionBudget>,
    liveness: Arc<dyn CapabilityLiveness>,
    revocations: Arc<dyn BrokerRevocations>,
    receipt_sink: Arc<dyn BrokerReceiptSink>,
    receipt_signer: Arc<dyn SigningBackend>,
    migration_enforcer: Arc<dyn BrokerMigrationEnforcer>,
    attempt_operation_gates: [Mutex<()>; ATTEMPT_OPERATION_GATE_COUNT],
    retained_prepared_dispatches: Mutex<BTreeMap<String, RetainedPreparedDispatch>>,
    dispatch_claim_counter: AtomicU64,
}

struct RetainedPreparedDispatch {
    operation_id: String,
    attempt_id: String,
    prepared_dispatch_id: String,
    request_canonical_digest: String,
    prepared_at_unix_seconds: u64,
    dispatch: PreparedHttpsDispatch,
    credential: SecretMaterial,
    credential_version: chio_store_sqlite::BlobHandle,
    revocation_set: CanonicalBrokerRevocationSet,
}

struct ValidatedBrokerAuthorities {
    revocation_set: CanonicalBrokerRevocationSet,
}

struct ValidatedBrokerAuditAuthorities {
    liveness_exchange: crate::authority_ipc::VerifiedAuthorityExchange,
    revocation_exchange: crate::authority_ipc::VerifiedAuthorityExchange,
    validated_at_unix_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerExecuteOutcome {
    Success(Box<BrokerExecuteResponse>),
    Failure(Box<BrokerExecuteFailure>),
}

mod authorization;

mod execution;

mod failure;


mod ipc;
pub use ipc::BrokerIpcHandler;
# [cfg (unix)]
pub use ipc::UnixBrokerEndpoint;
pub use ipc::BrokerIpcDeadlines;
pub use ipc::BrokerIpcServeOutcome;

mod lifecycle;

mod registration;

mod request_digest;
pub use request_digest::broker_request_digest;

mod wire;
pub use wire::IpcOperation;
pub use wire::SensitiveIpcBytes;
pub use wire::AuthenticatedIpcRequest;
pub use wire::canonical_ipc_request_bytes;
pub use wire::IpcResponse;
pub use wire::read_bounded_frame;
pub use wire::write_bounded_frame;
use failure::FailureOrigin;
use failure::FailureProjection;
use failure::ExecutionFailure;
use failure::ExecutionResult;
use failure::execution_failure_after_capture_release;







use failure::failure_receipt_key_digest;



use request_digest::FAILURE_RECEIPT_REQUEST_DOMAIN;
use request_digest::attempt_operation_gate_index;

use wire::read_bounded_sensitive_frame;
#[cfg(test)]
use wire::read_sensitive_frame_body;
#[cfg(test)]
pub(crate) use wire::reset_sensitive_drop_observer;
#[cfg(test)]
pub(crate) use wire::sensitive_drop_observation;
pub(crate) use wire::BoundedZeroizingByteArray;

pub(crate) use wire::SensitiveJsonParser;
pub(crate) use wire::checked_canonical_length;
pub(crate) use wire::canonical_json_string_length;
pub(crate) use wire::canonical_json_byte_array_length;
pub(crate) use wire::canonical_json_u64_length;
pub(crate) use wire::ZeroizingCanonicalJsonWriter;
pub(crate) use wire::decode_canonical_ipc_request;

#[cfg(test)]
mod tests;

#[cfg(all(test, unix))]
use ipc::{classify_broker_ipc_handler_result, classify_broker_ipc_write_error, validate_broker_ipc_response_envelope, BrokerIpcServeFailure, BrokerIpcWriteFailureClass, ProvisionalBrokerSocketCleanup};

#[cfg(all(test, unix))]
use ipc::validate_broker_peer_uid;

#[cfg(all(test, unix))]
use ipc::{is_well_formed_broker_ipc_error_code, validate_broker_socket_identity};

pub(crate) use failure::failure_receipt_id_for_canonical_request_digest;
