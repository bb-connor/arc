use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::Arc;

use chio_core_types::{canonical_json_bytes, Keypair, PublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::backend::SecretBackend;
use crate::budget::{
    canonicalize_quotas, AuthorizeExecutionHoldRequest, BrokerExecutionBudget,
    CaptureExecutionHoldRequest, ExecutionHoldState, ExecutionQuota, ReverseExecutionHoldRequest,
};
use crate::capability::{capability_digest, verify_capability};
use crate::encrypted_blob_backend::EncryptedBlobSecretBackend;
use crate::generic_https::{response_digest, GenericHttpsExecutor};
use crate::proof::{proof_digest, verify_request_proof};
use crate::protocol::{
    BrokerExecuteRequest, BrokerExecuteResponse, BrokerExecutionEvidence, BROKER_EVIDENCE_SCHEMA,
    MAX_WIRE_BYTES,
};
use crate::provider::{GenericCredentialProvider, ProviderAdapter};
use crate::receipt::{
    sign_execution_receipt, BrokerReceiptBody, BrokerReceiptSink, BROKER_RECEIPT_SCHEMA,
};
use crate::reconcile::reconcile_attempt;
use crate::revocation::{
    validate_parent_liveness, validate_revocation_snapshot, BrokerRevocationRequest,
    BrokerRevocations, CanonicalBrokerRevocationSet, CapabilityLiveness, CapabilityLivenessRequest,
};
use crate::store::{
    derive_attempt_ids, AttemptRegistration, AttemptState, AttemptStore, AttemptTransitionEvidence,
    RegisterAttemptOutcome,
};
use crate::{validate_digest, validate_identifier, BrokerError, Result};

const REQUEST_DIGEST_DOMAIN: &[u8] = b"chio.broker-canonical-request.v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustedExecutionContext {
    pub quotas: Vec<ExecutionQuota>,
    pub authority_metadata_digest: String,
    pub revocation_authority_domain: String,
}

impl TrustedExecutionContext {
    pub fn validate_for(&self, request: &BrokerExecuteRequest) -> Result<()> {
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
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct BrokerServiceConfig {
    pub production: bool,
    pub audience: String,
    pub parent_audience: String,
    pub maximum_clock_skew_seconds: u64,
    pub maximum_liveness_snapshot_age_seconds: u64,
    pub maximum_revocation_snapshot_age_seconds: u64,
}

impl BrokerServiceConfig {
    pub fn validate(&self) -> Result<()> {
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

pub struct BrokerService {
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
    receipt_signer: Keypair,
}

impl BrokerService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
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
        receipt_signer: Keypair,
    ) -> Result<Self> {
        config.validate()?;
        if config.production {
            budget.capabilities().require_production()?;
        }
        Ok(Self {
            config,
            trusted_issuer,
            backend,
            provider,
            https,
            attempts,
            budget,
            liveness,
            revocations,
            receipt_sink,
            receipt_signer,
        })
    }

    pub fn execute(
        &self,
        request: &BrokerExecuteRequest,
        trusted: &TrustedExecutionContext,
        now_unix_seconds: u64,
    ) -> Result<BrokerExecuteResponse> {
        self.budget.capabilities().require_production()?;
        request.validate_bounds()?;
        trusted.validate_for(request)?;
        verify_capability(
            &request.capability,
            &self.trusted_issuer,
            &self.config.audience,
            now_unix_seconds,
            self.config.production,
        )?;
        if self.provider.adapter_id() != request.capability.body.provider_adapter_id
            || self.provider.adapter_version() != request.capability.body.provider_adapter_version
            || request.request.destination != request.capability.body.destination
        {
            return Err(BrokerError::AuthorizationDenied(
                "provider or destination does not match the signed capability".to_string(),
            ));
        }
        verify_request_proof(
            &request.proof,
            &request.capability,
            &request.request,
            now_unix_seconds,
            self.config.maximum_clock_skew_seconds,
        )?;
        self.https.preflight(
            &request.request,
            &request.capability.body.constraints,
            &request.proof,
        )?;

        let live_request = CapabilityLivenessRequest {
            parent_capability_id: request.capability.body.parent_capability_id.clone(),
            expected_subject: request.capability.body.subject.clone(),
            expected_audience: self.config.parent_audience.clone(),
            now_unix_seconds,
        };
        let live_parent = self.liveness.verify_live_parent(&live_request)?;
        validate_parent_liveness(
            &live_request,
            &live_parent,
            self.config.maximum_liveness_snapshot_age_seconds,
        )?;
        let revocation_request = BrokerRevocationRequest {
            broker_capability_id: request.capability.body.capability_id.clone(),
            revocation_id: request.capability.body.revocation_id.clone(),
            now_unix_seconds,
        };
        let revocation_snapshot = self
            .revocations
            .check_broker_revocation(&revocation_request)?;
        validate_revocation_snapshot(
            &revocation_snapshot,
            now_unix_seconds,
            self.config.maximum_revocation_snapshot_age_seconds,
            &trusted.revocation_authority_domain,
        )?;
        let revocation_set = CanonicalBrokerRevocationSet::new(
            &request.capability.body.parent_capability_id,
            &live_parent.delegation_ancestor_ids,
            &request.capability.body.capability_id,
            &request.capability.body.revocation_id,
        )?;

        let request_digest = broker_request_digest(request)?;
        let capability_digest = capability_digest(&request.capability)?;
        let proof_digest = proof_digest(&request.proof)?;
        let ids = derive_attempt_ids(
            &request.capability.body.capability_id,
            &request.invocation_id,
            &request.proof.body.nonce,
            &request_digest,
        )?;
        let nonce_expires_at = request
            .proof
            .body
            .issued_at_unix_seconds
            .checked_add(request.capability.body.proof.nonce_ttl_seconds)
            .ok_or_else(|| BrokerError::InvalidRequest("nonce expiry overflow".to_string()))?;
        let registration = AttemptRegistration {
            ids: ids.clone(),
            invocation_id: request.invocation_id.clone(),
            parent_capability_id: request.capability.body.parent_capability_id.clone(),
            broker_capability_id: request.capability.body.capability_id.clone(),
            request_digest: request_digest.clone(),
            proof_digest,
            proof_key_id: request.proof.body.authority_key.to_hex(),
            proof_nonce: request.proof.body.nonce.clone(),
            nonce_expires_at_unix_seconds: nonce_expires_at,
            quotas: trusted.quotas.clone(),
            authority_metadata_digest: trusted.authority_metadata_digest.clone(),
        };
        match self
            .attempts
            .register_attempt(&registration, now_unix_seconds)?
        {
            RegisterAttemptOutcome::Inserted(_) => {}
            RegisterAttemptOutcome::ExactRetry(existing) => {
                let reconciled = reconcile_attempt(
                    self.attempts.as_ref(),
                    self.budget.as_ref(),
                    &existing,
                    now_unix_seconds,
                )?;
                return Err(BrokerError::Conflict(format!(
                    "duplicate invocation reconciled as {}",
                    reconciled.state.as_str()
                )));
            }
        }

        let hold_request = AuthorizeExecutionHoldRequest {
            operation_id: ids.operation_id.clone(),
            invocation_id: request.invocation_id.clone(),
            parent_capability_id: request.capability.body.parent_capability_id.clone(),
            broker_capability_id: request.capability.body.capability_id.clone(),
            hold_id: ids.hold_id.clone(),
            authorize_event_id: ids.authorize_event_id.clone(),
            quotas: trusted.quotas.clone(),
            authority_metadata_digest: trusted.authority_metadata_digest.clone(),
        };
        hold_request.validate()?;
        match self.budget.authorize_execution_hold(&hold_request)? {
            ExecutionHoldState::Held => {
                self.attempts.transition(
                    &ids.attempt_id,
                    AttemptState::Prepared,
                    AttemptState::Held,
                    &AttemptTransitionEvidence::default(),
                    now_unix_seconds,
                )?;
            }
            ExecutionHoldState::Denied => {
                self.attempts.transition(
                    &ids.attempt_id,
                    AttemptState::Prepared,
                    AttemptState::Failed,
                    &AttemptTransitionEvidence::default(),
                    now_unix_seconds,
                )?;
                return Err(BrokerError::AuthorizationDenied(
                    "authoritative execution quota denied the hold".to_string(),
                ));
            }
            ExecutionHoldState::Unknown => {
                return Err(BrokerError::AuthorityUnavailable(
                    "authoritative hold result is unknown".to_string(),
                ));
            }
            _ => {
                return Err(BrokerError::Invariant(
                    "authority returned an invalid state for a new hold".to_string(),
                ))
            }
        }

        let second_revocation = self
            .revocations
            .check_broker_revocation(&revocation_request);
        if let Err(error) = second_revocation.and_then(|snapshot| {
            validate_revocation_snapshot(
                &snapshot,
                now_unix_seconds,
                self.config.maximum_revocation_snapshot_age_seconds,
                &trusted.revocation_authority_domain,
            )
        }) {
            self.reverse_before_dispatch(request, &ids, now_unix_seconds)?;
            return Err(error);
        }

        let credential = match self
            .backend
            .materialize(&request.capability.body.credential)
        {
            Ok(credential) => credential,
            Err(error) => {
                self.reverse_before_dispatch(request, &ids, now_unix_seconds)?;
                return Err(error);
            }
        };
        let prepared = match self.https.prepare(
            self.provider.as_ref(),
            &request.request,
            &request.capability.body.constraints,
            &credential,
        ) {
            Ok(prepared) => prepared,
            Err(error) => {
                self.reverse_before_dispatch(request, &ids, now_unix_seconds)?;
                return Err(error);
            }
        };

        let capture_request = CaptureExecutionHoldRequest {
            operation_id: ids.operation_id.clone(),
            invocation_id: request.invocation_id.clone(),
            parent_capability_id: request.capability.body.parent_capability_id.clone(),
            broker_capability_id: request.capability.body.capability_id.clone(),
            hold_id: ids.hold_id.clone(),
            capture_event_id: ids.capture_event_id.clone(),
            revocation_ids: revocation_set.ids().to_vec(),
            revocation_set_digest: revocation_set.digest().to_string(),
            authorization_artifact_digest: capability_digest.clone(),
            authority_metadata_digest: trusted.authority_metadata_digest.clone(),
        };
        capture_request.validate()?;
        let commit = match self.budget.capture_execution_hold(&capture_request) {
            Ok(ExecutionHoldState::Captured(commit)) => commit,
            Ok(_) | Err(_) => {
                let _ = self.attempts.transition(
                    &ids.attempt_id,
                    AttemptState::Held,
                    AttemptState::UnknownOutcome,
                    &AttemptTransitionEvidence::default(),
                    now_unix_seconds,
                );
                return Err(BrokerError::AuthorityUnavailable(
                    "combined capture result is unavailable or ambiguous".to_string(),
                ));
            }
        };
        if let Err(error) = commit.validate_for(&capture_request) {
            let _ = self.attempts.transition(
                &ids.attempt_id,
                AttemptState::Held,
                AttemptState::UnknownOutcome,
                &AttemptTransitionEvidence::default(),
                now_unix_seconds,
            );
            return Err(error);
        }
        let capture_evidence = AttemptTransitionEvidence {
            revocation_set_digest: Some(commit.checked_revocation_set_digest.clone()),
            budget_commit_index: Some(commit.budget_commit_index),
            revocation_commit_index: Some(commit.revocation_commit_index),
            authority_commit_index: Some(commit.authority_commit_index),
            leader_epoch: Some(commit.leader_epoch),
            response_digest: None,
        };
        self.attempts.transition(
            &ids.attempt_id,
            AttemptState::Held,
            AttemptState::Captured,
            &capture_evidence,
            now_unix_seconds,
        )?;
        self.attempts.transition(
            &ids.attempt_id,
            AttemptState::Captured,
            AttemptState::DispatchCommitted,
            &capture_evidence,
            now_unix_seconds,
        )?;

        let (status, headers, body) =
            match self
                .https
                .dispatch(prepared, &request.capability.body.constraints, &credential)
            {
                Ok(response) => response,
                Err(error) => {
                    let _ = self.attempts.transition(
                        &ids.attempt_id,
                        AttemptState::DispatchCommitted,
                        AttemptState::UnknownOutcome,
                        &capture_evidence,
                        now_unix_seconds,
                    );
                    return Err(error);
                }
            };
        drop(credential);
        let response_body_sha256 = response_digest(&body);
        let evidence = BrokerExecutionEvidence {
            schema: BROKER_EVIDENCE_SCHEMA.to_string(),
            attempt_id: ids.attempt_id.clone(),
            invocation_id: request.invocation_id.clone(),
            hold_id: ids.hold_id,
            request_digest,
            capability_digest,
            revocation_set_digest: commit.checked_revocation_set_digest,
            budget_commit_index: commit.budget_commit_index,
            revocation_commit_index: commit.revocation_commit_index,
            authority_commit_index: commit.authority_commit_index,
            leader_epoch: commit.leader_epoch,
            upstream_status: status,
            response_body_sha256: response_body_sha256.clone(),
        };
        let receipt_id = format!("broker-receipt-{}", ids.attempt_id);
        let receipt = sign_execution_receipt(
            BrokerReceiptBody {
                schema: BROKER_RECEIPT_SCHEMA.to_string(),
                receipt_id,
                issued_at_unix_seconds: now_unix_seconds,
                evidence: evidence.clone(),
                outcome: "completed".to_string(),
            },
            &self.receipt_signer,
        )?;
        let receipt_reference = match self.receipt_sink.persist(&receipt) {
            Ok(reference) => reference,
            Err(error) => {
                let _ = self.attempts.transition(
                    &ids.attempt_id,
                    AttemptState::DispatchCommitted,
                    AttemptState::UnknownOutcome,
                    &capture_evidence,
                    now_unix_seconds,
                );
                return Err(error);
            }
        };
        validate_identifier(&receipt_reference, "receipt reference", 512)?;
        let completion = AttemptTransitionEvidence {
            response_digest: Some(response_body_sha256),
            ..capture_evidence
        };
        self.attempts.transition(
            &ids.attempt_id,
            AttemptState::DispatchCommitted,
            AttemptState::Completed,
            &completion,
            now_unix_seconds,
        )?;
        Ok(BrokerExecuteResponse {
            status,
            headers,
            body,
            evidence,
            receipt_reference,
        })
    }

    fn reverse_before_dispatch(
        &self,
        request: &BrokerExecuteRequest,
        ids: &crate::store::AttemptIds,
        now_unix_seconds: u64,
    ) -> Result<()> {
        let reverse = ReverseExecutionHoldRequest {
            operation_id: ids.operation_id.clone(),
            invocation_id: request.invocation_id.clone(),
            parent_capability_id: request.capability.body.parent_capability_id.clone(),
            broker_capability_id: request.capability.body.capability_id.clone(),
            hold_id: ids.hold_id.clone(),
            reverse_event_id: ids.reverse_event_id.clone(),
            proof_dispatch_did_not_begin: true,
        };
        reverse.validate()?;
        match self.budget.reverse_execution_hold(&reverse)? {
            ExecutionHoldState::Reversed => {
                self.attempts.transition(
                    &ids.attempt_id,
                    AttemptState::Held,
                    AttemptState::Reversed,
                    &AttemptTransitionEvidence::default(),
                    now_unix_seconds,
                )?;
                Ok(())
            }
            _ => {
                let _ = self.attempts.transition(
                    &ids.attempt_id,
                    AttemptState::Held,
                    AttemptState::UnknownOutcome,
                    &AttemptTransitionEvidence::default(),
                    now_unix_seconds,
                );
                Err(BrokerError::AuthorityUnavailable(
                    "hold reversal result is unknown".to_string(),
                ))
            }
        }
    }
}

pub fn broker_request_digest(request: &BrokerExecuteRequest) -> Result<String> {
    let canonical = canonical_json_bytes(&request.request)
        .map_err(|error| BrokerError::Invariant(format!("request digest failed: {error}")))?;
    let mut hasher = Sha256::new();
    hasher.update(REQUEST_DIGEST_DOMAIN);
    hasher.update(canonical);
    Ok(hex::encode(hasher.finalize()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpcOperation {
    Issue,
    Revoke,
    Status,
    Execute,
    Provision,
    Rotate,
    Disable,
    Delete,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthenticatedIpcRequest {
    pub operation: IpcOperation,
    pub tenant_scope: String,
    pub authorization: Vec<u8>,
    pub payload: Vec<u8>,
}

impl Drop for AuthenticatedIpcRequest {
    fn drop(&mut self) {
        self.authorization.zeroize();
        self.payload.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IpcResponse {
    pub operation: IpcOperation,
    pub accepted: bool,
    pub response: Vec<u8>,
    pub error_code: Option<String>,
}

pub trait BrokerIpcHandler: Send + Sync {
    fn issue(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse>;
    fn revoke(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse>;
    fn status(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse>;
    fn execute(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse>;
    fn provision(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse>;
    fn rotate(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse>;
    fn disable(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse>;
    fn delete(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse>;
}

#[cfg(unix)]
pub struct UnixBrokerEndpoint {
    listener: UnixListener,
    handler: Arc<dyn BrokerIpcHandler>,
}

#[cfg(unix)]
impl UnixBrokerEndpoint {
    pub fn bind(path: impl AsRef<Path>, handler: Arc<dyn BrokerIpcHandler>) -> Result<Self> {
        let path = path.as_ref();
        if path.exists() {
            return Err(BrokerError::Storage(
                "broker IPC path already exists".to_string(),
            ));
        }
        let listener = UnixListener::bind(path)
            .map_err(|error| BrokerError::Storage(format!("IPC bind failed: {error}")))?;
        fs_permissions(path, 0o600)?;
        Ok(Self { listener, handler })
    }

    pub fn serve_one(&self) -> Result<()> {
        let (mut stream, _) = self
            .listener
            .accept()
            .map_err(|error| BrokerError::Storage(format!("IPC accept failed: {error}")))?;
        let _request_result = self.serve_stream(&mut stream);
        Ok(())
    }

    fn serve_stream(&self, stream: &mut std::os::unix::net::UnixStream) -> Result<()> {
        let frame = Zeroizing::new(read_bounded_frame(&mut *stream)?);
        let value: serde_json::Value = serde_json::from_slice(frame.as_slice())
            .map_err(|error| BrokerError::InvalidRequest(format!("IPC request failed: {error}")))?;
        let canonical = Zeroizing::new(canonical_json_bytes(&value).map_err(|error| {
            BrokerError::InvalidRequest(format!("IPC request failed: {error}"))
        })?);
        if canonical.as_slice() != frame.as_slice() {
            return Err(BrokerError::InvalidRequest(
                "IPC request is not canonical JSON".to_string(),
            ));
        }
        let request: AuthenticatedIpcRequest = serde_json::from_slice(frame.as_slice())
            .map_err(|error| BrokerError::InvalidRequest(format!("IPC request failed: {error}")))?;
        if request.authorization.is_empty() || request.authorization.len() > 65_536 {
            return Err(BrokerError::AuthorizationDenied(
                "IPC operation authorization is missing or oversized".to_string(),
            ));
        }
        validate_identifier(&request.tenant_scope, "IPC tenant scope", 512)?;
        if request.payload.len() > MAX_WIRE_BYTES {
            return Err(BrokerError::InvalidRequest(
                "IPC operation payload is oversized".to_string(),
            ));
        }
        let operation = request.operation;
        let handled = match operation {
            IpcOperation::Issue => self.handler.issue(request),
            IpcOperation::Revoke => self.handler.revoke(request),
            IpcOperation::Status => self.handler.status(request),
            IpcOperation::Execute => self.handler.execute(request),
            IpcOperation::Provision => self.handler.provision(request),
            IpcOperation::Rotate => self.handler.rotate(request),
            IpcOperation::Disable => self.handler.disable(request),
            IpcOperation::Delete => self.handler.delete(request),
        };
        let response = match handled {
            Ok(response) => response,
            Err(error) => IpcResponse {
                operation,
                accepted: false,
                response: Vec::new(),
                error_code: Some(error.diagnostic_code().to_string()),
            },
        };
        if response.operation != operation
            || response.response.len() > MAX_WIRE_BYTES
            || (response.accepted && response.error_code.is_some())
            || (!response.accepted && response.error_code.is_none())
        {
            return Err(BrokerError::Invariant(
                "IPC handler returned an invalid response envelope".to_string(),
            ));
        }
        let encoded = canonical_json_bytes(&response)
            .map_err(|error| BrokerError::Invariant(format!("IPC response failed: {error}")))?;
        write_bounded_frame(&mut *stream, &encoded)
    }
}

pub fn read_bounded_frame(reader: &mut impl Read) -> Result<Vec<u8>> {
    let mut prefix = [0_u8; 4];
    reader.read_exact(&mut prefix).map_err(|error| {
        BrokerError::InvalidRequest(format!("IPC frame prefix failed: {error}"))
    })?;
    let length = usize::try_from(u32::from_be_bytes(prefix))
        .map_err(|_| BrokerError::InvalidRequest("IPC frame length overflow".to_string()))?;
    if length == 0 || length > MAX_WIRE_BYTES {
        return Err(BrokerError::InvalidRequest(
            "IPC frame is empty or oversized".to_string(),
        ));
    }
    let mut frame = vec![0_u8; length];
    reader
        .read_exact(&mut frame)
        .map_err(|error| BrokerError::InvalidRequest(format!("IPC frame body failed: {error}")))?;
    Ok(frame)
}

pub fn write_bounded_frame(writer: &mut impl Write, frame: &[u8]) -> Result<()> {
    if frame.is_empty() || frame.len() > MAX_WIRE_BYTES {
        return Err(BrokerError::InvalidRequest(
            "IPC response frame is empty or oversized".to_string(),
        ));
    }
    let length = u32::try_from(frame.len())
        .map_err(|_| BrokerError::InvalidRequest("IPC response length overflow".to_string()))?;
    writer
        .write_all(&length.to_be_bytes())
        .and_then(|()| writer.write_all(frame))
        .and_then(|()| writer.flush())
        .map_err(|error| BrokerError::Storage(format!("IPC response write failed: {error}")))
}

#[cfg(unix)]
fn fs_permissions(path: &Path, mode: u32) -> Result<()> {
    let permissions = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, permissions)
        .map_err(|error| BrokerError::Storage(format!("IPC permissions failed: {error}")))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Barrier, Mutex};
    use std::thread;

    use crate::budget::{
        CombinedCaptureCommit, ExecutionAuthorityCapabilities, ExecutionAuthorityProfile,
        QueryExecutionHoldRequest,
    };
    use crate::capability::issue_capability;
    use crate::generic_https::{
        DestinationResolver, NetworkPolicy, PinnedHttpsRequest, PinnedHttpsTransport,
        RawHttpsResponse,
    };
    use crate::proof::{body_digest, issue_request_proof};
    use crate::protocol::{
        AttemptConsumption, BrokerCapabilityBody, BrokerDestination, BrokerRequest, CallerOptions,
        CredentialRef, HeaderField, ProofBinding, ProofMode, RedirectPolicy, RequestConstraints,
        BROKER_CAPABILITY_SCHEMA, BROKER_EXECUTE_SCHEMA,
    };
    use crate::provider::CredentialPlacement;
    use crate::receipt::SignedBrokerReceipt;
    use crate::revocation::{BrokerRevocationSnapshot, LiveParentCapability};
    use crate::sqlite::SqliteAttemptStore;

    use super::*;

    struct PublicResolver;

    impl DestinationResolver for PublicResolver {
        fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>> {
            Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
        }
    }

    struct ObservingTransport {
        observed_authorizations: Arc<Mutex<Vec<Vec<u8>>>>,
        fail: bool,
        redirect: bool,
    }

    impl PinnedHttpsTransport for ObservingTransport {
        fn dispatch(&self, request: PinnedHttpsRequest) -> Result<RawHttpsResponse> {
            assert!(!request.redirects_allowed());
            let values = request
                .secret_headers()
                .map(|(_name, value)| value.to_vec())
                .collect::<Vec<_>>();
            self.observed_authorizations
                .lock()
                .expect("observed lock")
                .extend(values);
            if self.fail {
                return Err(BrokerError::Upstream("injected timeout".to_string()));
            }
            let status = if self.redirect { 302 } else { 200 };
            let response = b"sanitized-upstream-response".to_vec();
            let (headers, response_head_bytes) = if self.redirect {
                (Vec::new(), b"HTTP/1.1 302 Found\r\n\r\n".len())
            } else {
                let value = response.len().to_string();
                let header = HeaderField::normalized("content-length", value.as_bytes())?;
                let head = format!("HTTP/1.1 200 OK\r\ncontent-length: {value}\r\n\r\n");
                (vec![header], head.len())
            };
            Ok(RawHttpsResponse {
                status,
                headers,
                decoded_body_chunks: vec![response],
                response_head_bytes,
                connected_address: request.pinned_address(),
                tls_server_name: request.original_hostname().to_string(),
                redirected: false,
            })
        }
    }

    #[derive(Default)]
    struct AuthorityState {
        holds: HashMap<String, ExecutionHoldState>,
        quotas: HashMap<String, u32>,
        hold_quotas: HashMap<String, Vec<ExecutionQuota>>,
    }

    struct AtomicAuthority {
        state: Mutex<AuthorityState>,
        deny_capture: bool,
    }

    impl AtomicAuthority {
        fn new(deny_capture: bool) -> Self {
            Self {
                state: Mutex::new(AuthorityState::default()),
                deny_capture,
            }
        }

        fn captured_count(&self) -> usize {
            self.state
                .lock()
                .expect("authority lock")
                .holds
                .values()
                .filter(|state| matches!(state, ExecutionHoldState::Captured(_)))
                .count()
        }
    }

    impl BrokerExecutionBudget for AtomicAuthority {
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
            Ok(self
                .state
                .lock()
                .expect("authority lock")
                .holds
                .get(&request.hold_id)
                .cloned()
                .unwrap_or(ExecutionHoldState::Unknown))
        }

        fn authorize_execution_hold(
            &self,
            request: &AuthorizeExecutionHoldRequest,
        ) -> Result<ExecutionHoldState> {
            request.validate()?;
            let mut state = self.state.lock().expect("authority lock");
            if let Some(existing) = state.holds.get(&request.hold_id) {
                return Ok(existing.clone());
            }
            let denied = request.quotas.iter().any(|quota| {
                state.quotas.get(&quota.key_id).copied().unwrap_or(0) >= quota.maximum_executions
            });
            if denied {
                state
                    .holds
                    .insert(request.hold_id.clone(), ExecutionHoldState::Denied);
                return Ok(ExecutionHoldState::Denied);
            }
            for quota in &request.quotas {
                let count = state.quotas.entry(quota.key_id.clone()).or_insert(0);
                *count = count.checked_add(1).ok_or_else(|| {
                    BrokerError::Invariant("test authority quota overflow".to_string())
                })?;
            }
            state
                .hold_quotas
                .insert(request.hold_id.clone(), request.quotas.clone());
            state
                .holds
                .insert(request.hold_id.clone(), ExecutionHoldState::Held);
            Ok(ExecutionHoldState::Held)
        }

        fn reverse_execution_hold(
            &self,
            request: &ReverseExecutionHoldRequest,
        ) -> Result<ExecutionHoldState> {
            if !request.proof_dispatch_did_not_begin {
                return Err(BrokerError::AuthorizationDenied(
                    "test reversal lacks dispatch proof".to_string(),
                ));
            }
            let mut state = self.state.lock().expect("authority lock");
            match state.holds.get(&request.hold_id) {
                Some(ExecutionHoldState::Reversed) => return Ok(ExecutionHoldState::Reversed),
                Some(ExecutionHoldState::Held) => {}
                _ => {
                    return Err(BrokerError::Conflict(
                        "test reversal found an incompatible hold".to_string(),
                    ))
                }
            }
            let quotas = state.hold_quotas.remove(&request.hold_id).ok_or_else(|| {
                BrokerError::Invariant("test authority lost hold quotas".to_string())
            })?;
            for quota in quotas {
                let count = state.quotas.get_mut(&quota.key_id).ok_or_else(|| {
                    BrokerError::Invariant("test authority lost quota".to_string())
                })?;
                *count = count.checked_sub(1).ok_or_else(|| {
                    BrokerError::Invariant("test authority quota underflow".to_string())
                })?;
            }
            state
                .holds
                .insert(request.hold_id.clone(), ExecutionHoldState::Reversed);
            Ok(ExecutionHoldState::Reversed)
        }

        fn capture_execution_hold(
            &self,
            request: &CaptureExecutionHoldRequest,
        ) -> Result<ExecutionHoldState> {
            request.validate()?;
            let mut state = self.state.lock().expect("authority lock");
            if let Some(ExecutionHoldState::Captured(commit)) = state.holds.get(&request.hold_id) {
                return Ok(ExecutionHoldState::Captured(commit.clone()));
            }
            if !matches!(
                state.holds.get(&request.hold_id),
                Some(ExecutionHoldState::Held)
            ) {
                return Err(BrokerError::Conflict(
                    "test capture found a non-held reservation".to_string(),
                ));
            }
            if self.deny_capture {
                state
                    .holds
                    .insert(request.hold_id.clone(), ExecutionHoldState::Denied);
                return Ok(ExecutionHoldState::Denied);
            }
            let index = u64::try_from(state.holds.len())
                .expect("hold count")
                .checked_add(1)
                .expect("index");
            let commit = CombinedCaptureCommit {
                checked_revocation_set_digest: request.revocation_set_digest.clone(),
                budget_commit_index: index,
                revocation_commit_index: index,
                authority_commit_index: index,
                leader_epoch: 1,
            };
            state.holds.insert(
                request.hold_id.clone(),
                ExecutionHoldState::Captured(commit.clone()),
            );
            Ok(ExecutionHoldState::Captured(commit))
        }
    }

    struct LiveAuthority;

    impl CapabilityLiveness for LiveAuthority {
        fn verify_live_parent(
            &self,
            request: &CapabilityLivenessRequest,
        ) -> Result<LiveParentCapability> {
            Ok(LiveParentCapability {
                capability_id: request.parent_capability_id.clone(),
                subject: request.expected_subject.clone(),
                audience: request.expected_audience.clone(),
                delegation_ancestor_ids: vec!["delegation-ancestor".to_string()],
                expires_at_unix_seconds: 1_000,
                verified_at_unix_seconds: request.now_unix_seconds,
                authority_snapshot_digest: "a".repeat(64),
            })
        }
    }

    struct LiveRevocations;

    impl BrokerRevocations for LiveRevocations {
        fn check_broker_revocation(
            &self,
            request: &BrokerRevocationRequest,
        ) -> Result<BrokerRevocationSnapshot> {
            Ok(BrokerRevocationSnapshot {
                revoked: false,
                observed_at_unix_seconds: request.now_unix_seconds,
                commit_index: 1,
                authority_domain: "combined-authority".to_string(),
            })
        }
    }

    struct InspectingReceiptSink {
        canary: Vec<u8>,
        receipts: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl BrokerReceiptSink for InspectingReceiptSink {
        fn persist(&self, receipt: &SignedBrokerReceipt) -> Result<String> {
            let encoded = canonical_json_bytes(receipt)
                .map_err(|error| BrokerError::Storage(format!("test receipt: {error}")))?;
            if encoded
                .windows(self.canary.len())
                .any(|window| window == self.canary.as_slice())
            {
                return Err(BrokerError::Invariant(
                    "credential crossed into a receipt".to_string(),
                ));
            }
            self.receipts.lock().expect("receipt lock").push(encoded);
            Ok(format!("receipt-{}", receipt.body.receipt_id))
        }
    }

    struct Fixture {
        service: Arc<BrokerService>,
        issuer: Keypair,
        caller: Keypair,
        authority: Arc<AtomicAuthority>,
        observed_authorizations: Arc<Mutex<Vec<Vec<u8>>>>,
        canary: Vec<u8>,
    }

    fn fixture(maximum_executions: u32, fail_transport: bool, deny_capture: bool) -> Fixture {
        let canary = b"unique-service-credential-canary".to_vec();
        let backend = Arc::new(
            EncryptedBlobSecretBackend::open_in_memory_for_test("tenant-a", [7; 32])
                .expect("backend"),
        );
        backend
            .provision(
                &CredentialRef {
                    provider: "generic-https".to_string(),
                    credential_id: "credential-a".to_string(),
                    version: 1,
                },
                &canary,
            )
            .expect("provision");
        let observed_authorizations = Arc::new(Mutex::new(Vec::new()));
        let transport = Arc::new(ObservingTransport {
            observed_authorizations: Arc::clone(&observed_authorizations),
            fail: fail_transport,
            redirect: false,
        });
        let https = Arc::new(GenericHttpsExecutor::new(
            Arc::new(PublicResolver),
            transport,
            NetworkPolicy::production(),
        ));
        let authority = Arc::new(AtomicAuthority::new(deny_capture));
        let receipts = Arc::new(Mutex::new(Vec::new()));
        let issuer = Keypair::from_seed(&[1; 32]);
        let caller = Keypair::from_seed(&[2; 32]);
        let service = BrokerService::new(
            BrokerServiceConfig {
                production: true,
                audience: "broker-service".to_string(),
                parent_audience: "broker-parent".to_string(),
                maximum_clock_skew_seconds: 2,
                maximum_liveness_snapshot_age_seconds: 5,
                maximum_revocation_snapshot_age_seconds: 5,
            },
            issuer.public_key(),
            backend,
            Arc::new(
                GenericCredentialProvider::new(
                    "generic-bearer".to_string(),
                    1,
                    CredentialPlacement::BearerAuthorization,
                )
                .expect("provider"),
            ),
            https,
            Arc::new(SqliteAttemptStore::open_in_memory().expect("attempt store")),
            authority.clone(),
            Arc::new(LiveAuthority),
            Arc::new(LiveRevocations),
            Arc::new(InspectingReceiptSink {
                canary: canary.clone(),
                receipts,
            }),
            Keypair::from_seed(&[3; 32]),
        )
        .expect("service");
        let _ = maximum_executions;
        Fixture {
            service: Arc::new(service),
            issuer,
            caller,
            authority,
            observed_authorizations,
            canary,
        }
    }

    fn execution(
        fixture: &Fixture,
        invocation_index: usize,
        maximum_executions: u32,
    ) -> (BrokerExecuteRequest, TrustedExecutionContext) {
        let destination =
            BrokerDestination::parse("https://example.com/v1", "POST", false).expect("destination");
        let request = BrokerRequest {
            destination: destination.clone(),
            headers: Vec::new(),
            body: b"request-body".to_vec(),
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
                issuer: fixture.issuer.public_key(),
                capability_id: "broker-capability".to_string(),
                parent_capability_id: "parent-capability".to_string(),
                subject: fixture.caller.public_key(),
                audience: "broker-service".to_string(),
                issued_at_unix_seconds: 10,
                not_before_unix_seconds: 10,
                expires_at_unix_seconds: 1_000,
                credential: CredentialRef {
                    provider: "generic-https".to_string(),
                    credential_id: "credential-a".to_string(),
                    version: 1,
                },
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
                broker_quota_key_id: "broker-quota".to_string(),
                maximum_executions,
                consumption: AttemptConsumption::CaptureBeforeDispatch,
                revocation_id: "broker-revocation".to_string(),
                proof: ProofBinding {
                    mode: ProofMode::PublicKey,
                    caller_public_key: fixture.caller.public_key(),
                    nonce_ttl_seconds: 30,
                },
            },
            &fixture.issuer,
            true,
        )
        .expect("capability");
        let proof = issue_request_proof(
            &capability,
            &request,
            format!("nonce-{invocation_index:016}"),
            20,
            &fixture.caller,
        )
        .expect("proof");
        (
            BrokerExecuteRequest {
                schema: BROKER_EXECUTE_SCHEMA.to_string(),
                invocation_id: format!("invocation-{invocation_index}"),
                capability,
                proof,
                request,
            },
            TrustedExecutionContext {
                quotas: vec![
                    ExecutionQuota {
                        key_id: "broker-quota".to_string(),
                        maximum_executions,
                    },
                    ExecutionQuota {
                        key_id: "parent-grant-quota".to_string(),
                        maximum_executions: 100,
                    },
                ],
                authority_metadata_digest: "e".repeat(64),
                revocation_authority_domain: "combined-authority".to_string(),
            },
        )
    }

    #[test]
    fn framing_rejects_empty_and_oversized_frames() {
        let empty_bytes = 0_u32.to_be_bytes();
        let mut empty = empty_bytes.as_slice();
        assert!(read_bounded_frame(&mut empty).is_err());
        let oversized_bytes = u32::try_from(MAX_WIRE_BYTES + 1)
            .expect("u32")
            .to_be_bytes();
        let mut oversized = oversized_bytes.as_slice();
        assert!(read_bounded_frame(&mut oversized).is_err());
    }

    #[test]
    fn exactly_n_concurrent_requests_capture_and_only_upstream_sees_secret() {
        let maximum = 4;
        let fixture = Arc::new(fixture(maximum, false, false));
        let barrier = Arc::new(Barrier::new(12));
        let mut workers = Vec::new();
        for index in 0..12 {
            let fixture = Arc::clone(&fixture);
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                let (request, trusted) = execution(&fixture, index, maximum);
                barrier.wait();
                fixture.service.execute(&request, &trusted, 21)
            }));
        }
        let responses = workers
            .into_iter()
            .filter_map(|worker| worker.join().expect("worker").ok())
            .collect::<Vec<_>>();
        assert_eq!(responses.len(), usize::try_from(maximum).expect("maximum"));
        assert_eq!(fixture.authority.captured_count(), responses.len());
        let observed = fixture
            .observed_authorizations
            .lock()
            .expect("observed lock");
        assert_eq!(observed.len(), responses.len());
        for value in observed.iter() {
            assert_eq!(
                value,
                &[b"Bearer ".as_slice(), fixture.canary.as_slice()].concat()
            );
        }
        for response in responses {
            let encoded = canonical_json_bytes(&response).expect("response");
            assert!(!encoded
                .windows(fixture.canary.len())
                .any(|window| window == fixture.canary.as_slice()));
        }
    }

    #[test]
    fn timeout_after_capture_consumes_quota_and_records_unknown_outcome() {
        let fixture = fixture(1, true, false);
        let (request, trusted) = execution(&fixture, 1, 1);
        assert!(fixture.service.execute(&request, &trusted, 21).is_err());
        assert_eq!(fixture.authority.captured_count(), 1);
        let (second, trusted) = execution(&fixture, 2, 1);
        assert!(fixture.service.execute(&second, &trusted, 21).is_err());
        assert_eq!(fixture.authority.captured_count(), 1);
    }

    #[test]
    fn denied_combined_capture_never_dispatches() {
        let fixture = fixture(1, false, true);
        let (request, trusted) = execution(&fixture, 1, 1);
        assert!(fixture.service.execute(&request, &trusted, 21).is_err());
        assert!(fixture
            .observed_authorizations
            .lock()
            .expect("observed lock")
            .is_empty());
    }
}
