use std::os::unix::net::UnixStream;
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::{collections::BTreeMap, sync::Mutex};

#[cfg(target_os = "linux")]
use chio_core::{canonical_json_bytes, sha256_hex};
use chio_core::{PublicKey, SigningBackend};
use chio_secure_ipc::PeerIdentity;
#[cfg(target_os = "linux")]
use chio_secure_ipc::{read_bounded_frame, write_bounded_frame};
#[cfg(target_os = "linux")]
use chio_security_types::ports::RequestId;
use chio_security_types::ports::{
    AdmissionArtifactRef, AttestedFindingBatchBinding, Digest32, ErrorCode, OpaqueReceiptRef,
    PortError, PortErrorKind, PortResult,
};
use chio_security_types::ResponsePlan;
use serde::{Deserialize, Serialize};

#[cfg(target_os = "linux")]
use super::transport::{
    now_unix_millis, now_unix_seconds, validate_connected_peer, AbsoluteDeadlineUnixStream,
};
#[cfg(target_os = "linux")]
use super::{
    active_response_authority_request_signing_bytes,
    active_response_authority_response_signing_bytes, ActiveResponseAdmissionArtifactsWire,
    ActiveResponseAuthorityResponseBody, SignedActiveResponseAuthorityRequest,
    SignedActiveResponseAuthorityResponse,
};
use super::{
    validate_active_response_artifacts_draft, validate_active_response_policy_selection,
    ActiveResponseAdmissionArtifactsDraftWire, ActiveResponseAuthorityOperation,
    ActiveResponseAuthorityRejection, ActiveResponseAuthorityResult,
    ActiveResponsePolicySelectionWire, ACTIVE_RESPONSE_AUTHORITY_SCHEMA,
    MAX_ACTIVE_RESPONSE_AUTHORITY_CLOCK_SKEW_SECONDS,
};
#[cfg(target_os = "linux")]
use chio_kernel::ActiveResponseArtifactAuthorityAttestation;

#[cfg(target_os = "linux")]
use crate::security::AttestedFindingAdmissionArtifacts;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActiveResponseAuthorityProtocolServerConfig {
    pub expected_client_peer: PeerIdentity,
    pub trusted_client: PublicKey,
    pub deployment_digest: Digest32,
    pub store_digest: Digest32,
    pub timeout_ms: u64,
    pub maximum_clock_skew_seconds: u64,
    pub maximum_replay_entries: usize,
}

impl ActiveResponseAuthorityProtocolServerConfig {
    fn validate(&self) -> Result<(), String> {
        if self.expected_client_peer.process_id == 0
            || self.timeout_ms == 0
            || self.timeout_ms > 30_000
            || self.maximum_clock_skew_seconds == 0
            || self.maximum_clock_skew_seconds > MAX_ACTIVE_RESPONSE_AUTHORITY_CLOCK_SKEW_SECONDS
            || self.maximum_replay_entries == 0
            || self.maximum_replay_entries > 65_536
            || self.deployment_digest.is_zero()
            || self.store_digest.is_zero()
        {
            return Err("active-response protocol server bounds are invalid".to_string());
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum ActiveResponseAuthorityHandlerError {
    Rejected(ActiveResponseAuthorityRejection),
    Fatal(PortError),
}

impl From<ActiveResponseAuthorityRejection> for ActiveResponseAuthorityHandlerError {
    fn from(rejection: ActiveResponseAuthorityRejection) -> Self {
        Self::Rejected(rejection)
    }
}

pub type ActiveResponseAuthorityHandlerResult<T> = Result<T, ActiveResponseAuthorityHandlerError>;

pub trait ActiveResponseAuthorityHandler: Send + Sync {
    fn health(&self) -> ActiveResponseAuthorityHandlerResult<()>;

    fn select_policy(
        &self,
        evidence_id: &OpaqueReceiptRef,
        finding: &chio_core::receipt::security::CorrelatedFindingReceiptBody,
        binding: &AttestedFindingBatchBinding,
    ) -> ActiveResponseAuthorityHandlerResult<ActiveResponsePolicySelectionWire>;

    fn load_artifacts(
        &self,
        response_plan: &ResponsePlan,
        admission_artifact_ref: &AdmissionArtifactRef,
    ) -> ActiveResponseAuthorityHandlerResult<ActiveResponseAdmissionArtifactsDraftWire>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActiveResponseAuthorityServeOutcome {
    ResponseWritten,
    ClientFault {
        kind: PortErrorKind,
        code: ErrorCode,
    },
}

#[cfg(target_os = "linux")]
enum ServeFailure {
    Client(PortError),
    Internal(PortError),
}

/// Authenticated wire protocol for an externally owned response authority.
///
/// This type deliberately does not bind, unlink, chmod, or otherwise own a
/// socket path. The caller must accept the stream from a broker-grade socket
/// lifecycle that provides exclusive bind custody and exact inode cleanup.
/// `serve_one` authenticates the connected peer before parsing any bytes and
/// then enforces canonical framing, signatures, freshness, replay protection,
/// and one absolute I/O deadline.
pub struct ActiveResponseAuthorityProtocolServer {
    #[cfg(target_os = "linux")]
    config: ActiveResponseAuthorityProtocolServerConfig,
    #[cfg(target_os = "linux")]
    authority_signer: Arc<dyn SigningBackend>,
    #[cfg(target_os = "linux")]
    authority_identity: PublicKey,
    #[cfg(target_os = "linux")]
    handler: Arc<dyn ActiveResponseAuthorityHandler>,
    #[cfg(target_os = "linux")]
    replay_cache: Mutex<BTreeMap<RequestId, u64>>,
    #[cfg(all(test, target_os = "linux"))]
    allow_same_process_peer_for_test: bool,
}

impl ActiveResponseAuthorityProtocolServer {
    pub fn new(
        config: ActiveResponseAuthorityProtocolServerConfig,
        authority_signer: Arc<dyn SigningBackend>,
        handler: Arc<dyn ActiveResponseAuthorityHandler>,
    ) -> Result<Self, String> {
        config.validate()?;
        let authority_identity =
            Self::validate_signer_and_role_separation(&config, &authority_signer)?;
        #[cfg(target_os = "linux")]
        if config.expected_client_peer.process_id == std::process::id() {
            return Err(
                "active-response authority server and broker client must be separate processes"
                    .to_string(),
            );
        }
        #[cfg(not(target_os = "linux"))]
        let _ = (authority_identity, handler);
        Ok(Self {
            #[cfg(target_os = "linux")]
            config,
            #[cfg(target_os = "linux")]
            authority_signer,
            #[cfg(target_os = "linux")]
            authority_identity,
            #[cfg(target_os = "linux")]
            handler,
            #[cfg(target_os = "linux")]
            replay_cache: Mutex::new(BTreeMap::new()),
            #[cfg(all(test, target_os = "linux"))]
            allow_same_process_peer_for_test: false,
        })
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(super) fn new_for_test_with_same_process_policy(
        config: ActiveResponseAuthorityProtocolServerConfig,
        authority_signer: Arc<dyn SigningBackend>,
        handler: Arc<dyn ActiveResponseAuthorityHandler>,
        allow_same_process_peer_for_test: bool,
    ) -> Result<Self, String> {
        config.validate()?;
        let authority_identity =
            Self::validate_signer_and_role_separation(&config, &authority_signer)?;
        Ok(Self {
            config,
            authority_signer,
            authority_identity,
            handler,
            replay_cache: Mutex::new(BTreeMap::new()),
            allow_same_process_peer_for_test,
        })
    }

    fn validate_signer_and_role_separation(
        config: &ActiveResponseAuthorityProtocolServerConfig,
        authority_signer: &Arc<dyn SigningBackend>,
    ) -> Result<PublicKey, String> {
        let authority_identity = authority_signer.public_key();
        if authority_identity.algorithm() != authority_signer.algorithm() {
            return Err(
                "active-response authority signer algorithm does not match its public key"
                    .to_string(),
            );
        }
        if authority_identity == config.trusted_client {
            return Err(
                "active-response authority server and broker client signing roles must use distinct keys"
                    .to_string(),
            );
        }
        Ok(authority_identity)
    }

    #[cfg(target_os = "linux")]
    pub fn serve_one(&self, stream: UnixStream) -> PortResult<ActiveResponseAuthorityServeOutcome> {
        match self.serve_stream(stream) {
            Ok(()) => Ok(ActiveResponseAuthorityServeOutcome::ResponseWritten),
            Err(ServeFailure::Client(error)) => {
                Ok(ActiveResponseAuthorityServeOutcome::ClientFault {
                    kind: error.kind(),
                    code: error.code().clone(),
                })
            }
            Err(ServeFailure::Internal(error)) => Err(error),
        }
    }

    #[cfg(target_os = "linux")]
    fn serve_stream(&self, stream: UnixStream) -> Result<(), ServeFailure> {
        if self.config.expected_client_peer.process_id == std::process::id() {
            #[cfg(test)]
            if !self.allow_same_process_peer_for_test {
                return Err(ServeFailure::Internal(PortError::integrity_failure()));
            }
            #[cfg(not(test))]
            return Err(ServeFailure::Internal(PortError::integrity_failure()));
        }
        validate_connected_peer(&stream, &self.config.expected_client_peer)
            .map_err(ServeFailure::Client)?;
        let mut stream =
            AbsoluteDeadlineUnixStream::new(stream, Duration::from_millis(self.config.timeout_ms))
                .map_err(ServeFailure::Internal)?;
        let request_bytes =
            read_bounded_frame(&mut stream, super::MAX_ACTIVE_RESPONSE_AUTHORITY_WIRE_BYTES)
                .map_err(|_| ServeFailure::Client(PortError::invalid_data()))?;
        let request: SignedActiveResponseAuthorityRequest = serde_json::from_slice(&request_bytes)
            .map_err(|_| ServeFailure::Client(PortError::integrity_failure()))?;
        let canonical = canonical_json_bytes(&request)
            .map_err(|_| ServeFailure::Client(PortError::integrity_failure()))?;
        if canonical != request_bytes {
            return Err(ServeFailure::Client(PortError::integrity_failure()));
        }
        self.verify_and_reserve_request(
            &request,
            now_unix_seconds().map_err(ServeFailure::Internal)?,
        )?;
        let result = self.dispatch(&request.body.operation)?;
        validate_operation_result(&request.body.operation, &result)
            .map_err(ServeFailure::Internal)?;
        if self.authority_signer.public_key() != self.authority_identity
            || self.authority_signer.algorithm() != self.authority_identity.algorithm()
        {
            return Err(ServeFailure::Internal(PortError::integrity_failure()));
        }
        let body = ActiveResponseAuthorityResponseBody {
            schema: ACTIVE_RESPONSE_AUTHORITY_SCHEMA.to_string(),
            deployment_digest: self.config.deployment_digest,
            store_digest: self.config.store_digest,
            request_id: request.body.request_id.clone(),
            request_digest: sha256_hex(&request_bytes),
            issued_at_unix_seconds: now_unix_seconds().map_err(ServeFailure::Internal)?,
            authority: self.authority_identity.clone(),
            result,
        };
        let canonical_signing_input = active_response_authority_response_signing_bytes(&body)
            .map_err(ServeFailure::Internal)?;
        let signed = self
            .authority_signer
            .sign_bytes_for_identity(&self.authority_identity, &canonical_signing_input)
            .map_err(|_| ServeFailure::Internal(PortError::unavailable()))?;
        if signed.public_key != self.authority_identity
            || signed.algorithm != self.authority_identity.algorithm()
            || signed.signature.algorithm() != signed.algorithm
            || !self
                .authority_identity
                .verify(&canonical_signing_input, &signed.signature)
        {
            return Err(ServeFailure::Internal(PortError::integrity_failure()));
        }
        let response = SignedActiveResponseAuthorityResponse {
            body,
            algorithm: signed.algorithm,
            signature: signed.signature,
        };
        let response_bytes = canonical_json_bytes(&response)
            .map_err(|_| ServeFailure::Internal(PortError::invalid_data()))?;
        write_bounded_frame(
            &mut stream,
            &response_bytes,
            super::MAX_ACTIVE_RESPONSE_AUTHORITY_WIRE_BYTES,
        )
        .map_err(|_| ServeFailure::Client(PortError::unavailable()))
    }

    #[cfg(not(target_os = "linux"))]
    pub fn serve_one(
        &self,
        _stream: UnixStream,
    ) -> PortResult<ActiveResponseAuthorityServeOutcome> {
        Err(PortError::unavailable())
    }

    #[cfg(target_os = "linux")]
    fn dispatch(
        &self,
        operation: &ActiveResponseAuthorityOperation,
    ) -> Result<ActiveResponseAuthorityResult, ServeFailure> {
        let result = match operation {
            ActiveResponseAuthorityOperation::Health => {
                self.handler
                    .health()
                    .map(|()| ActiveResponseAuthorityResult::Ready {
                        protocol: ACTIVE_RESPONSE_AUTHORITY_SCHEMA.to_string(),
                        deployment_digest: self.config.deployment_digest,
                        store_digest: self.config.store_digest,
                    })
            }
            ActiveResponseAuthorityOperation::SelectPolicy {
                evidence_id,
                finding,
                binding,
            } => self
                .handler
                .select_policy(evidence_id, finding, binding)
                .map(|selection| ActiveResponseAuthorityResult::Policy(Box::new(selection))),
            ActiveResponseAuthorityOperation::LoadArtifacts {
                response_plan,
                admission_artifact_ref,
            } => match self
                .handler
                .load_artifacts(response_plan, admission_artifact_ref)
            {
                Ok(draft) => {
                    return self
                        .sign_artifact_bundle(response_plan, admission_artifact_ref, draft)
                        .map(|artifacts| {
                            ActiveResponseAuthorityResult::Artifacts(Box::new(artifacts))
                        })
                        .map_err(ServeFailure::Internal)
                }
                Err(error) => Err(error),
            },
        };
        match result {
            Ok(result) => Ok(result),
            Err(ActiveResponseAuthorityHandlerError::Rejected(rejection)) => {
                Ok(ActiveResponseAuthorityResult::Rejected(rejection))
            }
            Err(ActiveResponseAuthorityHandlerError::Fatal(error)) => {
                Err(ServeFailure::Internal(error))
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn sign_artifact_bundle(
        &self,
        response_plan: &ResponsePlan,
        expected_ref: &AdmissionArtifactRef,
        draft: ActiveResponseAdmissionArtifactsDraftWire,
    ) -> PortResult<ActiveResponseAdmissionArtifactsWire> {
        validate_active_response_artifacts_draft(
            response_plan,
            expected_ref,
            &self.authority_identity,
            &draft,
        )?;
        let authority_attestation = ActiveResponseArtifactAuthorityAttestation::sign_with_backend(
            draft.authority_attestation_body,
            self.authority_signer.as_ref(),
        )
        .map_err(|_| PortError::integrity_failure())?;
        let verified = AttestedFindingAdmissionArtifacts::new(
            draft.admission_artifact_ref.clone(),
            draft.operator_capability.clone(),
            draft.governed_intent.clone(),
            draft.submission_proof.clone(),
            authority_attestation.clone(),
            draft.threshold_proposal.clone(),
            draft.approval_tokens.as_slice().to_vec(),
        );
        verified.verify_authority_attestation(
            expected_ref,
            response_plan,
            &self.authority_identity,
            now_unix_millis()?,
        )?;
        Ok(ActiveResponseAdmissionArtifactsWire {
            action_id: draft.action_id,
            plan_hash: draft.plan_hash,
            admission_artifact_ref: draft.admission_artifact_ref,
            operator_capability: draft.operator_capability,
            governed_intent: draft.governed_intent,
            submission_proof: draft.submission_proof,
            authority_attestation,
            threshold_proposal: draft.threshold_proposal,
            approval_tokens: draft.approval_tokens,
        })
    }

    #[cfg(target_os = "linux")]
    fn verify_and_reserve_request(
        &self,
        request: &SignedActiveResponseAuthorityRequest,
        now_unix_seconds: u64,
    ) -> Result<(), ServeFailure> {
        let body = &request.body;
        let earliest = now_unix_seconds.saturating_sub(self.config.maximum_clock_skew_seconds);
        let latest = now_unix_seconds
            .checked_add(self.config.maximum_clock_skew_seconds)
            .ok_or_else(PortError::invalid_data)
            .map_err(ServeFailure::Client)?;
        if body.schema != ACTIVE_RESPONSE_AUTHORITY_SCHEMA
            || body.deployment_digest != self.config.deployment_digest
            || body.store_digest != self.config.store_digest
            || body.issued_at_unix_seconds < earliest
            || body.issued_at_unix_seconds > latest
            || body.client != self.config.trusted_client
            || request.algorithm != self.config.trusted_client.algorithm()
            || request.signature.algorithm() != request.algorithm
        {
            return Err(ServeFailure::Client(PortError::integrity_failure()));
        }
        let canonical =
            active_response_authority_request_signing_bytes(body).map_err(ServeFailure::Client)?;
        if !self
            .config
            .trusted_client
            .verify(&canonical, &request.signature)
        {
            return Err(ServeFailure::Client(PortError::integrity_failure()));
        }
        let mut replay_cache = self
            .replay_cache
            .lock()
            .map_err(|_| ServeFailure::Internal(PortError::unavailable()))?;
        replay_cache.retain(|_, issued_at| *issued_at >= earliest);
        if replay_cache.contains_key(&body.request_id) {
            return Err(ServeFailure::Client(PortError::conflict()));
        }
        if replay_cache.len() >= self.config.maximum_replay_entries {
            return Err(ServeFailure::Client(PortError::unavailable()));
        }
        replay_cache.insert(body.request_id.clone(), body.issued_at_unix_seconds);
        Ok(())
    }
}

pub(super) fn validate_operation_result(
    operation: &ActiveResponseAuthorityOperation,
    result: &ActiveResponseAuthorityResult,
) -> PortResult<()> {
    match (operation, result) {
        (
            ActiveResponseAuthorityOperation::Health,
            ActiveResponseAuthorityResult::Ready {
                protocol,
                deployment_digest,
                store_digest,
            },
        ) if protocol == ACTIVE_RESPONSE_AUTHORITY_SCHEMA
            && !deployment_digest.is_zero()
            && !store_digest.is_zero() =>
        {
            Ok(())
        }
        (
            ActiveResponseAuthorityOperation::SelectPolicy {
                evidence_id,
                binding,
                ..
            },
            ActiveResponseAuthorityResult::Policy(selection),
        ) if validate_active_response_policy_selection(evidence_id, binding, selection).is_ok() => {
            Ok(())
        }
        (
            ActiveResponseAuthorityOperation::LoadArtifacts {
                response_plan,
                admission_artifact_ref,
            },
            ActiveResponseAuthorityResult::Artifacts(artifacts),
        ) if artifacts.action_id == response_plan.action_id
            && artifacts.plan_hash == response_plan.plan_hash
            && &artifacts.admission_artifact_ref == admission_artifact_ref
            && &artifacts.authority_attestation.body.artifact_ref == admission_artifact_ref
            && artifacts.authority_attestation.body.action_id == response_plan.action_id
            && artifacts.authority_attestation.body.tenant_id == response_plan.tenant_id =>
        {
            Ok(())
        }
        (_, ActiveResponseAuthorityResult::Rejected(_)) => Ok(()),
        _ => Err(PortError::integrity_failure()),
    }
}
