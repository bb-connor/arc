use std::os::unix::net::UnixStream;
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

use chio_core::{canonical_json_bytes, sha256_hex, Keypair, PublicKey, SigningBackend};
use chio_kernel::AuthoritativeCorrelatedFindingEvidence;
use chio_secure_ipc::{read_bounded_frame, write_bounded_frame};
use chio_security_types::ports::{
    AdmissionArtifactRef, AttestedFindingBatchBinding, PortError, PortResult, RequestId,
};

use super::protocol::validate_operation_result;
use super::transport::now_unix_seconds;
#[cfg(target_os = "linux")]
use super::transport::{
    connect_unix_stream_before, validate_connected_peer, validate_socket_metadata,
    AbsoluteDeadlineUnixStream,
};
use super::{
    active_response_authority_request_signing_bytes,
    active_response_authority_response_signing_bytes, ActiveResponseAuthorityOperation,
    ActiveResponseAuthorityRequestBody, ActiveResponseAuthorityResult,
    ProductionActiveResponseAuthorityFileConfig, SignedActiveResponseAuthorityRequest,
    SignedActiveResponseAuthorityResponse, ACTIVE_RESPONSE_AUTHORITY_REJECTION_KIND,
    ACTIVE_RESPONSE_AUTHORITY_SCHEMA,
};
use crate::security::event_consumer::{
    AttestedFindingAdmissionArtifacts, AttestedFindingResponsePolicyPlanner,
    AttestedFindingResponsePolicySelection, ReservedAttestedFindingResponsePlan,
};

pub struct ProductionActiveResponseAuthorityClient {
    config: ProductionActiveResponseAuthorityFileConfig,
    client_signer: Arc<dyn SigningBackend>,
    client_identity: PublicKey,
    #[cfg(all(test, target_os = "linux"))]
    allow_same_process_peer_for_test: bool,
}

impl ProductionActiveResponseAuthorityClient {
    pub fn new(
        config: ProductionActiveResponseAuthorityFileConfig,
        client_signer: Arc<dyn SigningBackend>,
    ) -> Result<Self, String> {
        config.validate()?;
        let signer_key = Self::validate_signer_and_role_separation(&config, &client_signer)?;
        #[cfg(target_os = "linux")]
        if config.expected_peer.process_id == std::process::id() {
            return Err(
                "active-response authority client and response authority must be separate processes"
                    .to_string(),
            );
        }
        Ok(Self {
            config,
            client_signer,
            client_identity: signer_key,
            #[cfg(all(test, target_os = "linux"))]
            allow_same_process_peer_for_test: false,
        })
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(super) fn new_for_test_with_same_process_policy(
        config: ProductionActiveResponseAuthorityFileConfig,
        client_signer: Arc<dyn SigningBackend>,
        allow_same_process_peer_for_test: bool,
    ) -> Result<Self, String> {
        config.validate()?;
        let signer_key = Self::validate_signer_and_role_separation(&config, &client_signer)?;
        Ok(Self {
            config,
            client_signer,
            client_identity: signer_key,
            allow_same_process_peer_for_test,
        })
    }

    fn validate_signer_and_role_separation(
        config: &ProductionActiveResponseAuthorityFileConfig,
        client_signer: &Arc<dyn SigningBackend>,
    ) -> Result<PublicKey, String> {
        let signer_key = client_signer.public_key();
        if signer_key.algorithm() != client_signer.algorithm() {
            return Err(
                "active-response authority client signer algorithm does not match its public key"
                    .to_string(),
            );
        }
        if config.trusted_authority == signer_key {
            return Err(
                "active-response authority client and response authority signing roles must use distinct keys"
                    .to_string(),
            );
        }
        Ok(signer_key)
    }

    pub(super) fn call(
        &self,
        operation: ActiveResponseAuthorityOperation,
    ) -> PortResult<ActiveResponseAuthorityResult> {
        #[cfg(target_os = "linux")]
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(self.config.timeout_ms))
            .ok_or_else(PortError::invalid_data)?;
        let expected_operation = operation.clone();
        let issued_at_unix_seconds = now_unix_seconds()?;
        let request = self.sign_request(operation, issued_at_unix_seconds)?;
        let request_bytes =
            canonical_json_bytes(&request).map_err(|_| PortError::invalid_data())?;
        let request_digest = sha256_hex(&request_bytes);
        #[cfg(target_os = "linux")]
        let mut stream = AbsoluteDeadlineUnixStream::with_deadline(
            self.connect_authenticated(deadline)?,
            deadline,
        )?;
        #[cfg(not(target_os = "linux"))]
        let mut stream = self.connect_authenticated()?;
        write_bounded_frame(
            &mut stream,
            &request_bytes,
            super::MAX_ACTIVE_RESPONSE_AUTHORITY_WIRE_BYTES,
        )
        .map_err(|_| PortError::unavailable())?;
        let response_bytes =
            read_bounded_frame(&mut stream, super::MAX_ACTIVE_RESPONSE_AUTHORITY_WIRE_BYTES)
                .map_err(|_| PortError::unavailable())?;
        let response: SignedActiveResponseAuthorityResponse =
            serde_json::from_slice(&response_bytes).map_err(|_| PortError::integrity_failure())?;
        let canonical =
            canonical_json_bytes(&response).map_err(|_| PortError::integrity_failure())?;
        if canonical != response_bytes {
            return Err(PortError::integrity_failure());
        }
        self.verify_response(
            &response,
            request.body.request_id.as_str(),
            &request_digest,
            now_unix_seconds()?,
        )?;
        validate_operation_result(&expected_operation, &response.body.result)?;
        match response.body.result {
            ActiveResponseAuthorityResult::Rejected(rejection) => Err(PortError::new(
                match rejection.classification {
                    super::ActiveResponseAuthorityRejectionClass::Permanent => {
                        ACTIVE_RESPONSE_AUTHORITY_REJECTION_KIND
                    }
                    super::ActiveResponseAuthorityRejectionClass::Transient => {
                        super::ACTIVE_RESPONSE_AUTHORITY_TRANSIENT_REJECTION_KIND
                    }
                },
                rejection.code,
            )),
            result => Ok(result),
        }
    }

    pub(super) fn sign_request(
        &self,
        operation: ActiveResponseAuthorityOperation,
        issued_at_unix_seconds: u64,
    ) -> PortResult<SignedActiveResponseAuthorityRequest> {
        if issued_at_unix_seconds == 0 {
            return Err(PortError::unavailable());
        }
        let expected_client = self.client_identity.clone();
        if self.client_signer.public_key() != expected_client
            || self.client_signer.algorithm() != expected_client.algorithm()
        {
            return Err(PortError::integrity_failure());
        }
        let body = ActiveResponseAuthorityRequestBody {
            schema: ACTIVE_RESPONSE_AUTHORITY_SCHEMA.to_string(),
            request_id: RequestId::new(Keypair::generate().public_key().to_hex())
                .map_err(PortError::from)?,
            issued_at_unix_seconds,
            client: expected_client.clone(),
            operation,
        };
        let canonical = active_response_authority_request_signing_bytes(&body)?;
        let signed = self
            .client_signer
            .sign_bytes_for_identity(&expected_client, &canonical)
            .map_err(|_| PortError::unavailable())?;
        if signed.public_key != expected_client
            || signed.algorithm != expected_client.algorithm()
            || signed.signature.algorithm() != signed.algorithm
            || !expected_client.verify(&canonical, &signed.signature)
        {
            return Err(PortError::integrity_failure());
        }
        Ok(SignedActiveResponseAuthorityRequest {
            body,
            algorithm: signed.algorithm,
            signature: signed.signature,
        })
    }

    pub(super) fn verify_response(
        &self,
        response: &SignedActiveResponseAuthorityResponse,
        expected_request_id: &str,
        expected_request_digest: &str,
        now_unix_seconds: u64,
    ) -> PortResult<()> {
        let body = &response.body;
        let trusted = &self.config.trusted_authority;
        let earliest = now_unix_seconds.saturating_sub(self.config.maximum_clock_skew_seconds);
        let latest = now_unix_seconds
            .checked_add(self.config.maximum_clock_skew_seconds)
            .ok_or_else(PortError::invalid_data)?;
        if body.schema != ACTIVE_RESPONSE_AUTHORITY_SCHEMA
            || body.request_id.as_str() != expected_request_id
            || body.request_digest != expected_request_digest
            || body.issued_at_unix_seconds < earliest
            || body.issued_at_unix_seconds > latest
            || &body.authority != trusted
            || response.algorithm != trusted.algorithm()
            || response.signature.algorithm() != response.algorithm
        {
            return Err(PortError::integrity_failure());
        }
        let canonical = active_response_authority_response_signing_bytes(body)?;
        if !trusted.verify(&canonical, &response.signature) {
            return Err(PortError::integrity_failure());
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn connect_authenticated(&self, deadline: Instant) -> PortResult<UnixStream> {
        if self.config.expected_peer.process_id == std::process::id() {
            #[cfg(test)]
            if self.allow_same_process_peer_for_test {
                return self.connect_authenticated_after_process_check(deadline);
            }
            return Err(PortError::integrity_failure());
        }
        self.connect_authenticated_after_process_check(deadline)
    }

    #[cfg(target_os = "linux")]
    fn connect_authenticated_after_process_check(
        &self,
        deadline: Instant,
    ) -> PortResult<UnixStream> {
        let socket_identity =
            validate_socket_metadata(&self.config.socket_path, self.config.expected_peer.user_id)?;
        let stream = connect_unix_stream_before(&self.config.socket_path, deadline)?;
        validate_connected_peer(&stream, &self.config.expected_peer)?;
        if validate_socket_metadata(&self.config.socket_path, self.config.expected_peer.user_id)?
            != socket_identity
        {
            return Err(PortError::integrity_failure());
        }
        Ok(stream)
    }

    #[cfg(not(target_os = "linux"))]
    fn connect_authenticated(&self) -> PortResult<UnixStream> {
        Err(PortError::unavailable())
    }
}

impl AttestedFindingResponsePolicyPlanner for ProductionActiveResponseAuthorityClient {
    fn ensure_ready(&self) -> PortResult<()> {
        match self.call(ActiveResponseAuthorityOperation::Health)? {
            ActiveResponseAuthorityResult::Ready { protocol }
                if protocol == ACTIVE_RESPONSE_AUTHORITY_SCHEMA =>
            {
                Ok(())
            }
            _ => Err(PortError::integrity_failure()),
        }
    }

    fn trusted_artifact_authority(&self) -> PortResult<PublicKey> {
        Ok(self.config.trusted_authority.clone())
    }

    fn select_response_policy(
        &self,
        finding: &AuthoritativeCorrelatedFindingEvidence,
        binding: &AttestedFindingBatchBinding,
    ) -> PortResult<AttestedFindingResponsePolicySelection> {
        let result = self.call(ActiveResponseAuthorityOperation::SelectPolicy {
            evidence_id: finding.evidence_id().clone(),
            finding: finding.body().clone(),
            binding: binding.clone(),
        })?;
        let ActiveResponseAuthorityResult::Policy(selection) = result else {
            return Err(PortError::integrity_failure());
        };
        if selection.action_id != binding.action_id || selection.evidence_id != binding.evidence_id
        {
            return Err(PortError::integrity_failure());
        }
        Ok(AttestedFindingResponsePolicySelection {
            admission_artifact_ref: selection.admission_artifact_ref,
            affected_ids: selection.affected_ids.into_vec(),
            effects: selection.effects.into_vec(),
            ttl_ms: selection.ttl_ms,
            created_at_unix_ms: selection.created_at_unix_ms,
            operator_capability: selection.operator_capability,
            approval_requirement: selection.approval_requirement,
            submitter: selection.submitter,
            reason_hash: selection.reason_hash,
        })
    }

    fn load_admission_artifacts(
        &self,
        plan: &ReservedAttestedFindingResponsePlan,
        artifact_ref: &AdmissionArtifactRef,
    ) -> PortResult<AttestedFindingAdmissionArtifacts> {
        let result = self.call(ActiveResponseAuthorityOperation::LoadArtifacts {
            response_plan: plan.response_plan().clone(),
            admission_artifact_ref: artifact_ref.clone(),
        })?;
        let ActiveResponseAuthorityResult::Artifacts(artifacts) = result else {
            return Err(PortError::integrity_failure());
        };
        if artifacts.action_id != plan.response_plan().action_id
            || artifacts.plan_hash != plan.response_plan().plan_hash
            || &artifacts.admission_artifact_ref != artifact_ref
        {
            return Err(PortError::integrity_failure());
        }
        Ok(AttestedFindingAdmissionArtifacts::new(
            artifacts.admission_artifact_ref,
            artifacts.operator_capability,
            artifacts.governed_intent,
            artifacts.submission_proof,
            artifacts.authority_attestation,
            artifacts.threshold_proposal,
            artifacts.approval_tokens.into_vec(),
        ))
    }
}
