use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core_types::canonical_json_bytes;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::authority_ipc::{AuthorityControlRequest, BrokerAdmissionAuthority};
use crate::capability::verify_capability;
use crate::encrypted_blob_backend::EncryptedBlobSecretBackend;
use crate::protocol::{
    BrokerCapabilityBody, BrokerExecuteRequest, CredentialRef, SignedBrokerCapability,
};
use crate::provision::{
    AdminAuthorization, AdminOperation, GovernedAdminAuthorizer, RedactedAdminReceipt,
};
use crate::service::{
    AuthenticatedIpcRequest, BrokerIpcHandler, BrokerService, IpcOperation, IpcResponse,
};
use crate::{validate_digest, validate_identifier, BrokerError, Result};

pub const DAEMON_ADMIN_INTENT_SCHEMA: &str = "chio.broker-daemon-admin-intent.v1";
pub const ISSUE_CAPABILITY_SCHEMA: &str = "chio.broker-issue-capability.v1";
pub const CAPABILITY_CONTROL_SCHEMA: &str = "chio.broker-capability-control.v1";
pub const CAPABILITY_STATUS_SCHEMA: &str = "chio.broker-capability-status.v1";
pub const CREDENTIAL_MUTATION_SCHEMA: &str = "chio.broker-credential-mutation.v1";
const DAEMON_ADMIN_INTENT_DOMAIN: &[u8] = b"chio.broker-daemon-admin-intent.v1\0";
const MAX_DAEMON_COMBINED_RESPONSE_BYTES: u64 = 16_384;

pub trait DaemonClock: Send + Sync {
    fn now_unix_seconds(&self) -> Result<u64>;
}

#[derive(Debug, Default)]
pub struct SystemDaemonClock;

impl DaemonClock for SystemDaemonClock {
    fn now_unix_seconds(&self) -> Result<u64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|error| {
                BrokerError::AuthorityUnavailable(format!("daemon clock failed: {error}"))
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IssueCapabilityCommand {
    pub schema: String,
    pub body: BrokerCapabilityBody,
}

impl IssueCapabilityCommand {
    fn validate(&self, trusted_issuer: &chio_core_types::PublicKey) -> Result<()> {
        if self.schema != ISSUE_CAPABILITY_SCHEMA || &self.body.issuer != trusted_issuer {
            return Err(BrokerError::AuthorizationDenied(
                "capability issue schema or issuer is invalid".to_string(),
            ));
        }
        self.body.validate(true)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityControlCommand {
    pub schema: String,
    pub capability_id: String,
    pub revocation_id: String,
    pub credential: CredentialRef,
}

impl CapabilityControlCommand {
    fn validate(&self) -> Result<()> {
        if self.schema != CAPABILITY_CONTROL_SCHEMA {
            return Err(BrokerError::InvalidRequest(
                "capability control schema is invalid".to_string(),
            ));
        }
        validate_identifier(&self.capability_id, "broker capability id", 512)?;
        validate_identifier(&self.revocation_id, "broker revocation id", 512)?;
        self.credential.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityStatusResponse {
    pub schema: String,
    pub capability_id: String,
    pub revocation_id: String,
    pub revoked: bool,
    pub authority_commit_index: u64,
    pub observed_at_unix_seconds: u64,
}

impl CapabilityStatusResponse {
    fn validate_for(&self, command: &CapabilityControlCommand) -> Result<()> {
        if self.schema != CAPABILITY_STATUS_SCHEMA
            || self.capability_id != command.capability_id
            || self.revocation_id != command.revocation_id
            || self.observed_at_unix_seconds == 0
        {
            return Err(BrokerError::AuthorityUnavailable(
                "authority capability status is misbound or malformed".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CredentialMutationKind {
    Provision,
    Rotate,
    Disable,
    Delete,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CredentialMutationCommand {
    schema: String,
    mutation: CredentialMutationKind,
    credential: CredentialRef,
    secret: Vec<u8>,
}

impl CredentialMutationCommand {
    fn validate(&self, expected: CredentialMutationKind) -> Result<()> {
        if self.schema != CREDENTIAL_MUTATION_SCHEMA || self.mutation != expected {
            return Err(BrokerError::InvalidRequest(
                "credential mutation schema or operation is invalid".to_string(),
            ));
        }
        self.credential.validate()?;
        let requires_secret = matches!(
            self.mutation,
            CredentialMutationKind::Provision | CredentialMutationKind::Rotate
        );
        if (requires_secret && (self.secret.is_empty() || self.secret.len() > 65_536))
            || (!requires_secret && !self.secret.is_empty())
        {
            return Err(BrokerError::InvalidRequest(
                "credential mutation secret presence or size is invalid".to_string(),
            ));
        }
        Ok(())
    }
}

impl Drop for CredentialMutationCommand {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DaemonAdminIntent<'a> {
    schema: &'static str,
    operation: IpcOperation,
    tenant_scope: &'a str,
    payload_digest: String,
}

pub fn daemon_admin_intent_digest(
    operation: IpcOperation,
    tenant_scope: &str,
    canonical_payload: &[u8],
) -> Result<String> {
    validate_identifier(tenant_scope, "daemon tenant scope", 512)?;
    if canonical_payload.is_empty() || canonical_payload.len() > crate::protocol::MAX_WIRE_BYTES {
        return Err(BrokerError::InvalidRequest(
            "daemon admin payload is empty or oversized".to_string(),
        ));
    }
    let intent = DaemonAdminIntent {
        schema: DAEMON_ADMIN_INTENT_SCHEMA,
        operation,
        tenant_scope,
        payload_digest: hex::encode(Sha256::digest(canonical_payload)),
    };
    let canonical = canonical_json_bytes(&intent).map_err(|error| {
        BrokerError::Invariant(format!("daemon admin intent encoding failed: {error}"))
    })?;
    let mut hasher = Sha256::new();
    hasher.update(DAEMON_ADMIN_INTENT_DOMAIN);
    hasher.update(canonical);
    Ok(hex::encode(hasher.finalize()))
}

pub struct BrokerDaemonHandler {
    tenant_scope: String,
    audience: String,
    trusted_issuer: chio_core_types::PublicKey,
    service: Arc<BrokerService>,
    admission: Arc<dyn BrokerAdmissionAuthority>,
    admin: Arc<GovernedAdminAuthorizer>,
    backend: Arc<EncryptedBlobSecretBackend>,
    clock: Arc<dyn DaemonClock>,
}

impl BrokerDaemonHandler {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant_scope: String,
        audience: String,
        trusted_issuer: chio_core_types::PublicKey,
        service: Arc<BrokerService>,
        admission: Arc<dyn BrokerAdmissionAuthority>,
        admin: Arc<GovernedAdminAuthorizer>,
        backend: Arc<EncryptedBlobSecretBackend>,
        clock: Arc<dyn DaemonClock>,
    ) -> Result<Self> {
        validate_identifier(&tenant_scope, "daemon tenant scope", 512)?;
        validate_identifier(&audience, "daemon broker audience", 512)?;
        Ok(Self {
            tenant_scope,
            audience,
            trusted_issuer,
            service,
            admission,
            admin,
            backend,
            clock,
        })
    }

    fn validate_envelope(
        &self,
        request: &AuthenticatedIpcRequest,
        expected: IpcOperation,
    ) -> Result<()> {
        if request.operation != expected || request.tenant_scope != self.tenant_scope {
            return Err(BrokerError::AuthorizationDenied(
                "IPC operation or tenant scope is invalid".to_string(),
            ));
        }
        if request.authorization.is_empty()
            || request.authorization.len() > 65_536
            || request.payload.is_empty()
            || request.payload.len() > crate::protocol::MAX_WIRE_BYTES
        {
            return Err(BrokerError::InvalidRequest(
                "IPC authorization or payload is empty or oversized".to_string(),
            ));
        }
        Ok(())
    }

    fn govern(&self, request: &AuthenticatedIpcRequest) -> Result<String> {
        let intent =
            daemon_admin_intent_digest(request.operation, &request.tenant_scope, &request.payload)?;
        let authorization = AdminAuthorization::new(request.authorization.clone())?;
        self.admin.authorize_intent_digest(&authorization, &intent)
    }

    fn remote_control(&self, request: &AuthenticatedIpcRequest) -> Result<Vec<u8>> {
        let _authorization_digest = self.govern(request)?;
        self.admission.control(AuthorityControlRequest {
            operation: request.operation,
            tenant_scope: request.tenant_scope.clone(),
            authorization: request.authorization.clone(),
            payload: request.payload.clone(),
        })
    }

    fn credential_mutation(
        &self,
        request: &AuthenticatedIpcRequest,
        expected_operation: IpcOperation,
        expected_mutation: CredentialMutationKind,
        admin_operation: AdminOperation,
    ) -> Result<IpcResponse> {
        self.validate_envelope(request, expected_operation)?;
        let command: CredentialMutationCommand = decode_canonical_payload(&request.payload)?;
        command.validate(expected_mutation)?;
        let authorization_digest = self.govern(request)?;
        validate_digest(&authorization_digest, "admin authorization digest")?;
        match command.mutation {
            CredentialMutationKind::Provision | CredentialMutationKind::Rotate => {
                self.backend
                    .provision(&command.credential, &command.secret)?;
            }
            CredentialMutationKind::Disable => self.backend.disable(&command.credential)?,
            CredentialMutationKind::Delete => self.backend.delete(&command.credential)?,
        }
        let receipt = RedactedAdminReceipt {
            operation: admin_operation,
            tenant_scope: self.tenant_scope.clone(),
            credential: command.credential.clone(),
            authorization_digest,
            outcome: "applied".to_string(),
        };
        accepted_response(expected_operation, &receipt)
    }
}

impl BrokerIpcHandler for BrokerDaemonHandler {
    fn issue(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse> {
        self.validate_envelope(&request, IpcOperation::Issue)?;
        let command: IssueCapabilityCommand = decode_canonical_payload(&request.payload)?;
        command.validate(&self.trusted_issuer)?;
        let response = self.remote_control(&request)?;
        let capability: SignedBrokerCapability = decode_canonical_payload(&response)?;
        if capability.body != command.body {
            return Err(BrokerError::AuthorityUnavailable(
                "authority issued a different broker capability body".to_string(),
            ));
        }
        verify_capability(
            &capability,
            &self.trusted_issuer,
            &self.audience,
            self.clock.now_unix_seconds()?,
            true,
        )?;
        accepted_bytes(IpcOperation::Issue, response)
    }

    fn revoke(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse> {
        self.validate_envelope(&request, IpcOperation::Revoke)?;
        let command: CapabilityControlCommand = decode_canonical_payload(&request.payload)?;
        command.validate()?;
        let response = self.remote_control(&request)?;
        let status: CapabilityStatusResponse = decode_canonical_payload(&response)?;
        status.validate_for(&command)?;
        if !status.revoked {
            return Err(BrokerError::AuthorityUnavailable(
                "authority did not commit broker capability revocation".to_string(),
            ));
        }
        accepted_bytes(IpcOperation::Revoke, response)
    }

    fn status(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse> {
        self.validate_envelope(&request, IpcOperation::Status)?;
        let command: CapabilityControlCommand = decode_canonical_payload(&request.payload)?;
        command.validate()?;
        let response = self.remote_control(&request)?;
        let status: CapabilityStatusResponse = decode_canonical_payload(&response)?;
        status.validate_for(&command)?;
        accepted_bytes(IpcOperation::Status, response)
    }

    fn execute(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse> {
        self.validate_envelope(&request, IpcOperation::Execute)?;
        let execute: BrokerExecuteRequest = decode_canonical_payload(&request.payload)?;
        if execute.capability.body.constraints.maximum_response_bytes
            > MAX_DAEMON_COMBINED_RESPONSE_BYTES
            || execute.request.options.response_limit_bytes > MAX_DAEMON_COMBINED_RESPONSE_BYTES
        {
            return Err(BrokerError::InvalidRequest(
                "IPC execute response limit exceeds the bounded daemon envelope".to_string(),
            ));
        }
        let proof = canonical_json_bytes(&execute.proof).map_err(|error| {
            BrokerError::InvalidRequest(format!("request proof encoding failed: {error}"))
        })?;
        if proof != request.authorization {
            return Err(BrokerError::AuthorizationDenied(
                "IPC execute authorization is not the embedded signed request proof".to_string(),
            ));
        }
        let trusted = self.admission.prepare_execution(&execute)?;
        let response = self
            .service
            .execute(&execute, &trusted, self.clock.now_unix_seconds()?)?;
        accepted_response(IpcOperation::Execute, &response)
    }

    fn provision(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse> {
        self.credential_mutation(
            &request,
            IpcOperation::Provision,
            CredentialMutationKind::Provision,
            AdminOperation::Provision,
        )
    }

    fn rotate(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse> {
        self.credential_mutation(
            &request,
            IpcOperation::Rotate,
            CredentialMutationKind::Rotate,
            AdminOperation::Rotate,
        )
    }

    fn disable(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse> {
        self.credential_mutation(
            &request,
            IpcOperation::Disable,
            CredentialMutationKind::Disable,
            AdminOperation::Disable,
        )
    }

    fn delete(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse> {
        self.credential_mutation(
            &request,
            IpcOperation::Delete,
            CredentialMutationKind::Delete,
            AdminOperation::Delete,
        )
    }
}

fn decode_canonical_payload<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|error| {
        BrokerError::InvalidRequest(format!("IPC payload decoding failed: {error}"))
    })?;
    let canonical = Zeroizing::new(canonical_json_bytes(&value).map_err(|error| {
        BrokerError::InvalidRequest(format!("IPC payload encoding failed: {error}"))
    })?);
    if canonical.as_slice() != bytes {
        return Err(BrokerError::InvalidRequest(
            "IPC payload is not canonical JSON".to_string(),
        ));
    }
    serde_json::from_slice(bytes)
        .map_err(|error| BrokerError::InvalidRequest(format!("IPC payload is invalid: {error}")))
}

fn accepted_response<T: Serialize>(operation: IpcOperation, response: &T) -> Result<IpcResponse> {
    let encoded = canonical_json_bytes(response)
        .map_err(|error| BrokerError::Invariant(format!("IPC response failed: {error}")))?;
    accepted_bytes(operation, encoded)
}

fn accepted_bytes(operation: IpcOperation, response: Vec<u8>) -> Result<IpcResponse> {
    if response.is_empty() || response.len() > crate::protocol::MAX_WIRE_BYTES {
        return Err(BrokerError::Invariant(
            "IPC success response is empty or oversized".to_string(),
        ));
    }
    Ok(IpcResponse {
        operation,
        accepted: true,
        response,
        error_code: None,
    })
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Mutex;

    use chio_core_types::capability::governance::{
        GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    };
    use chio_core_types::Keypair;

    use super::*;
    use crate::authority_ipc::AuthorityControlRequest;
    use crate::budget::{
        AuthorizeExecutionHoldRequest, BrokerExecutionBudget, CaptureExecutionHoldRequest,
        CombinedCaptureCommit, ExecutionAuthorityCapabilities, ExecutionAuthorityProfile,
        ExecutionHoldState, ExecutionQuota, QueryExecutionHoldRequest, ReverseExecutionHoldRequest,
    };
    use crate::capability::issue_capability;
    use crate::generic_https::{
        DestinationResolver, GenericHttpsExecutor, NetworkPolicy, PinnedHttpsRequest,
        PinnedHttpsTransport, RawHttpsResponse,
    };
    use crate::proof::{body_digest, issue_request_proof};
    use crate::protocol::{
        AttemptConsumption, BrokerCapabilityBody, BrokerDestination, BrokerRequest, CallerOptions,
        CredentialRef, HeaderField, ProofBinding, ProofMode, RedirectPolicy, RequestConstraints,
        BROKER_CAPABILITY_SCHEMA, BROKER_EXECUTE_SCHEMA,
    };
    use crate::provider::{CredentialPlacement, GenericCredentialProvider};
    use crate::provision::{AdminClock, GovernedAdminAuthorizationEnvelope, GovernedAdminPolicy};
    use crate::receipt::{BrokerReceiptSink, SignedBrokerReceipt};
    use crate::revocation::{
        BrokerRevocationRequest, BrokerRevocationSnapshot, BrokerRevocations, CapabilityLiveness,
        CapabilityLivenessRequest, LiveParentCapability,
    };
    use crate::sqlite::SqliteAttemptStore;

    struct FixedClock(u64);

    impl DaemonClock for FixedClock {
        fn now_unix_seconds(&self) -> Result<u64> {
            Ok(self.0)
        }
    }

    impl AdminClock for FixedClock {
        fn now_unix_seconds(&self) -> Result<u64> {
            Ok(self.0)
        }
    }

    struct FakeAuthority;

    impl BrokerExecutionBudget for FakeAuthority {
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
            _request: &QueryExecutionHoldRequest,
        ) -> Result<ExecutionHoldState> {
            Ok(ExecutionHoldState::Unknown)
        }

        fn authorize_execution_hold(
            &self,
            _request: &AuthorizeExecutionHoldRequest,
        ) -> Result<ExecutionHoldState> {
            Ok(ExecutionHoldState::Held)
        }

        fn reverse_execution_hold(
            &self,
            _request: &ReverseExecutionHoldRequest,
        ) -> Result<ExecutionHoldState> {
            Ok(ExecutionHoldState::Reversed)
        }

        fn capture_execution_hold(
            &self,
            request: &CaptureExecutionHoldRequest,
        ) -> Result<ExecutionHoldState> {
            Ok(ExecutionHoldState::Captured(CombinedCaptureCommit {
                checked_revocation_set_digest: request.revocation_set_digest.clone(),
                budget_commit_index: 10,
                revocation_commit_index: 11,
                authority_commit_index: 12,
                leader_epoch: 13,
            }))
        }
    }

    impl CapabilityLiveness for FakeAuthority {
        fn verify_live_parent(
            &self,
            request: &CapabilityLivenessRequest,
        ) -> Result<LiveParentCapability> {
            Ok(LiveParentCapability {
                capability_id: request.parent_capability_id.clone(),
                subject: request.expected_subject.clone(),
                audience: request.expected_audience.clone(),
                delegation_ancestor_ids: Vec::new(),
                expires_at_unix_seconds: 120,
                verified_at_unix_seconds: request.now_unix_seconds,
                authority_snapshot_digest: "aa".repeat(32),
            })
        }
    }

    impl BrokerRevocations for FakeAuthority {
        fn check_broker_revocation(
            &self,
            request: &BrokerRevocationRequest,
        ) -> Result<BrokerRevocationSnapshot> {
            Ok(BrokerRevocationSnapshot {
                revoked: false,
                observed_at_unix_seconds: request.now_unix_seconds,
                commit_index: 9,
                authority_domain: "combined-production".to_string(),
            })
        }
    }

    impl BrokerAdmissionAuthority for FakeAuthority {
        fn prepare_execution(
            &self,
            request: &BrokerExecuteRequest,
        ) -> Result<crate::service::TrustedExecutionContext> {
            Ok(crate::service::TrustedExecutionContext {
                quotas: vec![
                    ExecutionQuota {
                        key_id: request.capability.body.broker_quota_key_id.clone(),
                        maximum_executions: request.capability.body.maximum_executions,
                    },
                    ExecutionQuota {
                        key_id: "parent-quota-production".to_string(),
                        maximum_executions: 10,
                    },
                ],
                authority_metadata_digest: "bb".repeat(32),
                revocation_authority_domain: "combined-production".to_string(),
            })
        }

        fn control(&self, _request: AuthorityControlRequest) -> Result<Vec<u8>> {
            Err(BrokerError::InvalidRequest(
                "control is unused by this fixture".to_string(),
            ))
        }
    }

    struct Resolver;

    impl DestinationResolver for Resolver {
        fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>> {
            Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
        }
    }

    struct ObservingTransport {
        observed_authorization: Arc<Mutex<Option<Vec<u8>>>>,
    }

    impl PinnedHttpsTransport for ObservingTransport {
        fn dispatch(&self, request: PinnedHttpsRequest) -> Result<RawHttpsResponse> {
            let authorization = request
                .secret_headers()
                .find(|(name, _)| *name == "authorization")
                .map(|(_, value)| value.to_vec())
                .ok_or_else(|| BrokerError::Upstream("missing credential header".to_string()))?;
            *self.observed_authorization.lock().map_err(|_| {
                BrokerError::Invariant("observation lock is poisoned".to_string())
            })? = Some(authorization);
            let response = b"sanitized-upstream-response".to_vec();
            let content_length = response.len().to_string();
            let headers = vec![HeaderField::normalized(
                "content-length",
                content_length.as_bytes(),
            )?];
            let response_head =
                format!("HTTP/1.1 200 OK\r\ncontent-length: {content_length}\r\n\r\n");
            Ok(RawHttpsResponse {
                status: 200,
                headers,
                decoded_body_chunks: vec![response],
                response_head_bytes: response_head.len(),
                connected_address: request.pinned_address(),
                tls_server_name: request.original_hostname().to_string(),
                redirected: false,
            })
        }
    }

    struct InspectingReceiptSink {
        canary: Vec<u8>,
    }

    impl BrokerReceiptSink for InspectingReceiptSink {
        fn persist(&self, receipt: &SignedBrokerReceipt) -> Result<String> {
            let canonical = canonical_json_bytes(receipt).map_err(|error| {
                BrokerError::Invariant(format!("receipt test encoding failed: {error}"))
            })?;
            if canonical
                .windows(self.canary.len())
                .any(|window| window == self.canary)
            {
                return Err(BrokerError::Invariant(
                    "credential crossed into the broker receipt".to_string(),
                ));
            }
            Ok("broker-receipt-test-reference".to_string())
        }
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct MutationPayload<'a> {
        schema: &'static str,
        mutation: &'static str,
        credential: &'a CredentialRef,
        secret: &'a [u8],
    }

    fn governed_authorization(
        approver: &Keypair,
        subject: &chio_core_types::PublicKey,
        intent: &str,
    ) -> Vec<u8> {
        let approval = GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: "daemon-approval-production-1".to_string(),
                approver: approver.public_key(),
                subject: subject.clone(),
                governed_intent_hash: intent.to_string(),
                threshold_proposal_hash: Some("cc".repeat(32)),
                request_id: "daemon-admin-request-production-1".to_string(),
                issued_at: 90,
                expires_at: 110,
                decision: GovernedApprovalDecision::Approved,
            },
            approver,
        )
        .expect("approval");
        GovernedAdminAuthorizationEnvelope::new(vec![approval])
            .expect("envelope")
            .canonical_bytes()
            .expect("canonical envelope")
    }

    #[test]
    fn daemon_governance_binds_payload_and_fake_upstream_is_the_only_secret_sink() {
        let canary = b"daemon-process-secret-canary-91f7".to_vec();
        let backend = Arc::new(
            EncryptedBlobSecretBackend::open_in_memory_for_test("tenant-production", [81; 32])
                .expect("backend"),
        );
        let issuer = Keypair::from_seed(&[82; 32]);
        let caller = Keypair::from_seed(&[83; 32]);
        let receipt_signer = Keypair::from_seed(&[84; 32]);
        let authority = Arc::new(FakeAuthority);
        let budget: Arc<dyn BrokerExecutionBudget> = authority.clone();
        let liveness: Arc<dyn CapabilityLiveness> = authority.clone();
        let revocations: Arc<dyn BrokerRevocations> = authority.clone();
        let observed_authorization = Arc::new(Mutex::new(None));
        let service = Arc::new(
            BrokerService::new(
                crate::service::BrokerServiceConfig {
                    production: true,
                    audience: "broker-service-production".to_string(),
                    parent_audience: "parent-service-production".to_string(),
                    maximum_clock_skew_seconds: 1,
                    maximum_liveness_snapshot_age_seconds: 1,
                    maximum_revocation_snapshot_age_seconds: 1,
                },
                issuer.public_key(),
                Arc::clone(&backend),
                Arc::new(
                    GenericCredentialProvider::new(
                        "generic-bearer".to_string(),
                        1,
                        CredentialPlacement::BearerAuthorization,
                    )
                    .expect("provider"),
                ),
                Arc::new(GenericHttpsExecutor::new(
                    Arc::new(Resolver),
                    Arc::new(ObservingTransport {
                        observed_authorization: Arc::clone(&observed_authorization),
                    }),
                    NetworkPolicy::production(),
                )),
                Arc::new(SqliteAttemptStore::open_in_memory().expect("attempts")),
                budget,
                liveness,
                revocations,
                Arc::new(InspectingReceiptSink {
                    canary: canary.clone(),
                }),
                receipt_signer,
            )
            .expect("service"),
        );
        let admin_directory = tempfile::tempdir().expect("admin directory");
        let approver = Keypair::from_seed(&[85; 32]);
        let admin_subject = Keypair::from_seed(&[86; 32]).public_key();
        let admin = Arc::new(
            GovernedAdminAuthorizer::open(
                admin_directory.path().join("admin.sqlite3"),
                GovernedAdminPolicy {
                    trusted_approvers: vec![approver.public_key()],
                    subject: admin_subject.clone(),
                    threshold: 1,
                    maximum_token_lifetime_seconds: 60,
                },
                Arc::new(FixedClock(100)),
            )
            .expect("admin"),
        );
        let admission: Arc<dyn BrokerAdmissionAuthority> = authority;
        let handler = BrokerDaemonHandler::new(
            "tenant-production".to_string(),
            "broker-service-production".to_string(),
            issuer.public_key(),
            service,
            admission,
            admin,
            Arc::clone(&backend),
            Arc::new(FixedClock(100)),
        )
        .expect("handler");

        let credential = CredentialRef {
            provider: "generic-https".to_string(),
            credential_id: "credential-production".to_string(),
            version: 1,
        };
        let payload = canonical_json_bytes(&MutationPayload {
            schema: CREDENTIAL_MUTATION_SCHEMA,
            mutation: "provision",
            credential: &credential,
            secret: &canary,
        })
        .expect("mutation payload");
        let intent =
            daemon_admin_intent_digest(IpcOperation::Provision, "tenant-production", &payload)
                .expect("admin intent");
        let authorization = governed_authorization(&approver, &admin_subject, &intent);
        let mut changed_canary = canary.clone();
        changed_canary.push(b'x');
        let changed_payload = canonical_json_bytes(&MutationPayload {
            schema: CREDENTIAL_MUTATION_SCHEMA,
            mutation: "provision",
            credential: &credential,
            secret: &changed_canary,
        })
        .expect("changed mutation payload");
        assert!(handler
            .provision(AuthenticatedIpcRequest {
                operation: IpcOperation::Provision,
                tenant_scope: "tenant-production".to_string(),
                authorization: authorization.clone(),
                payload: changed_payload,
            })
            .is_err());
        let provisioned = handler
            .provision(AuthenticatedIpcRequest {
                operation: IpcOperation::Provision,
                tenant_scope: "tenant-production".to_string(),
                authorization: authorization.clone(),
                payload: payload.clone(),
            })
            .expect("provisioned");
        assert!(provisioned.accepted);
        let provisioned_wire = canonical_json_bytes(&provisioned).expect("provision response");
        assert!(!provisioned_wire
            .windows(canary.len())
            .any(|window| window == canary));
        assert!(handler
            .provision(AuthenticatedIpcRequest {
                operation: IpcOperation::Provision,
                tenant_scope: "tenant-production".to_string(),
                authorization,
                payload,
            })
            .is_err());

        let destination =
            BrokerDestination::parse("https://example.com/v1", "post", false).expect("destination");
        let broker_request = BrokerRequest {
            destination: destination.clone(),
            headers: Vec::new(),
            body: b"broker-request-body".to_vec(),
            approved_preview_sha256: None,
            options: CallerOptions {
                timeout_ms: 1_000,
                streaming: false,
                response_limit_bytes: 4_096,
            },
        };
        let capability = issue_capability(
            BrokerCapabilityBody {
                schema: BROKER_CAPABILITY_SCHEMA.to_string(),
                issuer: issuer.public_key(),
                capability_id: "broker-capability-production".to_string(),
                parent_capability_id: "parent-capability-production".to_string(),
                subject: caller.public_key(),
                audience: "broker-service-production".to_string(),
                issued_at_unix_seconds: 90,
                not_before_unix_seconds: 90,
                expires_at_unix_seconds: 110,
                credential,
                provider_adapter_id: "generic-bearer".to_string(),
                provider_adapter_version: 1,
                destination,
                constraints: RequestConstraints {
                    allowed_caller_headers: Vec::new(),
                    provider_owned_headers: vec!["authorization".to_string()],
                    maximum_body_bytes: 4_096,
                    required_body_sha256: body_digest(&broker_request.body),
                    required_preview_sha256: None,
                    redirect_policy: RedirectPolicy::Disabled,
                    maximum_response_bytes: 4_096,
                    streaming_allowed: false,
                    maximum_timeout_ms: 1_000,
                },
                broker_quota_key_id: "broker-quota-production".to_string(),
                maximum_executions: 2,
                consumption: AttemptConsumption::CaptureBeforeDispatch,
                revocation_id: "broker-revocation-production".to_string(),
                proof: ProofBinding {
                    mode: ProofMode::PublicKey,
                    caller_public_key: caller.public_key(),
                    nonce_ttl_seconds: 30,
                },
            },
            &issuer,
            true,
        )
        .expect("capability");
        let proof = issue_request_proof(
            &capability,
            &broker_request,
            "daemon-proof-nonce-production".to_string(),
            100,
            &caller,
        )
        .expect("proof");
        let execute = BrokerExecuteRequest {
            schema: BROKER_EXECUTE_SCHEMA.to_string(),
            invocation_id: "daemon-invocation-production".to_string(),
            capability,
            proof,
            request: broker_request,
        };
        let execute_payload = canonical_json_bytes(&execute).expect("execute payload");
        let proof_authorization =
            canonical_json_bytes(&execute.proof).expect("proof authorization");
        let response = handler
            .execute(AuthenticatedIpcRequest {
                operation: IpcOperation::Execute,
                tenant_scope: "tenant-production".to_string(),
                authorization: proof_authorization,
                payload: execute_payload,
            })
            .expect("execute");
        assert!(response.accepted);
        let response_wire = canonical_json_bytes(&response).expect("response wire");
        assert!(!response_wire
            .windows(canary.len())
            .any(|window| window == canary));
        let observed = observed_authorization
            .lock()
            .expect("observation")
            .clone()
            .expect("credential observed upstream");
        assert_eq!(
            observed,
            [b"Bearer ".as_slice(), canary.as_slice()].concat()
        );
    }
}
