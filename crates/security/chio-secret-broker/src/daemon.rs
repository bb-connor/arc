use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core_types::{canonical_json_bytes, SigningBackend};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::authority_ipc::{AuthorityControlRequest, BrokerAdmissionAuthority};
use crate::capability::verify_capability;
use crate::encrypted_blob_backend::EncryptedBlobSecretBackend;
use crate::protocol::{
    BrokerCapabilityBody, BrokerExecuteRequest, CredentialRef, SignedBrokerCapability,
};
use crate::provision::{
    sign_admin_control_receipt, sign_admin_mutation_receipt, verify_admin_mutation_receipt,
    AdminAuthorization, AdminControlReceiptBody, AdminMutationOutcome, AdminMutationReceiptBody,
    AdminOperation, GovernedAdminAuthorizer, SignedAdminMutationReceipt,
    ADMIN_CONTROL_RECEIPT_SCHEMA, ADMIN_MUTATION_RECEIPT_SCHEMA,
};
use crate::registration::{
    verify_register_attempt_authorization, AuthenticatedAttemptRequest, RegisterAttemptAction,
    SignedRegisterAttemptAuthorization,
};
use crate::service::{
    canonical_json_byte_array_length, canonical_json_string_length, canonical_json_u64_length,
    checked_canonical_length, AuthenticatedIpcRequest, BoundedZeroizingByteArray,
    BrokerExecuteOutcome, BrokerIpcHandler, BrokerService, IpcOperation, IpcResponse,
    ZeroizingCanonicalJsonWriter,
};
use crate::{validate_identifier, BrokerError, Result};

pub const DAEMON_ADMIN_INTENT_SCHEMA: &str = "chio.broker-daemon-admin-intent.v1";
pub const ISSUE_CAPABILITY_SCHEMA: &str = "chio.broker-issue-capability.v1";
pub const CAPABILITY_CONTROL_SCHEMA: &str = "chio.broker-capability-control.v1";
pub const CAPABILITY_STATUS_SCHEMA: &str = "chio.broker-capability-status.v1";
pub const CREDENTIAL_MUTATION_SCHEMA: &str = "chio.broker-credential-mutation.v1";
const DAEMON_ADMIN_INTENT_DOMAIN: &[u8] = b"chio.broker-daemon-admin-intent.v1\0";
const MAX_DAEMON_COMBINED_RESPONSE_BYTES: u64 = 16_384;
const I_JSON_MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CredentialMutationKind {
    Provision,
    Rotate,
    Disable,
    Delete,
}

impl CredentialMutationKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Provision => "provision",
            Self::Rotate => "rotate",
            Self::Disable => "disable",
            Self::Delete => "delete",
        }
    }
}

struct CredentialMutationCommand {
    schema: String,
    mutation: CredentialMutationKind,
    credential: CredentialRef,
    secret: BoundedZeroizingByteArray<65_536>,
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

impl zeroize::ZeroizeOnDrop for CredentialMutationCommand {}

fn canonical_credential_mutation_payload(
    command: &CredentialMutationCommand,
) -> Result<Zeroizing<Vec<u8>>> {
    if command.credential.version > I_JSON_MAX_SAFE_INTEGER {
        return Err(BrokerError::InvalidRequest(
            "credential mutation version exceeds the I-JSON safe integer range".to_string(),
        ));
    }
    let mut exact_length = b"{\"credential\":{\"credentialId\":".len();
    exact_length = checked_canonical_length(
        exact_length,
        canonical_json_string_length(&command.credential.credential_id)?,
    )?;
    exact_length = checked_canonical_length(exact_length, b",\"provider\":".len())?;
    exact_length = checked_canonical_length(
        exact_length,
        canonical_json_string_length(&command.credential.provider)?,
    )?;
    exact_length = checked_canonical_length(exact_length, b",\"version\":".len())?;
    exact_length = checked_canonical_length(
        exact_length,
        canonical_json_u64_length(command.credential.version),
    )?;
    exact_length = checked_canonical_length(exact_length, b"},\"mutation\":".len())?;
    exact_length = checked_canonical_length(
        exact_length,
        canonical_json_string_length(command.mutation.as_str())?,
    )?;
    exact_length = checked_canonical_length(exact_length, b",\"schema\":".len())?;
    exact_length =
        checked_canonical_length(exact_length, canonical_json_string_length(&command.schema)?)?;
    exact_length = checked_canonical_length(exact_length, b",\"secret\":".len())?;
    exact_length = checked_canonical_length(
        exact_length,
        canonical_json_byte_array_length(command.secret.as_slice())?,
    )?;
    exact_length = checked_canonical_length(exact_length, 1)?;

    let mut encoded = ZeroizingCanonicalJsonWriter::with_exact_length(exact_length)?;
    encoded.extend_from_slice(b"{\"credential\":{\"credentialId\":")?;
    encoded.write_string(&command.credential.credential_id)?;
    encoded.extend_from_slice(b",\"provider\":")?;
    encoded.write_string(&command.credential.provider)?;
    encoded.extend_from_slice(b",\"version\":")?;
    encoded.write_u64(command.credential.version)?;
    encoded.extend_from_slice(b"},\"mutation\":")?;
    encoded.write_string(command.mutation.as_str())?;
    encoded.extend_from_slice(b",\"schema\":")?;
    encoded.write_string(&command.schema)?;
    encoded.extend_from_slice(b",\"secret\":")?;
    encoded.write_byte_array(command.secret.as_slice())?;
    encoded.push(b'}')?;
    encoded.finish()
}

pub fn encode_credential_mutation_payload(
    operation: IpcOperation,
    credential: &CredentialRef,
    secret: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let mutation = match operation {
        IpcOperation::Provision => CredentialMutationKind::Provision,
        IpcOperation::Rotate => CredentialMutationKind::Rotate,
        IpcOperation::Disable => CredentialMutationKind::Disable,
        IpcOperation::Delete => CredentialMutationKind::Delete,
        _ => {
            return Err(BrokerError::InvalidRequest(
                "credential mutation operation is invalid".to_string(),
            ))
        }
    };
    let command = CredentialMutationCommand {
        schema: CREDENTIAL_MUTATION_SCHEMA.to_string(),
        mutation,
        credential: credential.clone(),
        secret: BoundedZeroizingByteArray::copy_from_slice(secret)?,
    };
    command.validate(mutation)?;
    canonical_credential_mutation_payload(&command)
}

fn decode_canonical_credential_mutation_payload(bytes: &[u8]) -> Result<CredentialMutationCommand> {
    let mut parser = crate::service::SensitiveJsonParser::new(bytes);
    parser.expect_literal(b"{\"credential\":{\"credentialId\":")?;
    let credential_id = parser.parse_string::<512>()?;
    parser.expect_literal(b",\"provider\":")?;
    let provider = parser.parse_string::<512>()?;
    parser.expect_literal(b",\"version\":")?;
    let version = parser.parse_i_json_u64()?;
    parser.expect_literal(b"},\"mutation\":")?;
    let mutation = parser.parse_string::<16>()?;
    let mutation = match mutation.as_str() {
        "provision" => CredentialMutationKind::Provision,
        "rotate" => CredentialMutationKind::Rotate,
        "disable" => CredentialMutationKind::Disable,
        "delete" => CredentialMutationKind::Delete,
        _ => {
            return Err(BrokerError::InvalidRequest(
                "sensitive JSON payload is invalid".to_string(),
            ))
        }
    };
    parser.expect_literal(b",\"schema\":")?;
    let schema = parser.parse_string::<128>()?;
    parser.expect_literal(b",\"secret\":")?;
    let secret = parser.parse_byte_array::<65_536>()?;
    parser.expect_literal(b"}")?;
    parser.finish()?;
    let command = CredentialMutationCommand {
        schema: schema.into_string(),
        mutation,
        credential: CredentialRef {
            provider: provider.into_string(),
            credential_id: credential_id.into_string(),
            version,
        },
        secret,
    };
    let canonical = canonical_credential_mutation_payload(&command)?;
    if canonical.as_slice() != bytes {
        return Err(BrokerError::InvalidRequest(
            "IPC credential mutation payload is not canonical JSON".to_string(),
        ));
    }
    Ok(command)
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
    trusted_authority: chio_core_types::PublicKey,
    maximum_clock_skew_seconds: u64,
    service: Arc<BrokerService>,
    admission: Arc<dyn BrokerAdmissionAuthority>,
    admin: Arc<GovernedAdminAuthorizer>,
    admin_receipt_signer: Arc<dyn SigningBackend>,
    backend: Arc<EncryptedBlobSecretBackend>,
    clock: Arc<dyn DaemonClock>,
}

impl BrokerDaemonHandler {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant_scope: String,
        audience: String,
        trusted_issuer: chio_core_types::PublicKey,
        trusted_authority: chio_core_types::PublicKey,
        maximum_clock_skew_seconds: u64,
        service: Arc<BrokerService>,
        admission: Arc<dyn BrokerAdmissionAuthority>,
        admin: Arc<GovernedAdminAuthorizer>,
        admin_receipt_signer: Arc<dyn SigningBackend>,
        backend: Arc<EncryptedBlobSecretBackend>,
        clock: Arc<dyn DaemonClock>,
    ) -> Result<Self> {
        validate_identifier(&tenant_scope, "daemon tenant scope", 512)?;
        validate_identifier(&audience, "daemon broker audience", 512)?;
        if maximum_clock_skew_seconds == 0 || maximum_clock_skew_seconds > 30 {
            return Err(BrokerError::InvalidRequest(
                "daemon register-attempt clock skew is invalid".to_string(),
            ));
        }
        if admin.trusted_mutation_receipt_signer() != &admin_receipt_signer.public_key() {
            return Err(BrokerError::InvalidRequest(
                "daemon admin authorizer receipt signer does not match the signing backend"
                    .to_string(),
            ));
        }
        Ok(Self {
            tenant_scope,
            audience,
            trusted_issuer,
            trusted_authority,
            maximum_clock_skew_seconds,
            service,
            admission,
            admin,
            admin_receipt_signer,
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

    fn remote_control<F>(
        &self,
        request: &AuthenticatedIpcRequest,
        operation_name: &str,
        validate_response: F,
    ) -> Result<Vec<u8>>
    where
        F: Fn(&[u8]) -> Result<()>,
    {
        let intent =
            daemon_admin_intent_digest(request.operation, &request.tenant_scope, &request.payload)?;
        let authorization = AdminAuthorization::new(request.authorization.as_slice().to_vec())?;
        let operation = self.admin.begin_intent_digest(&authorization, &intent)?;
        if operation.completed_receipt().is_some() {
            return Err(BrokerError::Conflict(
                "admin operation cannot be both a credential mutation and remote control"
                    .to_string(),
            ));
        }
        if let Some(completion) = self
            .admin
            .query_control_completion(operation.operation_id())?
        {
            let receipt = completion.receipt();
            if receipt.body.request_id != operation.request_id()
                || receipt.body.intent_digest != operation.intent_digest()
                || receipt.body.authorization_digest != operation.authorization_digest()
                || receipt.body.operation != operation_name
                || receipt.body.tenant_scope != self.tenant_scope
                || receipt.signer != self.admin_receipt_signer.public_key()
            {
                return Err(BrokerError::Conflict(
                    "durable admin control completion is misbound or untrusted".to_string(),
                ));
            }
            validate_response(completion.response())?;
            return Ok(completion.response().to_vec());
        }
        let response = self.admission.control(AuthorityControlRequest {
            operation: request.operation,
            tenant_scope: request.tenant_scope.clone(),
            authorization: request.authorization.as_slice().to_vec(),
            payload: request.payload.as_slice().to_vec(),
        })?;
        validate_response(&response)?;
        let receipt = sign_admin_control_receipt(
            AdminControlReceiptBody {
                schema: ADMIN_CONTROL_RECEIPT_SCHEMA.to_string(),
                operation_id: operation.operation_id().to_string(),
                request_id: operation.request_id().to_string(),
                intent_digest: operation.intent_digest().to_string(),
                authorization_digest: operation.authorization_digest().to_string(),
                operation: operation_name.to_string(),
                tenant_scope: self.tenant_scope.clone(),
                response_digest: hex::encode(Sha256::digest(&response)),
                completed_at_unix_seconds: self.clock.now_unix_seconds()?,
                outcome: AdminMutationOutcome::Applied,
            },
            self.admin_receipt_signer.as_ref(),
        )?;
        let completion = self
            .admin
            .complete_control_operation(&operation, &receipt, &response)?;
        if completion.receipt().signer != self.admin_receipt_signer.public_key() {
            return Err(BrokerError::Conflict(
                "durable admin control completion signer is untrusted".to_string(),
            ));
        }
        validate_response(completion.response())?;
        Ok(completion.response().to_vec())
    }

    fn credential_mutation(
        &self,
        request: &AuthenticatedIpcRequest,
        expected_operation: IpcOperation,
        expected_mutation: CredentialMutationKind,
        admin_operation: AdminOperation,
    ) -> Result<IpcResponse> {
        self.validate_envelope(request, expected_operation)?;
        let command = decode_canonical_credential_mutation_payload(&request.payload)?;
        command.validate(expected_mutation)?;
        let intent =
            daemon_admin_intent_digest(request.operation, &request.tenant_scope, &request.payload)?;
        let authorization = AdminAuthorization::new(request.authorization.as_slice().to_vec())?;
        let operation = self.admin.begin_intent_digest(&authorization, &intent)?;
        if let Some(receipt) = operation.completed_receipt() {
            validate_mutation_retry_receipt(
                receipt,
                self.admin.trusted_mutation_receipt_signer(),
                admin_operation,
                &self.tenant_scope,
                &command.credential,
            )?;
            return accepted_response(expected_operation, receipt);
        }
        self.service
            .require_migrations_for_provider(&command.credential.provider)?;
        match command.mutation {
            CredentialMutationKind::Provision | CredentialMutationKind::Rotate => {
                self.backend.provision_once(
                    &command.credential,
                    command.secret.as_slice(),
                    operation.operation_id(),
                    operation.intent_digest(),
                )?;
            }
            CredentialMutationKind::Disable => {
                self.backend.disable_once(
                    &command.credential,
                    operation.operation_id(),
                    operation.intent_digest(),
                )?;
            }
            CredentialMutationKind::Delete => {
                self.backend.delete_once(
                    &command.credential,
                    operation.operation_id(),
                    operation.intent_digest(),
                )?;
            }
        }
        let receipt = sign_admin_mutation_receipt(
            AdminMutationReceiptBody {
                schema: ADMIN_MUTATION_RECEIPT_SCHEMA.to_string(),
                operation_id: operation.operation_id().to_string(),
                request_id: operation.request_id().to_string(),
                intent_digest: operation.intent_digest().to_string(),
                authorization_digest: operation.authorization_digest().to_string(),
                operation: admin_operation,
                tenant_scope: self.tenant_scope.clone(),
                credential: command.credential.clone(),
                completed_at_unix_seconds: self.clock.now_unix_seconds()?,
                outcome: AdminMutationOutcome::Applied,
            },
            self.admin_receipt_signer.as_ref(),
        )?;
        let receipt = self.admin.complete_operation(&operation, &receipt)?;
        validate_mutation_retry_receipt(
            &receipt,
            self.admin.trusted_mutation_receipt_signer(),
            admin_operation,
            &self.tenant_scope,
            &command.credential,
        )?;
        accepted_response(expected_operation, &receipt)
    }
}

fn validate_mutation_retry_receipt(
    receipt: &SignedAdminMutationReceipt,
    trusted_signer: &chio_core_types::PublicKey,
    operation: AdminOperation,
    tenant_scope: &str,
    credential: &CredentialRef,
) -> Result<()> {
    verify_admin_mutation_receipt(receipt)?;
    if &receipt.signer != trusted_signer
        || receipt.body.operation != operation
        || receipt.body.tenant_scope != tenant_scope
        || &receipt.body.credential != credential
        || receipt.body.outcome != AdminMutationOutcome::Applied
    {
        return Err(BrokerError::Conflict(
            "durable admin mutation completion is misbound or untrusted".to_string(),
        ));
    }
    Ok(())
}

impl BrokerIpcHandler for BrokerDaemonHandler {
    fn register_attempt(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse> {
        self.validate_envelope(&request, IpcOperation::RegisterAttempt)?;
        let authenticated: AuthenticatedAttemptRequest =
            decode_canonical_payload(&request.payload)?;
        let registration = &authenticated.registration;
        let authorization: SignedRegisterAttemptAuthorization =
            decode_canonical_payload(&request.authorization)?;
        let now = self.clock.now_unix_seconds()?;
        verify_register_attempt_authorization(
            &authorization,
            registration,
            RegisterAttemptAction::Register,
            &self.tenant_scope,
            &self.trusted_authority,
            now,
            self.maximum_clock_skew_seconds,
        )?;
        let acknowledgement =
            self.service
                .register_attempt(registration, &authenticated.request, now)?;
        acknowledgement.validate_for(registration)?;
        accepted_response(IpcOperation::RegisterAttempt, &acknowledgement)
    }

    fn prepare_dispatch(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse> {
        self.validate_envelope(&request, IpcOperation::PrepareDispatch)?;
        let authenticated: AuthenticatedAttemptRequest =
            decode_canonical_payload(&request.payload)?;
        let registration = &authenticated.registration;
        let authorization: SignedRegisterAttemptAuthorization =
            decode_canonical_payload(&request.authorization)?;
        let now = self.clock.now_unix_seconds()?;
        verify_register_attempt_authorization(
            &authorization,
            registration,
            RegisterAttemptAction::Prepare,
            &self.tenant_scope,
            &self.trusted_authority,
            now,
            self.maximum_clock_skew_seconds,
        )?;
        let acknowledgement =
            self.service
                .prepare_dispatch(registration, &authenticated.request, now)?;
        acknowledgement.validate_for(registration, &authenticated.request)?;
        accepted_response(IpcOperation::PrepareDispatch, &acknowledgement)
    }

    fn release_attempt(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse> {
        self.validate_envelope(&request, IpcOperation::ReleaseAttempt)?;
        let authenticated: AuthenticatedAttemptRequest =
            decode_canonical_payload(&request.payload)?;
        let registration = &authenticated.registration;
        let authorization: SignedRegisterAttemptAuthorization =
            decode_canonical_payload(&request.authorization)?;
        let now = self.clock.now_unix_seconds()?;
        verify_register_attempt_authorization(
            &authorization,
            registration,
            RegisterAttemptAction::Release,
            &self.tenant_scope,
            &self.trusted_authority,
            now,
            self.maximum_clock_skew_seconds,
        )?;
        let acknowledgement =
            self.service
                .release_attempt(registration, &authenticated.request, now)?;
        acknowledgement.validate_for(registration)?;
        accepted_response(IpcOperation::ReleaseAttempt, &acknowledgement)
    }

    fn issue(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse> {
        self.validate_envelope(&request, IpcOperation::Issue)?;
        let command: IssueCapabilityCommand = decode_canonical_payload(&request.payload)?;
        command.validate(&self.trusted_issuer)?;
        let response = self.remote_control(&request, "issue", |response| {
            let capability: SignedBrokerCapability = decode_canonical_payload(response)?;
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
            )
        })?;
        accepted_bytes(IpcOperation::Issue, response)
    }

    fn revoke(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse> {
        self.validate_envelope(&request, IpcOperation::Revoke)?;
        let command: CapabilityControlCommand = decode_canonical_payload(&request.payload)?;
        command.validate()?;
        let response = self.remote_control(&request, "revoke", |response| {
            let status: CapabilityStatusResponse = decode_canonical_payload(response)?;
            status.validate_for(&command)?;
            if !status.revoked {
                return Err(BrokerError::AuthorityUnavailable(
                    "authority did not commit broker capability revocation".to_string(),
                ));
            }
            Ok(())
        })?;
        accepted_bytes(IpcOperation::Revoke, response)
    }

    fn status(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse> {
        self.validate_envelope(&request, IpcOperation::Status)?;
        let command: CapabilityControlCommand = decode_canonical_payload(&request.payload)?;
        command.validate()?;
        let response = self.remote_control(&request, "status", |response| {
            let status: CapabilityStatusResponse = decode_canonical_payload(response)?;
            status.validate_for(&command)
        })?;
        accepted_bytes(IpcOperation::Status, response)
    }

    fn execute(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse> {
        self.validate_envelope(&request, IpcOperation::Execute)?;
        let execute: BrokerExecuteRequest = decode_canonical_payload(&request.payload)?;
        let now_unix_seconds = self.clock.now_unix_seconds()?;
        canonical_json_bytes(&execute.proof)
            .map_err(|error| {
                BrokerError::InvalidRequest(format!("request proof encoding failed: {error}"))
            })
            .and_then(|proof| {
                if proof.as_slice() == request.authorization.as_slice() {
                    Ok(())
                } else {
                    Err(BrokerError::AuthorizationDenied(
                        "IPC execute authorization is not the embedded signed request proof"
                            .to_string(),
                    ))
                }
            })?;
        if let Some(failure) = self.service.replay_failure(&execute, now_unix_seconds)? {
            return denied_response(IpcOperation::Execute, &failure.diagnostic_code, &failure);
        }
        if let Some(response) = self.service.replay_completed(&execute, now_unix_seconds)? {
            return accepted_response(IpcOperation::Execute, &response);
        }
        let trusted = (|| {
            if execute.capability.body.constraints.maximum_response_bytes
                > MAX_DAEMON_COMBINED_RESPONSE_BYTES
                || execute.request.options.response_limit_bytes > MAX_DAEMON_COMBINED_RESPONSE_BYTES
            {
                return Err(BrokerError::InvalidRequest(
                    "IPC execute response limit exceeds the bounded daemon envelope".to_string(),
                ));
            }
            self.admission.prepare_execution(&execute)
        })();
        let trusted = match trusted {
            Ok(trusted) => trusted,
            Err(error) => {
                let failure =
                    self.service
                        .persist_admission_failure(&execute, now_unix_seconds, &error)?;
                return denied_response(IpcOperation::Execute, &failure.diagnostic_code, &failure);
            }
        };
        match self.service.execute_evidenced_with_terminal_clock(
            &execute,
            &trusted,
            now_unix_seconds,
            &|| self.clock.now_unix_seconds(),
        )? {
            BrokerExecuteOutcome::Success(response) => {
                accepted_response(IpcOperation::Execute, response.as_ref())
            }
            BrokerExecuteOutcome::Failure(failure) => denied_response(
                IpcOperation::Execute,
                &failure.diagnostic_code,
                failure.as_ref(),
            ),
        }
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

fn decode_canonical_payload<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T> {
    let decoded: T = serde_json::from_slice(bytes).map_err(|error| {
        BrokerError::InvalidRequest(format!("IPC payload decoding failed: {error}"))
    })?;
    let canonical = Zeroizing::new(canonical_json_bytes(&decoded).map_err(|error| {
        BrokerError::InvalidRequest(format!("IPC payload encoding failed: {error}"))
    })?);
    if canonical.as_slice() != bytes {
        return Err(BrokerError::InvalidRequest(
            "IPC payload is not canonical JSON".to_string(),
        ));
    }
    Ok(decoded)
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

fn denied_response<T: Serialize>(
    operation: IpcOperation,
    error_code: &str,
    response: &T,
) -> Result<IpcResponse> {
    validate_identifier(error_code, "IPC error code", 128)?;
    let encoded = canonical_json_bytes(response)
        .map_err(|error| BrokerError::Invariant(format!("IPC denial response failed: {error}")))?;
    if encoded.is_empty() || encoded.len() > crate::protocol::MAX_WIRE_BYTES {
        return Err(BrokerError::Invariant(
            "IPC denial response is empty or oversized".to_string(),
        ));
    }
    Ok(IpcResponse {
        operation,
        accepted: false,
        response: encoded,
        error_code: Some(error_code.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use chio_test_support::prelude::*;
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    use chio_core_types::capability::governance::{
        GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    };
    use chio_core_types::{Ed25519Backend, Keypair};

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
    use crate::proof::{body_digest, issue_request_proof, proof_digest};
    use crate::protocol::{
        AttemptConsumption, BrokerCapabilityBody, BrokerDestination, BrokerRequest, CallerOptions,
        CredentialRef, HeaderField, ProofBinding, ProofMode, RedirectPolicy, RequestConstraints,
        BROKER_CAPABILITY_SCHEMA, BROKER_EXECUTE_SCHEMA,
    };
    use crate::provider::{CredentialPlacement, GenericCredentialProvider};
    use crate::provision::{AdminClock, GovernedAdminAuthorizationEnvelope, GovernedAdminPolicy};
    use crate::receipt::{BrokerReceiptSink, SignedBrokerFailureReceipt, SignedBrokerReceipt};
    use crate::registration::{
        broker_execute_request_registration_digest, prepared_dispatch_id,
        sign_register_attempt_authorization, AuthenticatedAttemptRequest, RegisterAttemptAction,
    };
    use crate::revocation::{
        BrokerRevocationRequest, BrokerRevocationSnapshot, BrokerRevocations, CapabilityLiveness,
        CapabilityLivenessRequest, LiveParentCapability,
    };
    use crate::service::{BrokerServiceAuthorityBundle, BrokerServiceConfig};
    use crate::sqlite::SqliteAttemptStore;
    use crate::store::{derive_attempt_ids_for_operation, AttemptRegistration};

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

    struct CredentialMutationTraitProbe<T>(std::marker::PhantomData<T>);

    trait CredentialMutationDebugAmbiguity<Marker> {
        fn assert_absent() {}
    }

    impl<T> CredentialMutationDebugAmbiguity<()> for CredentialMutationTraitProbe<T> {}
    impl<T: std::fmt::Debug> CredentialMutationDebugAmbiguity<u8> for CredentialMutationTraitProbe<T> {}

    trait CredentialMutationCloneAmbiguity<Marker> {
        fn assert_absent() {}
    }

    impl<T> CredentialMutationCloneAmbiguity<()> for CredentialMutationTraitProbe<T> {}
    impl<T: Clone> CredentialMutationCloneAmbiguity<u8> for CredentialMutationTraitProbe<T> {}

    trait CredentialMutationSerializeAmbiguity<Marker> {
        fn assert_absent() {}
    }

    impl<T> CredentialMutationSerializeAmbiguity<()> for CredentialMutationTraitProbe<T> {}
    impl<T: serde::Serialize> CredentialMutationSerializeAmbiguity<u8>
        for CredentialMutationTraitProbe<T>
    {
    }

    #[test]
    fn credential_mutation_parser_is_strictly_canonical_redacted_and_zeroizing() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

        assert_zeroize_on_drop::<CredentialMutationCommand>();
        assert_zeroize_on_drop::<BoundedZeroizingByteArray<65_536>>();
        assert_zeroize_on_drop::<Zeroizing<Vec<u8>>>();
        type CommandProbe = CredentialMutationTraitProbe<CredentialMutationCommand>;
        <CommandProbe as CredentialMutationDebugAmbiguity<_>>::assert_absent();
        <CommandProbe as CredentialMutationCloneAmbiguity<_>>::assert_absent();
        <CommandProbe as CredentialMutationSerializeAmbiguity<_>>::assert_absent();

        crate::service::reset_sensitive_drop_observer();
        let canonical = br#"{"credential":{"credentialId":"credential-ipc","provider":"generic-https","version":1},"mutation":"provision","schema":"chio.broker-credential-mutation.v1","secret":[7,8,9]}"#;
        let decoded = decode_canonical_credential_mutation_payload(canonical)
            .test_expect("canonical credential mutation");
        assert_eq!(decoded.mutation, CredentialMutationKind::Provision);
        assert_eq!(decoded.secret.as_slice(), [7, 8, 9]);
        assert_eq!(
            canonical_credential_mutation_payload(&decoded)
                .test_expect("canonical credential mutation encoding")
                .as_slice(),
            canonical
        );
        drop(decoded);
        assert_eq!(crate::service::sensitive_drop_observation().0, 1);

        let reordered = br#"{"schema":"chio.broker-credential-mutation.v1","credential":{"credentialId":"credential-ipc","provider":"generic-https","version":1},"mutation":"provision","secret":[7,8,9]}"#;
        assert!(decode_canonical_credential_mutation_payload(reordered).is_err());
        let duplicate = br#"{"credential":{"credentialId":"credential-ipc","provider":"generic-https","version":1},"mutation":"provision","schema":"chio.broker-credential-mutation.v1","secret":[7,8,9],"secret":[10]}"#;
        assert!(decode_canonical_credential_mutation_payload(duplicate).is_err());
        let duplicate_nested = br#"{"credential":{"credentialId":"credential-ipc","provider":"generic-https","provider":"other","version":1},"mutation":"provision","schema":"chio.broker-credential-mutation.v1","secret":[7,8,9]}"#;
        assert!(decode_canonical_credential_mutation_payload(duplicate_nested).is_err());
        let unknown = br#"{"credential":{"credentialId":"credential-ipc","provider":"generic-https","version":1},"mutation":"provision","schema":"chio.broker-credential-mutation.v1","secret":[7,8,9],"unexpected":true}"#;
        assert!(decode_canonical_credential_mutation_payload(unknown).is_err());
        let unsafe_integer = br#"{"credential":{"credentialId":"credential-ipc","provider":"generic-https","version":9007199254740992},"mutation":"provision","schema":"chio.broker-credential-mutation.v1","secret":[7,8,9]}"#;
        assert!(decode_canonical_credential_mutation_payload(unsafe_integer).is_err());
        let exponent_version = br#"{"credential":{"credentialId":"credential-ipc","provider":"generic-https","version":1e0},"mutation":"provision","schema":"chio.broker-credential-mutation.v1","secret":[7,8,9]}"#;
        assert!(decode_canonical_credential_mutation_payload(exponent_version).is_err());
        let negative_version = br#"{"credential":{"credentialId":"credential-ipc","provider":"generic-https","version":-1},"mutation":"provision","schema":"chio.broker-credential-mutation.v1","secret":[7,8,9]}"#;
        assert!(decode_canonical_credential_mutation_payload(negative_version).is_err());
        let fractional_version = br#"{"credential":{"credentialId":"credential-ipc","provider":"generic-https","version":1.0},"mutation":"provision","schema":"chio.broker-credential-mutation.v1","secret":[7,8,9]}"#;
        assert!(decode_canonical_credential_mutation_payload(fractional_version).is_err());
        let escaped_key = br#"{"credential":{"credential\u0049d":"credential-ipc","provider":"generic-https","version":1},"mutation":"provision","schema":"chio.broker-credential-mutation.v1","secret":[7,8,9]}"#;
        assert!(decode_canonical_credential_mutation_payload(escaped_key).is_err());
        let surrogate_pair = br#"{"credential":{"credentialId":"\ud83d\ude00","provider":"generic-https","version":1},"mutation":"provision","schema":"chio.broker-credential-mutation.v1","secret":[7,8,9]}"#;
        assert!(decode_canonical_credential_mutation_payload(surrogate_pair).is_err());
        let exponent_byte = br#"{"credential":{"credentialId":"credential-ipc","provider":"generic-https","version":1},"mutation":"provision","schema":"chio.broker-credential-mutation.v1","secret":[7e0]}"#;
        assert!(decode_canonical_credential_mutation_payload(exponent_byte).is_err());
        let negative_byte = br#"{"credential":{"credentialId":"credential-ipc","provider":"generic-https","version":1},"mutation":"provision","schema":"chio.broker-credential-mutation.v1","secret":[-7]}"#;
        assert!(decode_canonical_credential_mutation_payload(negative_byte).is_err());
        let fractional_byte = br#"{"credential":{"credentialId":"credential-ipc","provider":"generic-https","version":1},"mutation":"provision","schema":"chio.broker-credential-mutation.v1","secret":[7.0]}"#;
        assert!(decode_canonical_credential_mutation_payload(fractional_byte).is_err());
        let trailing_data = br#"{"credential":{"credentialId":"credential-ipc","provider":"generic-https","version":1},"mutation":"provision","schema":"chio.broker-credential-mutation.v1","secret":[7,8,9]}null"#;
        assert!(decode_canonical_credential_mutation_payload(trailing_data).is_err());
        let deep_nesting = br#"{"credential":{"credentialId":"credential-ipc","provider":"generic-https","version":1},"mutation":"provision","schema":"chio.broker-credential-mutation.v1","secret":[[[[7]]]]}"#;
        assert!(decode_canonical_credential_mutation_payload(deep_nesting).is_err());

        let mut malformed_utf8 = Zeroizing::new(br#"{"credential":{"credentialId":""#.to_vec());
        malformed_utf8.push(0xff);
        malformed_utf8.extend_from_slice(br#"","provider":"generic-https","version":1},"mutation":"provision","schema":"chio.broker-credential-mutation.v1","secret":[7,8,9]}"#);
        assert!(decode_canonical_credential_mutation_payload(&malformed_utf8).is_err());

        let malformed_secret = br#"{"credential":{"credentialId":"credential-ipc","provider":"generic-https","version":1},"mutation":"provision","schema":"chio.broker-credential-mutation.v1","secret":[7,"secret-canary"]}"#;
        crate::service::reset_sensitive_drop_observer();
        let error = match decode_canonical_credential_mutation_payload(malformed_secret) {
            Ok(_) => panic!("malformed secret must fail closed"),
            Err(error) => error,
        };
        assert!(!error.to_string().contains("secret-canary"));
        assert!(crate::service::sensitive_drop_observation().0 >= 1);
    }

    #[test]
    fn long_credential_mutation_uses_one_exact_canonical_allocation() {
        let secret = Zeroizing::new(vec![255; 65_536]);
        let command = CredentialMutationCommand {
            schema: CREDENTIAL_MUTATION_SCHEMA.to_string(),
            mutation: CredentialMutationKind::Rotate,
            credential: CredentialRef {
                provider: "p".repeat(512),
                credential_id: "c".repeat(512),
                version: I_JSON_MAX_SAFE_INTEGER,
            },
            secret: BoundedZeroizingByteArray::copy_from_slice(secret.as_slice())
                .test_expect("maximum credential secret"),
        };
        let canonical =
            canonical_credential_mutation_payload(&command).test_expect("long credential mutation");
        assert_eq!(canonical.len(), canonical.capacity());
        assert!(canonical.len() < crate::protocol::MAX_WIRE_BYTES);
    }

    struct FakeAuthority {
        control_calls: AtomicU64,
        prepare_calls: AtomicU64,
    }

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
            self.prepare_calls.fetch_add(1, Ordering::SeqCst);
            let operation_id = "kernel-admission-operation-production".to_string();
            let request_digest = crate::service::broker_request_digest(request)?;
            let ids = derive_attempt_ids_for_operation(
                &request.capability.body.capability_id,
                &request.invocation_id,
                &request.proof.body.nonce,
                &request_digest,
                &operation_id,
            )?;
            let quotas = vec![
                ExecutionQuota {
                    key_id: request.capability.body.broker_quota_key_id.clone(),
                    maximum_executions: request.capability.body.maximum_executions,
                },
                ExecutionQuota {
                    key_id: "parent-quota-production".to_string(),
                    maximum_executions: 10,
                },
            ];
            let registration = AttemptRegistration {
                ids,
                invocation_id: request.invocation_id.clone(),
                parent_capability_id: request.capability.body.parent_capability_id.clone(),
                broker_capability_id: request.capability.body.capability_id.clone(),
                request_digest,
                request_canonical_digest: broker_execute_request_registration_digest(request)?,
                proof_digest: proof_digest(&request.proof)?,
                proof_key_id: request.proof.body.authority_key.to_hex(),
                proof_nonce: request.proof.body.nonce.clone(),
                nonce_expires_at_unix_seconds: 130,
                quotas: quotas.clone(),
                authority_metadata_digest: "bb".repeat(32),
                revocation_authority_domain: "combined-production".to_string(),
            };
            Ok(crate::service::TrustedExecutionContext {
                admission_operation_id: operation_id,
                prepared_dispatch_id: prepared_dispatch_id(&registration, request)?,
                quotas,
                authority_metadata_digest: "bb".repeat(32),
                revocation_authority_domain: "combined-production".to_string(),
                source_receipt_ids: vec!["source-receipt-production".to_string()],
            })
        }

        fn control(&self, request: AuthorityControlRequest) -> Result<Vec<u8>> {
            self.control_calls.fetch_add(1, Ordering::SeqCst);
            let command: CapabilityControlCommand = decode_canonical_payload(&request.payload)?;
            command.validate()?;
            canonical_json_bytes(&CapabilityStatusResponse {
                schema: CAPABILITY_STATUS_SCHEMA.to_string(),
                capability_id: command.capability_id,
                revocation_id: command.revocation_id,
                revoked: false,
                authority_commit_index: 14,
                observed_at_unix_seconds: 100,
            })
            .map_err(|error| {
                BrokerError::Invariant(format!("fake authority status encoding failed: {error}"))
            })
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
        failures: Mutex<BTreeMap<String, SignedBrokerFailureReceipt>>,
        completed: Mutex<BTreeMap<String, crate::protocol::BrokerExecuteResponse>>,
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
            Ok(format!(
                "broker-receipt-sha256-{}",
                crate::receipt::receipt_digest(receipt)?
            ))
        }

        fn persist_failure(&self, receipt: &SignedBrokerFailureReceipt) -> Result<String> {
            let canonical = canonical_json_bytes(receipt).map_err(|error| {
                BrokerError::Invariant(format!("failure receipt test encoding failed: {error}"))
            })?;
            if canonical
                .windows(self.canary.len())
                .any(|window| window == self.canary)
            {
                return Err(BrokerError::Invariant(
                    "credential crossed into the broker failure receipt".to_string(),
                ));
            }
            let mut failures = self.failures.lock().map_err(|_| {
                BrokerError::Invariant("failure receipt test lock is poisoned".to_string())
            })?;
            if let Some(existing) = failures.get(&receipt.body.receipt_id) {
                if existing != receipt {
                    return Err(BrokerError::Conflict(
                        "test failure receipt ID has different content".to_string(),
                    ));
                }
            } else {
                failures.insert(receipt.body.receipt_id.clone(), receipt.clone());
            }
            Ok(format!(
                "broker-failure-receipt-sha256-{}",
                crate::receipt::failure_receipt_digest(receipt)?
            ))
        }

        fn load_failure(&self, receipt_id: &str) -> Result<Option<SignedBrokerFailureReceipt>> {
            Ok(self
                .failures
                .lock()
                .map_err(|_| {
                    BrokerError::Invariant("failure receipt test lock is poisoned".to_string())
                })?
                .get(receipt_id)
                .cloned())
        }

        fn supports_failure_receipts(&self) -> bool {
            true
        }

        fn persist_completed(
            &self,
            response: &crate::protocol::BrokerExecuteResponse,
        ) -> Result<String> {
            let canonical = canonical_json_bytes(response).map_err(|error| {
                BrokerError::Invariant(format!("completed response test encoding failed: {error}"))
            })?;
            if canonical
                .windows(self.canary.len())
                .any(|window| window == self.canary)
            {
                return Err(BrokerError::Invariant(
                    "credential crossed into the completed broker response".to_string(),
                ));
            }
            let reference = self.persist(&response.receipt)?;
            let mut completed = self.completed.lock().map_err(|_| {
                BrokerError::Invariant("completed response test lock is poisoned".to_string())
            })?;
            if let Some(existing) = completed.get(&response.evidence.attempt_id) {
                if existing != response {
                    return Err(BrokerError::Conflict(
                        "test attempt has a different completed response".to_string(),
                    ));
                }
            } else {
                completed.insert(response.evidence.attempt_id.clone(), response.clone());
            }
            Ok(reference)
        }

        fn load_completed(
            &self,
            attempt_id: &str,
        ) -> Result<Option<crate::protocol::BrokerExecuteResponse>> {
            Ok(self
                .completed
                .lock()
                .map_err(|_| {
                    BrokerError::Invariant("completed response test lock is poisoned".to_string())
                })?
                .get(attempt_id)
                .cloned())
        }

        fn supports_completed_replay(&self) -> bool {
            true
        }
    }

    fn credential_mutation_payload_for_test(
        mutation: CredentialMutationKind,
        credential: &CredentialRef,
        secret: &[u8],
    ) -> Zeroizing<Vec<u8>> {
        canonical_credential_mutation_payload(&CredentialMutationCommand {
            schema: CREDENTIAL_MUTATION_SCHEMA.to_string(),
            mutation,
            credential: credential.clone(),
            secret: BoundedZeroizingByteArray::copy_from_slice(secret)
                .test_expect("credential mutation secret"),
        })
        .test_expect("credential mutation payload")
    }

    fn governed_authorization(
        approver: &Keypair,
        subject: &chio_core_types::PublicKey,
        intent: &str,
    ) -> Vec<u8> {
        governed_authorization_for(
            approver,
            subject,
            intent,
            "daemon-approval-production-1",
            "daemon-admin-request-production-1",
        )
    }

    fn governed_authorization_for(
        approver: &Keypair,
        subject: &chio_core_types::PublicKey,
        intent: &str,
        approval_id: &str,
        request_id: &str,
    ) -> Vec<u8> {
        let approval = GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: approval_id.to_string(),
                approver: approver.public_key(),
                subject: subject.clone(),
                governed_intent_hash: intent.to_string(),
                threshold_proposal_hash: Some("cc".repeat(32)),
                request_id: request_id.to_string(),
                issued_at: 90,
                expires_at: 110,
                decision: GovernedApprovalDecision::Approved,
            },
            approver,
        )
        .test_expect("approval");
        GovernedAdminAuthorizationEnvelope::new(vec![approval])
            .test_expect("envelope")
            .canonical_bytes()
            .test_expect("canonical envelope")
    }

    #[test]
    fn daemon_mutation_retry_rejects_untrusted_or_command_misbound_receipt() {
        let trusted_signer = Keypair::from_seed(&[78; 32]);
        let untrusted_signer = Keypair::from_seed(&[79; 32]);
        let credential = CredentialRef {
            provider: "generic-https".to_string(),
            credential_id: "credential-retry-binding".to_string(),
            version: 1,
        };
        let body = AdminMutationReceiptBody {
            schema: ADMIN_MUTATION_RECEIPT_SCHEMA.to_string(),
            operation_id: "11".repeat(32),
            request_id: "request-retry-binding".to_string(),
            intent_digest: "22".repeat(32),
            authorization_digest: "33".repeat(32),
            operation: AdminOperation::Rotate,
            tenant_scope: "tenant-production".to_string(),
            credential: credential.clone(),
            completed_at_unix_seconds: 100,
            outcome: AdminMutationOutcome::Applied,
        };
        let trusted =
            sign_admin_mutation_receipt(body.clone(), &Ed25519Backend::new(trusted_signer.clone()))
                .test_expect("trusted receipt");
        validate_mutation_retry_receipt(
            &trusted,
            &trusted_signer.public_key(),
            AdminOperation::Rotate,
            "tenant-production",
            &credential,
        )
        .test_expect("exact trusted retry binding");

        let untrusted =
            sign_admin_mutation_receipt(body.clone(), &Ed25519Backend::new(untrusted_signer))
                .test_expect("untrusted self-signed receipt");
        assert!(validate_mutation_retry_receipt(
            &untrusted,
            &trusted_signer.public_key(),
            AdminOperation::Rotate,
            "tenant-production",
            &credential,
        )
        .is_err());
        assert!(validate_mutation_retry_receipt(
            &trusted,
            &trusted_signer.public_key(),
            AdminOperation::Disable,
            "tenant-production",
            &credential,
        )
        .is_err());
        assert!(validate_mutation_retry_receipt(
            &trusted,
            &trusted_signer.public_key(),
            AdminOperation::Rotate,
            "tenant-other",
            &credential,
        )
        .is_err());
        let mut changed_credential = credential;
        changed_credential.version += 1;
        assert!(validate_mutation_retry_receipt(
            &trusted,
            &trusted_signer.public_key(),
            AdminOperation::Rotate,
            "tenant-production",
            &changed_credential,
        )
        .is_err());
    }

    #[test]
    fn daemon_governance_binds_payload_and_fake_upstream_is_the_only_secret_sink() {
        let canary = b"daemon-process-secret-canary-91f7".to_vec();
        let backend = Arc::new(
            EncryptedBlobSecretBackend::open_in_memory_for_test("tenant-production", [81; 32])
                .test_expect("backend"),
        );
        let issuer = Keypair::from_seed(&[82; 32]);
        let caller = Keypair::from_seed(&[83; 32]);
        let receipt_signer = Keypair::from_seed(&[84; 32]);
        let authority_signer = Keypair::from_seed(&[87; 32]);
        let issuer_backend = Ed25519Backend::new(issuer.clone());
        let receipt_signing_backend: Arc<dyn SigningBackend> =
            Arc::new(Ed25519Backend::new(receipt_signer));
        let authority_signing_backend = Ed25519Backend::new(authority_signer.clone());
        let authority = Arc::new(FakeAuthority {
            control_calls: AtomicU64::new(0),
            prepare_calls: AtomicU64::new(0),
        });
        let budget: Arc<dyn BrokerExecutionBudget> = authority.clone();
        let liveness: Arc<dyn CapabilityLiveness> = authority.clone();
        let revocations: Arc<dyn BrokerRevocations> = authority.clone();
        let observed_authorization = Arc::new(Mutex::new(None));
        let service = Arc::new(
            BrokerService::new_for_test(
                BrokerServiceConfig {
                    audience: "broker-service-production".to_string(),
                    parent_audience: "parent-service-production".to_string(),
                    maximum_clock_skew_seconds: 1,
                    maximum_liveness_snapshot_age_seconds: 1,
                    maximum_revocation_snapshot_age_seconds: 1,
                },
                Arc::new(SqliteAttemptStore::open_in_memory().test_expect("attempts")),
                BrokerServiceAuthorityBundle {
                    trusted_issuer: issuer.public_key(),
                    backend: Arc::clone(&backend),
                    provider: Arc::new(
                        GenericCredentialProvider::new(
                            "generic-bearer".to_string(),
                            1,
                            CredentialPlacement::BearerAuthorization,
                        )
                        .test_expect("provider"),
                    ),
                    https: Arc::new(GenericHttpsExecutor::new(
                        Arc::new(Resolver),
                        Arc::new(ObservingTransport {
                            observed_authorization: Arc::clone(&observed_authorization),
                        }),
                        NetworkPolicy::production(),
                    )),
                    budget,
                    liveness,
                    revocations,
                    receipt_sink: Arc::new(InspectingReceiptSink {
                        canary: canary.clone(),
                        failures: Mutex::new(BTreeMap::new()),
                        completed: Mutex::new(BTreeMap::new()),
                    }),
                    receipt_signer: Arc::clone(&receipt_signing_backend),
                    migration_enforcer: crate::migration::TestBrokerMigrationEnforcer::new(vec![
                        "generic-https".to_string(),
                    ]),
                },
            )
            .test_expect("service"),
        );
        let admin_directory = crate::private_tempdir().test_expect("admin directory");
        #[cfg(unix)]
        std::fs::set_permissions(
            admin_directory.path(),
            std::fs::Permissions::from_mode(0o700),
        )
        .test_expect("harden admin database directory");
        let trusted_admin_directory = std::fs::canonicalize(admin_directory.path())
            .test_expect("canonicalize admin database directory");
        let approver = Keypair::from_seed(&[85; 32]);
        let admin_subject = Keypair::from_seed(&[86; 32]).public_key();
        let admin = Arc::new(
            GovernedAdminAuthorizer::open(
                trusted_admin_directory.join("admin.sqlite3"),
                GovernedAdminPolicy {
                    trusted_approvers: vec![approver.public_key()],
                    subject: admin_subject.clone(),
                    threshold: 1,
                    maximum_token_lifetime_seconds: 60,
                },
                receipt_signing_backend.public_key(),
                Arc::new(FixedClock(100)),
            )
            .test_expect("admin"),
        );
        let admission: Arc<dyn BrokerAdmissionAuthority> = authority.clone();
        let handler = BrokerDaemonHandler::new(
            "tenant-production".to_string(),
            "broker-service-production".to_string(),
            issuer.public_key(),
            authority_signer.public_key(),
            1,
            service,
            admission,
            Arc::clone(&admin),
            receipt_signing_backend,
            Arc::clone(&backend),
            Arc::new(FixedClock(100)),
        )
        .test_expect("handler");

        let credential = CredentialRef {
            provider: "generic-https".to_string(),
            credential_id: "credential-production".to_string(),
            version: 1,
        };
        let payload = credential_mutation_payload_for_test(
            CredentialMutationKind::Provision,
            &credential,
            &canary,
        );
        let intent =
            daemon_admin_intent_digest(IpcOperation::Provision, "tenant-production", &payload)
                .test_expect("admin intent");
        let authorization = governed_authorization(&approver, &admin_subject, &intent);
        let mut changed_canary = canary.clone();
        changed_canary.push(b'x');
        let changed_payload = credential_mutation_payload_for_test(
            CredentialMutationKind::Provision,
            &credential,
            &changed_canary,
        );
        assert!(handler
            .provision(AuthenticatedIpcRequest {
                operation: IpcOperation::Provision,
                tenant_scope: "tenant-production".to_string(),
                authorization: authorization.clone().into(),
                payload: changed_payload.to_vec().into(),
            })
            .is_err());
        let pending = admin
            .begin_intent_digest(
                &AdminAuthorization::new(authorization.clone()).test_expect("authorization"),
                &intent,
            )
            .test_expect("durable pending operation");
        backend
            .provision_once(
                &credential,
                &canary,
                pending.operation_id(),
                pending.intent_digest(),
            )
            .test_expect("backend mutation before simulated crash");
        assert!(pending.completed_receipt().is_none());
        let provisioned = handler
            .provision(AuthenticatedIpcRequest {
                operation: IpcOperation::Provision,
                tenant_scope: "tenant-production".to_string(),
                authorization: authorization.clone().into(),
                payload: payload.to_vec().into(),
            })
            .test_expect("provisioned");
        assert!(provisioned.accepted);
        let provisioned_wire = canonical_json_bytes(&provisioned).test_expect("provision response");
        assert!(!provisioned_wire
            .windows(canary.len())
            .any(|window| window == canary));
        let replayed = handler
            .provision(AuthenticatedIpcRequest {
                operation: IpcOperation::Provision,
                tenant_scope: "tenant-production".to_string(),
                authorization: authorization.into(),
                payload: payload.to_vec().into(),
            })
            .test_expect("exact retry");
        assert_eq!(replayed, provisioned);

        let destination = BrokerDestination::parse("https://example.com/v1", "post", false)
            .test_expect("destination");
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
            &issuer_backend,
            true,
        )
        .test_expect("capability");
        let proof = issue_request_proof(
            &capability,
            &broker_request,
            "daemon-proof-nonce-production".to_string(),
            100,
            &caller,
        )
        .test_expect("proof");
        let execute = BrokerExecuteRequest {
            schema: BROKER_EXECUTE_SCHEMA.to_string(),
            invocation_id: "daemon-invocation-production".to_string(),
            capability,
            proof,
            request: broker_request,
        };
        let request_digest =
            crate::service::broker_request_digest(&execute).test_expect("broker request digest");
        let ids = derive_attempt_ids_for_operation(
            &execute.capability.body.capability_id,
            &execute.invocation_id,
            &execute.proof.body.nonce,
            &request_digest,
            "kernel-admission-operation-production",
        )
        .test_expect("attempt ids");
        let registration = AttemptRegistration {
            ids,
            invocation_id: execute.invocation_id.clone(),
            parent_capability_id: execute.capability.body.parent_capability_id.clone(),
            broker_capability_id: execute.capability.body.capability_id.clone(),
            request_digest,
            request_canonical_digest: broker_execute_request_registration_digest(&execute)
                .test_expect("canonical request digest"),
            proof_digest: proof_digest(&execute.proof).test_expect("proof digest"),
            proof_key_id: execute.proof.body.authority_key.to_hex(),
            proof_nonce: execute.proof.body.nonce.clone(),
            nonce_expires_at_unix_seconds: 130,
            quotas: vec![
                ExecutionQuota {
                    key_id: execute.capability.body.broker_quota_key_id.clone(),
                    maximum_executions: execute.capability.body.maximum_executions,
                },
                ExecutionQuota {
                    key_id: "parent-quota-production".to_string(),
                    maximum_executions: 10,
                },
            ],
            authority_metadata_digest: "bb".repeat(32),
            revocation_authority_domain: "combined-production".to_string(),
        };
        let registration_payload = canonical_json_bytes(&AuthenticatedAttemptRequest {
            registration: registration.clone(),
            request: execute.clone(),
        })
        .test_expect("registration payload");
        let registration_authorization = canonical_json_bytes(
            &sign_register_attempt_authorization(
                RegisterAttemptAction::Register,
                "tenant-production".to_string(),
                &registration,
                100,
                &authority_signing_backend,
            )
            .test_expect("registration authorization"),
        )
        .test_expect("registration authorization encoding");
        let registered = handler
            .register_attempt(AuthenticatedIpcRequest {
                operation: IpcOperation::RegisterAttempt,
                tenant_scope: "tenant-production".to_string(),
                authorization: registration_authorization.into(),
                payload: registration_payload.into(),
            })
            .test_expect("register attempt");
        assert!(registered.accepted);
        let prepare_authorization = canonical_json_bytes(
            &sign_register_attempt_authorization(
                RegisterAttemptAction::Prepare,
                "tenant-production".to_string(),
                &registration,
                100,
                &authority_signing_backend,
            )
            .test_expect("prepare authorization"),
        )
        .test_expect("prepare authorization encoding");
        let prepared = handler
            .prepare_dispatch(AuthenticatedIpcRequest {
                operation: IpcOperation::PrepareDispatch,
                tenant_scope: "tenant-production".to_string(),
                authorization: prepare_authorization.into(),
                payload: canonical_json_bytes(&AuthenticatedAttemptRequest {
                    registration: registration.clone(),
                    request: execute.clone(),
                })
                .test_expect("prepare payload")
                .into(),
            })
            .test_expect("prepare dispatch");
        assert!(prepared.accepted);
        let execute_payload = canonical_json_bytes(&execute).test_expect("execute payload");
        let proof_authorization =
            canonical_json_bytes(&execute.proof).test_expect("proof authorization");
        assert!(matches!(
            handler.execute(AuthenticatedIpcRequest {
                operation: IpcOperation::Execute,
                tenant_scope: "tenant-production".to_string(),
                authorization: b"{}".to_vec().into(),
                payload: execute_payload.clone().into(),
            }),
            Err(BrokerError::AuthorizationDenied(_))
        ));
        assert_eq!(
            authority.prepare_calls.load(Ordering::SeqCst),
            0,
            "wrong outer proof must not consult admission or persist a denial"
        );
        let response = handler
            .execute(AuthenticatedIpcRequest {
                operation: IpcOperation::Execute,
                tenant_scope: "tenant-production".to_string(),
                authorization: proof_authorization.into(),
                payload: execute_payload.into(),
            })
            .test_expect("execute");
        assert!(response.accepted);
        assert_eq!(authority.prepare_calls.load(Ordering::SeqCst), 1);
        let response_wire = canonical_json_bytes(&response).test_expect("response wire");
        assert!(!response_wire
            .windows(canary.len())
            .any(|window| window == canary));
        let observed = observed_authorization
            .lock()
            .test_expect("observation")
            .clone()
            .test_expect("credential observed upstream");
        assert_eq!(
            observed,
            [b"Bearer ".as_slice(), canary.as_slice()].concat()
        );
        let replayed_execution = handler
            .execute(AuthenticatedIpcRequest {
                operation: IpcOperation::Execute,
                tenant_scope: "tenant-production".to_string(),
                authorization: canonical_json_bytes(&execute.proof)
                    .test_expect("replay proof authorization")
                    .into(),
                payload: canonical_json_bytes(&execute)
                    .test_expect("replay execute payload")
                    .into(),
            })
            .test_expect("replay completed execution");
        assert_eq!(replayed_execution, response);
        assert_eq!(
            authority.prepare_calls.load(Ordering::SeqCst),
            1,
            "completed replay must not consult the live admission authority"
        );

        let status_command = CapabilityControlCommand {
            schema: CAPABILITY_CONTROL_SCHEMA.to_string(),
            capability_id: "broker-capability-production".to_string(),
            revocation_id: "broker-revocation-production".to_string(),
            credential: CredentialRef {
                provider: "generic-https".to_string(),
                credential_id: "credential-production".to_string(),
                version: 1,
            },
        };
        let status_payload = canonical_json_bytes(&status_command).test_expect("status payload");
        let status_intent =
            daemon_admin_intent_digest(IpcOperation::Status, "tenant-production", &status_payload)
                .test_expect("status intent");
        let status_authorization = governed_authorization_for(
            &approver,
            &admin_subject,
            &status_intent,
            "daemon-approval-status-production-1",
            "daemon-admin-status-request-production-1",
        );
        let first_status = handler
            .status(AuthenticatedIpcRequest {
                operation: IpcOperation::Status,
                tenant_scope: "tenant-production".to_string(),
                authorization: status_authorization.clone().into(),
                payload: status_payload.clone().into(),
            })
            .test_expect("first governed status");
        let retried_status = handler
            .status(AuthenticatedIpcRequest {
                operation: IpcOperation::Status,
                tenant_scope: "tenant-production".to_string(),
                authorization: status_authorization.into(),
                payload: status_payload.into(),
            })
            .test_expect("retried governed status");
        assert_eq!(first_status, retried_status);
        assert_eq!(authority.control_calls.load(Ordering::SeqCst), 1);
    }
}
