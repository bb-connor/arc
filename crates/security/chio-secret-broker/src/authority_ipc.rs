use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};

use chio_core_types::{
    canonical_json_bytes, PublicKey, Signature, SigningAlgorithm, SigningBackend,
};
#[cfg(test)]
use chio_core_types::{Ed25519Backend, Keypair};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::budget::{
    AuthorizeExecutionHoldRequest, BrokerExecutionBudget, CaptureExecutionHoldRequest,
    ExecutionAuthorityCapabilities, ExecutionHoldState, QueryExecutionHoldRequest,
    ReverseExecutionHoldRequest,
};
use crate::protocol::{BrokerExecuteRequest, MAX_WIRE_BYTES};
use crate::revocation::{
    BrokerRevocationRequest, BrokerRevocationSnapshot, BrokerRevocations, CapabilityLiveness,
    CapabilityLivenessRequest, LiveParentCapability,
};
use crate::service::{
    read_bounded_frame, write_bounded_frame, IpcOperation, TrustedExecutionContext,
};
use crate::{validate_digest, validate_identifier, BrokerError, Result};

pub const AUTHORITY_RPC_SCHEMA: &str = "chio.broker-authority-rpc.v1";
const AUTHORITY_REQUEST_DOMAIN: &str = "chio.broker-authority-request.v1\0";
const AUTHORITY_RESPONSE_DOMAIN: &str = "chio.broker-authority-response.v1\0";
const MAX_AUTHORITY_CLOCK_SKEW_SECONDS: u64 = 30;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "request")]
pub enum AuthorityOperation {
    Capabilities,
    PrepareExecution(Box<BrokerExecuteRequest>),
    VerifyLiveParent(CapabilityLivenessRequest),
    CheckBrokerRevocation(BrokerRevocationRequest),
    QueryExecutionHold(QueryExecutionHoldRequest),
    AuthorizeExecutionHold(AuthorizeExecutionHoldRequest),
    ReverseExecutionHold(ReverseExecutionHoldRequest),
    CaptureExecutionHold(CaptureExecutionHoldRequest),
    Control(AuthorityControlRequest),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityControlRequest {
    pub operation: IpcOperation,
    pub tenant_scope: String,
    pub authorization: Vec<u8>,
    pub payload: Vec<u8>,
}

impl AuthorityControlRequest {
    fn validate(&self) -> Result<()> {
        if !matches!(
            self.operation,
            IpcOperation::Issue | IpcOperation::Revoke | IpcOperation::Status
        ) {
            return Err(BrokerError::InvalidRequest(
                "authority control operation is not remotely governed".to_string(),
            ));
        }
        validate_identifier(&self.tenant_scope, "authority tenant scope", 512)?;
        if self.authorization.is_empty() || self.authorization.len() > 65_536 {
            return Err(BrokerError::AuthorizationDenied(
                "authority control authorization is missing or oversized".to_string(),
            ));
        }
        if self.payload.is_empty() || self.payload.len() > MAX_WIRE_BYTES {
            return Err(BrokerError::InvalidRequest(
                "authority control payload is empty or oversized".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "response")]
pub enum AuthorityResult {
    Capabilities(ExecutionAuthorityCapabilities),
    Prepared(TrustedExecutionContext),
    LiveParent(LiveParentCapability),
    Revocation(BrokerRevocationSnapshot),
    Hold(ExecutionHoldState),
    Control(Vec<u8>),
    Rejected { code: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityRequestBody {
    pub schema: String,
    pub request_id: String,
    pub issued_at_unix_seconds: u64,
    pub broker: PublicKey,
    pub operation: AuthorityOperation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedAuthorityRequest {
    pub body: AuthorityRequestBody,
    pub algorithm: SigningAlgorithm,
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityResponseBody {
    pub schema: String,
    pub request_id: String,
    pub request_digest: String,
    pub issued_at_unix_seconds: u64,
    pub authority: PublicKey,
    pub result: AuthorityResult,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedAuthorityResponse {
    pub body: AuthorityResponseBody,
    pub algorithm: SigningAlgorithm,
    pub signature: Signature,
}

/// Exact signed authority request and response retained for broker audit
/// evidence. Construction verifies both signatures, the response-to-request
/// binding, the independently trusted authority key, and the configured
/// freshness interval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAuthorityExchange {
    request: SignedAuthorityRequest,
    response: SignedAuthorityResponse,
    trusted_authority: PublicKey,
    verified_at_unix_seconds: u64,
    maximum_clock_skew_seconds: u64,
}

impl VerifiedAuthorityExchange {
    #[must_use]
    pub fn request(&self) -> &SignedAuthorityRequest {
        &self.request
    }

    #[must_use]
    pub fn response(&self) -> &SignedAuthorityResponse {
        &self.response
    }

    #[must_use]
    pub fn trusted_authority(&self) -> &PublicKey {
        &self.trusted_authority
    }

    #[must_use]
    pub const fn verified_at_unix_seconds(&self) -> u64 {
        self.verified_at_unix_seconds
    }

    #[must_use]
    pub const fn maximum_clock_skew_seconds(&self) -> u64 {
        self.maximum_clock_skew_seconds
    }

    pub fn request_sha256(&self) -> Result<String> {
        signed_request_digest(&self.request)
    }

    pub fn response_sha256(&self) -> Result<String> {
        let canonical = canonical_json_bytes(&self.response).map_err(|error| {
            BrokerError::Invariant(format!(
                "authority response evidence digest failed: {error}"
            ))
        })?;
        Ok(hex::encode(Sha256::digest(canonical)))
    }
}

/// Verify and retain one exact signed authority exchange for later audit
/// evidence verification.
pub fn verify_authority_exchange(
    request: SignedAuthorityRequest,
    response: SignedAuthorityResponse,
    trusted_authority: &PublicKey,
    verified_at_unix_seconds: u64,
    maximum_clock_skew_seconds: u64,
) -> Result<VerifiedAuthorityExchange> {
    verify_authority_request(
        &request,
        &request.body.broker,
        verified_at_unix_seconds,
        maximum_clock_skew_seconds,
    )?;
    let request_digest = signed_request_digest(&request)?;
    verify_authority_response(
        &response,
        trusted_authority,
        &request.body.request_id,
        &request_digest,
        verified_at_unix_seconds,
        maximum_clock_skew_seconds,
    )?;
    Ok(VerifiedAuthorityExchange {
        request,
        response,
        trusted_authority: trusted_authority.clone(),
        verified_at_unix_seconds,
        maximum_clock_skew_seconds,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AuthoritySigningInput<'a, T> {
    domain: &'static str,
    body: &'a T,
}

pub trait BrokerAdmissionAuthority: Send + Sync {
    fn prepare_execution(&self, request: &BrokerExecuteRequest) -> Result<TrustedExecutionContext>;

    fn control(&self, request: AuthorityControlRequest) -> Result<Vec<u8>>;
}

#[derive(Debug, Clone)]
pub struct AuthorityRpcClientConfig {
    pub socket_path: PathBuf,
    pub trusted_authority: PublicKey,
    pub timeout_ms: u64,
    pub maximum_clock_skew_seconds: u64,
}

impl AuthorityRpcClientConfig {
    fn validate(&self) -> Result<()> {
        validate_absolute_socket_path(&self.socket_path, "authority socket")?;
        if self.timeout_ms == 0
            || self.timeout_ms > 30_000
            || self.maximum_clock_skew_seconds == 0
            || self.maximum_clock_skew_seconds > MAX_AUTHORITY_CLOCK_SKEW_SECONDS
        {
            return Err(BrokerError::InvalidRequest(
                "authority RPC timeout or clock skew is invalid".to_string(),
            ));
        }
        Ok(())
    }
}

pub struct AuthorityRpcClient {
    config: AuthorityRpcClientConfig,
    broker_signer: Arc<dyn SigningBackend>,
    capabilities: ExecutionAuthorityCapabilities,
}

impl AuthorityRpcClient {
    #[cfg(unix)]
    pub fn connect(
        config: AuthorityRpcClientConfig,
        broker_signer: Arc<dyn SigningBackend>,
    ) -> Result<Self> {
        config.validate()?;
        let mut client = Self {
            config,
            broker_signer,
            capabilities: unavailable_capabilities(),
        };
        let AuthorityResult::Capabilities(capabilities) =
            client.call(AuthorityOperation::Capabilities)?
        else {
            return Err(BrokerError::AuthorityUnavailable(
                "authority capability handshake returned the wrong response".to_string(),
            ));
        };
        capabilities.require_production()?;
        client.capabilities = capabilities;
        Ok(client)
    }

    #[cfg(not(unix))]
    pub fn connect(
        _config: AuthorityRpcClientConfig,
        _broker_signer: Arc<dyn SigningBackend>,
    ) -> Result<Self> {
        Err(BrokerError::AuthorityUnavailable(
            "broker authority IPC requires Unix domain sockets".to_string(),
        ))
    }

    #[cfg(unix)]
    fn call(&self, operation: AuthorityOperation) -> Result<AuthorityResult> {
        self.call_with_exchange(operation).map(|(result, _)| result)
    }

    #[cfg(unix)]
    fn call_with_exchange(
        &self,
        operation: AuthorityOperation,
    ) -> Result<(AuthorityResult, VerifiedAuthorityExchange)> {
        validate_authority_operation(&operation)?;
        let now = now_unix_seconds()?;
        let request = sign_authority_request(operation, now, self.broker_signer.as_ref())?;
        let encoded = canonical_json_bytes(&request).map_err(|error| {
            BrokerError::Invariant(format!("authority request encoding failed: {error}"))
        })?;
        let mut stream = UnixStream::connect(&self.config.socket_path).map_err(|error| {
            BrokerError::AuthorityUnavailable(format!("authority IPC connect failed: {error}"))
        })?;
        let timeout = Duration::from_millis(self.config.timeout_ms);
        stream.set_read_timeout(Some(timeout)).map_err(|error| {
            BrokerError::AuthorityUnavailable(format!(
                "authority IPC read timeout setup failed: {error}"
            ))
        })?;
        stream.set_write_timeout(Some(timeout)).map_err(|error| {
            BrokerError::AuthorityUnavailable(format!(
                "authority IPC write timeout setup failed: {error}"
            ))
        })?;
        write_bounded_frame(&mut stream, &encoded)?;
        let response_bytes = read_bounded_frame(&mut stream)?;
        let response: SignedAuthorityResponse =
            serde_json::from_slice(&response_bytes).map_err(|error| {
                BrokerError::AuthorityUnavailable(format!(
                    "authority response decoding failed: {error}"
                ))
            })?;
        let canonical = canonical_json_bytes(&response).map_err(|error| {
            BrokerError::AuthorityUnavailable(format!(
                "authority response encoding failed: {error}"
            ))
        })?;
        if canonical != response_bytes {
            return Err(BrokerError::AuthorizationDenied(
                "authority response is not canonical JSON".to_string(),
            ));
        }
        let result = response.body.result.clone();
        let exchange = verify_authority_exchange(
            request,
            response,
            &self.config.trusted_authority,
            now_unix_seconds()?,
            self.config.maximum_clock_skew_seconds,
        )?;
        match result {
            AuthorityResult::Rejected { .. } => Err(BrokerError::AuthorizationDenied(
                "authority rejected broker operation".to_string(),
            )),
            result => Ok((result, exchange)),
        }
    }

    #[cfg(not(unix))]
    fn call(&self, _operation: AuthorityOperation) -> Result<AuthorityResult> {
        Err(BrokerError::AuthorityUnavailable(
            "broker authority IPC requires Unix domain sockets".to_string(),
        ))
    }

    #[cfg(not(unix))]
    fn call_with_exchange(
        &self,
        _operation: AuthorityOperation,
    ) -> Result<(AuthorityResult, VerifiedAuthorityExchange)> {
        Err(BrokerError::AuthorityUnavailable(
            "broker authority IPC requires Unix domain sockets".to_string(),
        ))
    }

    fn expect_hold(&self, operation: AuthorityOperation) -> Result<ExecutionHoldState> {
        match self.call(operation)? {
            AuthorityResult::Hold(state) => Ok(state),
            _ => Err(BrokerError::AuthorityUnavailable(
                "authority returned the wrong hold response".to_string(),
            )),
        }
    }
}

impl BrokerAdmissionAuthority for AuthorityRpcClient {
    fn prepare_execution(&self, request: &BrokerExecuteRequest) -> Result<TrustedExecutionContext> {
        match self.call(AuthorityOperation::PrepareExecution(Box::new(
            request.clone(),
        )))? {
            AuthorityResult::Prepared(context) => Ok(context),
            _ => Err(BrokerError::AuthorityUnavailable(
                "authority returned the wrong admission response".to_string(),
            )),
        }
    }

    fn control(&self, request: AuthorityControlRequest) -> Result<Vec<u8>> {
        request.validate()?;
        match self.call(AuthorityOperation::Control(request))? {
            AuthorityResult::Control(response) if response.len() <= MAX_WIRE_BYTES => Ok(response),
            AuthorityResult::Control(_) => Err(BrokerError::AuthorityUnavailable(
                "authority control response is oversized".to_string(),
            )),
            _ => Err(BrokerError::AuthorityUnavailable(
                "authority returned the wrong control response".to_string(),
            )),
        }
    }
}

impl CapabilityLiveness for AuthorityRpcClient {
    fn verify_live_parent(
        &self,
        request: &CapabilityLivenessRequest,
    ) -> Result<LiveParentCapability> {
        match self.call(AuthorityOperation::VerifyLiveParent(request.clone()))? {
            AuthorityResult::LiveParent(parent) => Ok(parent),
            _ => Err(BrokerError::AuthorityUnavailable(
                "authority returned the wrong liveness response".to_string(),
            )),
        }
    }

    fn verify_live_parent_with_audit_evidence(
        &self,
        request: &CapabilityLivenessRequest,
    ) -> Result<VerifiedAuthorityExchange> {
        match self.call_with_exchange(AuthorityOperation::VerifyLiveParent(request.clone()))? {
            (AuthorityResult::LiveParent(_), exchange) => Ok(exchange),
            _ => Err(BrokerError::AuthorityUnavailable(
                "authority returned the wrong liveness audit response".to_string(),
            )),
        }
    }
}

impl BrokerRevocations for AuthorityRpcClient {
    fn check_broker_revocation(
        &self,
        request: &BrokerRevocationRequest,
    ) -> Result<BrokerRevocationSnapshot> {
        match self.call(AuthorityOperation::CheckBrokerRevocation(request.clone()))? {
            AuthorityResult::Revocation(snapshot) => Ok(snapshot),
            _ => Err(BrokerError::AuthorityUnavailable(
                "authority returned the wrong revocation response".to_string(),
            )),
        }
    }

    fn check_broker_revocation_with_audit_evidence(
        &self,
        request: &BrokerRevocationRequest,
    ) -> Result<VerifiedAuthorityExchange> {
        match self.call_with_exchange(AuthorityOperation::CheckBrokerRevocation(request.clone()))? {
            (AuthorityResult::Revocation(_), exchange) => Ok(exchange),
            _ => Err(BrokerError::AuthorityUnavailable(
                "authority returned the wrong revocation audit response".to_string(),
            )),
        }
    }
}

impl BrokerExecutionBudget for AuthorityRpcClient {
    fn capabilities(&self) -> ExecutionAuthorityCapabilities {
        self.capabilities
    }

    fn query_execution_hold(
        &self,
        request: &QueryExecutionHoldRequest,
    ) -> Result<ExecutionHoldState> {
        request.validate()?;
        self.expect_hold(AuthorityOperation::QueryExecutionHold(request.clone()))
    }

    fn authorize_execution_hold(
        &self,
        request: &AuthorizeExecutionHoldRequest,
    ) -> Result<ExecutionHoldState> {
        request.validate()?;
        self.expect_hold(AuthorityOperation::AuthorizeExecutionHold(request.clone()))
    }

    fn reverse_execution_hold(
        &self,
        request: &ReverseExecutionHoldRequest,
    ) -> Result<ExecutionHoldState> {
        request.validate()?;
        self.expect_hold(AuthorityOperation::ReverseExecutionHold(request.clone()))
    }

    fn capture_execution_hold(
        &self,
        request: &CaptureExecutionHoldRequest,
    ) -> Result<ExecutionHoldState> {
        request.validate()?;
        self.expect_hold(AuthorityOperation::CaptureExecutionHold(request.clone()))
    }
}

pub trait BrokerAuthorityHandler: Send + Sync {
    fn handle(&self, operation: &AuthorityOperation) -> Result<AuthorityResult>;
}

#[cfg(unix)]
pub struct AuthorityRpcServer {
    listener: UnixListener,
    trusted_broker: PublicKey,
    authority_signer: Arc<dyn SigningBackend>,
    handler: Arc<dyn BrokerAuthorityHandler>,
    maximum_clock_skew_seconds: u64,
}

#[cfg(unix)]
impl AuthorityRpcServer {
    pub fn bind(
        path: impl AsRef<Path>,
        trusted_broker: PublicKey,
        authority_signer: Arc<dyn SigningBackend>,
        handler: Arc<dyn BrokerAuthorityHandler>,
        maximum_clock_skew_seconds: u64,
    ) -> Result<Self> {
        let path = path.as_ref();
        validate_absolute_socket_path(path, "authority listener socket")?;
        if maximum_clock_skew_seconds == 0
            || maximum_clock_skew_seconds > MAX_AUTHORITY_CLOCK_SKEW_SECONDS
        {
            return Err(BrokerError::InvalidRequest(
                "authority server clock skew is invalid".to_string(),
            ));
        }
        if path.exists() {
            return Err(BrokerError::Storage(
                "authority RPC socket path already exists".to_string(),
            ));
        }
        let listener = UnixListener::bind(path)
            .map_err(|error| BrokerError::Storage(format!("authority RPC bind failed: {error}")))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|error| {
            BrokerError::Storage(format!("authority RPC permissions failed: {error}"))
        })?;
        Ok(Self {
            listener,
            trusted_broker,
            authority_signer,
            handler,
            maximum_clock_skew_seconds,
        })
    }

    pub fn serve_one(&self) -> Result<()> {
        let (stream, _) = self.listener.accept().map_err(|error| {
            BrokerError::Storage(format!("authority RPC accept failed: {error}"))
        })?;
        self.serve_stream(stream)
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        self.listener.set_nonblocking(nonblocking).map_err(|error| {
            BrokerError::Storage(format!("authority RPC listener mode failed: {error}"))
        })
    }

    /// Serve one pending connection from a nonblocking listener.
    ///
    /// `Ok(false)` is an idle poll. Every accepted connection is handled to
    /// completion or returns its protocol/storage failure.
    pub fn try_serve_one(&self) -> Result<bool> {
        let stream = match self.listener.accept() {
            Ok((stream, _)) => stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) => {
                return Err(BrokerError::Storage(format!(
                    "authority RPC accept failed: {error}"
                )))
            }
        };
        self.serve_stream(stream)?;
        Ok(true)
    }

    fn serve_stream(&self, mut stream: UnixStream) -> Result<()> {
        let request_bytes = read_bounded_frame(&mut stream)?;
        let request: SignedAuthorityRequest =
            serde_json::from_slice(&request_bytes).map_err(|error| {
                BrokerError::InvalidRequest(format!("authority request failed: {error}"))
            })?;
        let canonical = canonical_json_bytes(&request).map_err(|error| {
            BrokerError::InvalidRequest(format!("authority request encoding failed: {error}"))
        })?;
        if canonical != request_bytes {
            return Err(BrokerError::AuthorizationDenied(
                "authority request is not canonical JSON".to_string(),
            ));
        }
        verify_authority_request(
            &request,
            &self.trusted_broker,
            now_unix_seconds()?,
            self.maximum_clock_skew_seconds,
        )?;
        let request_digest = signed_request_digest(&request)?;
        let result = self
            .handler
            .handle(&request.body.operation)
            .unwrap_or_else(|error| AuthorityResult::Rejected {
                code: error.diagnostic_code().to_string(),
            });
        let response = sign_authority_response(
            &request.body.request_id,
            &request_digest,
            result,
            now_unix_seconds()?,
            self.authority_signer.as_ref(),
        )?;
        let encoded = canonical_json_bytes(&response).map_err(|error| {
            BrokerError::Invariant(format!("authority response encoding failed: {error}"))
        })?;
        write_bounded_frame(&mut stream, &encoded)
    }
}

fn validate_authority_operation(operation: &AuthorityOperation) -> Result<()> {
    match operation {
        AuthorityOperation::Capabilities => Ok(()),
        AuthorityOperation::PrepareExecution(request) => request.as_ref().validate_bounds(),
        AuthorityOperation::VerifyLiveParent(request) => {
            validate_identifier(&request.parent_capability_id, "parent capability id", 512)?;
            validate_identifier(&request.expected_audience, "parent audience", 512)
        }
        AuthorityOperation::CheckBrokerRevocation(request) => {
            validate_identifier(&request.broker_capability_id, "broker capability id", 512)?;
            validate_identifier(&request.revocation_id, "broker revocation id", 512)
        }
        AuthorityOperation::QueryExecutionHold(request) => request.validate(),
        AuthorityOperation::AuthorizeExecutionHold(request) => request.validate(),
        AuthorityOperation::ReverseExecutionHold(request) => request.validate(),
        AuthorityOperation::CaptureExecutionHold(request) => request.validate(),
        AuthorityOperation::Control(request) => request.validate(),
    }
}

fn sign_authority_request(
    operation: AuthorityOperation,
    issued_at_unix_seconds: u64,
    signer: &dyn SigningBackend,
) -> Result<SignedAuthorityRequest> {
    if issued_at_unix_seconds == 0 {
        return Err(BrokerError::Invariant(
            "authority request clock returned zero".to_string(),
        ));
    }
    let mut random = [0_u8; 32];
    OsRng.fill_bytes(&mut random);
    let expected_broker = signer.public_key();
    let body = AuthorityRequestBody {
        schema: AUTHORITY_RPC_SCHEMA.to_string(),
        request_id: hex::encode(random),
        issued_at_unix_seconds,
        broker: expected_broker.clone(),
        operation,
    };
    let input = AuthoritySigningInput {
        domain: AUTHORITY_REQUEST_DOMAIN,
        body: &body,
    };
    let canonical = canonical_json_bytes(&input).map_err(|error| {
        BrokerError::Invariant(format!(
            "authority request signing input encoding failed: {error}"
        ))
    })?;
    let signed = signer
        .sign_bytes_for_identity(&expected_broker, &canonical)
        .map_err(|error| {
            BrokerError::Invariant(format!("authority request signing failed: {error}"))
        })?;
    if signed.public_key != expected_broker
        || signed.algorithm != expected_broker.algorithm()
        || signed.signature.algorithm() != signed.algorithm
        || !signed.public_key.verify(&canonical, &signed.signature)
    {
        return Err(BrokerError::Invariant(
            "authority request signer returned a mismatched identity or signature".to_string(),
        ));
    }
    Ok(SignedAuthorityRequest {
        body,
        algorithm: signed.algorithm,
        signature: signed.signature,
    })
}

fn verify_authority_request(
    request: &SignedAuthorityRequest,
    trusted_broker: &PublicKey,
    now: u64,
    maximum_clock_skew_seconds: u64,
) -> Result<()> {
    validate_authority_operation(&request.body.operation)?;
    validate_signed_frame_identity(
        &request.body.schema,
        &request.body.request_id,
        request.body.issued_at_unix_seconds,
        &request.body.broker,
        request.algorithm,
        request.signature.algorithm(),
        trusted_broker,
        now,
        maximum_clock_skew_seconds,
    )?;
    let input = AuthoritySigningInput {
        domain: AUTHORITY_REQUEST_DOMAIN,
        body: &request.body,
    };
    if !trusted_broker
        .verify_canonical(&input, &request.signature)
        .map_err(|error| {
            BrokerError::AuthorizationDenied(format!(
                "authority request verification failed: {error}"
            ))
        })?
    {
        return Err(BrokerError::AuthorizationDenied(
            "authority request signature is invalid".to_string(),
        ));
    }
    Ok(())
}

fn sign_authority_response(
    request_id: &str,
    request_digest: &str,
    result: AuthorityResult,
    issued_at_unix_seconds: u64,
    signer: &dyn SigningBackend,
) -> Result<SignedAuthorityResponse> {
    validate_identifier(request_id, "authority request id", 512)?;
    validate_digest(request_digest, "authority request digest")?;
    let expected_authority = signer.public_key();
    let body = AuthorityResponseBody {
        schema: AUTHORITY_RPC_SCHEMA.to_string(),
        request_id: request_id.to_string(),
        request_digest: request_digest.to_string(),
        issued_at_unix_seconds,
        authority: expected_authority.clone(),
        result,
    };
    let input = AuthoritySigningInput {
        domain: AUTHORITY_RESPONSE_DOMAIN,
        body: &body,
    };
    let canonical = canonical_json_bytes(&input).map_err(|error| {
        BrokerError::Invariant(format!(
            "authority response signing input encoding failed: {error}"
        ))
    })?;
    let signed = signer
        .sign_bytes_for_identity(&expected_authority, &canonical)
        .map_err(|error| {
            BrokerError::Invariant(format!("authority response signing failed: {error}"))
        })?;
    if signed.public_key != expected_authority
        || signed.algorithm != expected_authority.algorithm()
        || signed.signature.algorithm() != signed.algorithm
        || !signed.public_key.verify(&canonical, &signed.signature)
    {
        return Err(BrokerError::Invariant(
            "authority response signer returned a mismatched identity or signature".to_string(),
        ));
    }
    Ok(SignedAuthorityResponse {
        body,
        algorithm: signed.algorithm,
        signature: signed.signature,
    })
}

#[cfg(test)]
pub(crate) fn sign_test_authority_exchange(
    operation: AuthorityOperation,
    result: AuthorityResult,
    issued_at_unix_seconds: u64,
    broker_signer: &dyn SigningBackend,
    authority_signer: &dyn SigningBackend,
    maximum_clock_skew_seconds: u64,
) -> Result<VerifiedAuthorityExchange> {
    let request = sign_authority_request(operation, issued_at_unix_seconds, broker_signer)?;
    let request_digest = signed_request_digest(&request)?;
    let response = sign_authority_response(
        &request.body.request_id,
        &request_digest,
        result,
        issued_at_unix_seconds,
        authority_signer,
    )?;
    verify_authority_exchange(
        request,
        response,
        &authority_signer.public_key(),
        issued_at_unix_seconds,
        maximum_clock_skew_seconds,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_authority_response(
    response: &SignedAuthorityResponse,
    trusted_authority: &PublicKey,
    expected_request_id: &str,
    expected_request_digest: &str,
    now: u64,
    maximum_clock_skew_seconds: u64,
) -> Result<()> {
    validate_digest(&response.body.request_digest, "authority request digest")?;
    validate_signed_frame_identity(
        &response.body.schema,
        &response.body.request_id,
        response.body.issued_at_unix_seconds,
        &response.body.authority,
        response.algorithm,
        response.signature.algorithm(),
        trusted_authority,
        now,
        maximum_clock_skew_seconds,
    )?;
    if response.body.request_id != expected_request_id
        || response.body.request_digest != expected_request_digest
    {
        return Err(BrokerError::AuthorizationDenied(
            "authority response is bound to a different request".to_string(),
        ));
    }
    let input = AuthoritySigningInput {
        domain: AUTHORITY_RESPONSE_DOMAIN,
        body: &response.body,
    };
    if !trusted_authority
        .verify_canonical(&input, &response.signature)
        .map_err(|error| {
            BrokerError::AuthorizationDenied(format!(
                "authority response verification failed: {error}"
            ))
        })?
    {
        return Err(BrokerError::AuthorizationDenied(
            "authority response signature is invalid".to_string(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_signed_frame_identity(
    schema: &str,
    request_id: &str,
    issued_at_unix_seconds: u64,
    signer: &PublicKey,
    algorithm: SigningAlgorithm,
    signature_algorithm: SigningAlgorithm,
    trusted_signer: &PublicKey,
    now: u64,
    maximum_clock_skew_seconds: u64,
) -> Result<()> {
    validate_identifier(request_id, "authority request id", 512)?;
    let earliest = issued_at_unix_seconds.saturating_sub(maximum_clock_skew_seconds);
    let latest = issued_at_unix_seconds
        .checked_add(maximum_clock_skew_seconds)
        .ok_or_else(|| {
            BrokerError::AuthorizationDenied("authority frame time overflow".to_string())
        })?;
    if schema != AUTHORITY_RPC_SCHEMA
        || signer != trusted_signer
        || signer.algorithm() != algorithm
        || signature_algorithm != algorithm
        || now < earliest
        || now > latest
    {
        return Err(BrokerError::AuthorizationDenied(
            "authority frame schema, signer, algorithm, or freshness is invalid".to_string(),
        ));
    }
    Ok(())
}

fn signed_request_digest(request: &SignedAuthorityRequest) -> Result<String> {
    let canonical = canonical_json_bytes(request).map_err(|error| {
        BrokerError::Invariant(format!("authority request digest failed: {error}"))
    })?;
    Ok(hex::encode(Sha256::digest(canonical)))
}

fn now_unix_seconds() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| BrokerError::AuthorityUnavailable(format!("system clock failed: {error}")))
}

fn validate_absolute_socket_path(path: &Path, label: &str) -> Result<()> {
    if !path.is_absolute()
        || path.as_os_str().is_empty()
        || path.as_os_str().as_encoded_bytes().len() > 100
    {
        return Err(BrokerError::InvalidRequest(format!(
            "{label} path is not absolute or exceeds the Unix socket limit"
        )));
    }
    Ok(())
}

fn unavailable_capabilities() -> ExecutionAuthorityCapabilities {
    ExecutionAuthorityCapabilities {
        profile: crate::budget::ExecutionAuthorityProfile::AuthoritativeHoldEvent,
        atomic_multi_key_holds: false,
        combined_capture_and_revocation: false,
        query_by_id: false,
        shared_revocation_write_domain: false,
    }
}

#[cfg(test)]
mod tests {
    use chio_test_support::prelude::*;
    use std::thread;

    use super::*;
    use crate::budget::{ExecutionAuthorityCapabilities, ExecutionAuthorityProfile};

    struct Handler;

    impl BrokerAuthorityHandler for Handler {
        fn handle(&self, operation: &AuthorityOperation) -> Result<AuthorityResult> {
            match operation {
                AuthorityOperation::Capabilities => Ok(AuthorityResult::Capabilities(
                    ExecutionAuthorityCapabilities {
                        profile: ExecutionAuthorityProfile::AuthoritativeHoldEvent,
                        atomic_multi_key_holds: true,
                        combined_capture_and_revocation: true,
                        query_by_id: true,
                        shared_revocation_write_domain: true,
                    },
                )),
                AuthorityOperation::Control(_) => {
                    Ok(AuthorityResult::Control(br#"{"accepted":true}"#.to_vec()))
                }
                _ => Err(BrokerError::InvalidRequest(
                    "unexpected authority test operation".to_string(),
                )),
            }
        }
    }

    #[test]
    fn authority_rpc_requires_signed_exact_responses_and_full_capabilities() {
        let directory = crate::private_tempdir().test_expect("tempdir");
        let socket = directory.path().join("authority.sock");
        let broker = Keypair::from_seed(&[71; 32]);
        let authority = Keypair::from_seed(&[72; 32]);
        let server = AuthorityRpcServer::bind(
            &socket,
            broker.public_key(),
            Arc::new(Ed25519Backend::new(authority.clone())),
            Arc::new(Handler),
            30,
        )
        .test_expect("server");
        let server_thread = thread::spawn(move || {
            server.serve_one().test_expect("capabilities");
            server.serve_one().test_expect("control");
        });
        let client = AuthorityRpcClient::connect(
            AuthorityRpcClientConfig {
                socket_path: socket,
                trusted_authority: authority.public_key(),
                timeout_ms: 1_000,
                maximum_clock_skew_seconds: 30,
            },
            Arc::new(Ed25519Backend::new(broker)),
        )
        .test_expect("client");
        let response = client
            .control(AuthorityControlRequest {
                operation: IpcOperation::Status,
                tenant_scope: "tenant-production".to_string(),
                authorization: vec![1],
                payload: br#"{"status":true}"#.to_vec(),
            })
            .test_expect("control");
        assert_eq!(response, br#"{"accepted":true}"#);
        server_thread.join().test_expect("server thread");

        let bad_socket = directory.path().join("bad-authority.sock");
        let broker = Keypair::from_seed(&[73; 32]);
        let server = AuthorityRpcServer::bind(
            &bad_socket,
            broker.public_key(),
            Arc::new(Ed25519Backend::new(Keypair::from_seed(&[74; 32]))),
            Arc::new(Handler),
            30,
        )
        .test_expect("bad server");
        let server_thread = thread::spawn(move || server.serve_one().test_expect("bad handshake"));
        assert!(AuthorityRpcClient::connect(
            AuthorityRpcClientConfig {
                socket_path: bad_socket,
                trusted_authority: Keypair::from_seed(&[75; 32]).public_key(),
                timeout_ms: 1_000,
                maximum_clock_skew_seconds: 30,
            },
            Arc::new(Ed25519Backend::new(broker)),
        )
        .is_err());
        server_thread.join().test_expect("bad server thread");
    }

    #[cfg(unix)]
    #[test]
    fn nonblocking_authority_server_distinguishes_idle_from_failure() {
        let directory = crate::private_tempdir().test_expect("tempdir");
        let socket = directory.path().join("nonblocking-authority.sock");
        let broker = Keypair::from_seed(&[76; 32]);
        let authority = Keypair::from_seed(&[77; 32]);
        let server = AuthorityRpcServer::bind(
            &socket,
            broker.public_key(),
            Arc::new(Ed25519Backend::new(authority)),
            Arc::new(Handler),
            30,
        )
        .test_expect("server");

        server.set_nonblocking(true).test_expect("nonblocking mode");
        assert!(!server.try_serve_one().test_expect("idle poll"));
    }
}
