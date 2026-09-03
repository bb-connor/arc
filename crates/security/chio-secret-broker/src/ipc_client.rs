use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(all(unix, target_os = "linux"))]
use std::time::Duration;
#[cfg(all(unix, target_os = "linux"))]
use std::{
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::Path,
};

use chio_core_types::{canonical_json_bytes, PublicKey, SigningBackend};
use serde::{Deserialize, Serialize};

use crate::capability::capability_digest;
use crate::generic_https::response_digest;
use crate::proof::{body_digest, caller_header_digest, caller_option_digest};
use crate::protocol::{
    is_well_formed_broker_execute_diagnostic_code, BrokerExecuteFailure, BrokerExecuteRequest,
    BrokerExecuteResponse,
};
use crate::receipt::{
    credential_reference_hash, failure_receipt_digest, validate_durable_completed_response,
    verify_failure_receipt,
};
use crate::registration::{
    sign_register_attempt_authorization, AuthenticatedAttemptRequest,
    PrepareDispatchAcknowledgement, RegisterAttemptAcknowledgement, RegisterAttemptAction,
    ReleaseAttemptAcknowledgement,
};
use crate::service::{
    broker_request_digest, canonical_ipc_request_bytes, read_bounded_frame, write_bounded_frame,
    AuthenticatedIpcRequest, IpcOperation, IpcResponse,
};
use crate::store::{derive_attempt_ids, AttemptRegistration};
use crate::{validate_identifier, BrokerError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrokerPeerIdentity {
    pub process_id: u32,
    pub user_id: u32,
    pub group_id: u32,
}

#[derive(Debug, Clone)]
pub struct BrokerIpcClientConfig {
    pub socket_path: PathBuf,
    pub tenant_scope: String,
    pub timeout_ms: u64,
    pub expected_peer: BrokerPeerIdentity,
    pub trusted_receipt_signer: PublicKey,
}

impl BrokerIpcClientConfig {
    fn validate(&self) -> Result<()> {
        validate_identifier(&self.tenant_scope, "broker IPC tenant scope", 512)?;
        if !self.socket_path.is_absolute()
            || self.socket_path.as_os_str().as_encoded_bytes().is_empty()
            || self.socket_path.as_os_str().as_encoded_bytes().len() > 100
            || self.timeout_ms == 0
            || self.timeout_ms > 30_000
            || self.expected_peer.process_id == 0
        {
            return Err(BrokerError::InvalidRequest(
                "broker IPC path, timeout, or peer identity is invalid".to_string(),
            ));
        }
        Ok(())
    }
}

pub struct BrokerIpcClient {
    config: BrokerIpcClientConfig,
    authority_signer: Arc<dyn SigningBackend>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerIpcExecutionOutcome {
    Success(Box<BrokerExecuteResponse>),
    Failure(Box<BrokerExecuteFailure>),
}

/// A validated execute outcome with the exact deframed IPC payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerIpcExecutionTranscript {
    /// Canonical request payload, excluding the four-byte length prefix.
    pub canonical_request_frame: Vec<u8>,
    /// Canonical response payload, excluding the four-byte length prefix.
    pub canonical_response_frame: Vec<u8>,
    pub outcome: BrokerIpcExecutionOutcome,
}

impl BrokerIpcClient {
    pub fn new(
        config: BrokerIpcClientConfig,
        authority_signer: Arc<dyn SigningBackend>,
    ) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            authority_signer,
        })
    }

    pub fn register_attempt(
        &self,
        registration: &AttemptRegistration,
        request: &BrokerExecuteRequest,
    ) -> Result<RegisterAttemptAcknowledgement> {
        registration.validate()?;
        let authenticated = AuthenticatedAttemptRequest {
            registration: registration.clone(),
            request: request.clone(),
        };
        let now = now_unix_seconds()?;
        let payload = canonical_json_bytes(&authenticated).map_err(|error| {
            BrokerError::Invariant(format!("register-attempt payload encoding failed: {error}"))
        })?;
        let authorization = canonical_json_bytes(&sign_register_attempt_authorization(
            RegisterAttemptAction::Register,
            self.config.tenant_scope.clone(),
            registration,
            now,
            self.authority_signer.as_ref(),
        )?)
        .map_err(|error| {
            BrokerError::Invariant(format!(
                "register-attempt authorization encoding failed: {error}"
            ))
        })?;
        let response = self.call(IpcOperation::RegisterAttempt, authorization, payload)?;
        let acknowledgement: RegisterAttemptAcknowledgement =
            decode_canonical_response(&response.response, "register-attempt acknowledgement")?;
        acknowledgement.validate_for(registration)?;
        Ok(acknowledgement)
    }

    pub fn prepare_dispatch(
        &self,
        registration: &AttemptRegistration,
        request: &BrokerExecuteRequest,
    ) -> Result<PrepareDispatchAcknowledgement> {
        registration.validate()?;
        let authenticated = AuthenticatedAttemptRequest {
            registration: registration.clone(),
            request: request.clone(),
        };
        let now = now_unix_seconds()?;
        let payload = canonical_json_bytes(&authenticated).map_err(|error| {
            BrokerError::Invariant(format!("prepare-dispatch payload encoding failed: {error}"))
        })?;
        let authorization = canonical_json_bytes(&sign_register_attempt_authorization(
            RegisterAttemptAction::Prepare,
            self.config.tenant_scope.clone(),
            registration,
            now,
            self.authority_signer.as_ref(),
        )?)
        .map_err(|error| {
            BrokerError::Invariant(format!(
                "prepare-dispatch authorization encoding failed: {error}"
            ))
        })?;
        let response = self.call(IpcOperation::PrepareDispatch, authorization, payload)?;
        let acknowledgement: PrepareDispatchAcknowledgement =
            decode_canonical_response(&response.response, "prepare-dispatch acknowledgement")?;
        acknowledgement.validate_for(registration, request)?;
        Ok(acknowledgement)
    }

    pub fn release_attempt(
        &self,
        registration: &AttemptRegistration,
        request: &BrokerExecuteRequest,
    ) -> Result<ReleaseAttemptAcknowledgement> {
        registration.validate()?;
        let authenticated = AuthenticatedAttemptRequest {
            registration: registration.clone(),
            request: request.clone(),
        };
        let now = now_unix_seconds()?;
        let payload = canonical_json_bytes(&authenticated).map_err(|error| {
            BrokerError::Invariant(format!("release-attempt payload encoding failed: {error}"))
        })?;
        let authorization = canonical_json_bytes(&sign_register_attempt_authorization(
            RegisterAttemptAction::Release,
            self.config.tenant_scope.clone(),
            registration,
            now,
            self.authority_signer.as_ref(),
        )?)
        .map_err(|error| {
            BrokerError::Invariant(format!(
                "release-attempt authorization encoding failed: {error}"
            ))
        })?;
        let response = self.call(IpcOperation::ReleaseAttempt, authorization, payload)?;
        let acknowledgement: ReleaseAttemptAcknowledgement =
            decode_canonical_response(&response.response, "release-attempt acknowledgement")?;
        acknowledgement.validate_for(registration)?;
        Ok(acknowledgement)
    }

    pub fn execute(&self, request: &BrokerExecuteRequest) -> Result<BrokerExecuteResponse> {
        match self.execute_evidenced(request)? {
            BrokerIpcExecutionOutcome::Success(response) => Ok(*response),
            BrokerIpcExecutionOutcome::Failure(failure) => {
                let failure = *failure;
                Err(BrokerError::AuthorizationDenied(failure.diagnostic_code))
            }
        }
    }

    pub fn execute_evidenced(
        &self,
        request: &BrokerExecuteRequest,
    ) -> Result<BrokerIpcExecutionOutcome> {
        let (authorization, payload) = encode_execute_call(request)?;
        let response = self.call_envelope(IpcOperation::Execute, authorization, payload)?;
        decode_execute_outcome(request, &response, &self.config.trusted_receipt_signer)
    }

    /// Execute one request over a caller-authenticated, deadline-bounded stream.
    ///
    /// This consumes the stream and never connects, retries, or falls back to a
    /// different transport. The exact canonical frame payloads are returned so
    /// callers can audit the process-boundary surfaces without reimplementing
    /// the wire protocol.
    #[cfg(unix)]
    pub fn execute_evidenced_on_authenticated_stream(
        mut stream: UnixStream,
        tenant_scope: &str,
        request: &BrokerExecuteRequest,
        trusted_receipt_signer: &PublicKey,
    ) -> Result<BrokerIpcExecutionTranscript> {
        validate_identifier(tenant_scope, "broker IPC tenant scope", 512)?;
        let (authorization, payload) = encode_execute_call(request)?;
        let ipc_request = AuthenticatedIpcRequest {
            operation: IpcOperation::Execute,
            tenant_scope: tenant_scope.to_string(),
            authorization: authorization.into(),
            payload: payload.into(),
        };
        let encoded = canonical_ipc_request_bytes(&ipc_request)?;
        let canonical_request_frame = encoded.to_vec();
        let (response, canonical_response_frame) = exchange_ipc_envelope(
            &mut stream,
            IpcOperation::Execute,
            canonical_request_frame.as_slice(),
        )?;
        let outcome = decode_execute_outcome(request, &response, trusted_receipt_signer)?;
        Ok(BrokerIpcExecutionTranscript {
            canonical_request_frame,
            canonical_response_frame,
            outcome,
        })
    }

    #[cfg(unix)]
    fn call(
        &self,
        operation: IpcOperation,
        authorization: Vec<u8>,
        payload: Vec<u8>,
    ) -> Result<IpcResponse> {
        let response = self.call_envelope(operation, authorization, payload)?;
        if !response.accepted {
            return Err(BrokerError::AuthorizationDenied(format!(
                "broker IPC operation was denied with code {}",
                response
                    .error_code
                    .as_deref()
                    .unwrap_or("missing_error_code")
            )));
        }
        Ok(response)
    }

    #[cfg(unix)]
    fn call_envelope(
        &self,
        operation: IpcOperation,
        authorization: Vec<u8>,
        payload: Vec<u8>,
    ) -> Result<IpcResponse> {
        let request = AuthenticatedIpcRequest {
            operation,
            tenant_scope: self.config.tenant_scope.clone(),
            authorization: authorization.into(),
            payload: payload.into(),
        };
        let encoded = canonical_ipc_request_bytes(&request)?;
        let mut stream = self.connect_authenticated()?;
        let (response, _) = exchange_ipc_envelope(&mut stream, operation, encoded.as_slice())?;
        Ok(response)
    }

    #[cfg(not(unix))]
    fn call(
        &self,
        _operation: IpcOperation,
        _authorization: Vec<u8>,
        _payload: Vec<u8>,
    ) -> Result<IpcResponse> {
        Err(BrokerError::AuthorityUnavailable(
            "broker IPC requires Unix process isolation".to_string(),
        ))
    }

    #[cfg(not(unix))]
    fn call_envelope(
        &self,
        _operation: IpcOperation,
        _authorization: Vec<u8>,
        _payload: Vec<u8>,
    ) -> Result<IpcResponse> {
        Err(BrokerError::AuthorityUnavailable(
            "broker IPC requires Unix process isolation".to_string(),
        ))
    }

    #[cfg(all(unix, target_os = "linux"))]
    pub fn connect_authenticated(&self) -> Result<UnixStream> {
        let socket_identity = validate_broker_socket_metadata(
            &self.config.socket_path,
            self.config.expected_peer.user_id,
        )?;
        let stream = UnixStream::connect(&self.config.socket_path).map_err(|error| {
            BrokerError::AuthorityUnavailable(format!("broker IPC connect failed: {error}"))
        })?;
        let timeout = Duration::from_millis(self.config.timeout_ms);
        stream.set_read_timeout(Some(timeout)).map_err(|error| {
            BrokerError::AuthorityUnavailable(format!(
                "broker IPC read timeout setup failed: {error}"
            ))
        })?;
        stream.set_write_timeout(Some(timeout)).map_err(|error| {
            BrokerError::AuthorityUnavailable(format!(
                "broker IPC write timeout setup failed: {error}"
            ))
        })?;
        let credentials = rustix::net::sockopt::socket_peercred(&stream).map_err(|error| {
            BrokerError::AuthorizationDenied(format!(
                "broker IPC peer credential lookup failed: {error}"
            ))
        })?;
        let observed = BrokerPeerIdentity {
            process_id: u32::try_from(credentials.pid.as_raw_pid()).map_err(|_| {
                BrokerError::AuthorizationDenied(
                    "broker IPC peer process ID is invalid".to_string(),
                )
            })?,
            user_id: credentials.uid.as_raw(),
            group_id: credentials.gid.as_raw(),
        };
        if observed != self.config.expected_peer {
            return Err(BrokerError::AuthorizationDenied(
                "broker IPC peer identity does not match production configuration".to_string(),
            ));
        }
        validate_stable_broker_socket_metadata(
            &self.config.socket_path,
            self.config.expected_peer.user_id,
            socket_identity,
        )?;
        Ok(stream)
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    pub fn connect_authenticated(&self) -> Result<UnixStream> {
        Err(BrokerError::AuthorityUnavailable(
            "authenticated broker IPC peer credentials require Linux".to_string(),
        ))
    }
}

#[cfg(all(unix, target_os = "linux"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BrokerSocketIdentity {
    device: u64,
    inode: u64,
}

#[cfg(all(unix, target_os = "linux"))]
fn validate_broker_socket_metadata(
    path: &Path,
    trusted_service_uid: u32,
) -> Result<BrokerSocketIdentity> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        BrokerError::AuthorizationDenied(format!("broker IPC socket metadata failed: {error}"))
    })?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != trusted_service_uid
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(BrokerError::AuthorizationDenied(
            "broker IPC socket is not a private socket owned by the trusted service UID"
                .to_string(),
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        BrokerError::AuthorizationDenied("broker IPC socket has no parent directory".to_string())
    })?;
    let parent_metadata = std::fs::symlink_metadata(parent).map_err(|error| {
        BrokerError::AuthorizationDenied(format!(
            "broker IPC socket directory metadata failed: {error}"
        ))
    })?;
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.file_type().is_dir()
        || parent_metadata.uid() != trusted_service_uid
        || parent_metadata.permissions().mode() & 0o022 != 0
    {
        return Err(BrokerError::AuthorizationDenied(
            "broker IPC socket directory is not owned by the trusted service UID".to_string(),
        ));
    }
    Ok(BrokerSocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(all(unix, target_os = "linux"))]
fn validate_stable_broker_socket_metadata(
    path: &Path,
    trusted_service_uid: u32,
    expected: BrokerSocketIdentity,
) -> Result<()> {
    let observed = validate_broker_socket_metadata(path, trusted_service_uid)?;
    if observed != expected {
        return Err(BrokerError::AuthorizationDenied(
            "broker IPC socket identity changed during authentication".to_string(),
        ));
    }
    Ok(())
}

fn encode_execute_call(request: &BrokerExecuteRequest) -> Result<(Vec<u8>, Vec<u8>)> {
    request.validate_bounds()?;
    let payload = canonical_json_bytes(request).map_err(|error| {
        BrokerError::Invariant(format!("broker execute payload encoding failed: {error}"))
    })?;
    let authorization = canonical_json_bytes(&request.proof).map_err(|error| {
        BrokerError::Invariant(format!("broker execute proof encoding failed: {error}"))
    })?;
    Ok((authorization, payload))
}

#[cfg(unix)]
fn exchange_ipc_envelope(
    stream: &mut UnixStream,
    operation: IpcOperation,
    request_frame: &[u8],
) -> Result<(IpcResponse, Vec<u8>)> {
    write_bounded_frame(stream, request_frame).map_err(|error| {
        BrokerError::AuthorityUnavailable(format!("broker IPC write failed: {error}"))
    })?;
    let response_frame = read_bounded_frame(stream).map_err(|error| {
        BrokerError::AuthorityUnavailable(format!("broker IPC read failed: {error}"))
    })?;
    let response = decode_ipc_response_envelope(&response_frame, operation)?;
    Ok((response, response_frame))
}

#[cfg(unix)]
fn decode_ipc_response_envelope(bytes: &[u8], operation: IpcOperation) -> Result<IpcResponse> {
    let response: IpcResponse = decode_canonical_response(bytes, "broker IPC response")?;
    let valid = response.operation == operation
        && if response.accepted {
            !response.response.is_empty() && response.error_code.is_none()
        } else if operation == IpcOperation::Execute {
            !response.response.is_empty()
                && response
                    .error_code
                    .as_deref()
                    .is_some_and(is_well_formed_broker_execute_diagnostic_code)
        } else {
            response.response.is_empty()
                && response
                    .error_code
                    .as_deref()
                    .is_some_and(is_well_formed_ipc_error_code)
        };
    if !valid {
        return Err(BrokerError::AuthorityUnavailable(
            "broker IPC response envelope is malformed or misbound".to_string(),
        ));
    }
    Ok(response)
}

#[cfg(unix)]
fn is_well_formed_ipc_error_code(code: &str) -> bool {
    let bytes = code.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes.first().is_some_and(|byte| byte.is_ascii_lowercase())
        && bytes
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
        && !bytes.windows(2).any(|pair| pair == b"__")
}

fn decode_execute_outcome(
    request: &BrokerExecuteRequest,
    response: &IpcResponse,
    trusted_receipt_signer: &PublicKey,
) -> Result<BrokerIpcExecutionOutcome> {
    if response.accepted {
        let execution: BrokerExecuteResponse =
            decode_canonical_response(&response.response, "broker execute response")?;
        validate_execute_response(request, &execution, trusted_receipt_signer)?;
        Ok(BrokerIpcExecutionOutcome::Success(Box::new(execution)))
    } else {
        let failure: BrokerExecuteFailure =
            decode_canonical_response(&response.response, "broker execute failure")?;
        validate_execute_failure(
            request,
            &failure,
            response.error_code.as_deref(),
            trusted_receipt_signer,
        )?;
        Ok(BrokerIpcExecutionOutcome::Failure(Box::new(failure)))
    }
}

fn validate_execute_response(
    request: &BrokerExecuteRequest,
    response: &BrokerExecuteResponse,
    trusted_receipt_signer: &PublicKey,
) -> Result<()> {
    validate_durable_completed_response(response, trusted_receipt_signer)?;
    let request_digest = broker_request_digest(request)?;
    let ids = derive_attempt_ids(
        &request.capability.body.capability_id,
        &request.invocation_id,
        &request.proof.body.nonce,
        &request_digest,
    )?;
    let receipt = &response.receipt.body;
    let request_body_bytes = u64::try_from(request.request.body.len()).map_err(|_| {
        BrokerError::ResponseRejected("broker request body length overflowed".to_string())
    })?;
    if response.status != response.evidence.upstream_status
        || response.evidence.attempt_id != ids.attempt_id
        || response.evidence.invocation_id != request.invocation_id
        || response.evidence.hold_id != ids.hold_id
        || response.evidence.request_digest != request_digest
        || response.evidence.capability_digest != capability_digest(&request.capability)?
        || response.evidence.response_body_sha256 != response_digest(&response.body)
        || receipt.authorize_event_id != ids.authorize_event_id
        || receipt.capture_event_id != ids.capture_event_id
        || receipt.parent_capability_id != request.capability.body.parent_capability_id
        || receipt.broker_capability_id != request.capability.body.capability_id
        || receipt.subject != request.capability.body.subject
        || receipt.credential_reference_hash
            != credential_reference_hash(&request.capability.body.credential)?
        || receipt.credential_version != request.capability.body.credential.version
        || receipt.normalized_destination != request.request.destination
        || receipt.request_body_sha256 != body_digest(&request.request.body)
        || receipt.caller_headers_sha256 != caller_header_digest(&request.request.headers)?
        || receipt.caller_options_sha256 != caller_option_digest(&request.request.options)?
        || receipt.broker_quota_key_id != request.capability.body.broker_quota_key_id
        || receipt.provider_adapter_id != request.capability.body.provider_adapter_id
        || receipt.provider_adapter_version != request.capability.body.provider_adapter_version
        || receipt.request_body_bytes != request_body_bytes
    {
        return Err(BrokerError::ResponseRejected(
            "broker execute response evidence is malformed or misbound".to_string(),
        ));
    }
    Ok(())
}

fn validate_execute_failure(
    request: &BrokerExecuteRequest,
    failure: &BrokerExecuteFailure,
    envelope_error_code: Option<&str>,
    trusted_receipt_signer: &PublicKey,
) -> Result<()> {
    if !is_well_formed_broker_execute_diagnostic_code(&failure.diagnostic_code) {
        return Err(BrokerError::AuthorizationDenied(
            "broker failure diagnostic code is outside the signed execution domain".to_string(),
        ));
    }
    verify_failure_receipt(&failure.receipt, trusted_receipt_signer)?;
    let expected_reference = format!(
        "broker-failure-receipt-sha256-{}",
        failure_receipt_digest(&failure.receipt)?
    );
    let body = &failure.receipt.body;
    let request_digest = broker_request_digest(request)?;
    let capability_digest = capability_digest(&request.capability)?;
    let ids = derive_attempt_ids(
        &request.capability.body.capability_id,
        &request.invocation_id,
        &request.proof.body.nonce,
        &request_digest,
    )?;
    if failure.receipt_reference != expected_reference
        || failure.diagnostic_code != body.diagnostic_code
        || envelope_error_code != Some(failure.diagnostic_code.as_str())
        || body.request_digest != request_digest
        || body.capability_digest.as_deref() != Some(capability_digest.as_str())
        || body
            .attempt_id
            .as_deref()
            .is_some_and(|attempt_id| attempt_id != ids.attempt_id)
        || body
            .invocation_id
            .as_deref()
            .is_some_and(|invocation_id| invocation_id != request.invocation_id)
        || body
            .hold_id
            .as_deref()
            .is_some_and(|hold_id| hold_id != ids.hold_id)
        || body
            .parent_capability_id
            .as_deref()
            .is_some_and(|capability_id| {
                capability_id != request.capability.body.parent_capability_id
            })
        || body
            .broker_capability_id
            .as_deref()
            .is_some_and(|capability_id| capability_id != request.capability.body.capability_id)
    {
        return Err(BrokerError::AuthorizationDenied(
            "broker failure receipt envelope or request binding is invalid".to_string(),
        ));
    }
    validate_identifier(
        &failure.receipt_reference,
        "broker failure receipt reference",
        512,
    )?;
    Ok(())
}

fn decode_canonical_response<T: for<'de> Deserialize<'de>>(bytes: &[u8], label: &str) -> Result<T> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|error| {
        BrokerError::AuthorityUnavailable(format!("{label} decoding failed: {error}"))
    })?;
    let canonical = canonical_json_bytes(&value).map_err(|error| {
        BrokerError::AuthorityUnavailable(format!("{label} encoding failed: {error}"))
    })?;
    if canonical != bytes {
        return Err(BrokerError::AuthorizationDenied(format!(
            "{label} is not canonical JSON"
        )));
    }
    serde_json::from_slice(bytes)
        .map_err(|error| BrokerError::AuthorityUnavailable(format!("{label} is invalid: {error}")))
}

fn now_unix_seconds() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| BrokerError::AuthorityUnavailable(format!("system clock failed: {error}")))
}

#[cfg(test)]
mod vector_semantics_tests;

#[cfg(all(test, unix))]
mod preconnected_execution_tests {
    use std::path::PathBuf;
    use std::thread;
    use std::time::Duration;

    use chio_test_support::prelude::*;
    use serde::de::DeserializeOwned;

    use super::*;

    const RECEIPT_SIGNER_HEX: &str =
        "fa4834147f6e690c3693eff61336046403cd8ae2a14f31b3c407358569239565";
    const TENANT_SCOPE: &str = "tenant-production";

    #[test]
    fn preconnected_execute_returns_validated_outcome_and_exact_canonical_frames() {
        let request: BrokerExecuteRequest = read_vector("broker-execute-request-v1.json");
        let execute_response: BrokerExecuteResponse =
            read_vector("broker-execute-response-v1.json");
        let response_frame = canonical_json_bytes(&IpcResponse {
            operation: IpcOperation::Execute,
            accepted: true,
            response: canonical_json_bytes(&execute_response).test_expect("execute response"),
            error_code: None,
        })
        .test_expect("IPC response");
        let (client, mut server) = deadline_bounded_pair();
        let expected_response_frame = response_frame.clone();
        let server = thread::spawn(move || {
            let request_frame = read_bounded_frame(&mut server).test_expect("request frame");
            write_bounded_frame(&mut server, &response_frame).test_expect("response frame");
            request_frame
        });

        let signer = PublicKey::from_hex(RECEIPT_SIGNER_HEX).test_expect("receipt signer");
        let transcript = BrokerIpcClient::execute_evidenced_on_authenticated_stream(
            client,
            TENANT_SCOPE,
            &request,
            &signer,
        )
        .test_expect("preconnected execute");
        let observed_request_frame = server.join().test_expect("IPC server");

        assert_eq!(transcript.canonical_request_frame, observed_request_frame);
        assert_eq!(transcript.canonical_response_frame, expected_response_frame);
        assert_eq!(
            canonical_json_bytes(
                &decode_canonical_response::<IpcResponse>(
                    &transcript.canonical_response_frame,
                    "transcript response",
                )
                .test_expect("canonical transcript response")
            )
            .test_expect("canonical response bytes"),
            transcript.canonical_response_frame
        );
        match transcript.outcome {
            BrokerIpcExecutionOutcome::Success(actual) => {
                assert_eq!(*actual, execute_response);
                assert_eq!(
                    canonical_json_bytes(&actual.receipt).test_expect("canonical receipt"),
                    canonical_json_bytes(&execute_response.receipt)
                        .test_expect("expected canonical receipt")
                );
            }
            BrokerIpcExecutionOutcome::Failure(failure) => {
                panic!("unexpected execution failure: {}", failure.diagnostic_code)
            }
        }
    }

    #[test]
    fn preconnected_execute_maps_a_dead_peer_to_authority_unavailable() {
        let request: BrokerExecuteRequest = read_vector("broker-execute-request-v1.json");
        let signer = PublicKey::from_hex(RECEIPT_SIGNER_HEX).test_expect("receipt signer");
        let (client, server) = deadline_bounded_pair();
        drop(server);

        let error = BrokerIpcClient::execute_evidenced_on_authenticated_stream(
            client,
            TENANT_SCOPE,
            &request,
            &signer,
        )
        .test_expect_err("dead broker must fail closed");

        assert!(matches!(error, BrokerError::AuthorityUnavailable(_)));
    }

    #[test]
    fn preconnected_execute_preserves_a_valid_signed_failure() {
        let request: BrokerExecuteRequest = read_vector("broker-execute-request-v1.json");
        let execute_failure: BrokerExecuteFailure = read_vector("broker-execute-failure-v1.json");
        let response_frame = canonical_json_bytes(&IpcResponse {
            operation: IpcOperation::Execute,
            accepted: false,
            response: canonical_json_bytes(&execute_failure).test_expect("execute failure"),
            error_code: Some(execute_failure.diagnostic_code.clone()),
        })
        .test_expect("IPC failure response");
        let (client, mut server) = deadline_bounded_pair();
        let server = thread::spawn(move || {
            read_bounded_frame(&mut server).test_expect("request frame");
            write_bounded_frame(&mut server, &response_frame).test_expect("failure response frame");
        });

        let signer = PublicKey::from_hex(RECEIPT_SIGNER_HEX).test_expect("receipt signer");
        let transcript = BrokerIpcClient::execute_evidenced_on_authenticated_stream(
            client,
            TENANT_SCOPE,
            &request,
            &signer,
        )
        .test_expect("preconnected evidenced failure");
        server.join().test_expect("IPC server");

        match transcript.outcome {
            BrokerIpcExecutionOutcome::Failure(actual) => assert_eq!(*actual, execute_failure),
            BrokerIpcExecutionOutcome::Success(response) => {
                panic!("unexpected execution success: {}", response.status)
            }
        }
    }

    #[test]
    fn preconnected_execute_rejects_rebound_or_tampered_signed_failures() {
        let request: BrokerExecuteRequest = read_vector("broker-execute-request-v1.json");
        let failure: BrokerExecuteFailure = read_vector("broker-execute-failure-v1.json");
        let signer = PublicKey::from_hex(RECEIPT_SIGNER_HEX).test_expect("receipt signer");

        let mut rebound_failure = failure.clone();
        rebound_failure.diagnostic_code = "chio.broker.conflict".to_string();
        let mut receipt_tampered = failure.clone();
        receipt_tampered.diagnostic_code = "chio.broker.conflict".to_string();
        receipt_tampered.receipt.body.diagnostic_code = "chio.broker.conflict".to_string();
        let mut wrong_domain = failure.clone();
        wrong_domain.diagnostic_code = "chio.kernel.authorization_denied".to_string();

        let envelopes = [
            IpcResponse {
                operation: IpcOperation::Execute,
                accepted: false,
                response: canonical_json_bytes(&failure).test_expect("execute failure"),
                error_code: Some("chio.broker.conflict".to_string()),
            },
            IpcResponse {
                operation: IpcOperation::Execute,
                accepted: false,
                response: canonical_json_bytes(&rebound_failure)
                    .test_expect("rebound execute failure"),
                error_code: Some("chio.broker.conflict".to_string()),
            },
            IpcResponse {
                operation: IpcOperation::Execute,
                accepted: false,
                response: canonical_json_bytes(&receipt_tampered)
                    .test_expect("tampered execute failure"),
                error_code: Some("chio.broker.conflict".to_string()),
            },
            IpcResponse {
                operation: IpcOperation::Execute,
                accepted: false,
                response: canonical_json_bytes(&wrong_domain)
                    .test_expect("wrong-domain execute failure"),
                error_code: Some("chio.kernel.authorization_denied".to_string()),
            },
            IpcResponse {
                operation: IpcOperation::Execute,
                accepted: false,
                response: serde_json::to_vec_pretty(&failure)
                    .test_expect("noncanonical execute failure"),
                error_code: Some(failure.diagnostic_code.clone()),
            },
        ];

        for envelope in envelopes {
            let response_frame =
                canonical_json_bytes(&envelope).test_expect("denial response envelope");
            let (client, mut server) = deadline_bounded_pair();
            let server = thread::spawn(move || {
                read_bounded_frame(&mut server).test_expect("request frame");
                write_bounded_frame(&mut server, &response_frame)
                    .test_expect("denial response frame");
            });
            let error = BrokerIpcClient::execute_evidenced_on_authenticated_stream(
                client,
                TENANT_SCOPE,
                &request,
                &signer,
            )
            .test_expect_err("tampered denial must fail closed");
            server.join().test_expect("IPC server");
            assert!(matches!(
                error,
                BrokerError::AuthorizationDenied(_) | BrokerError::AuthorityUnavailable(_)
            ));
        }
    }

    #[test]
    fn preconnected_execute_rejects_a_signed_response_misbound_to_the_request() {
        let mut request: BrokerExecuteRequest = read_vector("broker-execute-request-v1.json");
        request.invocation_id = "invocation-production-misbound".to_string();
        let execute_response: BrokerExecuteResponse =
            read_vector("broker-execute-response-v1.json");
        let response_frame = canonical_json_bytes(&IpcResponse {
            operation: IpcOperation::Execute,
            accepted: true,
            response: canonical_json_bytes(&execute_response).test_expect("execute response"),
            error_code: None,
        })
        .test_expect("IPC response");
        let (client, mut server) = deadline_bounded_pair();
        let server = thread::spawn(move || {
            read_bounded_frame(&mut server).test_expect("request frame");
            write_bounded_frame(&mut server, &response_frame).test_expect("response frame");
        });

        let signer = PublicKey::from_hex(RECEIPT_SIGNER_HEX).test_expect("receipt signer");
        let error = BrokerIpcClient::execute_evidenced_on_authenticated_stream(
            client,
            TENANT_SCOPE,
            &request,
            &signer,
        )
        .test_expect_err("misbound response must fail closed");
        server.join().test_expect("IPC server");

        assert!(matches!(error, BrokerError::ResponseRejected(_)));
    }

    #[test]
    fn preconnected_execute_rejects_noncanonical_or_invalid_outer_envelopes() {
        let request: BrokerExecuteRequest = read_vector("broker-execute-request-v1.json");
        let signer = PublicKey::from_hex(RECEIPT_SIGNER_HEX).test_expect("receipt signer");
        let canonical_invalid_code = canonical_json_bytes(&IpcResponse {
            operation: IpcOperation::Execute,
            accepted: false,
            response: b"{}".to_vec(),
            error_code: Some("invalid error code".to_string()),
        })
        .test_expect("invalid-code envelope");
        let canonical_envelope = IpcResponse {
            operation: IpcOperation::Execute,
            accepted: true,
            response: b"{}".to_vec(),
            error_code: None,
        };
        let noncanonical = serde_json::to_vec_pretty(&canonical_envelope)
            .test_expect("noncanonical response envelope");

        for (frame, expected_authority_unavailable) in
            [(canonical_invalid_code, true), (noncanonical, false)]
        {
            let (client, mut server) = deadline_bounded_pair();
            let server = thread::spawn(move || {
                read_bounded_frame(&mut server).test_expect("request frame");
                write_bounded_frame(&mut server, &frame).test_expect("response frame");
            });
            let error = BrokerIpcClient::execute_evidenced_on_authenticated_stream(
                client,
                TENANT_SCOPE,
                &request,
                &signer,
            )
            .test_expect_err("invalid envelope must fail closed");
            server.join().test_expect("IPC server");
            if expected_authority_unavailable {
                assert!(matches!(error, BrokerError::AuthorityUnavailable(_)));
            } else {
                assert!(matches!(error, BrokerError::AuthorizationDenied(_)));
            }
        }
    }

    fn deadline_bounded_pair() -> (UnixStream, UnixStream) {
        let (client, server) = UnixStream::pair().test_expect("Unix stream pair");
        let timeout = Some(Duration::from_secs(1));
        client
            .set_read_timeout(timeout)
            .test_expect("client read timeout");
        client
            .set_write_timeout(timeout)
            .test_expect("client write timeout");
        server
            .set_read_timeout(timeout)
            .test_expect("server read timeout");
        server
            .set_write_timeout(timeout)
            .test_expect("server write timeout");
        (client, server)
    }

    fn read_vector<T: DeserializeOwned>(file: &str) -> T {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../tests/bindings/vectors/security/broker/positive")
            .join(file);
        let bytes =
            std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        serde_json::from_slice(&bytes).test_expect("broker vector")
    }
}

#[cfg(all(test, target_os = "linux"))]
mod service_identity_tests {
    use chio_test_support::prelude::*;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    use super::*;

    #[test]
    fn broker_socket_metadata_must_be_private_owned_and_stable() {
        let directory = tempfile::tempdir().test_expect("socket directory");
        let socket_path = directory.path().join("broker.sock");
        let listener = UnixListener::bind(&socket_path).test_expect("broker socket");
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
            .test_expect("private socket permissions");
        let expected_uid = rustix::process::geteuid().as_raw();

        let identity = validate_broker_socket_metadata(&socket_path, expected_uid)
            .test_expect("valid broker socket metadata");
        validate_stable_broker_socket_metadata(&socket_path, expected_uid, identity)
            .test_expect("stable broker socket metadata");

        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o666))
            .test_expect("widen socket permissions");
        assert!(validate_broker_socket_metadata(&socket_path, expected_uid).is_err());

        drop(listener);
    }
}
