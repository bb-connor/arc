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
use crate::protocol::{BrokerExecuteFailure, BrokerExecuteRequest, BrokerExecuteResponse};
use crate::receipt::{
    failure_receipt_digest, receipt_digest, verify_execution_receipt, verify_failure_receipt,
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
        request.validate_bounds()?;
        let payload = canonical_json_bytes(request).map_err(|error| {
            BrokerError::Invariant(format!("broker execute payload encoding failed: {error}"))
        })?;
        let authorization = canonical_json_bytes(&request.proof).map_err(|error| {
            BrokerError::Invariant(format!("broker execute proof encoding failed: {error}"))
        })?;
        let response = self.call_envelope(IpcOperation::Execute, authorization, payload)?;
        if response.accepted {
            let execution: BrokerExecuteResponse =
                decode_canonical_response(&response.response, "broker execute response")?;
            validate_execute_response(request, &execution, &self.config.trusted_receipt_signer)?;
            Ok(BrokerIpcExecutionOutcome::Success(Box::new(execution)))
        } else {
            let failure: BrokerExecuteFailure =
                decode_canonical_response(&response.response, "broker execute failure")?;
            validate_execute_failure(
                request,
                &failure,
                response.error_code.as_deref(),
                &self.config.trusted_receipt_signer,
            )?;
            Ok(BrokerIpcExecutionOutcome::Failure(Box::new(failure)))
        }
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
        write_bounded_frame(&mut stream, &encoded).map_err(|error| {
            BrokerError::AuthorityUnavailable(format!("broker IPC write failed: {error}"))
        })?;
        let response_bytes = read_bounded_frame(&mut stream).map_err(|error| {
            BrokerError::AuthorityUnavailable(format!("broker IPC read failed: {error}"))
        })?;
        let response: IpcResponse =
            decode_canonical_response(&response_bytes, "broker IPC response")?;
        if response.operation != operation
            || (response.accepted && response.error_code.is_some())
            || (!response.accepted && response.error_code.is_none())
        {
            return Err(BrokerError::AuthorityUnavailable(
                "broker IPC response envelope is malformed or misbound".to_string(),
            ));
        }
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

fn validate_execute_response(
    request: &BrokerExecuteRequest,
    response: &BrokerExecuteResponse,
    trusted_receipt_signer: &PublicKey,
) -> Result<()> {
    response.evidence.validate()?;
    verify_execution_receipt(&response.receipt, trusted_receipt_signer)?;
    let expected_reference = format!(
        "broker-receipt-sha256-{}",
        receipt_digest(&response.receipt)?
    );
    if response.receipt_reference != expected_reference
        || response.receipt.body.evidence != response.evidence
    {
        return Err(BrokerError::AuthorizationDenied(
            "broker execution receipt envelope or reference is misbound".to_string(),
        ));
    }
    validate_identifier(&response.receipt_reference, "broker receipt reference", 512)?;
    let request_digest = broker_request_digest(request)?;
    let ids = derive_attempt_ids(
        &request.capability.body.capability_id,
        &request.invocation_id,
        &request.proof.body.nonce,
        &request_digest,
    )?;
    if response.status != response.evidence.upstream_status
        || response.evidence.attempt_id != ids.attempt_id
        || response.evidence.invocation_id != request.invocation_id
        || response.evidence.hold_id != ids.hold_id
        || response.evidence.request_digest != request_digest
        || response.evidence.capability_digest != capability_digest(&request.capability)?
        || response.evidence.response_body_sha256 != response_digest(&response.body)
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
