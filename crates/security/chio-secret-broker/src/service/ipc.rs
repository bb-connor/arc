use super::{
    canonical_ipc_request_bytes, canonical_json_bytes, decode_canonical_ipc_request,
    failure_receipt_digest, read_bounded_sensitive_frame, validate_identifier,
    verify_failure_receipt, Arc, AuthenticatedIpcRequest, BrokerError, BrokerExecuteFailure,
    Digest, Duration, IpcOperation, IpcResponse, Mutex, Ordering, Path,
    PrepareDispatchAcknowledgement, Read, Result, Sha256, Write, MAX_WIRE_BYTES,
};
#[cfg(unix)]
use super::{
    is_well_formed_broker_execute_diagnostic_code, File, Instant, OpenOptions, OpenOptionsExt,
    PathBuf, PermissionsExt, UnixListener, UnixStream,
};
#[cfg(test)]
use super::{
    sign_failure_receipt, BrokerDispatchKnowledge, BrokerFailureOutcome, BrokerFailureReceiptBody,
    BrokerFailureStage, Ed25519Backend, Keypair, BROKER_FAILURE_RECEIPT_SCHEMA,
};

pub trait BrokerIpcHandler: Send + Sync {
    fn register_attempt(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse>;
    fn prepare_dispatch(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse>;
    fn prepare_connection(&self, _request: AuthenticatedIpcRequest) -> Result<IpcResponse> {
        Err(BrokerError::AuthorizationDenied(
            "prepared execution connections are unsupported".into(),
        ))
    }
    fn release_attempt(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse>;
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
#[derive(Debug)]
pub(super) enum BrokerIpcServeFailure {
    Client(BrokerError),
    Internal(BrokerError),
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct BrokerSocketIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
pub struct UnixBrokerEndpoint {
    listener: UnixListener,
    handler: Arc<dyn BrokerIpcHandler>,
    authorized_client_uid: u32,
    deadlines: BrokerIpcDeadlines,
    socket_path: PathBuf,
    socket_identity: BrokerSocketIdentity,
    trusted_service_uid: u32,
    _lifecycle_lock: File,
    prepared: PreparedIpcSlot,
}

#[cfg(unix)]
impl UnixBrokerEndpoint {
    pub fn bind(
        path: impl AsRef<Path>,
        handler: Arc<dyn BrokerIpcHandler>,
        trusted_service_uid: u32,
        authorized_client_uid: u32,
    ) -> Result<Self> {
        Self::bind_with_deadlines(
            path,
            handler,
            trusted_service_uid,
            authorized_client_uid,
            BrokerIpcDeadlines::default(),
        )
    }

    pub fn bind_with_deadlines(
        path: impl AsRef<Path>,
        handler: Arc<dyn BrokerIpcHandler>,
        trusted_service_uid: u32,
        authorized_client_uid: u32,
        deadlines: BrokerIpcDeadlines,
    ) -> Result<Self> {
        if !cfg!(target_os = "linux") {
            return Err(BrokerError::AuthorityUnavailable(
                "authenticated broker IPC peer credentials require Linux".to_string(),
            ));
        }
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(BrokerError::InvalidRequest(
                "broker IPC path must be absolute".to_string(),
            ));
        }
        let lifecycle_lock = acquire_broker_socket_lifecycle_lock(path, trusted_service_uid)?;
        if path.exists() {
            return Err(BrokerError::Storage(
                "broker IPC path already exists".to_string(),
            ));
        }
        let listener = UnixListener::bind(path)
            .map_err(|error| BrokerError::Storage(format!("IPC bind failed: {error}")))?;
        let mut provisional_cleanup = ProvisionalBrokerSocketCleanup::new(path)?;
        fs_permissions(path, 0o600)?;
        let socket_identity = validate_broker_socket_identity(path, trusted_service_uid)?;
        if socket_identity != provisional_cleanup.identity() {
            return Err(BrokerError::Custody(
                "broker IPC socket identity changed during bind".to_string(),
            ));
        }
        let endpoint = Self {
            listener,
            handler,
            authorized_client_uid,
            deadlines,
            socket_path: path.to_path_buf(),
            socket_identity,
            trusted_service_uid,
            _lifecycle_lock: lifecycle_lock,
            prepared: PreparedIpcSlot::default(),
        };
        provisional_cleanup.disarm();
        Ok(endpoint)
    }

    /// Serve one accepted connection under the v2 deadline contract.
    ///
    /// Peer-controlled faults return a typed nonfatal outcome. Service faults
    /// return `Err` so daemon supervision observes the failure.
    pub fn serve_one(&self) -> Result<BrokerIpcServeOutcome> {
        let (stream, _) = self
            .listener
            .accept()
            .map_err(|error| BrokerError::Storage(format!("IPC accept failed: {error}")))?;
        match self.serve_stream(stream) {
            Ok(()) => Ok(BrokerIpcServeOutcome::ResponseWritten),
            Err(BrokerIpcServeFailure::Client(error)) => Ok(BrokerIpcServeOutcome::ClientFault {
                diagnostic_code: error.diagnostic_code(),
            }),
            Err(BrokerIpcServeFailure::Internal(error)) => Err(error),
        }
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        self.listener
            .set_nonblocking(nonblocking)
            .map_err(|error| BrokerError::Storage(format!("IPC listener mode failed: {error}")))
    }

    /// Serve at most one connection from a nonblocking listener.
    pub fn try_serve_one(&self) -> Result<Option<BrokerIpcServeOutcome>> {
        let stream = match self.listener.accept() {
            Ok((stream, _)) => stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
            Err(error) => {
                return Err(BrokerError::Storage(format!(
                    "IPC nonblocking accept failed: {error}"
                )))
            }
        };
        let outcome = match self.serve_stream(stream) {
            Ok(()) => BrokerIpcServeOutcome::ResponseWritten,
            Err(BrokerIpcServeFailure::Client(error)) => BrokerIpcServeOutcome::ClientFault {
                diagnostic_code: error.diagnostic_code(),
            },
            Err(BrokerIpcServeFailure::Internal(error)) => return Err(error),
        };
        Ok(Some(outcome))
    }

    fn serve_stream(
        &self,
        stream: std::os::unix::net::UnixStream,
    ) -> std::result::Result<(), BrokerIpcServeFailure> {
        let mut stream = BrokerIpcDeadlineIo::new(stream, self.deadlines).map_err(|error| {
            BrokerIpcServeFailure::Internal(BrokerError::Storage(format!(
                "IPC stream deadline setup failed: {error}"
            )))
        })?;
        if let Err(error) = validate_broker_peer_uid(stream.stream(), self.authorized_client_uid) {
            return Err(if matches!(&error, BrokerError::AuthorizationDenied(_)) {
                BrokerIpcServeFailure::Client(error)
            } else {
                BrokerIpcServeFailure::Internal(error)
            });
        }
        let frame = match read_bounded_sensitive_frame(&mut stream) {
            Ok(frame) => frame,
            Err(_error) if stream.read_deadline_setup_failed() => {
                return Err(BrokerIpcServeFailure::Internal(BrokerError::Storage(
                    "IPC read deadline maintenance failed".to_string(),
                )))
            }
            Err(error) => return Err(BrokerIpcServeFailure::Client(error)),
        };
        let request = decode_canonical_ipc_request(frame.as_slice())
            .map_err(BrokerIpcServeFailure::Client)?;
        if request.authorization.is_empty() || request.authorization.len() > 65_536 {
            return Err(BrokerIpcServeFailure::Client(
                BrokerError::AuthorizationDenied(
                    "IPC operation authorization is missing or oversized".to_string(),
                ),
            ));
        }
        validate_identifier(&request.tenant_scope, "IPC tenant scope", 512)
            .map_err(BrokerIpcServeFailure::Client)?;
        if request.payload.len() > MAX_WIRE_BYTES {
            return Err(BrokerIpcServeFailure::Client(BrokerError::InvalidRequest(
                "IPC operation payload is oversized".to_string(),
            )));
        }
        let operation = request.operation;
        if operation == IpcOperation::PrepareConnection {
            return self.prepare_connection(stream, request);
        }
        let handled = match operation {
            IpcOperation::RegisterAttempt => self.handler.register_attempt(request),
            IpcOperation::PrepareDispatch => self.handler.prepare_dispatch(request),
            IpcOperation::PrepareConnection => self.handler.prepare_connection(request),
            IpcOperation::ReleaseAttempt => self.handler.release_attempt(request),
            IpcOperation::Issue => self.handler.issue(request),
            IpcOperation::Revoke => self.handler.revoke(request),
            IpcOperation::Status => self.handler.status(request),
            IpcOperation::Execute => self.handler.execute(request),
            IpcOperation::Provision => self.handler.provision(request),
            IpcOperation::Rotate => self.handler.rotate(request),
            IpcOperation::Disable => self.handler.disable(request),
            IpcOperation::Delete => self.handler.delete(request),
        };
        let response = classify_broker_ipc_handler_result(operation, handled)?;
        validate_broker_ipc_response_envelope(operation, &response)
            .map_err(BrokerIpcServeFailure::Internal)?;
        let encoded = canonical_json_bytes(&response)
            .map_err(|error| BrokerError::Invariant(format!("IPC response failed: {error}")))
            .map_err(BrokerIpcServeFailure::Internal)?;
        write_broker_ipc_response(&mut stream, &encoded, operation)
    }
}

#[cfg(target_os = "linux")]
pub(super) fn validate_broker_peer_uid(
    stream: &std::os::unix::net::UnixStream,
    authorized_client_uid: u32,
) -> Result<()> {
    let credentials = rustix::net::sockopt::socket_peercred(stream).map_err(|error| {
        BrokerError::Storage(format!(
            "broker IPC client credential lookup failed: {error}"
        ))
    })?;
    if credentials.uid.as_raw() != authorized_client_uid {
        return Err(BrokerError::AuthorizationDenied(
            "broker IPC client UID is not authorized".to_string(),
        ));
    }
    Ok(())
}

#[cfg(all(unix, not(target_os = "linux")))]
pub(super) fn validate_broker_peer_uid(
    _stream: &std::os::unix::net::UnixStream,
    _authorized_client_uid: u32,
) -> Result<()> {
    Err(BrokerError::AuthorityUnavailable(
        "kernel-observed broker IPC client credentials require Linux".to_string(),
    ))
}

#[cfg(unix)]
fn fs_permissions(path: &Path, mode: u32) -> Result<()> {
    let permissions = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, permissions)
        .map_err(|error| BrokerError::Storage(format!("IPC permissions failed: {error}")))
}

mod deadline;

#[cfg(unix)]
use deadline::BrokerIpcDeadlineIo;
use deadline::MAX_BROKER_IPC_DEADLINE_MS;
pub use deadline::{BrokerIpcDeadlines, BrokerIpcServeOutcome};

mod prepared;
#[cfg(unix)]
use prepared::PreparedIpcSlot;

mod response;

#[cfg(unix)]
use response::write_broker_ipc_response;

mod lifecycle;

#[cfg(unix)]
use lifecycle::acquire_broker_socket_lifecycle_lock;

#[cfg(all(test, unix))]
#[path = "error_wire_tests.rs"]
mod error_wire_tests;

#[cfg(unix)]
pub(super) use lifecycle::{validate_broker_socket_identity, ProvisionalBrokerSocketCleanup};
#[cfg(test)]
pub(super) use response::is_well_formed_broker_ipc_error_code;
#[cfg(unix)]
pub(super) use response::{
    classify_broker_ipc_handler_result, validate_broker_ipc_response_envelope,
};
#[cfg(unix)]
#[cfg(test)]
pub(super) use response::{classify_broker_ipc_write_error, BrokerIpcWriteFailureClass};
