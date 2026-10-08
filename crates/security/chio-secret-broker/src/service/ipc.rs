use super::{
    canonical_ipc_request_bytes, canonical_json_bytes, decode_canonical_ipc_request,
    failure_receipt_digest, read_bounded_sensitive_frame, validate_identifier,
    verify_failure_receipt, Arc, AuthenticatedIpcRequest, BrokerError, BrokerExecuteFailure,
    Digest, Duration, IpcOperation, IpcResponse, Mutex, Ordering, Path,
    PrepareDispatchAcknowledgement, Read, Result, Sha256, Write, MAX_WIRE_BYTES,
};
#[cfg(unix)]
use super::{is_well_formed_broker_execute_diagnostic_code, Instant, UnixStream};
#[cfg(test)]
use super::{
    sign_failure_receipt, BrokerDispatchKnowledge, BrokerFailureOutcome, BrokerFailureReceiptBody,
    BrokerFailureStage, Ed25519Backend, Keypair, BROKER_FAILURE_RECEIPT_SCHEMA,
};
#[cfg(unix)]
use chio_secure_ipc::listener::{
    CustodialUnixListener, ListenerError, PeerPolicy, SocketAccess, SocketCustody,
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
pub struct UnixBrokerEndpoint {
    listener: CustodialUnixListener,
    handler: Arc<dyn BrokerIpcHandler>,
    deadlines: BrokerIpcDeadlines,
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

    /// Bind the broker socket owner-only in a service-private directory. Each
    /// accepted client must run as `authorized_client_uid` before any byte of
    /// its request is read.
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
        let listener = CustodialUnixListener::bind(SocketCustody {
            socket_path: path.to_path_buf(),
            trusted_service_uid,
            access: SocketAccess::Owner,
            peer: PeerPolicy::User {
                uid: authorized_client_uid,
            },
        })
        .map_err(broker_listener_error)?;
        Ok(Self {
            listener,
            handler,
            deadlines,
            prepared: PreparedIpcSlot::default(),
        })
    }

    /// Serve one accepted connection under the v2 deadline contract.
    ///
    /// Peer-controlled faults return a typed nonfatal outcome. Service faults
    /// return `Err` so daemon supervision observes the failure.
    pub fn serve_one(&self) -> Result<BrokerIpcServeOutcome> {
        self.serve_accepted(self.listener.accept_authenticated())
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        self.listener
            .set_nonblocking(nonblocking)
            .map_err(broker_listener_error)
    }

    /// Serve at most one connection from a nonblocking listener.
    pub fn try_serve_one(&self) -> Result<Option<BrokerIpcServeOutcome>> {
        match self.listener.try_accept_authenticated() {
            Ok(None) => Ok(None),
            Ok(Some(stream)) => self.serve_accepted(Ok(stream)).map(Some),
            Err(error) => self.serve_accepted(Err(error)).map(Some),
        }
    }

    /// Serve one accepted connection. A client the peer policy refuses is a
    /// contained client fault; every other accept failure reaches supervision.
    fn serve_accepted(
        &self,
        accepted: std::result::Result<UnixStream, ListenerError>,
    ) -> Result<BrokerIpcServeOutcome> {
        let failure = match accepted {
            Ok(stream) => match self.serve_stream(stream) {
                Ok(()) => return Ok(BrokerIpcServeOutcome::ResponseWritten),
                Err(failure) => failure,
            },
            Err(error @ ListenerError::UnauthorizedPeer { .. }) => {
                BrokerIpcServeFailure::Client(broker_listener_error(error))
            }
            Err(error) => BrokerIpcServeFailure::Internal(broker_listener_error(error)),
        };
        match failure {
            BrokerIpcServeFailure::Client(error) => Ok(BrokerIpcServeOutcome::ClientFault {
                diagnostic_code: error.diagnostic_code(),
            }),
            BrokerIpcServeFailure::Internal(error) => Err(error),
        }
    }

    fn serve_stream(&self, stream: UnixStream) -> std::result::Result<(), BrokerIpcServeFailure> {
        let mut stream = BrokerIpcDeadlineIo::new(stream, self.deadlines).map_err(|error| {
            BrokerIpcServeFailure::Internal(BrokerError::Storage(format!(
                "IPC stream deadline setup failed: {error}"
            )))
        })?;
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

/// A listener fault as a broker error. A refused client is denied; a lock held
/// by another daemon is an unavailable authority; custody faults mean the
/// broker can no longer trust its own socket.
#[cfg(unix)]
pub(super) fn broker_listener_error(error: ListenerError) -> BrokerError {
    match error {
        ListenerError::UnauthorizedPeer { .. } => {
            BrokerError::AuthorizationDenied("broker IPC client UID is not authorized".to_string())
        }
        ListenerError::InvalidPath | ListenerError::InvalidPeerPolicy(_) => {
            BrokerError::InvalidRequest(format!("broker IPC socket configuration: {error}"))
        }
        ListenerError::Unsupported => BrokerError::AuthorityUnavailable(
            "authenticated broker IPC peer credentials require Linux".to_string(),
        ),
        ListenerError::LockHeld(source) => BrokerError::AuthorityUnavailable(format!(
            "broker IPC socket is owned by another daemon: {source}"
        )),
        ListenerError::PathOccupied => {
            BrokerError::Storage("broker IPC path already exists".to_string())
        }
        ListenerError::Io { .. } => BrokerError::Storage(format!("broker IPC {error}")),
        ListenerError::DirectoryCustody
        | ListenerError::LockCustody
        | ListenerError::SocketCustody
        | ListenerError::SocketReplaced => BrokerError::Custody(format!("broker IPC {error}")),
    }
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

#[cfg(all(test, unix))]
#[path = "error_wire_tests.rs"]
mod error_wire_tests;

#[cfg(test)]
pub(super) use response::is_well_formed_broker_ipc_error_code;
#[cfg(unix)]
pub(super) use response::{
    classify_broker_ipc_handler_result, validate_broker_ipc_response_envelope,
};
#[cfg(unix)]
#[cfg(test)]
pub(super) use response::{classify_broker_ipc_write_error, BrokerIpcWriteFailureClass};
