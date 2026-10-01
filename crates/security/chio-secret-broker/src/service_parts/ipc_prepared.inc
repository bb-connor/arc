/// A privileged preparation may retain one descriptor while the kernel performs
/// final authorization and capture. This is separate from the ordinary frame
/// read deadline. A first byte starts the ordinary deadline again; neither
/// trickled bytes nor another operation extend the prepared lifetime.
#[cfg(unix)]
#[derive(Default)]
struct PreparedIpcSlot {
    busy: Arc<std::sync::atomic::AtomicBool>,
    pending: Mutex<Option<PreparedIpcConnection>>,
}

#[cfg(unix)]
struct PreparedIpcPermit(Arc<std::sync::atomic::AtomicBool>);

#[cfg(unix)]
impl Drop for PreparedIpcPermit {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[cfg(unix)]
struct PreparedIpcConnection {
    stream: UnixStream,
    expected_frame_sha256: [u8; 32],
    deadline: Instant,
    _permit: PreparedIpcPermit,
}

#[cfg(unix)]
impl PreparedIpcSlot {
    fn reserve(&self) -> Result<PreparedIpcPermit> {
        self.busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                BrokerError::Conflict("prepared connection capacity is occupied".into())
            })?;
        Ok(PreparedIpcPermit(Arc::clone(&self.busy)))
    }
}

#[cfg(unix)]
impl UnixBrokerEndpoint {
    fn prepare_connection(
        &self,
        mut stream: BrokerIpcDeadlineIo<UnixStream>,
        request: AuthenticatedIpcRequest,
    ) -> std::result::Result<(), BrokerIpcServeFailure> {
        let operation = IpcOperation::PrepareConnection;
        let permit = self.prepared.reserve();
        let authenticated: crate::registration::AuthenticatedAttemptRequest =
            serde_json::from_slice(&request.payload)
                .map_err(|_| prepared_client_fault("prepared connection payload is invalid"))?;
        let tenant = request.tenant_scope.clone();
        let handled = match &permit {
            Ok(_) => self.handler.prepare_connection(request),
            Err(_) => Err(BrokerError::Conflict(
                "prepared connection capacity is occupied".into(),
            )),
        };
        let response = classify_broker_ipc_handler_result(operation, handled)?;
        validate_broker_ipc_response_envelope(operation, &response)
            .map_err(BrokerIpcServeFailure::Internal)?;
        let binding = if response.accepted {
            let acknowledgement: PrepareDispatchAcknowledgement =
                serde_json::from_slice(&response.response).map_err(|_| {
                    prepared_internal_fault("prepared connection acknowledgement is invalid")
                })?;
            acknowledgement
                .validate_for(&authenticated.registration, &authenticated.request)
                .map_err(BrokerIpcServeFailure::Internal)?;
            Some(prepared_connection_binding(&tenant, &authenticated)?)
        } else {
            None
        };
        let encoded = canonical_json_bytes(&response)
            .map_err(|_| prepared_internal_fault("prepared connection response encoding failed"))?;
        write_broker_ipc_response(&mut stream, &encoded)?;
        if let Some((expected_frame_sha256, deadline)) = binding {
            let permit = permit.map_err(BrokerIpcServeFailure::Internal)?;
            let stream = stream.into_inner();
            stream
                .set_nonblocking(true)
                .map_err(|_| prepared_internal_fault("prepared connection mode setup failed"))?;
            let mut pending = self
                .prepared
                .pending
                .lock()
                .map_err(|_| prepared_internal_fault("prepared connection slot lock failed"))?;
            if pending.is_some() {
                return Err(prepared_internal_fault(
                    "prepared connection slot was replaced",
                ));
            }
            *pending = Some(PreparedIpcConnection {
                stream,
                expected_frame_sha256,
                deadline,
                _permit: permit,
            });
        }
        Ok(())
    }

    /// Drive the single prepared execution slot from a dedicated bounded
    /// worker. Waiting never occupies the normal control or audit worker.
    /// EOF, expiry, and peer faults release capacity without stopping service.
    pub fn try_serve_prepared(&self) -> Result<Option<BrokerIpcServeOutcome>> {
        let mut first = [0_u8; 1];
        let prepared = {
            let mut pending =
                self.prepared.pending.lock().map_err(|_| {
                    BrokerError::Storage("prepared connection slot lock failed".into())
                })?;
            let Some(connection) = pending.as_mut() else {
                return Ok(None);
            };
            if Instant::now() >= connection.deadline {
                pending.take();
                return Ok(Some(BrokerIpcServeOutcome::ClientFault {
                    diagnostic_code: "authorization_denied",
                }));
            }
            match connection.stream.read(&mut first) {
                Ok(0) => {
                    pending.take();
                    return Ok(None);
                }
                Ok(_) => pending.take().ok_or_else(|| {
                    BrokerError::Invariant("prepared connection disappeared".into())
                })?,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    return Ok(None);
                }
                Err(error) => {
                    pending.take();
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::NotConnected
                    ) {
                        return Ok(Some(BrokerIpcServeOutcome::ClientFault {
                            diagnostic_code: "invalid_request",
                        }));
                    }
                    return Err(BrokerError::Storage(
                        "prepared connection read failed".into(),
                    ));
                }
            }
        };
        match self.serve_prepared(prepared, first) {
            Ok(()) => Ok(Some(BrokerIpcServeOutcome::ResponseWritten)),
            Err(BrokerIpcServeFailure::Client(error)) => {
                Ok(Some(BrokerIpcServeOutcome::ClientFault {
                    diagnostic_code: error.diagnostic_code(),
                }))
            }
            Err(BrokerIpcServeFailure::Internal(error)) => Err(error),
        }
    }

    fn serve_prepared(
        &self,
        connection: PreparedIpcConnection,
        first: [u8; 1],
    ) -> std::result::Result<(), BrokerIpcServeFailure> {
        let remaining = connection
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| prepared_client_fault("prepared connection expired"))?;
        connection
            .stream
            .set_nonblocking(false)
            .map_err(|_| prepared_internal_fault("prepared execution mode setup failed"))?;
        let mut stream = BrokerIpcDeadlineIo::new(
            connection.stream,
            BrokerIpcDeadlines {
                read: self.deadlines.read.min(remaining),
                write: self.deadlines.write,
            },
        )
        .map_err(|_| prepared_internal_fault("prepared execution deadline setup failed"))?;
        let frame =
            read_bounded_sensitive_frame(&mut std::io::Cursor::new(first).chain(&mut stream))
                .map_err(|error| {
                    if stream.read_deadline_setup_failed() {
                        prepared_internal_fault("prepared execution deadline maintenance failed")
                    } else {
                        BrokerIpcServeFailure::Client(error)
                    }
                })?;
        let observed: [u8; 32] = Sha256::digest(frame.as_slice()).into();
        if observed != connection.expected_frame_sha256 || Instant::now() >= connection.deadline {
            return Err(prepared_client_fault(
                "prepared execution binding or lifetime changed",
            ));
        }
        let request =
            decode_canonical_ipc_request(&frame).map_err(BrokerIpcServeFailure::Client)?;
        // Exact frame binding includes Execute, tenant, proof, and every request
        // byte. The production handler still requires current native capture.
        let response = classify_broker_ipc_handler_result(
            IpcOperation::Execute,
            self.handler.execute(request),
        )?;
        validate_broker_ipc_response_envelope(IpcOperation::Execute, &response)
            .map_err(BrokerIpcServeFailure::Internal)?;
        let encoded = canonical_json_bytes(&response)
            .map_err(|_| prepared_internal_fault("prepared execution response encoding failed"))?;
        write_broker_ipc_response(&mut stream, &encoded)
    }
}

#[cfg(unix)]
fn prepared_connection_binding(
    tenant: &str,
    authenticated: &crate::registration::AuthenticatedAttemptRequest,
) -> std::result::Result<([u8; 32], Instant), BrokerIpcServeFailure> {
    let request = &authenticated.request;
    let expires = request
        .capability
        .body
        .expires_at_unix_seconds
        .min(authenticated.registration.nonce_expires_at_unix_seconds);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| prepared_internal_fault("prepared connection clock unavailable"))?;
    let remaining = Duration::from_secs(expires)
        .checked_sub(now)
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| prepared_client_fault("prepared connection authorization expired"))?
        .min(Duration::from_millis(MAX_BROKER_IPC_DEADLINE_MS));
    let deadline = Instant::now()
        .checked_add(remaining)
        .ok_or_else(|| prepared_internal_fault("prepared connection deadline overflow"))?;
    let authorization = canonical_json_bytes(&request.proof)
        .map_err(|_| prepared_internal_fault("prepared proof encoding failed"))?;
    let payload = canonical_json_bytes(request)
        .map_err(|_| prepared_internal_fault("prepared request encoding failed"))?;
    let frame = canonical_ipc_request_bytes(&AuthenticatedIpcRequest {
        operation: IpcOperation::Execute,
        tenant_scope: tenant.to_string(),
        authorization: authorization.into(),
        payload: payload.into(),
    })
    .map_err(BrokerIpcServeFailure::Internal)?;
    Ok((Sha256::digest(frame.as_slice()).into(), deadline))
}

#[cfg(unix)]
fn prepared_client_fault(message: &str) -> BrokerIpcServeFailure {
    BrokerIpcServeFailure::Client(BrokerError::AuthorizationDenied(message.into()))
}

#[cfg(unix)]
fn prepared_internal_fault(message: &str) -> BrokerIpcServeFailure {
    BrokerIpcServeFailure::Internal(BrokerError::Storage(message.into()))
}
