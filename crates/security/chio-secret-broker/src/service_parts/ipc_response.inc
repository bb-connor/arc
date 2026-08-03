#[cfg(unix)]
fn classify_broker_ipc_handler_result(
    operation: IpcOperation,
    handled: Result<IpcResponse>,
) -> std::result::Result<IpcResponse, BrokerIpcServeFailure> {
    match handled {
        Ok(response) => Ok(response),
        Err(error)
            if matches!(
                &error,
                BrokerError::Invariant(_) | BrokerError::Storage(_) | BrokerError::Custody(_)
            ) =>
        {
            Err(BrokerIpcServeFailure::Internal(error))
        }
        Err(error) if operation == IpcOperation::Execute => {
            Err(BrokerIpcServeFailure::Client(error))
        }
        Err(error) => Ok(IpcResponse {
            operation,
            accepted: false,
            response: Vec::new(),
            error_code: Some(error.diagnostic_code().to_string()),
        }),
    }
}

#[cfg(unix)]
const MAX_BROKER_IPC_ERROR_CODE_BYTES: usize = 64;

#[cfg(unix)]
fn validate_broker_ipc_response_envelope(
    operation: IpcOperation,
    response: &IpcResponse,
) -> Result<()> {
    let valid = response.operation == operation
        && response.response.len() <= MAX_WIRE_BYTES
        && if response.accepted {
            !response.response.is_empty() && response.error_code.is_none()
        } else if operation == IpcOperation::Execute {
            !response.response.is_empty()
                && response
                    .error_code
                    .as_deref()
                    .is_some_and(is_well_formed_broker_execute_diagnostic_code)
                && validate_signed_broker_execute_failure(response)
        } else {
            response.response.is_empty()
                && response
                    .error_code
                    .as_deref()
                    .is_some_and(is_well_formed_broker_ipc_error_code)
        };
    if !valid {
        return Err(BrokerError::Invariant(
            "IPC handler returned an invalid response envelope".to_string(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn is_well_formed_broker_ipc_error_code(code: &str) -> bool {
    let bytes = code.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_BROKER_IPC_ERROR_CODE_BYTES
        || !bytes[0].is_ascii_lowercase()
        || !(bytes[bytes.len() - 1].is_ascii_lowercase() || bytes[bytes.len() - 1].is_ascii_digit())
    {
        return false;
    }
    bytes
        .iter()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
        && !bytes.windows(2).any(|pair| pair == b"__")
}

#[cfg(unix)]
fn validate_signed_broker_execute_failure(response: &IpcResponse) -> bool {
    let Some(error_code) = response.error_code.as_deref() else {
        return false;
    };
    if !is_well_formed_broker_execute_diagnostic_code(error_code) {
        return false;
    }
    let Ok(failure) = serde_json::from_slice::<BrokerExecuteFailure>(&response.response) else {
        return false;
    };
    let Ok(canonical) = canonical_json_bytes(&failure) else {
        return false;
    };
    if canonical != response.response
        || failure.diagnostic_code != error_code
        || failure.receipt.body.diagnostic_code != error_code
    {
        return false;
    }
    let Ok(receipt_digest) = failure_receipt_digest(&failure.receipt) else {
        return false;
    };
    failure.receipt_reference == format!("broker-failure-receipt-sha256-{receipt_digest}")
        && verify_failure_receipt(&failure.receipt, &failure.receipt.signer).is_ok()
}

#[cfg(unix)]
fn write_broker_ipc_response(
    stream: &mut BrokerIpcDeadlineIo<UnixStream>,
    frame: &[u8],
) -> std::result::Result<(), BrokerIpcServeFailure> {
    if frame.is_empty() || frame.len() > MAX_WIRE_BYTES {
        return Err(BrokerIpcServeFailure::Internal(BrokerError::Invariant(
            "encoded IPC response frame is empty or oversized".to_string(),
        )));
    }
    let length = u32::try_from(frame.len()).map_err(|_| {
        BrokerIpcServeFailure::Internal(BrokerError::Invariant(
            "encoded IPC response length overflow".to_string(),
        ))
    })?;
    let write_result = stream
        .write_all(&length.to_be_bytes())
        .and_then(|()| stream.write_all(frame))
        .and_then(|()| stream.flush());
    let Err(error) = write_result else {
        return Ok(());
    };
    match classify_broker_ipc_write_error(error.kind(), stream.write_deadline_setup_failed()) {
        BrokerIpcWriteFailureClass::Client => {
            return Err(BrokerIpcServeFailure::Client(BrokerError::InvalidRequest(
                format!("IPC client stopped receiving the response: {error}"),
            )))
        }
        BrokerIpcWriteFailureClass::DeadlineInternal => {
            return Err(BrokerIpcServeFailure::Internal(BrokerError::Storage(
                format!("IPC write deadline maintenance failed: {error}"),
            )))
        }
        BrokerIpcWriteFailureClass::OperatingSystemInternal => {}
    }
    Err(BrokerIpcServeFailure::Internal(BrokerError::Storage(
        format!("IPC response write failed: {error}"),
    )))
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BrokerIpcWriteFailureClass {
    Client,
    DeadlineInternal,
    OperatingSystemInternal,
}

#[cfg(unix)]
fn classify_broker_ipc_write_error(
    kind: std::io::ErrorKind,
    deadline_internal_failure: bool,
) -> BrokerIpcWriteFailureClass {
    if deadline_internal_failure {
        return BrokerIpcWriteFailureClass::DeadlineInternal;
    }
    if matches!(
        kind,
        std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::WriteZero
            | std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::TimedOut
    ) {
        BrokerIpcWriteFailureClass::Client
    } else {
        BrokerIpcWriteFailureClass::OperatingSystemInternal
    }
}
