use super::*;
use crate::protocol::{
    MAX_EXECUTE_RESPONSE_PAYLOAD_BYTES, MAX_EXECUTE_RESPONSE_WIRE_BYTES, MAX_WIRE_BYTES,
};
use chio_test_support::prelude::*;

#[test]
fn maximum_admitted_body_fits_both_response_envelopes() {
    let body = vec![255_u8; crate::daemon::MAX_DAEMON_COMBINED_RESPONSE_BYTES as usize];
    let payload = canonical_json_bytes(&serde_json::json!({"body": body})).test_unwrap();
    assert!(payload.len() > MAX_WIRE_BYTES && payload.len() < MAX_EXECUTE_RESPONSE_PAYLOAD_BYTES);
    let response = IpcResponse {
        operation: IpcOperation::Execute,
        accepted: true,
        response: payload,
        error_code: None,
    };
    let frame = canonical_json_bytes(&response).test_unwrap();
    assert!(frame.len() > MAX_WIRE_BYTES && frame.len() < MAX_EXECUTE_RESPONSE_WIRE_BYTES);
    assert_eq!(
        decode_ipc_response_envelope(&frame, IpcOperation::Execute).test_unwrap(),
        response
    );
    assert!(matches!(
        decode_ipc_response_envelope(&frame, IpcOperation::Status),
        Err(BrokerError::UntrustedInput(
            chio_core_types::canonical::UntrustedJsonError::TooLarge { .. }
        ))
    ));
}

#[test]
fn response_prefix_refuses_oversize_before_reading_body() {
    for operation in [IpcOperation::Execute, IpcOperation::Status] {
        let maximum = response_wire_limit(operation);
        let prefix = u32::try_from(maximum + 1).test_unwrap().to_be_bytes();
        let mut input = prefix.as_slice();
        assert!(
            matches!(read_frame_with_limit(&mut input, maximum), Err(BrokerError::InvalidRequest(message)) if message == "IPC frame is empty or oversized")
        );
    }
}
