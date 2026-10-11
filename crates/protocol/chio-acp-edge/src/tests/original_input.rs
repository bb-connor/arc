use super::*;
use chio_core::canonical::UntrustedJsonError;
use chio_security_types::clock::{Clock, ClockError, ClockReading, MonotonicInstant, UnixMillis};
use std::error::Error;

#[test]
fn public_byte_ingress_rejects_duplicates_and_bounds_before_dispatch() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let (kernel, execution) = kernel_execution(Box::new(test_server()), "test-srv", "read_file");
    let duplicate = br#"{"jsonrpc":"2.0","id":1,"method":"tool/invoke","params":{"capabilityId":"read_file","arguments":{"private_marker":1,"private_marker":2}}}"#;
    let error = edge
        .handle_jsonrpc(duplicate, &kernel, &execution)
        .test_unwrap_err();
    assert!(matches!(error, AcpEdgeError::UntrustedInput(_)));
    assert!(error.source().is_some());
    assert!(!format!("{error:?} {error}").contains("private_marker"));
    assert!(matches!(
        edge.handle_jsonrpc(&vec![b' '; 8 * 1024 * 1024 + 1], &kernel, &execution),
        Err(AcpEdgeError::UntrustedInput(
            UntrustedJsonError::TooLarge { .. }
        ))
    ));
    assert!(kernel.receipt_log().receipts().is_empty());
    let response = edge
        .handle_jsonrpc(
            br#"{"jsonrpc":"2.0","id":18446744073709551615,"method":"session/list_capabilities"}"#,
            &kernel,
            &execution,
        )
        .test_unwrap();
    assert_eq!(response["id"].as_u64(), Some(u64::MAX));
}

#[test]
fn invalid_notification_keeps_local_cause_without_emitting_a_wire_reply() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let (kernel, execution) = kernel_execution(Box::new(test_server()), "test-srv", "read_file");
    let response = edge
        .handle_jsonrpc(
            br#"{"jsonrpc":"2.0","method":"tool/invoke","params":{}}"#,
            &kernel,
            &execution,
        )
        .test_unwrap();
    assert!(response.as_value().is_none());
    assert!(matches!(
        response.local_error(),
        Some(AcpEdgeError::InvalidRequest(_))
    ));
    assert!(kernel.receipt_log().receipts().is_empty());
}

struct ControlledClock(Mutex<Result<ClockReading, ClockError>>);
impl Clock for ControlledClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        *self.0.lock().test_unwrap()
    }
}
#[test]
fn task_clock_failures_retain_pending_work_and_counters_never_wrap() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![streaming_manifest()]).test_unwrap();
    let (_, execution) =
        kernel_execution(Box::new(test_server()), "streaming-srv", "search_stream");
    let clock = Arc::new(ControlledClock(Mutex::new(Ok(ClockReading::new(
        UnixMillis::new(1_000),
        MonotonicInstant::from_nanos(0),
    )))));
    let kernel = ChioKernel::new_with_clock(test_kernel_config(), clock.clone());
    let task = edge
        .start_stream_with_request_id("request", "search_stream", json!({}), &execution, &kernel)
        .test_unwrap();
    *clock.0.lock().test_unwrap() = Err(ClockError::Unavailable);
    assert!(matches!(
        edge.cancel_stream_task(&task.id, &execution, &kernel),
        Err(AcpEdgeError::Clock(ClockError::Unavailable))
    ));
    assert_eq!(
        edge.tasks.borrow()[&task.id].task.status,
        AcpTaskStatus::Working
    );
    *clock.0.lock().test_unwrap() = Ok(ClockReading::new(
        UnixMillis::new(1_000),
        MonotonicInstant::from_nanos(DEFERRED_ACP_TASK_TTL_MILLIS * 1_000_000),
    ));
    assert!(matches!(
        edge.cancel_stream_task(&task.id, &execution, &kernel),
        Err(AcpEdgeError::ToolNotFound(_))
    ));
    assert!(edge.tasks.borrow().is_empty());
    edge.task_counter.set(u64::MAX);
    assert!(matches!(
        edge.start_stream_with_request_id(
            "overflow",
            "search_stream",
            json!({}),
            &execution,
            &kernel
        ),
        Err(AcpEdgeError::Clock(ClockError::Overflow))
    ));
    assert_eq!(edge.task_counter.get(), u64::MAX);
}
