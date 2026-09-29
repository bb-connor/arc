use super::*;
use crate::tests::{
    authorization_projection, capability_for_tool, test_kernel_config, test_manifest, text_message,
    unix_now,
};
use chio_core::Keypair;
use chio_security_types::clock::{Clock, ClockError, ClockReading, MonotonicInstant, UnixMillis};
use chio_test_support::prelude::*;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

struct TestClock {
    millis: AtomicU64,
    monotonic: AtomicU64,
    samples: Mutex<VecDeque<ClockReading>>,
    fail: AtomicBool,
}
impl Clock for TestClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(ClockError::Unavailable);
        }
        if let Some(sample) = self.samples.lock().test_unwrap().pop_front() {
            return Ok(sample);
        }
        Ok(ClockReading::new(
            UnixMillis::new(self.millis.load(Ordering::SeqCst)),
            MonotonicInstant::from_nanos(self.monotonic.load(Ordering::SeqCst)),
        ))
    }
}
fn harness() -> (
    ChioA2aEdge,
    ChioKernel,
    A2aKernelExecutionContext,
    Arc<TestClock>,
    Arc<AtomicU64>,
) {
    let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let subject = Keypair::generate();
    let capability = capability_for_tool(&config.keypair, &subject, "test-srv", "echo");
    let execution = A2aKernelExecutionContext {
        capability,
        agent_id: subject.public_key().to_hex(),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: vec![],
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
    };
    let clock = Arc::new(TestClock {
        millis: AtomicU64::new(unix_now() * 1000),
        monotonic: AtomicU64::new(0),
        samples: Mutex::new(VecDeque::new()),
        fail: AtomicBool::new(false),
    });
    let mut kernel = ChioKernel::new_with_clock(config, clock.clone());
    let calls = Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(authorization_projection::CountedToolServer {
        server: "test-srv".into(),
        tool: "echo".into(),
        calls: calls.clone(),
    }));
    (edge, kernel, execution, clock, calls)
}
#[test]
fn original_bytes_reject_duplicates_before_dispatch_and_preserve_integer_ids() {
    use std::error::Error;
    let (mut edge, kernel, execution, _, calls) = harness();
    let duplicate = br#"{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"role":"user","parts":[{"type":"data","data":{"secret_marker":1,"secret_marker":2}}]}}}"#;
    let error = edge
        .handle_jsonrpc(duplicate, &kernel, &execution)
        .test_expect_err("duplicate");
    assert!(matches!(error, A2aEdgeError::UntrustedInput(_)));
    assert!(error.source().is_some());
    assert!(!format!("{error:?} {error}").contains("secret_marker"));
    let response = edge
        .handle_jsonrpc(
            br#"{"jsonrpc":"2.0","id":18446744073709551615,"method":"unknown"}"#,
            &kernel,
            &execution,
        )
        .test_unwrap();
    assert_eq!(response["id"].as_u64(), Some(u64::MAX));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
#[test]
fn argument_objects_reject_unsafe_integer_values() {
    let (mut edge, kernel, execution, _, calls) = harness();
    let request = SendMessageRequest {
        message: A2aMessage {
            role: "user".into(),
            parts: vec![A2aPart::Data {
                data: json!({"value":u64::MAX}),
            }],
            metadata: None,
        },
        metadata: None,
    };
    let error = edge
        .handle_send_message("echo", &request, &kernel, &execution)
        .test_expect_err("unsafe argument");
    assert!(matches!(error, A2aEdgeError::UntrustedInput(_)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
#[test]
fn task_clock_fault_preserves_work_and_exact_expiry_prevents_dispatch() {
    let (mut edge, kernel, execution, clock, calls) = harness();
    let accepted = edge
        .handle_stream_message("echo", &text_message("hello"), &kernel, &execution)
        .test_unwrap();
    clock.fail.store(true, Ordering::SeqCst);
    let response = edge.handle_jsonrpc_value(
        json!({"jsonrpc":"2.0", "id":2,"method":"task/get","params":{"taskId":accepted.id}}),
        &kernel,
        &execution,
    );
    assert_eq!(response["error"]["message"], ClockError::Unavailable.code());
    assert_eq!(edge.tasks.len(), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    clock.fail.store(false, Ordering::SeqCst);
    clock
        .millis
        .fetch_add(DEFERRED_A2A_TASK_TTL_MILLIS, Ordering::SeqCst);
    let response = edge.handle_jsonrpc_value(
        json!({"jsonrpc":"2.0", "id":3,"method":"task/get","params":{"taskId":accepted.id}}),
        &kernel,
        &execution,
    );
    assert!(response.get("error").is_some());
    assert!(edge.tasks.is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
#[test]
fn terminal_tasks_use_capacity_until_expiry_and_counters_cannot_wrap() {
    let (mut edge, kernel, execution, clock, calls) = harness();
    let accepted = edge
        .handle_stream_message("echo", &text_message("hello"), &kernel, &execution)
        .test_unwrap();
    let response = edge.handle_jsonrpc_value(
        json!({"jsonrpc":"2.0", "id":2,"method":"task/get","params":{"taskId":accepted.id}}),
        &kernel,
        &execution,
    );
    assert!(response.get("error").is_none(), "{response:?}");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let terminal = edge.tasks.get(&accepted.id).test_unwrap().clone();
    assert!(terminal.response.status.is_terminal());
    for index in 1..MAX_DEFERRED_A2A_TASKS {
        edge.tasks
            .insert(format!("retained-{index}"), terminal.clone());
    }
    assert!(matches!(
        edge.handle_stream_message("echo", &text_message("hello"), &kernel, &execution),
        Err(A2aEdgeError::TaskCapacity)
    ));
    assert_eq!(
        edge.resolve_task(&accepted.id, &execution)
            .test_unwrap()
            .status,
        terminal.response.status
    );
    clock
        .millis
        .fetch_add(DEFERRED_A2A_TASK_TTL_MILLIS, Ordering::SeqCst);
    edge.handle_stream_message("echo", &text_message("hello"), &kernel, &execution)
        .test_unwrap();
    assert_eq!(edge.tasks.len(), 1);
    edge.task_counter = u64::MAX;
    assert!(matches!(
        edge.handle_stream_message("echo", &text_message("hello"), &kernel, &execution),
        Err(A2aEdgeError::TaskCapacity)
    ));
    assert_eq!(edge.task_counter, u64::MAX);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn monotonic_expiry_denies_dispatch_when_wall_time_stops() {
    let (mut edge, kernel, execution, clock, calls) = harness();
    let accepted = edge
        .handle_stream_message("echo", &text_message("hello"), &kernel, &execution)
        .test_unwrap();
    clock
        .monotonic
        .store(DEFERRED_A2A_TASK_TTL_MILLIS * 1_000_000, Ordering::SeqCst);
    let response = edge.handle_jsonrpc_value(
        json!({"jsonrpc":"2.0", "id":2,"method":"task/get","params":{"taskId":accepted.id}}),
        &kernel,
        &execution,
    );
    assert_eq!(response["error"]["code"], -32602);
    assert!(edge.tasks.is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn public_dispatch_preserves_typed_causes_without_emitting_them() {
    use std::error::Error;
    let (mut edge, kernel, execution, clock, calls) = harness();
    for id in [Some(1), None] {
        let mut request = json!({"jsonrpc":"2.0", "method":"message/send", "params":{"metadata":{"chio":{"targetSkillId":"echo"}},"message":{"role":"user", "parts":"secret_marker"}}});
        if let Some(id) = id {
            request["id"] = json!(id);
        }
        let response = edge
            .handle_jsonrpc(
                &serde_json::to_vec(&request).test_unwrap(),
                &kernel,
                &execution,
            )
            .test_unwrap();
        let error = response.local_error().test_expect("retain DTO failure");
        assert!(
            matches!(error, A2aEdgeError::UntrustedInput(_)),
            "{error:?}"
        );
        assert!(error.source().and_then(Error::source).is_some());
        assert_eq!(response.is_notification(), id.is_none());
        assert!(!format!("{response:?}").contains("secret_marker"));
    }
    let response = edge.handle_jsonrpc(br#"{"jsonrpc":"2.0","id":2,"method":"message/send","params":{"metadata":{"chio":{"targetSkillId":"echo"}},"message":{"role":"user","parts":[{"type":"data","data":{"value":18446744073709551615}}]}}}"#, &kernel, &execution).test_unwrap();
    assert!(matches!(
        response.local_error(),
        Some(A2aEdgeError::UntrustedInput(_))
    ));
    clock.fail.store(true, Ordering::SeqCst);
    let response = edge.handle_jsonrpc(br#"{"jsonrpc":"2.0","id":3,"method":"message/stream","params":{"metadata":{"chio":{"targetSkillId":"echo"}},"message":{"role":"user","parts":[{"type":"text","text":"hello"}]}}}"#, &kernel, &execution).test_unwrap();
    assert!(matches!(
        response.local_error(),
        Some(A2aEdgeError::Clock(ClockError::Unavailable))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn final_dispatch_expiry_removes_the_retained_task() {
    let (mut edge, kernel, execution, clock, calls) = harness();
    let accepted = edge
        .handle_stream_message("echo", &text_message("hello"), &kernel, &execution)
        .test_unwrap();
    let deadline = clock.millis.load(Ordering::SeqCst) + DEFERRED_A2A_TASK_TTL_MILLIS;
    clock.samples.lock().test_unwrap().extend([
        ClockReading::new(
            UnixMillis::new(deadline - 1),
            MonotonicInstant::from_nanos(1),
        ),
        ClockReading::new(UnixMillis::new(deadline), MonotonicInstant::from_nanos(2)),
    ]);
    let response = edge.handle_jsonrpc(&serde_json::to_vec(&json!({"jsonrpc":"2.0", "id":4,"method":"task/get","params":{"taskId":accepted.id}})).test_unwrap(), &kernel, &execution).test_unwrap();
    assert!(matches!(
        response.local_error(),
        Some(A2aEdgeError::Clock(ClockError::Expired))
    ));
    assert!(edge.tasks.is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
