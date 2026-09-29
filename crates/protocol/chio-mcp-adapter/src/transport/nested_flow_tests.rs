#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use chio_core::{CreateElicitationResult, CreateMessageResult, RequestId, RootDefinition};
use chio_kernel::KernelError;
use chio_security_types::clock::{FixedClock, MonotonicInstant, UnixMillis};
use std::sync::Mutex;

struct TestClock(Mutex<Result<ClockReading, ClockError>>);
impl Clock for TestClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        *self.0.lock().unwrap()
    }
}
struct NoDispatch;
impl NestedFlowBridge for NoDispatch {
    fn notify_elicitation_completed(&mut self, _: &str) -> Result<(), KernelError> {
        panic!("expired task dispatched")
    }
    fn notify_resource_updated(&mut self, _: &str) -> Result<(), KernelError> {
        panic!("expired task dispatched")
    }
    fn notify_resources_list_changed(&mut self) -> Result<(), KernelError> {
        panic!("expired task dispatched")
    }
    fn parent_request_id(&self) -> &RequestId {
        panic!("expired task dispatched")
    }
    fn list_roots(&mut self) -> Result<Vec<RootDefinition>, KernelError> {
        panic!("expired task dispatched")
    }
    fn create_message(
        &mut self,
        _: CreateMessageOperation,
    ) -> Result<CreateMessageResult, KernelError> {
        panic!("expired task dispatched")
    }
    fn create_elicitation(
        &mut self,
        _: CreateElicitationOperation,
    ) -> Result<CreateElicitationResult, KernelError> {
        panic!("expired task dispatched")
    }
}
fn operation() -> CreateMessageOperation {
    CreateMessageOperation {
        messages: vec![],
        model_preferences: None,
        system_prompt: None,
        include_context: None,
        temperature: None,
        max_tokens: 1,
        stop_sequences: vec![],
        metadata: None,
        tools: vec![],
        tool_choice: None,
    }
}
fn create(
    runtime: &mut NestedFlowTaskRuntime,
    ttl: u64,
) -> Result<serde_json::Value, AdapterError> {
    runtime.create_message_task(
        "owner".into(),
        "parent".into(),
        operation(),
        RequestedTask { ttl: Some(ttl) },
    )
}
#[test]
fn protocol_boundary_nested_expiry_is_enforced_before_dispatch_and_result() {
    for background in [false, true] {
        let clock = Arc::new(TestClock(Mutex::new(Ok(FixedClock::from_millis(1000)
            .read()
            .unwrap()))));
        let mut runtime = NestedFlowTaskRuntime {
            clock: clock.clone(),
            ..Default::default()
        };
        let task = create(&mut runtime, 1).unwrap();
        let id = task["task"]["taskId"].as_str().unwrap().to_string();
        *clock.0.lock().unwrap() = Ok(ClockReading::new(
            UnixMillis::new(1001),
            MonotonicInstant::from_nanos(1_000_000),
        ));
        if background {
            runtime
                .process_background_tasks(&mut NoDispatch, &mut Vec::new())
                .unwrap();
        } else {
            let result = runtime
                .handle_tasks_result(
                    json!(1),
                    &json!({"taskId":id}),
                    &mut NoDispatch,
                    &mut Vec::new(),
                )
                .unwrap();
            assert_eq!(result["error"]["code"], -32602);
        }
        assert!(runtime.tasks.is_empty());
        assert!(runtime.pending_background_tasks.is_empty());
    }
}
#[test]
fn protocol_boundary_nested_capacity_and_clock_faults_are_atomic() {
    let clock = Arc::new(TestClock(Mutex::new(Ok(FixedClock::from_millis(1000)
        .read()
        .unwrap()))));
    let mut runtime = NestedFlowTaskRuntime {
        clock: clock.clone(),
        ..Default::default()
    };
    for _ in 0..MAX_NESTED_TASKS {
        create(&mut runtime, 1000).unwrap();
    }
    assert!(matches!(
        create(&mut runtime, 1000),
        Err(AdapterError::TaskCapacity)
    ));
    assert_eq!(runtime.tasks.len(), MAX_NESTED_TASKS);
    *clock.0.lock().unwrap() = Err(ClockError::Unavailable);
    assert!(matches!(
        runtime.process_background_tasks(&mut NoDispatch, &mut Vec::new()),
        Err(AdapterError::Clock(ClockError::Unavailable))
    ));
    assert_eq!(runtime.pending_background_tasks.len(), MAX_NESTED_TASKS);
    assert_eq!(runtime.tasks.len(), MAX_NESTED_TASKS);
}
