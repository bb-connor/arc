//! A configured runtime hook never receives caller-supplied runtime metadata.
use super::*;
use std::sync::{Mutex, PoisonError};

const RUNTIME_KEY_REJECTION: &str =
    "chio_runtime is reserved for kernel-derived runtime admission reservations";

#[derive(Default)]
struct RecordingRuntimeHook {
    entries: Mutex<Vec<&'static str>>,
    released: Mutex<Vec<serde_json::Value>>,
}

impl RecordingRuntimeHook {
    fn record(&self, entry: &'static str) {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(entry);
    }

    fn entries(&self) -> Vec<&'static str> {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn released(&self) -> Vec<serde_json::Value> {
        self.released
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl RuntimeAdmissionHook for RecordingRuntimeHook {
    fn name(&self) -> &str {
        "reserved-metadata-recording-hook"
    }

    fn evaluate_operation_owned(
        &self,
        _context: &RuntimeAdmissionContext<'_>,
        _authority: &RuntimeParticipantClaimAuthority<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        self.record("evaluate_operation_owned");
        Err(KernelError::DurableAdmission(
            "recording hook has no operation-owned plan".into(),
        ))
    }

    fn evaluate(
        &self,
        _context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        self.record("evaluate");
        Ok(RuntimeAdmissionDecision::deny(
            "recording hook denies before budget",
            None,
        ))
    }

    fn release_reserved(&self, metadata: &serde_json::Value) -> Result<(), KernelError> {
        self.record("release_reserved");
        self.released
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(metadata.clone());
        Ok(())
    }
}

fn assert_runtime_key_rejected<T>(result: Result<T, KernelError>, entry: &str) {
    assert!(
        matches!(
            result,
            Err(KernelError::InvalidReceiptMetadata(ref reason)) if reason == RUNTIME_KEY_REJECTION
        ),
        "{entry} did not reject caller chio_runtime metadata as reserved"
    );
}

#[test]
fn installed_runtime_hook_never_receives_caller_runtime_metadata() -> TestResult {
    let (mut kernel, request, context, invocations) = fixture();
    let hook = StdArc::new(RecordingRuntimeHook::default());
    kernel.set_runtime_admission_hook(hook.clone());
    let foreign = metadata("chio_runtime");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    assert_runtime_key_rejected(
        kernel
            .authorize_tool_call_reserving_blocking_with_metadata(&request, Some(foreign.clone())),
        "reserving blocking",
    );
    assert_runtime_key_rejected(
        kernel.evaluate_tool_call_blocking_with_metadata(&request, Some(foreign.clone())),
        "blocking",
    );
    assert_runtime_key_rejected(
        runtime.block_on(kernel.evaluate_tool_call_with_metadata(&request, Some(foreign))),
        "async",
    );
    assert_runtime_key_rejected(
        kernel.evaluate_session_operation(
            &context,
            &SessionOperation::ToolCall(Box::new(operation(&request, "chio_runtime"))),
        ),
        "session",
    );
    assert_runtime_key_rejected(
        kernel.evaluate_tool_call_operation_with_nested_flow_client(
            &context,
            &operation(&request, "chio_runtime"),
            &mut NoopNestedFlowClient,
        ),
        "nested sync",
    );
    assert_runtime_key_rejected(
        runtime.block_on(
            kernel.evaluate_tool_call_operation_with_nested_flow_client_async(
                &context,
                &operation(&request, "chio_runtime"),
                &mut NoopNestedFlowClient,
            ),
        ),
        "nested async",
    );
    assert!(hook.entries().is_empty(), "{:?}", hook.entries());
    assert!(hook.released().is_empty());
    assert_untouched(&kernel, &context, &invocations);

    let host = serde_json::json!({"host_note": "caller-visible"});
    let response = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&request, Some(host.clone()))?;
    assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
    assert_eq!(hook.entries(), vec!["evaluate", "release_reserved"]);
    assert_eq!(hook.released(), vec![host]);
    assert_untouched(&kernel, &context, &invocations);
    Ok(())
}
