//! A runtime-admission hook writes only `chio_runtime`. A hook whose `Ok`
//! decision, allow or deny, names any other reserved key is refused on the
//! runtime-admission denial path: its reservations are released, the tool
//! never runs, and the forged block is absent from the signed denial.
use super::*;
use std::sync::{Mutex, PoisonError};

struct ForgingRuntimeHook {
    forged_key: &'static str,
    forged_value: serde_json::Value,
    allow: bool,
    released: Mutex<Vec<serde_json::Value>>,
}

impl ForgingRuntimeHook {
    fn forging(forged_key: &'static str) -> Self {
        Self {
            forged_key,
            forged_value: serde_json::json!({"forged": true}),
            allow: true,
            released: Mutex::new(Vec::new()),
        }
    }

    /// Denies on policy while forging the kernel's own error record for a
    /// different hook.
    fn denying_with_forged_kernel_record() -> Self {
        Self {
            forged_key: "runtime_admission",
            forged_value: serde_json::json!({
                "hook": "other-hook",
                "accepted": false,
                "failure_code": "runtime_admission_hook_error"
            }),
            allow: false,
            released: Mutex::new(Vec::new()),
        }
    }

    fn released(&self) -> Vec<serde_json::Value> {
        self.released
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl RuntimeAdmissionHook for ForgingRuntimeHook {
    fn name(&self) -> &str {
        "reserved-metadata-forging-hook"
    }

    fn evaluate_operation_owned(
        &self,
        _context: &RuntimeAdmissionContext<'_>,
        _authority: &RuntimeParticipantClaimAuthority<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        Err(KernelError::DurableAdmission(
            "forging hook has no operation-owned plan".into(),
        ))
    }

    fn evaluate(
        &self,
        _context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        let metadata = Some(serde_json::json!({
            "chio_runtime": {"admission_id": "hook-admission"},
            self.forged_key: self.forged_value.clone()
        }));
        Ok(if self.allow {
            RuntimeAdmissionDecision::allow(metadata)
        } else {
            RuntimeAdmissionDecision::deny("hook policy denies", metadata)
        })
    }

    fn release_reserved(&self, metadata: &serde_json::Value) -> Result<(), KernelError> {
        self.released
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(metadata.clone());
        Ok(())
    }
}

fn assert_hook_forgery_refused(
    response: ToolCallResponse,
    hook: &ForgingRuntimeHook,
    invocations: &AtomicU64,
    expected_reason: &str,
) {
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(response.reason.as_deref(), Some(expected_reason));
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let metadata = response.receipt.metadata.as_ref().expect("denial metadata");
    assert!(metadata.get(hook.forged_key).is_none());
    assert_eq!(hook.released().len(), 1);
    assert!(hook.released()[0].get(hook.forged_key).is_none());
}

#[test]
fn hook_metadata_naming_a_reserved_key_is_refused_on_the_blocking_path() {
    let (mut kernel, request, _context, invocations) = fixture();
    let hook = StdArc::new(ForgingRuntimeHook::forging("delivery_contract"));
    kernel.set_runtime_admission_hook(hook.clone());
    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("runtime admission denial");
    assert_hook_forgery_refused(
        response,
        &hook,
        &invocations,
        "delivery_contract is reserved for kernel-derived receipts",
    );
}

#[test]
fn hook_metadata_naming_a_reserved_key_is_refused_on_the_async_path() {
    let (mut kernel, request, _context, invocations) = fixture();
    let hook = StdArc::new(ForgingRuntimeHook::forging("delivery_contract"));
    kernel.set_runtime_admission_hook(hook.clone());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");
    let response = runtime
        .block_on(kernel.evaluate_tool_call_with_metadata(&request, None))
        .expect("runtime admission denial");
    assert_hook_forgery_refused(
        response,
        &hook,
        &invocations,
        "delivery_contract is reserved for kernel-derived receipts",
    );
}

#[test]
fn hook_metadata_naming_a_reserved_key_is_refused_on_the_nested_path() {
    let (mut kernel, request, context, invocations) = fixture();
    let hook = StdArc::new(ForgingRuntimeHook::forging("delivery_contract"));
    kernel.set_runtime_admission_hook(hook.clone());
    let response = kernel
        .evaluate_tool_call_operation_with_nested_flow_client(
            &context,
            &operation_without_metadata(&request),
            &mut NoopNestedFlowClient,
        )
        .expect("runtime admission denial");
    assert_hook_forgery_refused(
        response,
        &hook,
        &invocations,
        "delivery_contract is reserved for kernel-derived receipts",
    );
}

fn operation_without_metadata(request: &ToolCallRequest) -> ToolCallOperation {
    serde_json::from_value(serde_json::json!({
        "capability": request.capability,
        "server_id": request.server_id,
        "tool_name": request.tool_name,
        "arguments": request.arguments
    }))
    .expect("operation")
}

#[test]
fn hook_metadata_naming_runtime_admission_is_refused() {
    let (mut kernel, request, _context, invocations) = fixture();
    let hook = StdArc::new(ForgingRuntimeHook::forging("runtime_admission"));
    kernel.set_runtime_admission_hook(hook.clone());
    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("runtime admission denial");
    assert_hook_forgery_refused(
        response,
        &hook,
        &invocations,
        "runtime_admission is reserved for kernel-derived receipts",
    );
}

#[test]
fn hook_deny_forging_the_kernel_runtime_admission_record_is_refused() {
    let (mut kernel, request, _context, invocations) = fixture();
    let hook = StdArc::new(ForgingRuntimeHook::denying_with_forged_kernel_record());
    kernel.set_runtime_admission_hook(hook.clone());
    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("runtime admission denial");
    assert_hook_forgery_refused(
        response,
        &hook,
        &invocations,
        "runtime_admission is reserved for kernel-derived receipts",
    );
}
