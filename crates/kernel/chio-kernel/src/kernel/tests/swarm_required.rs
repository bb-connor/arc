use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn fixture() -> (ChioKernel, ToolCallRequest, std::sync::Arc<AtomicU64>) {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "swarm-required",
        vec!["write"],
        invocations.clone(),
    )));
    let capability = make_capability(
        &kernel,
        &make_keypair(),
        make_scope(vec![make_grant("swarm-required", "write")]),
        300,
    );
    let request = make_request_with_arguments(
        "swarm-required-request",
        &capability,
        "write",
        "swarm-required",
        serde_json::json!({}),
    );
    (kernel, request, invocations)
}

fn with_context(mut request: ToolCallRequest, context: serde_json::Value) -> ToolCallRequest {
    request.governed_intent = Some(GovernedTransactionIntent {
        id: "swarm-required-intent".to_string(),
        server_id: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        purpose: "verify required swarm admission".to_string(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: Some(context),
        body: Default::default(),
    });
    request
}

fn assert_denied(kernel: &ChioKernel, request: &ToolCallRequest, code: &str) -> TestResult {
    let response = kernel.evaluate_tool_call_blocking(request)?;
    assert_eq!(response.verdict, Verdict::Deny, "{response:?}");
    assert!(response.receipt.verify_signature()?);
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("missing deny metadata"))?;
    assert_eq!(metadata["chio_runtime"]["accepted"], false);
    assert_eq!(metadata["chio_runtime"]["failure_code"], code);
    Ok(())
}

#[test]
fn required_swarm_rejects_omitted_context_before_permissive_hook_or_tool() -> TestResult {
    for context in [
        None,
        Some(serde_json::json!({})),
        Some(serde_json::json!({"chioAdmission": {"admissionId": "ordinary"}})),
    ] {
        let (mut kernel, request, invocations) = fixture();
        let hook_calls = std::sync::Arc::new(AtomicU64::new(0));
        kernel.set_runtime_admission_hook(std::sync::Arc::new(AllowingRuntimeAdmissionHook {
            calls: hook_calls.clone(),
        }));
        kernel.require_swarm_admission();
        let request = match context {
            Some(context) => with_context(request, context),
            None => request,
        };
        assert_denied(&kernel, &request, "missing_chio_swarm_context")?;
        assert_eq!(hook_calls.load(Ordering::SeqCst), 0);
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[test]
fn required_swarm_rejects_malformed_context_without_dispatch() -> TestResult {
    for value in [
        serde_json::Value::Null,
        serde_json::json!(false),
        serde_json::json!([]),
        serde_json::json!("graph"),
    ] {
        let (mut kernel, request, invocations) = fixture();
        kernel.require_swarm_admission();
        let request = with_context(request, serde_json::json!({"chioSwarm": value}));
        assert_denied(&kernel, &request, "invalid_chio_swarm_context")?;
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[test]
fn required_swarm_rejects_missing_hook_and_replacement_with_ordinary_hook() -> TestResult {
    let (mut kernel, request, invocations) = fixture();
    kernel.require_swarm_admission();
    kernel.require_swarm_admission();
    assert!(kernel.swarm_admission_required());
    let request = with_context(request, serde_json::json!({"chioSwarm": {}}));
    assert_denied(&kernel, &request, "runtime_admission_hook_missing")?;
    kernel.set_runtime_admission_hook(std::sync::Arc::new(AllowingRuntimeAdmissionHook {
        calls: std::sync::Arc::new(AtomicU64::new(0)),
    }));
    assert!(kernel.swarm_admission_required());
    let mut retry = request.clone();
    retry.request_id = "swarm-required-replaced".to_string();
    assert_denied(&kernel, &retry, "runtime_admission_swarm_unsupported")?;
    kernel.clear_runtime_admission_hook();
    assert!(kernel.swarm_admission_required());
    retry.request_id = "swarm-required-cleared".to_string();
    assert_denied(&kernel, &retry, "runtime_admission_hook_missing")?;
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

struct NonRevalidatingSwarmHook;

impl RuntimeAdmissionHook for NonRevalidatingSwarmHook {
    fn name(&self) -> &str {
        "non-revalidating-swarm"
    }
    fn enforces_swarm_authority(&self) -> bool {
        true
    }
    fn evaluate(
        &self,
        _: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        Err(KernelError::Internal(
            "unsupported hook must never evaluate".to_string(),
        ))
    }
}

#[test]
fn required_swarm_rejects_hook_without_dispatch_revalidation() -> TestResult {
    let (mut kernel, request, invocations) = fixture();
    kernel.require_swarm_admission();
    kernel.set_runtime_admission_hook(std::sync::Arc::new(NonRevalidatingSwarmHook));
    let request = with_context(request, serde_json::json!({"chioSwarm": {}}));
    assert_denied(&kernel, &request, "runtime_admission_swarm_unsupported")?;
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn optional_kernel_preserves_non_swarm_dispatch() -> TestResult {
    let (kernel, request, invocations) = fixture();
    assert!(!kernel.swarm_admission_required());
    let response = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Allow, "{response:?}");
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    Ok(())
}
