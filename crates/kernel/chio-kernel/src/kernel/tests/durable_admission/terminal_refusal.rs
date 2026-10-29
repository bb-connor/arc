use super::*;
use crate::kernel::admission_coordinator::DurableRefusalResponse;

type TestResult = Result<(), Box<dyn std::error::Error>>;

static REFUSED: std::sync::LazyLock<crate::kernel::Denial> = std::sync::LazyLock::new(|| {
    crate::kernel::Denial::new(crate::ClientDenialCode::Denied, "request is refused")
});

pub(super) fn compensation_response() -> DurableRefusalResponse<'static> {
    DurableRefusalResponse {
        denial: &REFUSED,
        cancelled: false,
        matched_grant_index: None,
        metadata: None,
        verified_payee_binding: None,
    }
}

struct RefusingServer {
    store: std::sync::Arc<TestAdmissionOperationStore>,
    calls: std::sync::Arc<AtomicU64>,
}

#[async_trait::async_trait]
impl ToolServerConnection for RefusingServer {
    fn server_id(&self) -> &str {
        "durable-server"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["mutate".into()]
    }

    async fn invoke(
        &self,
        _: &str,
        _: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        assert_eq!(
            self.store.operation().state(),
            AdmissionOperationState::DispatchCommitted
        );
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(KernelError::ToolServerError(
            "child scope is refused".into(),
        ))
    }
}

fn install_refusing_server(
    kernel: &mut ChioKernel,
    store: &std::sync::Arc<TestAdmissionOperationStore>,
    calls: &std::sync::Arc<AtomicU64>,
) {
    kernel.register_tool_server(Box::new(RefusingServer {
        store: store.clone(),
        calls: calls.clone(),
    }));
}

fn restarted(
    original: &ChioKernel,
    store: &std::sync::Arc<TestAdmissionOperationStore>,
    calls: &std::sync::Arc<AtomicU64>,
) -> ChioKernel {
    let mut config = make_config();
    config.keypair = original.config.keypair.clone();
    config.policy_hash = original.config.policy_hash.clone();
    let mut kernel = make_kernel(config);
    kernel
        .set_durable_admission_store(store.clone(), store.clone(), admission_test_fence())
        .expect("qualified retained store");
    kernel.set_budget_store_handle(store.budget_store());
    install_refusing_server(&mut kernel, store, calls);
    kernel
}

fn assert_exact_response(original: &ToolCallResponse, replay: &ToolCallResponse) {
    assert_eq!(replay.request_id, original.request_id);
    assert_eq!(replay.verdict, original.verdict);
    assert_eq!(replay.output, original.output);
    assert_eq!(replay.reason, original.reason);
    assert_eq!(replay.terminal_state, original.terminal_state);
    assert!(original.execution_nonce.is_none());
    assert!(replay.execution_nonce.is_none());
    assert_eq!(
        chio_core::canonical::canonical_json_bytes(&replay.receipt).expect("replay bytes"),
        chio_core::canonical::canonical_json_bytes(&original.receipt).expect("original bytes"),
    );
}

#[test]
fn dispatched_refusal_replays_one_signed_terminal_across_restart() -> TestResult {
    let mut grant = make_grant("durable-server", "mutate");
    grant.max_invocations = Some(1);
    let (mut kernel, request, store, calls) =
        durable_admission_fixture_with_grants("retained-dispatched-refusal", vec![grant]);
    install_refusing_server(&mut kernel, &store, &calls);
    let initial = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(initial.verdict, Verdict::Deny);
    assert_eq!(
        initial.reason.as_deref(),
        Some("dispatch outcome is unknown after transport_return: CHIO-KERNEL-TOOL-SERVER")
    );
    assert!(initial.output.is_none());
    assert!(initial.receipt.verify_signature()?);
    let operation = assert_original_unknown_incident(
        &store,
        &request,
        &unknown_after("transport_return", "CHIO-KERNEL-TOOL-SERVER"),
    );
    let hold_id = operation.budget_hold_id().ok_or("captured hold")?;
    let hold = store
        .budget
        .get_budget_hold(hold_id.as_str())?
        .ok_or("retained hold")?;
    let usage = store
        .budget
        .get_usage(&request.capability.id, 0)?
        .ok_or("captured quota")?;
    assert_eq!(usage.invocation_count, 1);
    assert_ne!(
        hold.disposition,
        crate::budget_store::BudgetHoldDispositionView::Reversed
    );
    assert_eq!(kernel.receipt_log().len(), 1);
    assert_exact_response(&initial, &kernel.evaluate_tool_call_blocking(&request)?);
    assert_eq!(kernel.receipt_log().len(), 1);
    let recovered = restarted(&kernel, &store, &calls);
    assert_exact_response(&initial, &recovered.evaluate_tool_call_blocking(&request)?);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(store.operation(), operation);
    assert_eq!(store.budget.get_budget_hold(hold_id.as_str())?, Some(hold));
    assert_eq!(
        store.budget.get_usage(&request.capability.id, 0)?,
        Some(usage)
    );
    Ok(())
}

#[test]
fn compensated_budget_denial_replays_original_signed_bytes() -> TestResult {
    let mut grant = make_grant("durable-server", "mutate");
    grant.max_invocations = Some(1);
    let (kernel, request, store, calls) =
        durable_admission_fixture_with_grants("retained-budget-refusal", vec![grant]);
    assert!(kernel.with_budget_store(|budget| {
        Ok(budget.try_increment(&request.capability.id, 0, Some(1))?)
    })?);
    let initial = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(initial.verdict, Verdict::Deny);
    assert_eq!(
        initial.reason,
        Some(KernelError::BudgetExhausted(request.capability.id.clone()).to_string())
    );
    assert!(initial.receipt.verify_signature()?);
    let terminal = store.operation();
    assert_eq!(
        terminal.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(terminal.dispatch_commit().is_none());
    assert_exact_response(&initial, &kernel.evaluate_tool_call_blocking(&request)?);
    let recovered = restarted(&kernel, &store, &calls);
    assert_exact_response(&initial, &recovered.evaluate_tool_call_blocking(&request)?);
    assert_eq!(store.operation(), terminal);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(kernel.receipt_log().len(), 1);
    Ok(())
}

#[test]
fn refusal_replay_projects_the_generic_denied_code() -> TestResult {
    let mut grant = make_grant("durable-server", "mutate");
    grant.max_invocations = Some(1);
    let (kernel, request, store, calls) =
        durable_admission_fixture_with_grants("replayed-refusal-code", vec![grant]);
    assert!(kernel.with_budget_store(|budget| {
        Ok(budget.try_increment(&request.capability.id, 0, Some(1))?)
    })?);
    let initial = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(
        initial.denial_code,
        Some(crate::ClientDenialCode::BudgetExhausted)
    );
    let replay = kernel.evaluate_tool_call_blocking(&request)?;
    assert_exact_response(&initial, &replay);
    assert_eq!(replay.denial_code, Some(crate::ClientDenialCode::Denied));
    let recovered = restarted(&kernel, &store, &calls);
    let restarted_replay = recovered.evaluate_tool_call_blocking(&request)?;
    assert_exact_response(&initial, &restarted_replay);
    assert_eq!(
        restarted_replay.denial_code,
        Some(crate::ClientDenialCode::Denied)
    );
    Ok(())
}

#[test]
fn refused_delivery_mirror_failure_retains_the_committed_receipt() -> TestResult {
    let (mut kernel, request, store, calls) = durable_admission_fixture("refusal-mirror-failure");
    install_refusing_server(&mut kernel, &store, &calls);
    let mirror = AdmissionReceiptProjectionStore::default();
    mirror.fail_next_append();
    kernel.set_receipt_store(Box::new(mirror.clone()))?;
    let error = kernel
        .evaluate_tool_call_blocking(&request)
        .expect_err("mirror failure refuses delivery");
    let terminal = assert_original_unknown_incident(
        &store,
        &request,
        &unknown_after("transport_return", "CHIO-KERNEL-TOOL-SERVER"),
    );
    let original = store
        .state
        .lock()
        .map_err(|_| "state lock")?
        .receipt
        .clone()
        .ok_or("committed refusal")?;
    assert!(
        matches!(
            &error,
            KernelError::DeliveryFailedAfterReceipt {
                receipt_id,
                step: crate::kernel::ReceiptDeliveryStep::Trace,
                source,
            } if receipt_id == &original.id && matches!(
                source.as_ref(),
                KernelError::ReceiptPersistence(ReceiptStoreError::Conflict(reason))
                    if reason == "injected admission receipt projection failure"
            )
        ),
        "{error:?}"
    );
    assert!(mirror.receipt().is_none());
    let replay = kernel.evaluate_tool_call_blocking(&request)?;
    assert_same_receipt(&original, &replay.receipt);
    assert_same_receipt(&original, &mirror.receipt().ok_or("repaired mirror")?);
    assert_eq!(mirror.successful_appends(), 1);
    assert_eq!(store.operation(), terminal);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_exact_response(&replay, &kernel.evaluate_tool_call_blocking(&request)?);
    assert_eq!(mirror.successful_appends(), 1);
    Ok(())
}

#[test]
fn terminal_refusal_replay_requires_its_canonical_receipt() -> TestResult {
    let (mut kernel, request, store, calls) = durable_admission_fixture("refusal-receipt-absent");
    install_refusing_server(&mut kernel, &store, &calls);
    let initial = kernel.evaluate_tool_call_blocking(&request)?;
    let terminal = store.operation();
    store.state.lock().map_err(|_| "state lock")?.receipt = None;
    let error = kernel
        .evaluate_tool_call_blocking(&request)
        .expect_err("absent receipt refuses replay");
    assert!(
        matches!(error, KernelError::DurableAdmission(ref reason)
        if reason == "terminal refusal receipt is absent"),
        "{error:?}"
    );
    assert_eq!(store.operation(), terminal);
    assert_eq!(kernel.receipt_log().len(), 1);
    assert_same_receipt(
        &initial.receipt,
        kernel.receipt_log().get(0).ok_or("original receipt")?,
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

fn committed_operation(
    kernel: &ChioKernel,
    request: &ToolCallRequest,
) -> Result<AdmissionOperationV1, Box<dyn std::error::Error>> {
    let matching = resolve_required_matching_grants(
        &request.capability,
        &request.tool_name,
        &request.server_id,
        &request.arguments,
        request.model_metadata.as_ref(),
    )?;
    let now = current_unix_timestamp_ms();
    let mut admission = kernel
        .begin_durable_tool_admission(request, &matching, now)
        .map_err(|failure| *failure.error)?
        .ok_or_else(|| KernelError::Internal("test requires durable admission".into()))?;
    let (_, mut mutation) = kernel
        .check_and_increment_budget(
            request,
            &request.capability,
            &matching,
            false,
            Some(&mut admission),
            now,
        )?
        .into_authorized()?;
    kernel.mark_durable_capture_pending(&mut admission, now)?;
    kernel.freeze_and_commit_durable_dispatch(
        &mut admission,
        &request.capability,
        &mut mutation,
        DurableToolReturnContextInput {
            request,
            matched_grant_index: 0,
            extra_receipt_metadata: None,
            pre_invocation_guard_output: &crate::kernel::PreInvocationGuardOutput::default(),
            verified_payee_binding: None,
            verified_purchase: None,
            verified_recovery: None,
            trusted_now_unix_ms: now,
            security_invocation_context: None,
            security_release_required: false,
        },
    )?;
    Ok(admission.operation().clone())
}

#[test]
fn unknown_projection_requires_the_original_retained_request() -> TestResult {
    let (kernel, request, store, calls) = durable_admission_fixture("refusal-request-absent");
    let operation = committed_operation(&kernel, &request)?;
    store
        .state
        .lock()
        .map_err(|_| "state lock")?
        .retained_request = None;
    let error = kernel
        .terminalize_dispatch_committed_admission(
            &operation,
            current_unix_timestamp_ms(),
            None,
            compensation_response(),
        )
        .expect_err("absent original request prevents terminal projection");
    assert!(
        matches!(error, KernelError::DurableAdmission(ref reason)
        if reason == "terminal refusal original request is absent"),
        "{error:?}"
    );
    assert_eq!(store.operation(), operation);
    assert!(store
        .state
        .lock()
        .map_err(|_| "state lock")?
        .receipt
        .is_none());
    assert!(kernel.receipt_log().is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn unknown_projection_refuses_a_replacement_signer() -> TestResult {
    use crate::admission_operation::{AdmissionRecoveryError, AdmissionRecoveryFailureKind};
    let (mut kernel, request, store, calls) = durable_admission_fixture("refusal-original-signer");
    let operation = committed_operation(&kernel, &request)?;
    let original_key = kernel.receipt_signing_public_key().unwrap();
    kernel.signing_authority =
        crate::kernel::signing_authority::KernelSigningAuthority::classical(&Keypair::generate());
    let error = kernel
        .terminalize_dispatch_committed_admission(
            &operation,
            current_unix_timestamp_ms(),
            None,
            compensation_response(),
        )
        .expect_err("replacement signer cannot own the terminal");
    assert!(
        matches!(error, KernelError::AdmissionRecovery(ref failure)
        if matches!(failure.as_ref(), AdmissionRecoveryError::Item {
            kind: AdmissionRecoveryFailureKind::ContractChanged,
            detail,
        } if detail == "original receipt signing authority is unavailable")),
        "{error:?}"
    );
    assert_eq!(store.operation(), operation);
    assert!(store
        .state
        .lock()
        .map_err(|_| "state lock")?
        .receipt
        .is_none());
    assert!(kernel.receipt_log().is_empty());
    kernel.signing_authority =
        crate::kernel::signing_authority::KernelSigningAuthority::classical(&kernel.config.keypair);
    let recovered = kernel.terminalize_dispatch_committed_admission(
        &operation,
        current_unix_timestamp_ms(),
        None,
        compensation_response(),
    )?;
    assert_eq!(recovered.verdict, Verdict::Deny);
    assert_eq!(recovered.receipt.kernel_key, original_key);
    assert!(recovered.receipt.verify_signature()?);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::OutcomeUnknownAfterDispatch
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn compensation_refuses_financial_metadata_outside_the_original_grants() -> TestResult {
    for (grant_index, expected) in [
        (
            serde_json::json!("0"),
            "terminal refusal financial grant is invalid",
        ),
        (
            serde_json::json!(1),
            "terminal refusal financial grant is not retained",
        ),
    ] {
        let (kernel, request, store, calls) =
            durable_admission_fixture("compensation-financial-grant");
        let matching = resolve_required_matching_grants(
            &request.capability,
            &request.tool_name,
            &request.server_id,
            &request.arguments,
            request.model_metadata.as_ref(),
        )?;
        let now = current_unix_timestamp_ms();
        let admission = kernel
            .begin_durable_tool_admission(&request, &matching, now)
            .map_err(|failure| *failure.error)?
            .ok_or("missing admission")?;
        let mut refusal = compensation_response();
        refusal.metadata = Some(serde_json::json!({
            "financial": {"grant_index": grant_index}
        }));
        let error = kernel
            .compensate_durable_admission_before_dispatch(
                admission.operation(),
                serde_json::json!({"authority": "original-admission-owner"}),
                now,
                None,
                refusal,
            )
            .expect_err("financial attribution must bind an original grant");
        assert!(
            matches!(error, KernelError::DurableAdmission(ref reason) if reason == expected),
            "{error:?}"
        );
        assert_eq!(&store.operation(), admission.operation());
        assert!(store
            .state
            .lock()
            .map_err(|_| "state lock")?
            .receipt
            .is_none());
        assert!(kernel.receipt_log().is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
    Ok(())
}
