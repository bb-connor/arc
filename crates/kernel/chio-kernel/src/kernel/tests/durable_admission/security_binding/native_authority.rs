//! Original native selection is checked on actual begin, dispatch and recovery.
use super::*;
use crate::admission_operation::{
    AdmissionDigest, AdmissionIdentifier, NativeSecurityAuthorityBindingV1,
};

#[path = "native_authority/codec.rs"]
mod codec;

fn binding(
    store: &str,
    authority: &str,
    source: &[u8],
) -> Result<NativeSecurityAuthorityBindingV1, Box<dyn std::error::Error>> {
    Ok(NativeSecurityAuthorityBindingV1::new(
        AdmissionIdentifier::try_new("store", store)?,
        AdmissionIdentifier::try_new("authority", authority)?,
        AdmissionDigest::try_new("initialization", sha256_hex(source))?,
    ))
}

struct Hook(std::sync::Mutex<Option<NativeSecurityAuthorityBindingV1>>);
impl Hook {
    fn select(&self, selected: Option<NativeSecurityAuthorityBindingV1>) {
        *self.0.lock().expect("test native selection") = selected;
    }
}
impl SecurityPreDispatchHook for Hook {
    fn name(&self) -> &str {
        "original-native-selection"
    }
    fn native_authority_binding(
        &self,
    ) -> Result<Option<NativeSecurityAuthorityBindingV1>, KernelError> {
        Ok(self.0.lock().expect("test native selection").clone())
    }
    fn prepare_native_admission(
        &self,
        _: &NativeSecurityAdmissionContext<'_>,
        authority: &NativeSecurityFlowJoinAuthority<'_>,
    ) -> Result<(), KernelError> {
        super::super::native_acquisition::join(authority).map(|_| ())
    }
    fn commit(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        Ok(None)
    }
}

/// Construct already-returned history through the internal storage primitives.
/// Live native dispatch is unsupported, so recovery fixtures must not invoke a
/// connector to create old records or install a test-only activation bypass.
fn historical_native_response(
    kernel: &ChioKernel,
    request: &ToolCallRequest,
    security_context: &SecurityInvocationContext,
) -> Result<ToolCallResponse, KernelError> {
    use crate::kernel::admission_coordinator::DispatchTransport;
    let now = current_unix_timestamp_ms();
    let matching = matching(request)?;
    let mut admission = kernel
        .begin_durable_tool_admission_for_transport(
            request,
            &matching,
            Some(security_context),
            now,
            DispatchTransport::KernelToolServer,
        )?
        .ok_or_else(|| KernelError::Internal("historical native admission missing".into()))?;
    kernel.run_native_admission_preparation(
        request,
        Some(security_context),
        Some(&admission),
        now,
    )?;
    let (_, mut budget) = kernel
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
    assert_eq!(
        kernel
            .run_security_pre_dispatch_hook(request, Some(security_context), Some(&admission))
            .err()
            .expect("historical fixture cannot enter live native dispatch")
            .reason,
        "native security dispatch lifecycle is unsupported"
    );
    // Only historical setup uses these lower-level storage methods directly.
    // Both production evaluate paths require the final gate above to succeed.
    let frozen = kernel
        .freeze_and_commit_durable_dispatch(
            &mut admission,
            &request.capability,
            &mut budget,
            DurableToolReturnContextInput {
                request,
                matched_grant_index: 0,
                extra_receipt_metadata: None,
                pre_invocation_guard_evidence: &[],
                verified_payee_binding: None,
                verified_purchase: None,
                verified_recovery: None,
                trusted_now_unix_ms: now,
                security_invocation_context: Some(security_context),
                security_release_required: false,
            },
        )
        .map_err(|error| KernelError::Internal(error.to_string()))?;
    let returned = kernel.record_durable_tool_return(
        &mut admission,
        DurableToolReturnInput {
            request,
            output: &ToolServerOutput::Value(serde_json::json!({"historical_native_output": true})),
            reported_cost: None,
            context: &frozen,
            elapsed: Duration::ZERO,
            trusted_now_unix_ms: current_unix_timestamp_ms(),
        },
    )?;
    kernel.finalize_durable_tool_return(&mut admission, request, &returned)
}

fn replay(nested: bool) -> TestResult {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("native-selection-replay");
    let selected = binding("native-store", "source", b"initialization")?;
    let hook = Arc::new(Hook(std::sync::Mutex::new(Some(selected.clone()))));
    kernel.set_security_pre_dispatch_hook(hook.clone());
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    let session = kernel.open_session(request.agent_id.clone(), vec![])?;
    kernel.activate_session(&session)?;
    let parent = make_operation_context(&session, "native-parent", &request.agent_id);
    kernel.begin_session_request(&parent, OperationKind::ToolCall, true)?;
    let mut original = serde_json::to_value(context(&request, 1)?)?;
    original["context"]["sessionId"] = serde_json::json!(session.as_str());
    let original: SecurityInvocationContext = serde_json::from_value(original)?;
    let parent = nested.then_some(&parent);
    let first = historical_native_response(&kernel, &request, &original)?;
    assert_eq!(first.verdict, Verdict::Allow, "{first:?}");
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let operation = store.operation();
    let retained = store
        .state
        .lock()
        .expect("test store")
        .retained_request
        .clone()
        .ok_or("native ordinary admission must retain original request")?;
    retained.validate_native_security_authority(&selected)?;
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(retained.canonical_bytes())?["schema"],
        "chio.retained-tool-admission-request.v4"
    );
    assert!(retained.authority_profile().is_some());
    for changed in [
        None,
        Some(binding("different-store", "source", b"initialization")?),
        Some(binding("native-store", "other", b"initialization")?),
        Some(binding("native-store", "source", b"replacement")?),
    ] {
        hook.select(changed);
        let denied = evaluate(&kernel, &request, Some(&original), parent)?;
        assert_eq!(denied.verdict, Verdict::Deny, "{denied:?}");
        assert!(denied.output.is_none());
        assert_eq!(store.operation(), operation);
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
    }
    hook.select(Some(selected));
    let recovered = evaluate(&kernel, &request, Some(&original), parent)?;
    assert_eq!(recovered.verdict, Verdict::Allow);
    assert_eq!(recovered.receipt.id, first.receipt.id);
    assert_eq!(recovered.output, first.output);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn ordinary_native_selection_cannot_change_on_terminal_replay() -> TestResult {
    replay(false)
}

#[test]
fn nested_native_selection_cannot_change_on_terminal_replay() -> TestResult {
    replay(true)
}

#[test]
fn native_selection_cannot_be_added_to_context_only_history() -> TestResult {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("native-selection-added");
    let hook = Arc::new(Hook(std::sync::Mutex::new(None)));
    kernel.set_security_pre_dispatch_hook(hook.clone());
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    let original = context(&request, 1)?;
    assert_eq!(
        evaluate(&kernel, &request, Some(&original), None)?.verdict,
        Verdict::Allow
    );
    let operation = store.operation();
    hook.select(Some(binding("native-store", "source", b"initialization")?));
    let denied = evaluate(&kernel, &request, Some(&original), None)?;
    assert_eq!(denied.verdict, Verdict::Deny);
    assert!(denied.output.is_none());
    assert_eq!(store.operation(), operation);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn native_raw_return_recovery_requires_original_selection() -> TestResult {
    let (mut kernel, request, store, invocations) = durable_admission_fixture("native-recovery");
    let selected = binding("native-store", "source", b"initialization")?;
    let hook = Arc::new(Hook(std::sync::Mutex::new(Some(selected.clone()))));
    kernel.set_security_pre_dispatch_hook(hook.clone());
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    store.fail_next_evaluation_begin();
    assert!(historical_native_response(&kernel, &request, &context(&request, 1)?).is_err());
    let operation = store.operation();
    assert_eq!(operation.state(), AdmissionOperationState::Finalizing);
    let _clock = crate::scope_fixed_runtime_for_current_thread(current_unix_timestamp() + 61, []);
    for changed in [
        None,
        Some(binding("native-store", "other", b"initialization")?),
    ] {
        hook.select(changed);
        assert!(matches!(
            kernel.reconcile_recoverable_admissions(),
            Err(KernelError::DurableAdmission(_))
        ));
        assert_eq!(store.operation(), operation);
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
    }
    hook.select(Some(selected));
    assert_eq!(kernel.reconcile_recoverable_admissions()?, 1);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn native_selection_rejects_missing_context_or_optional_enforcement_before_begin() -> TestResult {
    for missing_context in [false, true] {
        let (mut kernel, request, store, invocations) =
            durable_admission_fixture("native-requirements");
        kernel.set_security_pre_dispatch_hook(Arc::new(Hook(std::sync::Mutex::new(Some(
            binding("native-store", "source", b"initialization")?,
        )))));
        if missing_context {
            kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
        }
        let original = context(&request, 1)?;
        let result = evaluate(
            &kernel,
            &request,
            (!missing_context).then_some(&original),
            None,
        )?;
        assert_eq!(result.verdict, Verdict::Deny);
        assert!(result.output.is_none());
        assert!(result
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("invalid stable admission security binding")));
        assert!(!store.has_operation());
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[test]
fn native_selection_requires_retained_admission_outside_mode_coverage() -> TestResult {
    use crate::admission_operation::DurableAdmissionMode;
    use crate::kernel::admission_coordinator::DispatchTransport;

    for mode in [DurableAdmissionMode::Off, DurableAdmissionMode::Monetary] {
        let (mut kernel, request, store, invocations) =
            durable_admission_fixture("native-outside-mode");
        kernel.configure_durable_admission(mode, true)?;
        let selected = binding("native-store", "source", b"initialization")?;
        kernel.set_security_pre_dispatch_hook(Arc::new(Hook(std::sync::Mutex::new(Some(
            selected.clone(),
        )))));
        kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
        let original = context(&request, 1)?;
        let admission = kernel.begin_durable_tool_admission_for_transport(
            &request,
            &matching(&request)?,
            Some(&original),
            current_unix_timestamp_ms(),
            DispatchTransport::KernelToolServer,
        )?;
        assert!(
            admission.is_some(),
            "native selection bypassed durable admission in {mode:?}"
        );
        let retained = store
            .state
            .lock()
            .expect("test store")
            .retained_request
            .clone()
            .ok_or("original native request missing")?;
        retained.validate_native_security_authority(&selected)?;
        assert!(retained.authority_profile().is_some());
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[test]
fn native_selection_cannot_fall_back_without_a_durable_store() -> TestResult {
    use crate::admission_operation::DurableAdmissionMode;
    use crate::kernel::admission_coordinator::DispatchTransport;

    for mode in [
        DurableAdmissionMode::Off,
        DurableAdmissionMode::Monetary,
        DurableAdmissionMode::All,
    ] {
        let (mut kernel, request, store, invocations) =
            durable_admission_fixture("native-without-store");
        kernel.configure_durable_admission(mode, true)?;
        kernel.durable_admission_runtime = None;
        kernel.set_security_pre_dispatch_hook(Arc::new(Hook(std::sync::Mutex::new(Some(
            binding("native-store", "source", b"initialization")?,
        )))));
        kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
        let original = context(&request, 1)?;
        let result = kernel.begin_durable_tool_admission_for_transport(
            &request,
            &matching(&request)?,
            Some(&original),
            current_unix_timestamp_ms(),
            DispatchTransport::KernelToolServer,
        );
        assert!(
            result.is_err(),
            "native selection fell back without durable storage in {mode:?}"
        );
        assert!(!store.has_operation());
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[test]
fn native_selection_change_is_rejected_before_dispatch_capture() -> TestResult {
    use crate::kernel::admission_coordinator::DispatchTransport;
    let (mut kernel, request, store, invocations) = durable_admission_fixture("native-freeze");
    let hook = Arc::new(Hook(std::sync::Mutex::new(Some(binding(
        "native-store",
        "source",
        b"initialization",
    )?))));
    kernel.set_security_pre_dispatch_hook(hook.clone());
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    let now = current_unix_timestamp_ms();
    let matching = matching(&request)?;
    let original = context(&request, 1)?;
    let mut admission = kernel
        .begin_durable_tool_admission_for_transport(
            &request,
            &matching,
            Some(&original),
            now,
            DispatchTransport::KernelToolServer,
        )?
        .ok_or("durable admission")?;
    let (_, mut budget) = kernel
        .check_and_increment_budget(
            &request,
            &request.capability,
            &matching,
            false,
            Some(&mut admission),
            now,
        )?
        .into_authorized()?;
    kernel.mark_durable_capture_pending(&mut admission, now)?;
    let operation = store.operation();
    hook.select(Some(binding("native-store", "other", b"initialization")?));
    let result = kernel.freeze_and_commit_durable_dispatch(
        &mut admission,
        &request.capability,
        &mut budget,
        DurableToolReturnContextInput {
            request: &request,
            matched_grant_index: 0,
            extra_receipt_metadata: None,
            pre_invocation_guard_evidence: &[],
            verified_payee_binding: None,
            verified_purchase: None,
            verified_recovery: None,
            trusted_now_unix_ms: now,
            security_invocation_context: Some(&original),
            security_release_required: false,
        },
    );
    assert!(matches!(
        result,
        Err(DurableDispatchCommitError::RejectedBeforeCommit(_))
    ));
    assert_eq!(store.operation(), operation);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn native_selection_errors_and_panics_fail_closed_before_admission() -> TestResult {
    struct FailingHook(bool);
    impl SecurityPreDispatchHook for FailingHook {
        fn name(&self) -> &str {
            "unavailable-native-selection"
        }
        fn native_authority_binding(
            &self,
        ) -> Result<Option<NativeSecurityAuthorityBindingV1>, KernelError> {
            assert!(!self.0, "injected selection panic");
            Err(KernelError::DurableAdmission(
                "native selection unavailable".into(),
            ))
        }
        fn commit(
            &self,
            _: &SecurityPreDispatchContext<'_>,
        ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
            panic!("unavailable selection must not reach security commit")
        }
    }
    for panic in [false, true] {
        let (mut kernel, request, store, invocations) =
            durable_admission_fixture("native-unavailable");
        kernel.set_security_pre_dispatch_hook(Arc::new(FailingHook(panic)));
        kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
        let response = evaluate(&kernel, &request, Some(&context(&request, 1)?), None)?;
        assert_eq!(response.verdict, Verdict::Deny);
        assert!(response.output.is_none());
        let expected = if panic {
            "native authority selection panicked"
        } else {
            "native selection unavailable"
        };
        assert!(response
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains(expected)));
        assert!(!store.has_operation());
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
    }
    Ok(())
}
