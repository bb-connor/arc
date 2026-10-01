// Production hook and connector, without a capture checkpoint or fabricated owner.
use super::*;
use chio_kernel::tool_outcome::ToolOutcomeStore;

#[test]
fn native_captured_lifecycle_invokes_once_and_replays_the_released_receipt() -> TestResult {
    for egress in [false, true] {
        let mut fixture = super::super::public_fixture()?;
        let resolver = NativeFlowResolver::new(
            fixture.binding.clone(),
            super::super::registry(egress, InformationLabel::bottom())?,
            Arc::new(CountingEmptyClassifier::new()),
            Arc::new(Clock::default()),
            flow_config(),
        )?
        .with_captured_lifecycle();
        fixture
            .kernel
            .set_security_pre_dispatch_hook(Arc::new(resolver));
        let response = fixture
            .kernel
            .evaluate_tool_call_blocking_with_security_context(
                &fixture.request,
                &fixture.context,
            )?;
        assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
        assert!(response.output.is_some());
        assert!(
            matches!(&response.output, Some(chio_kernel::ToolCallOutput::Value(value)) if value == &fixture.request.arguments)
        );
        assert!(response.receipt.verify_signature()?);
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
        let replay = fixture
            .kernel
            .evaluate_tool_call_blocking_with_security_context(
                &fixture.request,
                &fixture.context,
            )?;
        assert_eq!(
            chio_core::canonical::canonical_json_bytes(&replay.receipt)?,
            chio_core::canonical::canonical_json_bytes(&response.receipt)?,
        );
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
        let store = fixture.authority.admission_operation_store();
        let fence = fixture.authority.mutation_fence();
        let (operation, _) = store
            .load_unambiguous_retained_tool_request(
                &AdmissionIdentifier::try_new("request", &fixture.request.request_id)?,
                &fence,
                now_ms()?,
            )?
            .ok_or("original admission")?;
        assert_eq!(operation.state(), AdmissionOperationState::Completed);
        assert!(operation.native_dispatch_ledger_digest().is_some());
        assert!(store
            .load_native_security_output_join(
                operation.binding().operation_id(),
                &fence,
                now_ms()?,
            )?
            .ok_or("original output")?
            .1
            .is_some());
        assert!(fixture
            .authority
            .tool_outcome_store()
            .lookup_security_release(operation.binding().operation_id(),)?
            .is_some());
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum Fault {
    OmitCapture,
    FailAfterCapture,
    PanicAfterCapture,
    SuppressRepeatedCapture,
    ExpireAfterCapture,
    RefuseOutput,
    RevokeAfterOutputJoin,
    StopAfterOutputJoin,
}

struct FaultHook {
    resolver: NativeFlowResolver,
    fault: Fault,
    entered: AtomicUsize,
    captured: AtomicUsize,
    revocations: Arc<dyn chio_kernel::RevocationStore>,
    kernel: std::sync::OnceLock<std::sync::Weak<ChioKernel>>,
}

impl SecurityPreDispatchHook for FaultHook {
    fn name(&self) -> &str {
        "native-lifecycle-fault"
    }
    fn supports_native_dispatch(&self) -> bool {
        true
    }
    fn native_authority_binding(
        &self,
    ) -> Result<Option<NativeSecurityAuthorityBindingV1>, KernelError> {
        self.resolver.native_authority_binding()
    }
    fn prepare_native_admission(
        &self,
        context: &NativeSecurityAdmissionContext<'_>,
        authority: &NativeSecurityFlowJoinAuthority<'_>,
    ) -> Result<(), KernelError> {
        self.resolver.prepare_native_admission(context, authority)
    }
    fn prepare_native_output(
        &self,
        context: &chio_kernel::tool_outcome::DurableSecurityReleaseContext<'_>,
        authority: &chio_kernel::NativeSecurityOutputJoinAuthority<'_>,
    ) -> Result<(), KernelError> {
        if matches!(self.fault, Fault::RefuseOutput) {
            return Err(KernelError::GuardDenied("test output refusal".into()));
        }
        self.resolver.prepare_native_output(context, authority)?;
        if matches!(self.fault, Fault::RevokeAfterOutputJoin) {
            let request: ToolCallRequest =
                serde_json::from_str(context.request_canonical_json())
                    .map_err(|error| KernelError::Internal(error.to_string()))?;
            self.revocations
                .revoke(&request.capability.id)
                .map_err(|error| KernelError::Internal(error.to_string()))?;
        }
        if matches!(self.fault, Fault::StopAfterOutputJoin) {
            self.kernel
                .get()
                .and_then(std::sync::Weak::upgrade)
                .ok_or_else(|| KernelError::Internal("test kernel is absent".into()))?
                .emergency_stop("test stop after native output join")?;
        }
        Ok(())
    }
    fn commit(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        panic!("native lifecycle must not enter legacy dispatch")
    }
    fn commit_native_dispatch(
        &self,
        authority: &mut chio_kernel::NativeSecurityDispatchCaptureAuthority<'_, '_>,
    ) -> Result<(), KernelError> {
        self.entered.fetch_add(1, Ordering::SeqCst);
        if matches!(self.fault, Fault::OmitCapture) {
            return Ok(());
        }
        let second = if matches!(self.fault, Fault::SuppressRepeatedCapture) {
            Some(authority.prepare_egress()?)
        } else {
            None
        };
        let (custody, _) = self
            .resolver
            .prepare_dispatch(authority.prepare_egress()?)
            .and_then(|prepared| prepared.capture_invocation(authority))
            .map_err(|error| KernelError::GuardDenied(error.to_string()))?;
        self.captured.fetch_add(1, Ordering::SeqCst);
        match self.fault {
            Fault::FailAfterCapture => Err(KernelError::GuardDenied("test after capture".into())),
            Fault::PanicAfterCapture => panic!("test panic after capture"),
            Fault::SuppressRepeatedCapture => {
                let second = second
                    .ok_or_else(|| KernelError::Internal("second preparation absent".into()))?;
                assert!(authority
                    .capture(
                        second,
                        custody
                            .dispatch_ledger()
                            .ok_or_else(|| KernelError::Internal("ledger absent".into()))?,
                        custody.policy_evidence().canonical_bytes()
                    )
                    .is_err());
                Ok(())
            }
            Fault::ExpireAfterCapture => {
                let policy: serde_json::Value =
                    serde_json::from_slice(custody.policy_evidence().canonical_bytes())
                        .map_err(|error| KernelError::Internal(error.to_string()))?;
                let deadline = policy
                    .pointer("/inputs/valid_until_unix_ms")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or_else(|| KernelError::Internal("policy deadline absent".into()))?;
                let now = now_ms().map_err(|_| KernelError::Internal("clock failed".into()))?;
                assert!(now < deadline, "capture must precede the injected expiry");
                std::thread::sleep(std::time::Duration::from_millis(deadline - now + 1));
                Ok(())
            }
            Fault::RefuseOutput
            | Fault::RevokeAfterOutputJoin
            | Fault::StopAfterOutputJoin
            | Fault::OmitCapture => Ok(()),
        }
    }
}

fn fault_case(fault: Fault) -> TestResult {
    let mut fixture = super::super::public_fixture()?;
    let hook = Arc::new(FaultHook {
        resolver: NativeFlowResolver::new(
            fixture.binding.clone(),
            super::super::registry(false, InformationLabel::bottom())?,
            Arc::new(CountingEmptyClassifier::new()),
            Arc::new(Clock::default()),
            flow_config(),
        )?
        .with_captured_lifecycle(),
        fault,
        entered: AtomicUsize::new(0),
        captured: AtomicUsize::new(0),
        revocations: Arc::new(fixture.authority.revocation_store()),
        kernel: std::sync::OnceLock::new(),
    });
    fixture.kernel.set_security_pre_dispatch_hook(hook.clone());
    let kernel = Arc::new(fixture.kernel);
    hook.kernel
        .set(Arc::downgrade(&kernel))
        .map_err(|_| "test kernel was already set")?;
    let result = kernel
        .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.context);
    assert_eq!(
        hook.entered.load(Ordering::SeqCst),
        1,
        "{fault:?}: {result:?}"
    );
    let expected_capture = !matches!(fault, Fault::OmitCapture);
    assert_eq!(
        hook.captured.load(Ordering::SeqCst),
        usize::from(expected_capture),
        "{fault:?}: {result:?}"
    );
    let joined_before_denial = matches!(
        fault,
        Fault::RevokeAfterOutputJoin | Fault::StopAfterOutputJoin
    );
    let after_effect = matches!(fault, Fault::RefuseOutput) || joined_before_denial;
    if matches!(fault, Fault::RevokeAfterOutputJoin) {
        assert!(hook
            .revocations
            .is_revoked(&fixture.request.capability.id)?);
    }
    if matches!(fault, Fault::StopAfterOutputJoin) {
        assert!(kernel.is_emergency_stopped());
    }
    if after_effect {
        assert!(
            matches!(
                result,
                Err(KernelError::SecurityDispatchOutcomeRecoveryRequired(_))
            ),
            "{result:?}"
        );
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    } else {
        let denied = result?;
        assert_eq!(
            denied.verdict,
            Verdict::Deny,
            "{fault:?}: {:?}",
            denied.reason
        );
        assert!(denied.output.is_none());
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    }
    let store = fixture.authority.admission_operation_store();
    let fence = fixture.authority.mutation_fence();
    let (operation, _) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request", &fixture.request.request_id)?,
            &fence,
            now_ms()?,
        )?
        .ok_or("original fault operation")?;
    assert_ne!(operation.state(), AdmissionOperationState::Completed);
    if after_effect {
        assert_eq!(operation.state(), AdmissionOperationState::Finalizing);
    }
    assert_eq!(operation.dispatch_commit().is_some(), expected_capture);
    if joined_before_denial {
        assert!(store
            .load_native_security_output_join(
                operation.binding().operation_id(),
                &fence,
                now_ms()?,
            )?
            .ok_or("original output join")?
            .1
            .is_some());
    }
    let usage = fixture
        .authority
        .budget_store()
        .get_invocation_quota_usage(&BudgetQuotaKey::grant(&fixture.request.capability.id, 0))?
        .ok_or("original quota")?;
    assert_eq!(usage.captured_invocations, u32::from(expected_capture));
    assert_eq!(usage.reserved_invocations, 0);
    assert!(fixture
        .authority
        .tool_outcome_store()
        .lookup_security_release(operation.binding().operation_id())?
        .is_none());
    Ok(())
}

#[test]
fn native_captured_lifecycle_requires_one_successful_live_handoff() -> TestResult {
    for fault in [
        Fault::OmitCapture,
        Fault::FailAfterCapture,
        Fault::PanicAfterCapture,
        Fault::SuppressRepeatedCapture,
    ] {
        fault_case(fault)?;
    }
    Ok(())
}

#[test]
fn native_captured_lifecycle_rejects_real_expiry_after_capture() -> TestResult {
    fault_case(Fault::ExpireAfterCapture)
}

#[test]
fn native_captured_lifecycle_cannot_release_without_output_preparation() -> TestResult {
    fault_case(Fault::RefuseOutput)
}

#[test]
fn native_captured_lifecycle_rechecks_revocation_and_stop_after_output_join() -> TestResult {
    fault_case(Fault::RevokeAfterOutputJoin)?;
    fault_case(Fault::StopAfterOutputJoin)
}
