// Strict nonce preflight through the production native resolver and authority.
use super::*;
use chio_kernel::execution_nonce::{ExecutionNonceConfig, ExecutionNonceStore};

pub(super) mod execution {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/security/adapters/native_flow_nonce_execution_tests.rs"
    ));
}

pub(super) struct NoLegacyNonce(pub(super) Arc<AtomicUsize>);

impl ExecutionNonceStore for NoLegacyNonce {
    fn reserve(&self, _: &str) -> Result<bool, KernelError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(KernelError::Internal("legacy nonce store reached".into()))
    }
}

#[test]
fn native_nonce_preflight_issues_without_dispatch_or_legacy_nonce_custody() -> TestResult {
    let mut fixture = super::super::public_fixture()?;
    let legacy = Arc::new(AtomicUsize::new(0));
    fixture.kernel.set_execution_nonce_store(
        ExecutionNonceConfig {
            require_nonce: true,
            ..ExecutionNonceConfig::default()
        },
        Box::new(NoLegacyNonce(legacy.clone())),
    );
    let resolver = NativeFlowResolver::new(
        fixture.binding.clone(),
        super::super::registry(false, InformationLabel::bottom())?,
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
        .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.context)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert!(response.execution_nonce.is_some());
    assert!(response.output.is_none());
    assert!(response.receipt.verify_signature()?);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    assert_eq!(legacy.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.budget_observer()()?, 0);
    let store = fixture.authority.admission_operation_store();
    let fence = fixture.authority.mutation_fence();
    let (operation, _) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request", &fixture.request.request_id)?,
            &fence,
            now_ms()?,
        )?
        .ok_or("original nonce admission")?;
    assert_eq!(operation.state(), AdmissionOperationState::Prepared);
    assert!(operation.execution_nonce_issuance_digest().is_some());
    assert!(operation.execution_nonce_preflight_digest().is_some());
    assert!(operation.native_dispatch_ledger_digest().is_none());
    assert!(store
        .load_native_security_nonce_preflight_join(
            operation.binding().operation_id(),
            &fence,
            now_ms()?,
        )?
        .ok_or("preflight readback")?
        .1
        .is_some());
    assert!(store
        .load_native_security_input_join(operation.binding().operation_id(), &fence, now_ms()?,)?
        .ok_or("dispatch readback")?
        .1
        .is_none());
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum PreflightJoinFault {
    Skip,
    FailAfter,
    PanicAfter,
    SuppressSecond,
}

struct PreflightJoinFaultHook {
    resolver: NativeFlowResolver,
    fault: PreflightJoinFault,
}

impl SecurityPreDispatchHook for PreflightJoinFaultHook {
    fn name(&self) -> &str {
        "native-nonce-preflight-fault"
    }
    fn native_authority_binding(
        &self,
    ) -> Result<Option<NativeSecurityAuthorityBindingV1>, KernelError> {
        self.resolver.native_authority_binding()
    }
    fn prepare_native_nonce_preflight(
        &self,
        context: &NativeSecurityAdmissionContext<'_>,
        authority: &chio_kernel::NativeSecurityNoncePreflightJoinAuthority<'_>,
    ) -> Result<(), KernelError> {
        if matches!(self.fault, PreflightJoinFault::Skip) {
            return Ok(());
        }
        self.resolver
            .prepare_native_nonce_preflight(context, authority)?;
        match self.fault {
            PreflightJoinFault::FailAfter => {
                Err(KernelError::GuardDenied("preflight test refusal".into()))
            }
            PreflightJoinFault::PanicAfter => panic!("preflight test panic"),
            PreflightJoinFault::SuppressSecond => {
                assert!(authority.join_input(InformationLabel::bottom()).is_err());
                Ok(())
            }
            PreflightJoinFault::Skip => unreachable!(),
        }
    }
    fn commit(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        panic!("preflight must not enter legacy dispatch");
    }
}

#[test]
fn native_nonce_preflight_callback_faults_deny_issuance_but_preserve_committed_taint() -> TestResult
{
    for fault in [
        PreflightJoinFault::Skip,
        PreflightJoinFault::FailAfter,
        PreflightJoinFault::PanicAfter,
        PreflightJoinFault::SuppressSecond,
    ] {
        let mut fixture = super::super::public_fixture()?;
        let legacy = Arc::new(AtomicUsize::new(0));
        fixture.kernel.set_execution_nonce_store(
            ExecutionNonceConfig {
                require_nonce: true,
                ..ExecutionNonceConfig::default()
            },
            Box::new(NoLegacyNonce(legacy.clone())),
        );
        let resolver = NativeFlowResolver::new(
            fixture.binding.clone(),
            super::super::registry(false, InformationLabel::bottom())?,
            Arc::new(CountingEmptyClassifier::new()),
            Arc::new(Clock::default()),
            flow_config(),
        )?;
        fixture
            .kernel
            .set_security_pre_dispatch_hook(Arc::new(PreflightJoinFaultHook { resolver, fault }));
        let response = fixture
            .kernel
            .evaluate_tool_call_blocking_with_security_context(
                &fixture.request,
                &fixture.context,
            )?;
        assert_eq!(response.verdict, Verdict::Deny, "{fault:?}");
        assert!(response.execution_nonce.is_none());
        assert!(response.output.is_none());
        assert!(response.receipt.verify_signature()?);
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
        assert_eq!(legacy.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.budget_observer()()?, 0);
        let store = fixture.authority.admission_operation_store();
        let fence = fixture.authority.mutation_fence();
        let (operation, _) = store
            .load_unambiguous_retained_tool_request(
                &AdmissionIdentifier::try_new("request", &fixture.request.request_id)?,
                &fence,
                now_ms()?,
            )?
            .ok_or("original denied admission")?;
        assert!(operation.execution_nonce_issuance_digest().is_none());
        assert!(operation.native_dispatch_ledger_digest().is_none());
        let (_, preflight) = store
            .load_native_security_nonce_preflight_join(
                operation.binding().operation_id(),
                &fence,
                now_ms()?,
            )?
            .ok_or("denied preflight readback")?;
        assert_eq!(
            preflight.is_some(),
            !matches!(fault, PreflightJoinFault::Skip),
            "{fault:?}"
        );
        assert!(
            store
                .load_native_security_input_join(
                    operation.binding().operation_id(),
                    &fence,
                    now_ms()?,
                )?
                .ok_or("dispatch readback")?
                .1
                .is_none()
        );
    }
    Ok(())
}
