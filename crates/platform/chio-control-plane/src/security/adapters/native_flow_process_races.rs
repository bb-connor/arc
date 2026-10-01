// Deterministic in-flight races over the original native owner.
use super::*;
use chio_kernel::RevocationStore;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};

#[derive(Clone, Copy)]
enum Pause {
    BeforeCapture,
    AfterCapture,
}
struct PauseHook {
    resolver: NativeFlowResolver,
    pause: Pause,
    entered: SyncSender<()>,
    resume: Mutex<Receiver<()>>,
}
impl PauseHook {
    fn rendezvous(&self) -> Result<(), KernelError> {
        self.entered
            .send(())
            .map_err(|_| KernelError::Internal("capture observer left".into()))?;
        self.resume
            .lock()
            .map_err(|_| KernelError::Internal("capture barrier poisoned".into()))?
            .recv_timeout(Duration::from_secs(30))
            .map_err(|_| KernelError::Internal("capture observer timed out".into()))
    }
}
impl SecurityPreDispatchHook for PauseHook {
    fn name(&self) -> &str {
        "native-capture-rendezvous"
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
        self.resolver.prepare_native_output(context, authority)
    }
    fn commit_native_dispatch(
        &self,
        authority: &mut chio_kernel::NativeSecurityDispatchCaptureAuthority<'_, '_>,
    ) -> Result<(), KernelError> {
        if matches!(self.pause, Pause::BeforeCapture) {
            self.rendezvous()?;
        }
        self.resolver.commit_native_dispatch(authority)?;
        if matches!(self.pause, Pause::AfterCapture) {
            self.rendezvous()?;
        }
        Ok(())
    }
    fn commit(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        Err(KernelError::Internal(
            "native race reached legacy dispatch".into(),
        ))
    }
}

fn race(pause: Pause, revoke: bool) -> TestResult {
    let mut fixture = super::super::super::public_fixture()?;
    let (entered, observed) = sync_channel(1);
    let (resume, waiting) = sync_channel(1);
    fixture
        .kernel
        .set_security_pre_dispatch_hook(Arc::new(PauseHook {
            resolver: resolver(fixture.binding.clone(), None)?,
            pause,
            entered,
            resume: Mutex::new(waiting),
        }));
    let kernel = Arc::new(fixture.kernel);
    let worker = std::thread::spawn({
        let kernel = kernel.clone();
        let request = fixture.request.clone();
        let context = fixture.context.clone();
        move || kernel.evaluate_tool_call_blocking_with_security_context(&request, &context)
    });
    observed.recv_timeout(Duration::from_secs(30))?;
    if revoke {
        fixture
            .authority
            .revocation_store()
            .revoke(&fixture.request.capability.id)?;
    } else {
        assert_eq!(
            kernel.reconcile_recoverable_admissions()?,
            0,
            "recovery must skip the live evaluation"
        );
        let duplicate = kernel
            .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.context);
        if let Ok(response) = duplicate {
            assert_eq!(response.verdict, Verdict::Deny);
            assert!(response.output.is_none());
            assert!(
                response
                    .reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains("live evaluation or recovery owner")),
                "{:?}",
                response.reason
            );
        }
    }
    resume.send(())?;
    let result = worker.join().map_err(|_| "native worker panicked")?;
    let store = fixture.authority.admission_operation_store();
    let (operation, _) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request", &fixture.request.request_id)?,
            &fixture.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("original race operation")?;
    let usage = fixture
        .authority
        .budget_store()
        .get_invocation_quota_usage(&BudgetQuotaKey::grant(&fixture.request.capability.id, 0))?
        .ok_or("race quota")?;
    if revoke {
        if let Ok(response) = result {
            assert_eq!(response.verdict, Verdict::Deny);
            assert!(response.output.is_none());
        }
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
        let captured = matches!(pause, Pause::AfterCapture);
        assert_eq!(operation.dispatch_commit().is_some(), captured);
        assert_eq!(
            (usage.reserved_invocations, usage.captured_invocations),
            if captured { (0, 1) } else { (1, 0) }
        );
        if !captured {
            // The failed callback retains uncertainty and its unexpired lease.
            // A replacement serving owner must inspect and compensate the same
            // physical operation, not infer a refund from the callback error.
            let old_fence = fixture.authority.mutation_fence();
            drop(store);
            drop(kernel);
            drop(fixture.authority);
            let authority = SqliteAuthorityStore::open_serving(
                fixture._directory.path().join("admission.db"),
                fixture._directory.path().join("locks"),
            )?;
            assert!(authority.mutation_fence().owner_epoch > old_fence.owner_epoch);
            let (mut recovered, invocations) =
                open_kernel(fixture._directory.path(), &authority, &fixture.signer)?;
            recovered.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
            recovered.set_security_pre_dispatch_hook(Arc::new(resolver(fixture.binding, None)?));
            recovered.reconcile_durable_admission_startup()?;
            let (current, _) = authority
                .admission_operation_store()
                .load_retained_tool_request(
                    operation.binding().operation_id(),
                    &authority.mutation_fence(),
                    now_ms()?,
                )?
                .ok_or("original revoked operation")?;
            assert_eq!(
                current.state(),
                AdmissionOperationState::CompensatedBeforeDispatch
            );
            assert_eq!(current.binding(), operation.binding());
            let usage = authority
                .budget_store()
                .get_invocation_quota_usage(&BudgetQuotaKey::grant(
                    &fixture.request.capability.id,
                    0,
                ))?
                .ok_or("reconciled quota")?;
            assert_eq!(
                (usage.reserved_invocations, usage.captured_invocations),
                (0, 0)
            );
            let response = recovered.evaluate_tool_call_blocking_with_security_context(
                &fixture.request,
                &fixture.context,
            )?;
            assert_eq!(response.verdict, Verdict::Deny);
            assert!(response.output.is_none());
            assert_eq!(invocations.load(Ordering::SeqCst), 0);
        }
    } else {
        let response = result?;
        assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
        assert!(response.receipt.verify_signature()?);
        assert_eq!(operation.state(), AdmissionOperationState::Completed);
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
        assert_eq!(
            (usage.reserved_invocations, usage.captured_invocations),
            (0, 1)
        );
        let replay = kernel.evaluate_tool_call_blocking_with_security_context(
            &fixture.request,
            &fixture.context,
        )?;
        assert_eq!(
            chio_core::canonical_json_bytes(&response.receipt)?,
            chio_core::canonical_json_bytes(&replay.receipt)?
        );
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    }
    Ok(())
}

#[test]
fn revocation_wins_before_native_capture() -> TestResult {
    race(Pause::BeforeCapture, true)
}
#[test]
fn revocation_after_native_capture_fences_connector_handoff() -> TestResult {
    race(Pause::AfterCapture, true)
}
#[test]
fn duplicate_native_start_cannot_steal_the_live_operation() -> TestResult {
    race(Pause::BeforeCapture, false)
}
