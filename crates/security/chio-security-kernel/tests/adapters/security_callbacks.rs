//! The kernel contains extension faults at the final security boundary.
use super::*;
use chio_kernel::{
    KernelError, SecurityDispatchOutcome, SecurityDispatchOutcomeHandle,
    SecurityDispatchOutcomeRecorder,
};

#[derive(Clone, Copy)]
enum Fault {
    AcquirePanic,
    CommitPanic,
    RejectWithPanickingName,
    WrongRequest,
    WrongCommitment,
    RecordPanic,
    RecordError,
    FinalReleasePanic,
    FinalReleaseError,
    LifecycleDisposalPanic,
}

struct Hook {
    fault: Fault,
    outcomes: Arc<Mutex<Vec<SecurityDispatchOutcome>>>,
}

struct Recorder {
    fault: Fault,
    outcomes: Arc<Mutex<Vec<SecurityDispatchOutcome>>>,
}

impl SecurityDispatchOutcomeRecorder for Recorder {
    fn record(&mut self, outcome: SecurityDispatchOutcome) -> Result<(), KernelError> {
        self.outcomes.lock().test_unwrap().push(outcome);
        if matches!(self.fault, Fault::RecordPanic) {
            panic!("private security callback fault");
        }
        if matches!(self.fault, Fault::RecordError) {
            return Err(KernelError::GuardDenied("private outcome failure".into()));
        }
        Ok(())
    }
}

struct Permit(Fault);

impl SecurityRequestLifecyclePermit for Permit {
    fn ensure_final_release(self: Box<Self>) -> Result<(), KernelError> {
        if matches!(self.0, Fault::FinalReleaseError) {
            return Err(KernelError::GuardDenied("private release failure".into()));
        }
        panic!("private release callback fault");
    }
}

struct DropFaultPermit;

impl SecurityRequestLifecyclePermit for DropFaultPermit {
    fn ensure_final_release(self: Box<Self>) -> Result<(), KernelError> {
        Ok(())
    }
}

impl Drop for DropFaultPermit {
    fn drop(&mut self) {
        panic!("private lifecycle disposal fault");
    }
}

impl SecurityPreDispatchHook for Hook {
    fn name(&self) -> &str {
        panic!("a diagnostic must not invoke extension code");
    }

    fn acquire_request_lifecycle(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<Box<dyn SecurityRequestLifecyclePermit>>, KernelError> {
        if matches!(self.fault, Fault::AcquirePanic) {
            panic!("private lifecycle acquisition fault");
        }
        if matches!(self.fault, Fault::LifecycleDisposalPanic) {
            return Ok(Some(Box::new(DropFaultPermit)));
        }
        Ok(matches!(
            self.fault,
            Fault::FinalReleasePanic | Fault::FinalReleaseError
        )
        .then(|| Box::new(Permit(self.fault)) as Box<dyn SecurityRequestLifecyclePermit>))
    }

    fn commit(
        &self,
        context: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        if matches!(self.fault, Fault::CommitPanic) {
            panic!("private security commit fault");
        }
        if matches!(
            self.fault,
            Fault::RejectWithPanickingName | Fault::LifecycleDisposalPanic
        ) {
            return Err(KernelError::GuardDenied("private rejection".into()));
        }
        let mut request = context.request.clone();
        if matches!(self.fault, Fault::WrongRequest) {
            request.request_id = "another-security-request".into();
        }
        let commitment = if matches!(self.fault, Fault::WrongCommitment) {
            RecordId::new("dispatch-commitment:another").test_unwrap()
        } else {
            context.dispatch_commitment_id.clone()
        };
        Ok(Some(SecurityDispatchOutcomeHandle::new(
            &SecurityPreDispatchContext {
                request: &request,
                dispatch_commitment_id: &commitment,
                ..*context
            },
            Box::new(Recorder {
                fault: self.fault,
                outcomes: self.outcomes.clone(),
            }),
        )))
    }
}

fn run(
    fault: Fault,
) -> (
    Result<chio_kernel::ToolCallResponse, KernelError>,
    usize,
    Vec<SecurityDispatchOutcome>,
) {
    let (mut kernel, request, invocations) = kernel_with_server();
    let outcomes = Arc::new(Mutex::new(Vec::new()));
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    kernel.set_security_pre_dispatch_hook(Arc::new(Hook {
        fault,
        outcomes: outcomes.clone(),
    }));
    let response = kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &security_context(&request));
    let recorded = outcomes.lock().test_unwrap().clone();
    (response, invocations.load(Ordering::SeqCst), recorded)
}

fn assert_denied_before_dispatch(fault: Fault) {
    let (response, invocations, _) = run(fault);
    let response = response.test_unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(invocations, 0);
    assert!(response
        .receipt
        .evidence
        .iter()
        .any(|evidence| evidence.guard_name == "chio-security-pre-dispatch"));
    assert!(!response.reason.test_unwrap().contains("private"));
}

#[test]
fn pre_dispatch_acquisition_panic_is_a_signed_denial() {
    assert_denied_before_dispatch(Fault::AcquirePanic);
}

#[test]
fn pre_dispatch_commit_panic_is_a_signed_denial() {
    assert_denied_before_dispatch(Fault::CommitPanic);
}

#[test]
fn pre_dispatch_rejection_does_not_call_a_panicking_diagnostic() {
    assert_denied_before_dispatch(Fault::RejectWithPanickingName);
}

#[test]
fn pre_dispatch_outcome_requires_exact_request_and_commitment() {
    for fault in [Fault::WrongRequest, Fault::WrongCommitment] {
        let (response, invocations, outcomes) = run(fault);
        assert_eq!(response.test_unwrap().verdict, Verdict::Deny);
        assert_eq!(invocations, 0);
        assert_eq!(outcomes, vec![SecurityDispatchOutcome::DispatchFailed]);
    }
}

#[test]
fn outcome_record_panic_requires_recovery_without_releasing_output() {
    let (response, invocations, outcomes) = run(Fault::RecordPanic);
    assert_recovery_required(response.test_unwrap_err());
    assert_eq!(invocations, 1);
    assert_eq!(outcomes, vec![SecurityDispatchOutcome::Released]);
}

#[test]
fn final_release_panic_requires_recovery_without_releasing_output() {
    let (response, invocations, _) = run(Fault::FinalReleasePanic);
    assert_recovery_required(response.test_unwrap_err());
    assert_eq!(invocations, 1);
}

#[test]
fn post_effect_callback_errors_cannot_advertise_retryable_guard_denial() {
    for fault in [Fault::RecordError, Fault::FinalReleaseError] {
        let (response, invocations, _) = run(fault);
        assert_recovery_required(response.test_unwrap_err());
        assert_eq!(invocations, 1);
    }
}

#[test]
fn rejected_dispatch_contains_lifecycle_disposal_panic() {
    assert_denied_before_dispatch(Fault::LifecycleDisposalPanic);
}

#[test]
fn caller_reservation_rejects_live_security_hook_before_acquiring_it() {
    let (mut kernel, request, invocations) = kernel_with_server();
    let outcomes = Arc::new(Mutex::new(Vec::new()));
    // Acquisition panics if this unsupported owner is ever called.
    kernel.set_security_pre_dispatch_hook(Arc::new(Hook {
        fault: Fault::AcquirePanic,
        outcomes: outcomes.clone(),
    }));
    let response = kernel
        .reserve_caller_execution_blocking(&request)
        .test_unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .test_unwrap()
        .contains("recoverable security-hook custody"));
    assert!(response.execution_nonce.is_none());
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert!(outcomes.lock().test_unwrap().is_empty());
}

struct DropFaultRecorder {
    panic_on_record: bool,
    records: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
}

impl SecurityDispatchOutcomeRecorder for DropFaultRecorder {
    fn record(&mut self, _: SecurityDispatchOutcome) -> Result<(), KernelError> {
        self.records.fetch_add(1, Ordering::SeqCst);
        if self.panic_on_record {
            panic!("private outcome recording fault");
        }
        Ok(())
    }
}

impl Drop for DropFaultRecorder {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
        panic!("private outcome disposal fault");
    }
}

fn handle(recorder: Box<dyn SecurityDispatchOutcomeRecorder>) -> SecurityDispatchOutcomeHandle {
    let request = request();
    let security = security_context(&request);
    let canonical = canonical_json_bytes(&request).test_unwrap();
    let commitment = RecordId::new("dispatch-commitment:callback-test").test_unwrap();
    SecurityDispatchOutcomeHandle::new(
        &SecurityPreDispatchContext {
            request: &request,
            canonical_request: &canonical,
            security_context: &security,
            dispatch_commitment_id: &commitment,
        },
        recorder,
    )
}

#[test]
fn recording_and_disposal_panics_are_contained_separately() {
    for panic_on_record in [false, true] {
        let records = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let outcome = handle(Box::new(DropFaultRecorder {
            panic_on_record,
            records: records.clone(),
            drops: drops.clone(),
        }));
        assert_recovery_required(outcome.record_released().test_unwrap_err());
        assert_eq!(records.load(Ordering::SeqCst), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn outcome_cleanup_during_unwind_does_not_double_panic() {
    let records = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let recorder = DropFaultRecorder {
        panic_on_record: true,
        records: records.clone(),
        drops: drops.clone(),
    };
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _outcome = handle(Box::new(recorder));
        panic!("unrelated evaluation fault");
    }));
    assert!(unwound.is_err());
    assert_eq!(records.load(Ordering::SeqCst), 1);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

fn assert_recovery_required(error: KernelError) {
    assert!(
        matches!(
            error,
            KernelError::SecurityDispatchOutcomeRecoveryRequired(_)
        ),
        "{error}"
    );
    assert_eq!(error.report().context["retryable"], false);
    assert!(!error.to_string().contains("private"));
}
