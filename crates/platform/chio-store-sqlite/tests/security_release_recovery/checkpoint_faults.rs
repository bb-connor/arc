//! Faults wrap the real SQLite transaction; they do not fabricate its result.
use super::*;
use chio_kernel::admission_operation::{
    AdmissionOperationId, AdmissionOperationV1, AdmissionRecoveryLease, StoreMutationFence,
};
use chio_kernel::tool_outcome::*;
use chio_store_sqlite::SqliteToolOutcomeStore;

#[derive(Clone, Copy)]
enum Fault {
    Unsupported,
    BeforeCommit,
    LostAcknowledgement,
    ExpiredBeforeCheckpoint,
}

struct FaultStore {
    inner: SqliteToolOutcomeStore,
    fault: Fault,
}

macro_rules! forward {
    ($(fn $name:ident($($argument:ident: $kind:ty),* $(,)?) -> $result:ty;)+) => {
        $(fn $name(&self, $($argument: $kind),*) -> $result { self.inner.$name($($argument),*) })+
    };
}

impl ToolOutcomeStore for FaultStore {
    fn require_security_release_checkpoint_support(&self) -> Result<(), ToolOutcomeStoreError> {
        if matches!(self.fault, Fault::Unsupported) {
            Err(ToolOutcomeStoreError::Unavailable(
                "injected unsupported checkpoint backend".into(),
            ))
        } else {
            self.inner.require_security_release_checkpoint_support()
        }
    }

    fn record_security_release(
        &self,
        release: &AcknowledgedSecurityReleaseV1,
        lease: &AdmissionRecoveryLease,
    ) -> Result<SecurityReleaseRecordV1, ToolOutcomeStoreError> {
        if matches!(self.fault, Fault::BeforeCommit) {
            return Err(ToolOutcomeStoreError::Unavailable(
                "injected checkpoint write failure".into(),
            ));
        }
        if matches!(self.fault, Fault::ExpiredBeforeCheckpoint) {
            // Negative-only clock fault after the live callback. Keep the
            // acknowledgement's original timestamp and lease unchanged while
            // the real authority observes that its 60-second lease has expired.
            let at = release.record().acknowledged_at_unix_ms() / 1_000 + 61;
            let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(at, []);
            let result = self.inner.record_security_release(release, lease);
            assert!(
                result
                    .as_ref()
                    .is_err_and(|error| error.to_string().contains("expired")),
                "the real checkpoint transaction must reject its expired lease: {result:?}"
            );
            return result;
        }
        self.inner.record_security_release(release, lease)?;
        Err(ToolOutcomeStoreError::Unavailable(
            "injected lost checkpoint acknowledgement".into(),
        ))
    }

    forward! {
        fn lookup_security_release(operation: &AdmissionOperationId) -> Result<Option<SecurityReleaseRecordV1>, ToolOutcomeStoreError>;
        fn record_tool_returned(operation: &AdmissionOperationV1, lease: &AdmissionRecoveryLease, blob: &CanonicalInvocationBlobV1, record: &ToolOutcomeRecordV1, fence: &StoreMutationFence, now: u64) -> Result<ToolOutcomeInsertResultV1, ToolOutcomeStoreError>;
        fn lookup_by_operation(operation: &AdmissionOperationId) -> Result<Option<ToolOutcomeRecordV1>, ToolOutcomeStoreError>;
        fn load_raw_invocation_by_operation(operation: &AdmissionOperationId) -> Result<Option<RawInvocationOutcomeV1>, ToolOutcomeStoreError>;
        fn lookup_post_return_evaluation(operation: &AdmissionOperationId) -> Result<Option<PostReturnEvaluationRecordV1>, ToolOutcomeStoreError>;
        fn begin_post_return_evaluation(lease: &AdmissionRecoveryLease, record: &PostReturnEvaluationRecordV1, fence: &StoreMutationFence, now: u64) -> Result<PostReturnEvaluationRecordV1, ToolOutcomeStoreError>;
        fn stage_post_return_evaluation(operation: &AdmissionOperationId, version: u64, lease: &AdmissionRecoveryLease, next: &PostReturnEvaluationRecordV1, fence: &StoreMutationFence, now: u64) -> Result<PostReturnEvaluationRecordV1, ToolOutcomeStoreError>;
        fn finalize_post_return(operation: &AdmissionOperationId, evaluation_version: u64, lease: &AdmissionRecoveryLease, evaluation: &PostReturnEvaluationRecordV1, outcome_version: u64, outcome: &ToolOutcomeRecordV1, output: Option<&CanonicalResolvedOutputBlobV1>, fence: &StoreMutationFence, now: u64) -> Result<(PostReturnEvaluationRecordV1, ToolOutcomeRecordV1), ToolOutcomeStoreError>;
        fn load_resolved_output_by_operation(operation: &AdmissionOperationId) -> Result<Option<CanonicalResolvedOutputBlobV1>, ToolOutcomeStoreError>;
    }
}
impl QualifiedToolOutcomeStore for FaultStore {}

fn run(fault: Fault) -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.nonce_enabled = false;
    let hook = Arc::new(ReleaseHook {
        allowed: true,
        releases: Arc::new(AtomicUsize::new(0)),
    });
    let mut runtime = open(&fixture, hook.clone(), false)?;
    Arc::get_mut(&mut runtime.kernel)
        .ok_or("unique kernel")?
        .set_durable_admission_store(
            Arc::new(runtime.authority.admission_operation_store()),
            Arc::new(FaultStore {
                inner: runtime.authority.tool_outcome_store(),
                fault,
            }),
            runtime.authority.mutation_fence(),
        )?;
    runtime.kernel.reconcile_durable_admission_startup()?;
    let request = fixture.request(&runtime, "checkpoint-fault")?;
    let security_context = context(&request)?;
    let first = runtime
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &security_context);
    if matches!(fault, Fault::Unsupported) {
        assert_eq!(first?.verdict, chio_kernel::Verdict::Deny);
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
        assert_eq!(hook.releases.load(Ordering::SeqCst), 0);
        assert_eq!(grant_quota(&runtime, &request)?, (0, 0));
        return Ok(());
    }
    assert_withheld(first);
    assert_eq!(hook.releases.load(Ordering::SeqCst), 1);
    assert_eq!(
        operation_state(&fixture, &request.request_id)?
            .ok_or("operation")?
            .1,
        "finalizing"
    );
    let replay = runtime
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &security_context);
    if matches!(fault, Fault::LostAcknowledgement) {
        assert_eq!(replay?.verdict, chio_kernel::Verdict::Allow);
        drop(runtime);
        runtime = open(&fixture, hook.clone(), true)?;
        assert_eq!(
            runtime
                .kernel
                .evaluate_tool_call_blocking_with_security_context(&request, &security_context)?
                .verdict,
            chio_kernel::Verdict::Allow
        );
    } else {
        assert_withheld(replay);
    }
    assert_eq!(hook.releases.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    assert_eq!(grant_quota(&runtime, &request)?, (0, 1));
    Ok(())
}

#[test]
fn unsupported_checkpoint_backend_rejects_before_dispatch() -> TestResult {
    run(Fault::Unsupported)
}

#[test]
fn checkpoint_write_failure_cannot_reconsume_a_live_owner() -> TestResult {
    run(Fault::BeforeCommit)
}

#[test]
fn lost_checkpoint_acknowledgement_recovers_the_exact_committed_release() -> TestResult {
    run(Fault::LostAcknowledgement)
}

#[test]
fn successful_live_release_cannot_renew_a_lease_expired_before_checkpoint() -> TestResult {
    run(Fault::ExpiredBeforeCheckpoint)
}
