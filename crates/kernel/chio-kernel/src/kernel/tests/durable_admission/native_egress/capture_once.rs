//! A native capture authority admits one capture attempt. A failure after the
//! store call was entered leaves the commit unconfirmed and retains the hold;
//! a failure before it is a definite rejection that compensates the operation.
//! A replay never receives a second capture authority or reaches the tool.
use super::*;
use crate::budget_store::BudgetHoldDispositionView;

#[path = "capture_once/retained.rs"]
mod retained;

type CaptureResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const POLICY_SCHEMA: &str = "chio.native-flow-dispatch-policy.v1";
const ALREADY_ATTEMPTED: &str = "native capture authority already attempted capture";
const STORE_REFUSAL: &str =
    "combined admission capture is unavailable: atomic native dispatch capture is unsupported";
const DEADLINE_REFUSAL: &str = "native lifecycle policy deadline is absent or invalid";

#[derive(Clone, Copy, Debug, PartialEq)]
enum Boundary {
    StoreEntered,
    BeforeStore,
}

#[derive(Clone, Copy, Debug)]
enum Entry {
    Ordinary,
    Nested,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Site {
    Lifecycle,
    #[cfg(feature = "admission-test-support")]
    Checkpoint,
}

#[derive(Clone, Debug, PartialEq)]
enum Attempt {
    Captured,
    Refused(String),
    Other(String),
}

fn attempt<T>(result: &Result<T, KernelError>) -> Attempt {
    match result {
        Ok(_) => Attempt::Captured,
        Err(KernelError::DurableAdmission(reason)) => Attempt::Refused(reason.clone()),
        Err(other) => Attempt::Other(other.to_string()),
    }
}

fn poisoned<T>(_: std::sync::PoisonError<T>) -> KernelError {
    KernelError::Internal("native capture attempt record poisoned".into())
}

/// Two genuine preparations from the same live evaluation. Only the first is
/// retained for capture; the spare must still be refused after any attempt.
fn capture_twice(
    authority: &mut NativeSecurityDispatchCaptureAuthority<'_, '_>,
    policy: &[u8],
    attempts: &Mutex<Vec<Attempt>>,
) -> Result<(), KernelError> {
    let grant_index = authority.grant_index()?;
    let spare = authority.prepare_egress()?;
    let (prepared, egress, ledger) =
        authority
            .prepare_egress()?
            .retain_for_capture(None, grant_index, policy)?;
    if egress.is_some() {
        return Err(KernelError::Internal(
            "capture without an egress plan acquired egress custody".into(),
        ));
    }
    let first = authority.capture(prepared, &ledger, policy);
    let second = authority.capture(spare, &ledger, policy);
    attempts
        .lock()
        .map_err(poisoned)?
        .extend([attempt(&first), attempt(&second)]);
    first.map(|_| ())
}

struct CaptureOnceHook {
    binding: NativeSecurityAuthorityBindingV1,
    site: Site,
    policy: Vec<u8>,
    callbacks: AtomicU64,
    attempts: Arc<Mutex<Vec<Attempt>>>,
}

impl SecurityPreDispatchHook for CaptureOnceHook {
    fn name(&self) -> &str {
        "native-capture-once"
    }

    fn supports_native_dispatch(&self) -> bool {
        true
    }

    fn native_authority_binding(
        &self,
    ) -> Result<Option<NativeSecurityAuthorityBindingV1>, KernelError> {
        Ok(Some(self.binding.clone()))
    }

    fn prepare_native_admission(
        &self,
        _: &NativeSecurityAdmissionContext<'_>,
        authority: &NativeSecurityFlowJoinAuthority<'_>,
    ) -> Result<(), KernelError> {
        super::super::native_acquisition::join(authority).map(|_| ())
    }

    fn commit_native_dispatch(
        &self,
        authority: &mut NativeSecurityDispatchCaptureAuthority<'_, '_>,
    ) -> Result<(), KernelError> {
        self.callbacks.fetch_add(1, Ordering::SeqCst);
        if self.site != Site::Lifecycle {
            return Err(KernelError::Internal(
                "native lifecycle ran after the capture checkpoint".into(),
            ));
        }
        capture_twice(authority, &self.policy, &self.attempts)
    }

    fn commit(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        Err(KernelError::Internal(
            "native custody entered legacy dispatch".into(),
        ))
    }
}

/// Release-checkpoint readiness over the existing in-memory outcome store, as
/// a qualified backend reports it. No case here dispatches, so recording a
/// release stays unsupported.
struct ReleaseReadyOutcomes(Arc<TestAdmissionOperationStore>);

impl ToolOutcomeStore for ReleaseReadyOutcomes {
    fn require_security_release_checkpoint_support(&self) -> Result<(), ToolOutcomeStoreError> {
        Ok(())
    }

    fn record_tool_returned(
        &self,
        operation: &AdmissionOperationV1,
        recovery_lease: &crate::admission_operation::AdmissionRecoveryLease,
        blob: &CanonicalInvocationBlobV1,
        record: &ToolOutcomeRecordV1,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<ToolOutcomeInsertResultV1, ToolOutcomeStoreError> {
        ToolOutcomeStore::record_tool_returned(
            self.0.as_ref(),
            operation,
            recovery_lease,
            blob,
            record,
            active_fence,
            trusted_now_unix_ms,
        )
    }

    fn lookup_by_operation(
        &self,
        operation_id: &AdmissionOperationId,
    ) -> Result<Option<ToolOutcomeRecordV1>, ToolOutcomeStoreError> {
        ToolOutcomeStore::lookup_by_operation(self.0.as_ref(), operation_id)
    }

    fn load_raw_invocation_by_operation(
        &self,
        operation_id: &AdmissionOperationId,
    ) -> Result<Option<RawInvocationOutcomeV1>, ToolOutcomeStoreError> {
        ToolOutcomeStore::load_raw_invocation_by_operation(self.0.as_ref(), operation_id)
    }

    fn lookup_post_return_evaluation(
        &self,
        operation_id: &AdmissionOperationId,
    ) -> Result<Option<PostReturnEvaluationRecordV1>, ToolOutcomeStoreError> {
        ToolOutcomeStore::lookup_post_return_evaluation(self.0.as_ref(), operation_id)
    }

    fn begin_post_return_evaluation(
        &self,
        recovery_lease: &crate::admission_operation::AdmissionRecoveryLease,
        record: &PostReturnEvaluationRecordV1,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<PostReturnEvaluationRecordV1, ToolOutcomeStoreError> {
        ToolOutcomeStore::begin_post_return_evaluation(
            self.0.as_ref(),
            recovery_lease,
            record,
            active_fence,
            trusted_now_unix_ms,
        )
    }

    fn stage_post_return_evaluation(
        &self,
        operation_id: &AdmissionOperationId,
        expected_version: u64,
        recovery_lease: &crate::admission_operation::AdmissionRecoveryLease,
        next: &PostReturnEvaluationRecordV1,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<PostReturnEvaluationRecordV1, ToolOutcomeStoreError> {
        ToolOutcomeStore::stage_post_return_evaluation(
            self.0.as_ref(),
            operation_id,
            expected_version,
            recovery_lease,
            next,
            active_fence,
            trusted_now_unix_ms,
        )
    }

    fn finalize_post_return(
        &self,
        operation_id: &AdmissionOperationId,
        expected_evaluation_version: u64,
        recovery_lease: &crate::admission_operation::AdmissionRecoveryLease,
        terminal_evaluation: &PostReturnEvaluationRecordV1,
        expected_outcome_version: u64,
        terminal_outcome: &ToolOutcomeRecordV1,
        resolved_output: Option<&CanonicalResolvedOutputBlobV1>,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<(PostReturnEvaluationRecordV1, ToolOutcomeRecordV1), ToolOutcomeStoreError> {
        ToolOutcomeStore::finalize_post_return(
            self.0.as_ref(),
            operation_id,
            expected_evaluation_version,
            recovery_lease,
            terminal_evaluation,
            expected_outcome_version,
            terminal_outcome,
            resolved_output,
            active_fence,
            trusted_now_unix_ms,
        )
    }

    fn load_resolved_output_by_operation(
        &self,
        operation_id: &AdmissionOperationId,
    ) -> Result<Option<CanonicalResolvedOutputBlobV1>, ToolOutcomeStoreError> {
        ToolOutcomeStore::load_resolved_output_by_operation(self.0.as_ref(), operation_id)
    }
}

impl QualifiedToolOutcomeStore for ReleaseReadyOutcomes {}

struct Case {
    kernel: ChioKernel,
    request: ToolCallRequest,
    context: SecurityInvocationContext,
    parent: Option<OperationContext>,
    store: Arc<TestAdmissionOperationStore>,
    invocations: Arc<AtomicU64>,
    hook: Arc<CaptureOnceHook>,
}

fn arrange(site: Site, entry: Entry, boundary: Boundary) -> CaptureResult<Case> {
    let mut grant = make_grant("durable-server", "mutate");
    grant.max_invocations = Some(1);
    let (mut kernel, request, store, invocations) = durable_admission_fixture_with_grants(
        &format!("native-capture-once-{site:?}-{entry:?}-{boundary:?}"),
        vec![grant],
    );
    let inputs = match boundary {
        Boundary::StoreEntered => serde_json::json!({
            "valid_until_unix_ms": current_unix_timestamp_ms() + 60_000,
        }),
        Boundary::BeforeStore => serde_json::json!({}),
    };
    let policy = canonical_json_bytes(&serde_json::json!({
        "schema": POLICY_SCHEMA,
        "inputs": inputs,
    }))?;
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let hook = Arc::new(CaptureOnceHook {
        binding: NativeSecurityAuthorityBindingV1::new(
            AdmissionIdentifier::try_new("store", "native-store")?,
            AdmissionIdentifier::try_new("authority", "native-authority")?,
            AdmissionDigest::try_new("initialization", sha256_hex(b"native-init"))?,
        ),
        site,
        policy: policy.clone(),
        callbacks: AtomicU64::new(0),
        attempts: attempts.clone(),
    });
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    kernel.set_security_pre_dispatch_hook(hook.clone());
    #[cfg(feature = "admission-test-support")]
    if site == Site::Checkpoint {
        let checkpoint: NativeSecurityCaptureCheckpointHook =
            Arc::new(move |authority| capture_twice(authority, &policy, &attempts));
        kernel.install_native_capture_checkpoint_hook(checkpoint);
    }
    kernel.set_durable_admission_store(
        store.clone(),
        Arc::new(ReleaseReadyOutcomes(store.clone())),
        admission_test_fence(),
    )?;
    store.native_egress.enable(7)?;
    let mut context = security_binding::context(&request, 1)?;
    let parent = match entry {
        Entry::Ordinary => None,
        Entry::Nested => {
            let session = kernel.open_session(request.agent_id.clone(), Vec::new())?;
            kernel.activate_session(&session)?;
            let parent =
                make_operation_context(&session, "native-capture-parent", &request.agent_id);
            kernel.begin_session_request(&parent, OperationKind::ToolCall, true)?;
            let mut value = serde_json::to_value(&context)?;
            value["context"]["sessionId"] = serde_json::json!(session.as_str());
            context = serde_json::from_value(value)?;
            Some(parent)
        }
    };
    Ok(Case {
        kernel,
        request,
        context,
        parent,
        store,
        invocations,
        hook,
    })
}

fn evaluate(case: &Case) -> Result<ToolCallResponse, KernelError> {
    match case.parent.as_ref() {
        None => case
            .kernel
            .evaluate_tool_call_blocking_with_security_context(&case.request, &case.context),
        Some(parent) => case
            .kernel
            .evaluate_tool_call_with_nested_flow_client_and_security_context(
                parent,
                &case.request,
                &mut NoopNestedFlowClient,
                None,
                Some(&case.context),
            ),
    }
}

fn single_use_capture(site: Site, entry: Entry, boundary: Boundary) -> CaptureResult {
    let label = format!("{site:?}/{entry:?}/{boundary:?}");
    let case = arrange(site, entry, boundary)?;
    let denied = evaluate(&case)?;

    let first = match boundary {
        Boundary::StoreEntered => STORE_REFUSAL,
        Boundary::BeforeStore => DEADLINE_REFUSAL,
    };
    assert_eq!(
        case.hook
            .attempts
            .lock()
            .map_err(|_| "attempt record poisoned")?
            .as_slice(),
        [
            Attempt::Refused(first.into()),
            Attempt::Refused(ALREADY_ATTEMPTED.into()),
        ],
        "{label}"
    );
    assert_eq!(
        case.hook.callbacks.load(Ordering::SeqCst),
        u64::from(site == Site::Lifecycle),
        "{label}"
    );
    assert_eq!(denied.verdict, Verdict::Deny, "{label}: {denied:?}");
    let reason = match site {
        Site::Lifecycle => KernelError::SecurityDispatchOutcomeRecoveryRequired(
            "security native dispatch capture callback failed; authoritative recovery required"
                .into(),
        ),
        #[cfg(feature = "admission-test-support")]
        Site::Checkpoint => KernelError::DurableAdmission(first.into()),
    };
    assert_eq!(
        denied.reason.as_deref(),
        Some(reason.to_string().as_str()),
        "{label}"
    );
    assert!(denied.output.is_none());
    assert!(denied.receipt.verify_signature()?);
    assert!(denied.receipt.is_denied());
    assert_eq!(case.invocations.load(Ordering::SeqCst), 0, "{label}");

    let (state, hold, quota) = match boundary {
        Boundary::StoreEntered => (
            AdmissionOperationState::CapturePending,
            BudgetHoldDispositionView::Open,
            (1, 0),
        ),
        Boundary::BeforeStore => (
            AdmissionOperationState::CompensatedBeforeDispatch,
            BudgetHoldDispositionView::Reversed,
            (0, 0),
        ),
    };
    let operation = assert_retained(&case, &label, state, hold, quota)?;

    let replay = evaluate(&case)?;
    let replay_reason = KernelError::DurableAdmission(
        match boundary {
            Boundary::StoreEntered => "native preparation requires original pre-budget authority",
            Boundary::BeforeStore => {
                "request replay is retained in state CompensatedBeforeDispatch"
            }
        }
        .into(),
    );
    assert_eq!(replay.verdict, Verdict::Deny, "{label}: {replay:?}");
    assert_eq!(
        replay.reason.as_deref(),
        Some(replay_reason.to_string().as_str()),
        "{label}"
    );
    assert!(replay.output.is_none());
    assert!(replay.receipt.verify_signature()?);
    let replayed = assert_retained(
        &case,
        &label,
        AdmissionOperationState::CompensatedBeforeDispatch,
        BudgetHoldDispositionView::Reversed,
        (0, 0),
    )?;
    assert_eq!(replayed.binding(), operation.binding(), "{label}");
    if boundary == Boundary::BeforeStore {
        assert_eq!(replayed, operation, "{label}");
    }
    assert_eq!(case.invocations.load(Ordering::SeqCst), 0, "{label}");
    assert_eq!(
        case.hook.callbacks.load(Ordering::SeqCst),
        u64::from(site == Site::Lifecycle),
        "{label}"
    );
    assert_eq!(
        case.hook
            .attempts
            .lock()
            .map_err(|_| "attempt record poisoned")?
            .len(),
        2,
        "{label}"
    );
    Ok(())
}

fn assert_retained(
    case: &Case,
    label: &str,
    state: AdmissionOperationState,
    hold: BudgetHoldDispositionView,
    quota: (u32, u32),
) -> CaptureResult<AdmissionOperationV1> {
    let operation = case.store.operation();
    assert_eq!(operation.state(), state, "{label}");
    assert!(operation.dispatch_commit().is_none(), "{label}");
    let retained = case
        .store
        .budget_store()
        .get_budget_hold(
            operation
                .budget_hold_id()
                .ok_or("native operation lost its hold")?
                .as_str(),
        )?
        .ok_or("native operation hold is absent")?;
    assert_eq!(retained.disposition, hold, "{label}");
    let usage = case
        .store
        .budget_store()
        .get_invocation_quota_usage(&crate::budget_store::BudgetQuotaKey::grant(
            &case.request.capability.id,
            0,
        ))?
        .ok_or("native operation quota is absent")?;
    assert_eq!(
        (usage.reserved_invocations, usage.captured_invocations),
        quota,
        "{label}"
    );
    assert!(case
        .store
        .state
        .lock()
        .map_err(|_| "admission state poisoned")?
        .raw_outcome
        .is_none());
    Ok(operation)
}

fn every_boundary(site: Site) -> CaptureResult {
    for entry in [Entry::Ordinary, Entry::Nested] {
        for boundary in [Boundary::StoreEntered, Boundary::BeforeStore] {
            single_use_capture(site, entry, boundary)?;
        }
    }
    Ok(())
}

#[test]
fn native_lifecycle_capture_is_single_use_and_classified_by_store_entry() -> CaptureResult {
    every_boundary(Site::Lifecycle)
}

#[cfg(feature = "admission-test-support")]
#[test]
fn native_checkpoint_capture_is_single_use_and_classified_by_store_entry() -> CaptureResult {
    every_boundary(Site::Checkpoint)
}
