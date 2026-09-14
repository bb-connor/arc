//! Adversarial coordinator callbacks, not SQLite source or commit qualification.
use super::*;
use crate::admission_operation::governed_approval_claim::*;
use crate::admission_operation::governed_approval_replay::*;
use crate::admission_operation::{AdmissionDigest, AdmissionRecoveryLease};
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, Default, Debug)]
enum Mode {
    #[default]
    Normal,
    NoOp,
    LostAck,
    Panic,
    WrongReference,
    WrongSuccessor,
    HistoryPanic,
}

#[derive(Default)]
pub(super) struct TestApproval(Mutex<State>);
#[derive(Default)]
struct State {
    source: Option<GovernedApprovalReplaySourceSnapshot>,
    history: Vec<GovernedApprovalClaimHistoryV1>,
    mode: Mode,
    history_panics: usize,
    release_noop: bool,
}

impl TestApproval {
    pub(super) fn activation(
        &self,
        binding: &GovernedApprovalAuthorityBindingV1,
    ) -> Result<GovernedApprovalReplaySourceSnapshot, AdmissionOperationStoreError> {
        let state = self.0.lock().expect("approval state");
        let source = state.source.as_ref().ok_or_else(|| {
            AdmissionOperationStoreError::Unavailable("test approval source unsupported".into())
        })?;
        if binding.approval_authority_id().as_str() != source.approval_authority_id() {
            return Err(AdmissionOperationStoreError::Fenced);
        }
        Ok(source.clone())
    }

    pub(super) fn claim(
        &self,
        store: &TestAdmissionOperationStore,
        original: &AdmissionOperationV1,
        lease: &AdmissionRecoveryLease,
        intent: &GovernedApprovalClaimIntentV1,
        now: u64,
    ) -> Result<
        (AdmissionOperationV1, GovernedApprovalClaimReferenceV1),
        AdmissionOperationStoreError,
    > {
        let mode = self.0.lock().expect("state").mode;
        let reference = GovernedApprovalClaimReferenceV1::new(
            original.binding().operation_id().clone(),
            intent.episode_id().clone(),
            digest('c'),
        );
        if matches!(mode, Mode::NoOp) {
            return Ok((original.clone(), reference));
        }
        let command = AdmissionOperationCommand::new(
            original.binding().operation_id().clone(),
            original.version(),
            lease.clone(),
            vec![AdmissionAttachment::GovernedApprovalLedgerDigest(digest(
                'a',
            ))],
            Some(original.state()),
            None,
            None,
        )?;
        let updated = original.apply_command(&command, now)?.into_operation();
        store.state.lock().expect("operation").operation = Some(updated.clone());
        {
            let mut state = self.0.lock().expect("state");
            state.history.push(GovernedApprovalClaimHistoryV1 {
                reference: reference.clone(),
                intent: intent.clone(),
                disposition: GovernedApprovalClaimDisposition::ReservedBeforeDispatch,
            });
            if matches!(mode, Mode::HistoryPanic) {
                state.history_panics = 1;
            }
        }
        match mode {
            Mode::LostAck => Err(AdmissionOperationStoreError::OutcomeUnknown(
                "lost approval claim acknowledgement".into(),
            )),
            Mode::Panic => panic!("approval committed then callback panicked"),
            Mode::WrongReference => Ok((
                updated,
                GovernedApprovalClaimReferenceV1::new(
                    reference.operation_id().clone(),
                    reference.episode_id().clone(),
                    digest('f'),
                ),
            )),
            Mode::WrongSuccessor => Ok((original.clone(), reference)),
            _ => Ok((updated, reference)),
        }
    }

    pub(super) fn history(
        &self,
        operation: Option<AdmissionOperationV1>,
    ) -> Result<
        Option<(AdmissionOperationV1, Vec<GovernedApprovalClaimHistoryV1>)>,
        AdmissionOperationStoreError,
    > {
        let mut state = self.0.lock().expect("state");
        if state.history_panics > 0 {
            state.history_panics -= 1;
            drop(state);
            panic!("approval history readback panicked");
        }
        Ok(operation.map(|operation| (operation, state.history.clone())))
    }

    pub(super) fn release(
        &self,
        reference: &GovernedApprovalClaimReferenceV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        let mut state = self.0.lock().expect("state");
        if state.release_noop {
            return Ok(());
        }
        let claim = state
            .history
            .iter_mut()
            .find(|claim| &claim.reference == reference)
            .ok_or(AdmissionOperationStoreError::NotFound)?;
        claim.disposition = GovernedApprovalClaimDisposition::ReleasedBeforeDispatch;
        Ok(())
    }
}

struct Source(GovernedApprovalReplaySourceSnapshot);
impl GovernedApprovalReplaySourcePort for Source {
    fn preview_unsealed(
        &self,
        _: &GovernedApprovalReplaySourceBinding,
    ) -> Result<GovernedApprovalReplaySourceSnapshot, AdmissionOperationStoreError> {
        panic!("kernel must not preview a source");
    }
    fn seal_exact(
        &self,
        _: &GovernedApprovalReplaySourceSnapshot,
    ) -> Result<(), AdmissionOperationStoreError> {
        panic!("kernel must not activate a source");
    }
    fn verify_exact(
        &self,
        snapshot: &GovernedApprovalReplaySourceSnapshot,
    ) -> Result<(), AdmissionOperationStoreError> {
        assert_eq!(snapshot, &self.0);
        Ok(())
    }
}

fn digest(c: char) -> AdmissionDigest {
    AdmissionDigest::try_new("test", c.to_string().repeat(64)).expect("digest")
}
fn id(value: &str) -> AdmissionIdentifier {
    AdmissionIdentifier::try_new("test", value).expect("identifier")
}

fn fixture(
    mode: Mode,
) -> (
    ChioKernel,
    ToolCallRequest,
    Arc<TestAdmissionOperationStore>,
    Arc<AtomicU64>,
) {
    let (mut kernel, mut request, store, calls) =
        durable_admission_fixture("prepared-approval-owner");
    let source = GovernedApprovalReplaySourceSnapshot::from_inventory(
        GovernedApprovalReplaySourceBinding {
            source_id: id("test-source"),
            approval_authority_id: id("test-authority"),
            destination_authority_id: id(&store.fence.lock().expect("fence").store_uuid),
        },
        GovernedApprovalReplaySourceFileIdentity {
            device: 1,
            inode: 2,
            link_count: 1,
        },
        "b".repeat(64),
        GovernedApprovalReplaySourceInventory {
            wall_clock_high_water: "0".into(),
            pruned_through: "0".into(),
            capacity: "8".into(),
            markers: vec![],
        },
    )
    .expect("test snapshot data");
    *store.approval_recovery.0.lock().expect("state") = State {
        source: Some(source.clone()),
        mode,
        ..Default::default()
    };
    kernel
        .set_operation_owned_governed_approval_source(
            GovernedApprovalAuthorityBindingV1::new(id("test-authority"), id("test-generation")),
            Arc::new(Source(source)),
        )
        .expect("configured test port");
    let intent = chio_core::capability::governance::GovernedTransactionIntent {
        id: request.request_id.clone(),
        server_id: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        purpose: "test claim custody".into(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: None,
        body: Default::default(),
    };
    request.approval_token = Some(make_governed_approval_token(
        &kernel.config.keypair,
        &request.capability.subject,
        &intent,
        &request.request_id,
    ));
    request.governed_intent = Some(intent);
    (kernel, request, store, calls)
}

fn begin(kernel: &ChioKernel, request: &ToolCallRequest) -> DurableToolAdmission {
    let matching = resolve_required_matching_grants(
        &request.capability,
        &request.tool_name,
        &request.server_id,
        &request.arguments,
        request.model_metadata.as_ref(),
    )
    .expect("grants");
    kernel
        .begin_durable_tool_admission(request, &matching, current_unix_timestamp_ms())
        .expect("begin")
        .expect("durable")
}

#[test]
fn approval_claim_failures_preserve_the_confirmed_operation_for_cleanup() {
    for mode in [
        Mode::Normal,
        Mode::NoOp,
        Mode::LostAck,
        Mode::Panic,
        Mode::WrongReference,
        Mode::WrongSuccessor,
        Mode::HistoryPanic,
    ] {
        let (kernel, request, store, calls) = fixture(mode);
        let mut admission = begin(&kernel, &request);
        let original = admission.operation().clone();
        let decision = kernel.run_pre_budget_admission(
            &request,
            None,
            None,
            current_unix_timestamp(),
            current_unix_timestamp_ms(),
            0,
            false,
            Some(&mut admission),
        );
        assert_eq!(
            decision.allowed,
            matches!(mode, Mode::Normal),
            "{mode:?}: {:?}",
            decision.reason
        );
        assert_eq!(admission.operation(), &store.operation(), "{mode:?}");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        if matches!(mode, Mode::NoOp) {
            assert_eq!(admission.operation(), &original);
        } else {
            assert!(admission.operation().version() > original.version());
            kernel
                .release_operation_owned_approval_before_dispatch(Some(admission.operation()))
                .expect("exact cleanup");
            assert_eq!(
                store.approval_recovery.0.lock().expect("state").history[0].disposition,
                GovernedApprovalClaimDisposition::ReleasedBeforeDispatch
            );
        }
    }
}

#[test]
fn approval_reservation_requires_the_original_prepared_request_and_grant() {
    let (kernel, request, store, _) = fixture(Mode::Normal);
    let mut admission = begin(&kernel, &request);
    assert!(
        kernel
            .run_pre_budget_admission(
                &request,
                None,
                None,
                current_unix_timestamp(),
                current_unix_timestamp_ms(),
                0,
                false,
                Some(&mut admission)
            )
            .allowed
    );
    for substitute in ["arguments", "grant"] {
        let mut changed = request.clone();
        if substitute == "arguments" {
            changed.arguments = serde_json::json!({"replacement": true});
        }
        let result = kernel.reserve_admitted_dispatch_credentials(
            &changed,
            false,
            current_unix_timestamp(),
            Some(&admission),
            usize::from(substitute == "grant"),
        );
        assert!(result.is_err(), "{substitute}");
        assert_eq!(
            store.approval_recovery.0.lock().expect("state").history[0].disposition,
            GovernedApprovalClaimDisposition::ReservedBeforeDispatch
        );
    }
    let reservation = kernel
        .reserve_admitted_dispatch_credentials(
            &request,
            false,
            current_unix_timestamp(),
            Some(&admission),
            0,
        )
        .expect("exact prepared owner");
    drop(reservation);
    assert_eq!(
        store.approval_recovery.0.lock().expect("state").history[0].disposition,
        GovernedApprovalClaimDisposition::ReleasedBeforeDispatch
    );
}

#[test]
fn approval_cleanup_requires_a_confirmed_exact_release() {
    let (kernel, request, store, _) = fixture(Mode::Normal);
    let mut admission = begin(&kernel, &request);
    assert!(
        kernel
            .run_pre_budget_admission(
                &request,
                None,
                None,
                current_unix_timestamp(),
                current_unix_timestamp_ms(),
                0,
                false,
                Some(&mut admission)
            )
            .allowed
    );
    store
        .approval_recovery
        .0
        .lock()
        .expect("state")
        .release_noop = true;
    assert!(kernel
        .release_operation_owned_approval_before_dispatch(Some(admission.operation()))
        .is_err());
    assert_eq!(
        store.approval_recovery.0.lock().expect("state").history[0].disposition,
        GovernedApprovalClaimDisposition::ReservedBeforeDispatch
    );
    store
        .approval_recovery
        .0
        .lock()
        .expect("state")
        .release_noop = false;
    kernel
        .release_operation_owned_approval_before_dispatch(Some(admission.operation()))
        .expect("retry confirms release");
}

#[test]
fn foreign_prepared_kernel_cannot_claim_another_kernels_operation() {
    let (kernel, request, store, _) = fixture(Mode::Normal);
    let mut other_config = make_config();
    other_config.keypair = kernel.config.keypair.clone();
    let other = ChioKernel::new(other_config);
    let prepared = other
        .prepare_dispatch_credentials(
            &request,
            &request.capability,
            false,
            current_unix_timestamp(),
            false,
        )
        .expect("same signer validates on other kernel");
    let mut admission = begin(&kernel, &request);
    let original = admission.operation().clone();
    assert!(kernel
        .claim_prepared_governed_approval(prepared, &mut admission, 0, current_unix_timestamp_ms())
        .is_err());
    assert_eq!(admission.operation(), &original);
    assert!(store
        .approval_recovery
        .0
        .lock()
        .expect("state")
        .history
        .is_empty());
}

#[test]
fn dropping_an_old_reservation_cannot_release_its_successor_episode() {
    let (kernel, request, store, _) = fixture(Mode::Normal);
    let mut admission = begin(&kernel, &request);
    assert!(
        kernel
            .run_pre_budget_admission(
                &request,
                None,
                None,
                current_unix_timestamp(),
                current_unix_timestamp_ms(),
                0,
                false,
                Some(&mut admission)
            )
            .allowed
    );
    let first = kernel
        .reserve_admitted_dispatch_credentials(
            &request,
            false,
            current_unix_timestamp(),
            Some(&admission),
            0,
        )
        .expect("first owner");
    kernel
        .release_operation_owned_approval_before_dispatch(Some(admission.operation()))
        .expect("first release");
    assert!(
        kernel
            .run_pre_budget_admission(
                &request,
                None,
                None,
                current_unix_timestamp(),
                current_unix_timestamp_ms(),
                0,
                false,
                Some(&mut admission)
            )
            .allowed
    );
    drop(first);
    let state = store.approval_recovery.0.lock().expect("state");
    assert_eq!(state.history.len(), 2);
    assert_eq!(
        state.history[0].disposition,
        GovernedApprovalClaimDisposition::ReleasedBeforeDispatch
    );
    assert_eq!(
        state.history[1].disposition,
        GovernedApprovalClaimDisposition::ReservedBeforeDispatch
    );
}

#[test]
fn nested_flow_uses_operation_owned_approval_acquisition() {
    let (kernel, request, store, calls) = fixture(Mode::Normal);
    let session = kernel
        .open_session("approval-parent".into(), vec![])
        .expect("session");
    kernel.activate_session(&session).expect("active session");
    let parent = make_operation_context(&session, "parent-request", "approval-parent");
    kernel
        .begin_session_request(&parent, OperationKind::ToolCall, true)
        .expect("parent");
    let response = kernel
        .evaluate_tool_call_with_nested_flow_client(
            &parent,
            &request,
            &mut NoopNestedFlowClient,
            None,
        )
        .expect("nested evaluation");
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        store
            .approval_recovery
            .0
            .lock()
            .expect("state")
            .history
            .len(),
        1
    );
}
