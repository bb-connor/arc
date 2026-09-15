//! Coordinator boundary fault doubles, not qualified replay-store evidence.

use super::*;
use crate::admission_operation::runtime_participant::{
    RuntimeParticipantClaimHistoryV1, RuntimeParticipantClaimIntentInput,
    RuntimeParticipantClaimIntentV1, RuntimeParticipantClaimReferenceV1,
    RuntimeParticipantDisposition, RuntimeParticipantPhase,
};
use crate::admission_operation::AdmissionDigest;
use std::sync::{Arc, Mutex};

#[path = "runtime_participant/acquisition.rs"]
mod acquisition;
#[path = "runtime_participant/selection.rs"]
mod selection;

#[derive(Default)]
pub(super) struct TestRuntimeRecovery(Mutex<RecoveryState>);

#[derive(Default)]
struct RecoveryState {
    enabled: bool,
    history: Option<Vec<RuntimeParticipantClaimHistoryV1>>,
    snapshot: Option<AdmissionOperationV1>,
    release_mode: ReleaseMode,
    release_calls: usize,
    claim_mode: acquisition::ClaimMode,
    history_panics: usize,
}

#[derive(Clone, Copy, Default)]
enum ReleaseMode {
    #[default]
    Normal,
    NoOp,
    LoseAcknowledgement,
    ReplaceReference,
}

impl TestRuntimeRecovery {
    pub(super) fn load(
        &self,
        operation: Option<AdmissionOperationV1>,
    ) -> Result<
        Option<(AdmissionOperationV1, Vec<RuntimeParticipantClaimHistoryV1>)>,
        AdmissionOperationStoreError,
    > {
        let mut state = self.0.lock().expect("runtime recovery fixture");
        if state.history_panics > 0 {
            state.history_panics -= 1;
            drop(state);
            panic!("injected history callback panic");
        }
        if !state.enabled {
            return Err(AdmissionOperationStoreError::Unavailable(
                "test runtime port unsupported".into(),
            ));
        }
        Ok(operation
            .zip(state.history.clone())
            .map(|(operation, history)| (state.snapshot.clone().unwrap_or(operation), history)))
    }

    pub(super) fn release(
        &self,
        reference: &RuntimeParticipantClaimReferenceV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        let mut state = self.0.lock().expect("runtime recovery fixture");
        state.release_calls += 1;
        let mode = state.release_mode;
        let claim = state
            .history
            .as_mut()
            .and_then(|history| {
                history
                    .iter_mut()
                    .find(|claim| &claim.reference == reference)
            })
            .ok_or(AdmissionOperationStoreError::NotFound)?;
        if matches!(mode, ReleaseMode::NoOp) {
            return Ok(());
        }
        claim.disposition = RuntimeParticipantDisposition::ReleasedBeforeDispatch;
        if matches!(mode, ReleaseMode::ReplaceReference) {
            claim.reference = RuntimeParticipantClaimReferenceV1::new(
                reference.operation_id().clone(),
                reference.episode_id().clone(),
                digest('f'),
            );
        }
        if matches!(mode, ReleaseMode::LoseAcknowledgement) {
            state.release_mode = ReleaseMode::Normal;
            return Err(AdmissionOperationStoreError::OutcomeUnknown(
                "injected lost release acknowledgement".into(),
            ));
        }
        Ok(())
    }
}

fn digest(byte: char) -> AdmissionDigest {
    AdmissionDigest::try_new("test", byte.to_string().repeat(64)).expect("test digest")
}

fn fixture() -> (ChioKernel, Arc<TestAdmissionOperationStore>, Arc<AtomicU64>) {
    let (kernel, request, store, invocations) =
        durable_admission_fixture("runtime-release-boundary");
    let matching = resolve_required_matching_grants(
        &request.capability,
        &request.tool_name,
        &request.server_id,
        &request.arguments,
        request.model_metadata.as_ref(),
    )
    .expect("matching grants");
    kernel
        .begin_durable_tool_admission(&request, &matching, current_unix_timestamp_ms())
        .expect("begin")
        .expect("durable admission");
    // The in-memory double permits model attachment. Only the SQLite regressions
    // exercise real atomic acquisition and physical claim/commit verification.
    let operation = kernel
        .apply_admission_command(
            store.operation(),
            vec![AdmissionAttachment::RuntimeParticipantLedgerDigest(digest(
                'a',
            ))],
            AdmissionOperationState::BrokerAttemptRegistered,
            current_unix_timestamp_ms(),
        )
        .expect("model ledger attachment");
    let episode = AdmissionIdentifier::try_new("episode", "test-episode").expect("episode");
    let intent = RuntimeParticipantClaimIntentV1::new(RuntimeParticipantClaimIntentInput {
        episode_id: episode.clone(),
        runtime_authority_id: AdmissionIdentifier::try_new("runtime", "test-runtime")
            .expect("runtime"),
        expectation_id: AdmissionIdentifier::try_new("source", "test-source").expect("source"),
        request_binding_hash: operation.binding().request_binding_hash().clone(),
        grant_index: 0,
        phase: RuntimeParticipantPhase::Dispatch,
        plan_digest: digest('b'),
        resources: vec![],
    })
    .expect("model intent");
    *store.runtime_recovery.0.lock().expect("fixture") = RecoveryState {
        enabled: true,
        history: Some(vec![RuntimeParticipantClaimHistoryV1 {
            reference: RuntimeParticipantClaimReferenceV1::new(
                operation.binding().operation_id().clone(),
                episode,
                digest('c'),
            ),
            intent,
            disposition: RuntimeParticipantDisposition::ReservedBeforeDispatch,
        }]),
        ..RecoveryState::default()
    };
    (kernel, store, invocations)
}

fn compensate(kernel: &ChioKernel, store: &TestAdmissionOperationStore) -> Result<(), KernelError> {
    kernel.compensate_durable_admission_before_dispatch(
        &store.operation(),
        serde_json::json!({"authority": "test"}),
        current_unix_timestamp_ms(),
        None,
    )
}

#[test]
fn runtime_cleanup_rejects_success_without_exact_physical_release() {
    for mode in [ReleaseMode::NoOp, ReleaseMode::ReplaceReference] {
        let (kernel, store, invocations) = fixture();
        let original = store.operation();
        store
            .runtime_recovery
            .0
            .lock()
            .expect("fixture")
            .release_mode = mode;
        let error = compensate(&kernel, &store).expect_err("unproven release must reject");
        assert!(
            error.to_string().contains("exact released history"),
            "{error}"
        );
        assert_eq!(store.operation(), original);
        assert_eq!(
            store
                .runtime_recovery
                .0
                .lock()
                .expect("fixture")
                .release_calls,
            1
        );
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn runtime_cleanup_lost_acknowledgement_requires_readback_on_retry() {
    let (kernel, store, invocations) = fixture();
    let original = store.operation();
    store
        .runtime_recovery
        .0
        .lock()
        .expect("fixture")
        .release_mode = ReleaseMode::LoseAcknowledgement;
    let error = compensate(&kernel, &store).expect_err("unknown release is not success");
    assert!(error.to_string().contains("lost release acknowledgement"));
    assert_eq!(store.operation(), original);
    compensate(&kernel, &store).expect("retry acknowledges durable release");
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(
        store
            .runtime_recovery
            .0
            .lock()
            .expect("fixture")
            .release_calls,
        1
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}

#[test]
fn runtime_cleanup_missing_empty_and_unsupported_history_fail_closed() {
    for case in ["missing", "empty", "unsupported", "duplicate", "retained"] {
        let (kernel, store, _) = fixture();
        let original = store.operation();
        {
            let mut state = store.runtime_recovery.0.lock().expect("fixture");
            match case {
                "missing" => state.history = None,
                "empty" => state.history = Some(vec![]),
                "unsupported" => state.enabled = false,
                "duplicate" => {
                    let history = state.history.as_mut().expect("history");
                    history.push(history[0].clone());
                }
                "retained" => {
                    state.history.as_mut().expect("history")[0].disposition =
                        RuntimeParticipantDisposition::RetainedAfterDispatchCommit
                }
                _ => unreachable!(),
            }
        }
        assert!(compensate(&kernel, &store).is_err(), "{case}");
        assert_eq!(store.operation(), original, "{case}");
        assert_eq!(
            store
                .runtime_recovery
                .0
                .lock()
                .expect("fixture")
                .release_calls,
            0,
            "{case}"
        );
    }
}

#[test]
fn runtime_cleanup_rejects_changed_operation_readback_before_release() {
    let (kernel, store, _) = fixture();
    let original = store.operation();
    // A different version of the same operation is still not the leased snapshot.
    let changed = kernel
        .apply_admission_command(
            original.clone(),
            vec![AdmissionAttachment::BudgetHoldId(
                AdmissionIdentifier::try_new("hold", "different-hold").expect("hold"),
            )],
            AdmissionOperationState::BudgetAuthorized,
            current_unix_timestamp_ms(),
        )
        .expect("advanced model operation");
    store.state.lock().expect("fixture").operation = Some(original.clone());
    store.runtime_recovery.0.lock().expect("fixture").snapshot = Some(changed);
    let error = compensate(&kernel, &store).expect_err("changed readback must reject");
    assert!(error.to_string().contains("different operation snapshot"));
    assert_eq!(store.operation(), original);
    assert_eq!(
        store
            .runtime_recovery
            .0
            .lock()
            .expect("fixture")
            .release_calls,
        0
    );
}
