//! Adversarial coordinator callbacks, not SQLite source or commit qualification.
use super::*;
use crate::admission_operation::dpop_claim::*;
use crate::admission_operation::{AdmissionDigest, AdmissionRecoveryLease};
use crate::dpop::authority::DpopReplayAuthorityV1;
use std::sync::{Arc, Mutex};

#[path = "dpop_acquisition/callbacks.rs"]
mod callbacks;
#[path = "dpop_acquisition/fixture.rs"]
mod fixture;
pub(super) use callbacks::TestDpop;
use callbacks::{Mode, State};
use fixture::*;

#[test]
fn dpop_configuration_and_reservation_cannot_bypass_durable_custody() {
    let (kernel, request, store, _) = fixture(Mode::Normal);
    let domain = kernel.dpop_authority.clone().expect("configured domain");
    let mut no_runtime = make_kernel(make_config());
    assert!(no_runtime
        .set_operation_owned_dpop_authority(domain)
        .is_err());
    assert!(no_runtime.dpop_authority.is_none());
    assert!(kernel
        .verify_dpop_for_request(&request, &request.capability)
        .is_err());
    let prepared = kernel
        .prepare_dispatch_credentials(
            &request,
            &request.capability,
            true,
            current_unix_timestamp(),
            false,
        )
        .expect("proof preparation is not a reservation");
    assert!(prepared.reserve().is_err());
    assert!(kernel
        .reserve_admitted_dispatch_credentials(&request, true, current_unix_timestamp(), None, 0,)
        .is_err());
    assert!(store
        .dpop_recovery
        .0
        .lock()
        .expect("state")
        .history
        .is_empty());
}

#[test]
fn lost_claim_and_history_acknowledgements_require_fresh_recovery() {
    let (kernel, request, store, calls) = fixture(Mode::LostAckAndHistoryPanic);
    let mut admission = begin(&kernel, &request);
    let original = admission.operation().clone();
    let decision = kernel.run_pre_budget_admission(
        &request,
        None,
        None,
        current_unix_timestamp(),
        current_unix_timestamp_ms(),
        0,
        true,
        Some(&mut admission),
    );
    assert!(!decision.allowed);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        admission.operation(),
        &original,
        "no acknowledgement may invent a successor"
    );
    let current = store.operation();
    assert!(current.version() > original.version());
    assert_eq!(
        store.dpop_recovery.0.lock().expect("state").history[0].disposition,
        DpopReplayClaimDisposition::ReservedBeforeDispatch
    );
    kernel
        .release_operation_owned_dpop_before_dispatch(Some(&current))
        .expect("fresh recovery owns the confirmed version");
    assert_eq!(
        store.dpop_recovery.0.lock().expect("state").history[0].disposition,
        DpopReplayClaimDisposition::ReleasedBeforeDispatch
    );
}

#[test]
fn foreign_prepared_kernel_cannot_claim_another_kernels_dpop_operation() {
    let (kernel, request, store, _) = fixture(Mode::Normal);
    let (other, _, _, _) = fixture(Mode::Normal);
    let prepared = other
        .prepare_dispatch_credentials(
            &request,
            &request.capability,
            true,
            current_unix_timestamp(),
            false,
        )
        .expect("same independently configured domain verifies the proof");
    let mut admission = begin(&kernel, &request);
    let original = admission.operation().clone();
    assert!(kernel
        .claim_prepared_dpop(&prepared, &mut admission, 0, current_unix_timestamp_ms(),)
        .is_err());
    assert_eq!(admission.operation(), &original);
    assert!(store
        .dpop_recovery
        .0
        .lock()
        .expect("state")
        .history
        .is_empty());
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
fn dpop_claim_failures_preserve_the_confirmed_operation_for_cleanup() {
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
            true,
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
                .release_operation_owned_dpop_before_dispatch(Some(admission.operation()))
                .expect("exact cleanup");
            assert_eq!(
                store.dpop_recovery.0.lock().expect("state").history[0].disposition,
                DpopReplayClaimDisposition::ReleasedBeforeDispatch
            );
        }
    }
}

#[test]
fn dpop_reservation_requires_the_original_prepared_request_and_grant() {
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
                true,
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
            true,
            current_unix_timestamp(),
            Some(&admission),
            usize::from(substitute == "grant"),
        );
        assert!(result.is_err(), "{substitute}");
        assert_eq!(
            store.dpop_recovery.0.lock().expect("state").history[0].disposition,
            DpopReplayClaimDisposition::ReservedBeforeDispatch
        );
    }
    let reservation = kernel
        .reserve_admitted_dispatch_credentials(
            &request,
            true,
            current_unix_timestamp(),
            Some(&admission),
            0,
        )
        .expect("exact prepared owner");
    drop(reservation);
    assert_eq!(
        store.dpop_recovery.0.lock().expect("state").history[0].disposition,
        DpopReplayClaimDisposition::ReleasedBeforeDispatch
    );
}

#[test]
fn dpop_cleanup_requires_a_confirmed_exact_release() {
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
                true,
                Some(&mut admission)
            )
            .allowed
    );
    store.dpop_recovery.0.lock().expect("state").release_noop = true;
    assert!(kernel
        .release_operation_owned_dpop_before_dispatch(Some(admission.operation()))
        .is_err());
    assert_eq!(
        store.dpop_recovery.0.lock().expect("state").history[0].disposition,
        DpopReplayClaimDisposition::ReservedBeforeDispatch
    );
    store.dpop_recovery.0.lock().expect("state").release_noop = false;
    kernel
        .release_operation_owned_dpop_before_dispatch(Some(admission.operation()))
        .expect("retry confirms release");
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
                true,
                Some(&mut admission)
            )
            .allowed
    );
    let first = kernel
        .reserve_admitted_dispatch_credentials(
            &request,
            true,
            current_unix_timestamp(),
            Some(&admission),
            0,
        )
        .expect("first owner");
    kernel
        .release_operation_owned_dpop_before_dispatch(Some(admission.operation()))
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
                true,
                Some(&mut admission)
            )
            .allowed
    );
    drop(first);
    let state = store.dpop_recovery.0.lock().expect("state");
    assert_eq!(state.history.len(), 2);
    assert_eq!(
        state.history[0].disposition,
        DpopReplayClaimDisposition::ReleasedBeforeDispatch
    );
    assert_eq!(
        state.history[1].disposition,
        DpopReplayClaimDisposition::ReservedBeforeDispatch
    );
}

#[test]
fn nested_flow_uses_operation_owned_dpop_acquisition() {
    let (kernel, request, store, calls) = fixture(Mode::Normal);
    let session = kernel
        .open_session("dpop-parent".into(), vec![])
        .expect("session");
    kernel.activate_session(&session).expect("active session");
    let parent = make_operation_context(&session, "parent-request", "dpop-parent");
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
        store.dpop_recovery.0.lock().expect("state").history.len(),
        1
    );
}
