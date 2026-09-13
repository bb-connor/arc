//! Adversarial coordinator-port responses, not physical SQLite qualification.

use super::*;
use crate::admission_operation::runtime_participant::RuntimeParticipantAuthorityBindingV1;
use crate::admission_operation::{AdmissionRecoveryLease, RuntimeReplaySourceSnapshotV1};
use crate::RuntimeParticipantClaimAuthority;
use chio_core::canonical::canonical_json_bytes;

#[derive(Clone, Copy, Debug, Default)]
pub(super) enum ClaimMode {
    #[default]
    Unsupported,
    Normal,
    NoOpSuccess,
    LoseAcknowledgement,
    PanicAfterCommit,
    WrongReference,
    WrongSuccessor,
    HistoryPanicAfterCommit,
}

impl TestRuntimeRecovery {
    pub(in super::super) fn activation(
        &self,
        binding: &RuntimeParticipantAuthorityBindingV1,
        fence: &StoreMutationFence,
    ) -> Result<RuntimeReplaySourceSnapshotV1, AdmissionOperationStoreError> {
        if !self.0.lock().expect("fixture").enabled {
            return Err(AdmissionOperationStoreError::Unavailable(
                "unsupported test source".into(),
            ));
        }
        // This is deliberately fabricated canonical data supplied by a trusted
        // test port. It neither seals a source nor proves activation.
        let body = serde_json::json!({
            "schema": "chio.runtime-replay-source-seal.v1",
            "binding": {
                "sourceId": "test-source",
                "runtimeAuthorityId": binding.runtime_authority_id(),
                "destinationAuthorityId": fence.store_uuid,
            },
            "device": "1", "inode": "2", "linkCount": 1,
            "barrierSha256": "b".repeat(64),
            "markerCounts": [0, 0, 0], "markers": [],
        });
        let mut preimage = b"chio.runtime-replay-source-seal.v1\0".to_vec();
        preimage.extend(canonical_json_bytes(&body).expect("canonical body"));
        RuntimeReplaySourceSnapshotV1::from_canonical_bytes(
            &canonical_json_bytes(&serde_json::json!({
                "body": body, "inventorySha256": sha256_hex(&preimage),
            }))
            .expect("canonical snapshot"),
        )
    }

    pub(in super::super) fn claim(
        &self,
        store: &TestAdmissionOperationStore,
        original: &AdmissionOperationV1,
        lease: &AdmissionRecoveryLease,
        intent: &RuntimeParticipantClaimIntentV1,
        now: u64,
    ) -> Result<
        (AdmissionOperationV1, RuntimeParticipantClaimReferenceV1),
        AdmissionOperationStoreError,
    > {
        let mode = self.0.lock().expect("fixture").claim_mode;
        if matches!(mode, ClaimMode::Unsupported) {
            return Err(AdmissionOperationStoreError::Unavailable(
                "unsupported test claim".into(),
            ));
        }
        let reference = RuntimeParticipantClaimReferenceV1::new(
            original.binding().operation_id().clone(),
            intent.episode_id().clone(),
            digest('c'),
        );
        if matches!(mode, ClaimMode::NoOpSuccess) {
            return Ok((original.clone(), reference));
        }
        let command = AdmissionOperationCommand::new(
            original.binding().operation_id().clone(),
            original.version(),
            lease.clone(),
            vec![AdmissionAttachment::RuntimeParticipantLedgerDigest(digest(
                'a',
            ))],
            Some(original.state()),
            None,
            None,
        )?;
        let updated = original.apply_command(&command, now)?.into_operation();
        store.state.lock().expect("fixture").operation = Some(updated.clone());
        {
            let mut state = self.0.lock().expect("fixture");
            state.history = Some(vec![RuntimeParticipantClaimHistoryV1 {
                intent: intent.clone(),
                reference: reference.clone(),
                disposition: RuntimeParticipantDisposition::ReservedBeforeDispatch,
            }]);
            if matches!(mode, ClaimMode::HistoryPanicAfterCommit) {
                state.history_panics = 1;
            }
        }
        match mode {
            ClaimMode::LoseAcknowledgement => Err(AdmissionOperationStoreError::OutcomeUnknown(
                "injected lost claim acknowledgement".into(),
            )),
            ClaimMode::PanicAfterCommit => panic!("injected committed claim callback panic"),
            ClaimMode::WrongReference => Ok((
                updated,
                RuntimeParticipantClaimReferenceV1::new(
                    reference.operation_id().clone(),
                    reference.episode_id().clone(),
                    digest('f'),
                ),
            )),
            ClaimMode::WrongSuccessor => Ok((original.clone(), reference)),
            _ => Ok((updated, reference)),
        }
    }
}

struct ClaimingVerifier(RuntimeParticipantAuthorityBindingV1);

impl RuntimeAdmissionHook for ClaimingVerifier {
    fn name(&self) -> &str {
        "claim-boundary-test"
    }

    fn runtime_participant_binding(&self) -> Option<&RuntimeParticipantAuthorityBindingV1> {
        Some(&self.0)
    }

    fn requires_dispatch_revalidation(&self) -> bool {
        true
    }

    fn evaluate(
        &self,
        _: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        panic!("legacy evaluation is outside this test profile");
    }

    fn evaluate_operation_owned(
        &self,
        _: &RuntimeAdmissionContext<'_>,
        authority: &RuntimeParticipantClaimAuthority<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        assert_eq!(authority.binding(), &self.0);
        assert_eq!(authority.grant_index(), 0);
        assert_eq!(authority.phase(), RuntimeParticipantPhase::Dispatch);
        // Deliberately swallow every callback failure. Kernel completion must
        // remain fail-closed independently of the verifier's returned verdict.
        let _ = authority.claim(digest('b'), vec![]);
        Ok(RuntimeAdmissionDecision::allow(None))
    }
}

fn exercise(mode: ClaimMode, allowed: bool) {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("runtime-claim-boundary");
    let verifier = Arc::new(ClaimingVerifier(RuntimeParticipantAuthorityBindingV1::new(
        AdmissionIdentifier::try_new("runtime", "test-runtime").expect("runtime"),
        AdmissionIdentifier::try_new("source", "test-source").expect("source"),
    )));
    kernel.set_runtime_admission_hook(verifier.clone());
    *store.runtime_recovery.0.lock().expect("fixture") = RecoveryState {
        enabled: true,
        history: Some(vec![]),
        claim_mode: mode,
        ..RecoveryState::default()
    };
    let matching = resolve_required_matching_grants(
        &request.capability,
        &request.tool_name,
        &request.server_id,
        &request.arguments,
        request.model_metadata.as_ref(),
    )
    .expect("matching");
    let now = current_unix_timestamp_ms();
    let mut admission = kernel
        .begin_durable_tool_admission(&request, &matching, now)
        .expect("begin")
        .expect("durable");
    let original = admission.operation().clone();
    let context = RuntimeAdmissionContext {
        request: &request,
        extra_metadata: None,
        now_unix_secs: now / 1000,
        now_unix_ms: now,
        matched_grant_index: Some(0),
        local_kernel_id: "test-kernel".into(),
    };
    let result = kernel.evaluate_operation_owned_runtime_hook(
        verifier.as_ref(),
        &context,
        &mut admission,
        &verifier.0,
    );
    assert_eq!(
        result.as_ref().is_ok_and(|decision| decision.allowed),
        allowed,
        "{mode:?}: {result:?}"
    );
    assert_eq!(admission.operation(), &store.operation(), "{mode:?}");
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    {
        let state = store.runtime_recovery.0.lock().expect("fixture");
        let history = state.history.as_ref().expect("history");
        if matches!(mode, ClaimMode::NoOpSuccess) {
            assert_eq!(admission.operation(), &original);
            assert!(history.is_empty());
            assert_eq!(state.release_calls, 0);
        } else {
            assert!(admission.operation().version() > original.version());
            assert_eq!(history.len(), 1);
            assert_eq!(
                history[0].disposition,
                if allowed {
                    RuntimeParticipantDisposition::ReservedBeforeDispatch
                } else {
                    RuntimeParticipantDisposition::ReleasedBeforeDispatch
                }
            );
            assert_eq!(state.release_calls, usize::from(!allowed));
        }
    }
    // A callback panic must not poison the mutation sequencer or hide custody
    // behind the old operation version. Normal recovery remains usable.
    compensate(&kernel, &store).expect("recover after hook completion");
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}

#[test]
fn runtime_lease_panic_denies_swallowed_failure_and_preserves_recovery() {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("runtime-lease-panic");
    let verifier = Arc::new(ClaimingVerifier(RuntimeParticipantAuthorityBindingV1::new(
        AdmissionIdentifier::try_new("runtime", "test-runtime").expect("runtime"),
        AdmissionIdentifier::try_new("source", "test-source").expect("source"),
    )));
    kernel.set_runtime_admission_hook(verifier.clone());
    *store.runtime_recovery.0.lock().expect("fixture") = RecoveryState {
        enabled: true,
        history: Some(vec![]),
        claim_mode: ClaimMode::Normal,
        ..RecoveryState::default()
    };
    let now = current_unix_timestamp_ms();
    let mut admission = kernel
        .begin_durable_tool_admission(
            &request,
            &security_binding::matching(&request).expect("matching"),
            now,
        )
        .expect("begin")
        .expect("durable");
    let original = admission.operation().clone();
    let context = RuntimeAdmissionContext {
        request: &request,
        extra_metadata: None,
        now_unix_secs: now / 1000,
        now_unix_ms: now,
        matched_grant_index: Some(0),
        local_kernel_id: "test-kernel".into(),
    };
    store
        .recovery_lease_faults
        .arm(recovery_lease::Stage::ClaimAfter);
    assert!(
        kernel
            .evaluate_operation_owned_runtime_hook(
                verifier.as_ref(),
                &context,
                &mut admission,
                &verifier.0
            )
            .is_err(),
        "a verifier cannot suppress failed recovery qualification"
    );
    assert_eq!(admission.operation(), &original);
    assert_eq!(store.operation(), original);
    {
        let state = store.runtime_recovery.0.lock().expect("fixture");
        assert!(state.history.as_ref().expect("history").is_empty());
        assert_eq!(state.release_calls, 0);
    }
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    // This traverses the real kernel mutation sequencer, not a fixture lock.
    compensate(&kernel, &store).expect("qualification panic must not poison later recovery");
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}

#[test]
fn runtime_claim_allow_requires_exact_acknowledged_physical_readback() {
    exercise(ClaimMode::Normal, true);
    for mode in [
        ClaimMode::NoOpSuccess,
        ClaimMode::WrongReference,
        ClaimMode::WrongSuccessor,
    ] {
        exercise(mode, false);
    }
}

#[test]
fn runtime_claim_lost_ack_and_callback_panics_deny_without_losing_recovery() {
    for mode in [
        ClaimMode::LoseAcknowledgement,
        ClaimMode::PanicAfterCommit,
        ClaimMode::HistoryPanicAfterCommit,
    ] {
        exercise(mode, false);
    }
}
