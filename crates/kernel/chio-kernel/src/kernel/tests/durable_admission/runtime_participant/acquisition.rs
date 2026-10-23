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

#[test]
fn cleanup_fault_exhausted_budget_preserves_unconfirmed_runtime_owner() {
    for nested in [false, true] {
        exhausted_budget_with_unconfirmed_runtime_release(nested);
    }
}

fn exhausted_budget_with_unconfirmed_runtime_release(nested: bool) {
    let mut grant = make_grant("durable-server", "mutate");
    grant.max_invocations = Some(1);
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture_with_grants("runtime-release-exhausted", vec![grant]);
    kernel.set_runtime_admission_hook(Arc::new(ClaimingVerifier(
        RuntimeParticipantAuthorityBindingV1::new(
            AdmissionIdentifier::try_new("runtime", "test-runtime").expect("runtime"),
            AdmissionIdentifier::try_new("source", "test-source").expect("source"),
        ),
    )));
    *store.runtime_recovery.0.lock().expect("fixture") = RecoveryState {
        enabled: true,
        history: Some(vec![]),
        claim_mode: ClaimMode::Normal,
        release_mode: ReleaseMode::NoOp,
        ..RecoveryState::default()
    };
    assert!(kernel
        .budget_store
        .try_increment(&request.capability.id, 0, Some(1))
        .expect("consume the only invocation"));
    let result = if nested {
        let session = kernel
            .open_session(request.agent_id.clone(), Vec::new())
            .expect("session");
        kernel.activate_session(&session).expect("active session");
        let parent = make_operation_context(&session, "exhausted-parent", &request.agent_id);
        kernel
            .begin_session_request(&parent, OperationKind::ToolCall, true)
            .expect("parent request");
        kernel.evaluate_tool_call_with_nested_flow_client(
            &parent,
            &request,
            &mut NoopNestedFlowClient,
            None,
        )
    } else {
        kernel.evaluate_tool_call_blocking(&request)
    };
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    // The unreleased participant keeps the operation on its recovery path.
    let retained = store.operation();
    assert_eq!(
        retained.state(),
        AdmissionOperationState::BrokerAttemptRegistered
    );
    assert!(retained.dispatch_commit().is_none());
    assert!(retained.terminal_replay().is_none());
    let state = store.runtime_recovery.0.lock().expect("fixture");
    assert_eq!(state.release_calls, 1);
    assert_eq!(
        state.history.as_ref().expect("history")[0].disposition,
        RuntimeParticipantDisposition::ReservedBeforeDispatch
    );
    drop(state);
    let error = result.expect_err("the retained runtime participant owns the terminal");
    assert!(
        matches!(error, KernelError::BudgetExhausted(_)),
        "{error:?}"
    );
    assert!(kernel.receipt_log().is_empty());
    assert_eq!(store.operation(), retained);
}

/// An operation-owned hook that claims its runtime reservation and then
/// returns a decision naming a reserved key other than `chio_runtime`.
struct ForgingClaimingVerifier {
    binding: RuntimeParticipantAuthorityBindingV1,
    metadata: serde_json::Value,
    allow: bool,
}

impl RuntimeAdmissionHook for ForgingClaimingVerifier {
    fn name(&self) -> &str {
        "forging-claim-test"
    }

    fn runtime_participant_binding(&self) -> Option<&RuntimeParticipantAuthorityBindingV1> {
        Some(&self.binding)
    }

    fn requires_dispatch_revalidation(&self) -> bool {
        true
    }

    fn evaluate(
        &self,
        _: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        panic!("evaluation without operation-owned custody is outside this test profile");
    }

    fn evaluate_operation_owned(
        &self,
        _: &RuntimeAdmissionContext<'_>,
        authority: &RuntimeParticipantClaimAuthority<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        authority.claim(digest('b'), vec![])?;
        let metadata = Some(self.metadata.clone());
        Ok(if self.allow {
            RuntimeAdmissionDecision::allow(metadata)
        } else {
            RuntimeAdmissionDecision::deny("operation-owned hook policy denies", metadata)
        })
    }
}

fn operation_owned_hook_is_refused_and_released(
    metadata: serde_json::Value,
    allow: bool,
    expected_reason: &str,
    absent_key: Option<&str>,
) {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("runtime-claim-refused-metadata");
    kernel.set_runtime_admission_hook(Arc::new(ForgingClaimingVerifier {
        binding: RuntimeParticipantAuthorityBindingV1::new(
            AdmissionIdentifier::try_new("runtime", "test-runtime").expect("runtime"),
            AdmissionIdentifier::try_new("source", "test-source").expect("source"),
        ),
        metadata: metadata.clone(),
        allow,
    }));
    *store.runtime_recovery.0.lock().expect("fixture") = RecoveryState {
        enabled: true,
        history: Some(vec![]),
        claim_mode: ClaimMode::Normal,
        ..RecoveryState::default()
    };
    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("runtime admission denial");
    assert_eq!(response.verdict, Verdict::Deny, "{metadata}");
    assert_eq!(
        response.reason.as_deref(),
        Some(expected_reason),
        "{metadata}"
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0, "{metadata}");
    let signed = response.receipt.metadata.as_ref().expect("denial metadata");
    assert!(signed.is_object(), "{metadata}");
    assert!(signed.get("receipt_context").is_some(), "{metadata}");
    if let Some(key) = absent_key {
        assert!(signed.get(key).is_none(), "{metadata}");
    }
    let state = store.runtime_recovery.0.lock().expect("fixture");
    let history = state.history.as_ref().expect("history");
    assert_eq!(history.len(), 1, "{metadata}");
    assert_eq!(
        history[0].disposition,
        RuntimeParticipantDisposition::ReleasedBeforeDispatch,
        "{metadata}"
    );
    assert_eq!(state.release_calls, 1, "{metadata}");
}

fn forged(key: &str) -> serde_json::Value {
    serde_json::json!({
        "chio_runtime": {"admission_id": "operation-owned"},
        key: {"hook": "other-hook", "accepted": false}
    })
}

const NON_OBJECT_REFUSAL: &str = "runtime admission hook metadata must be a JSON object";

#[test]
fn operation_owned_allow_naming_a_reserved_key_is_refused_and_released() {
    operation_owned_hook_is_refused_and_released(
        forged("delivery_contract"),
        true,
        "delivery_contract is reserved for kernel-derived receipts",
        Some("delivery_contract"),
    );
}

#[test]
fn operation_owned_deny_forging_the_kernel_runtime_admission_record_is_refused_and_released() {
    operation_owned_hook_is_refused_and_released(
        forged("runtime_admission"),
        false,
        "runtime_admission is reserved for kernel-derived receipts",
        Some("runtime_admission"),
    );
}

#[test]
fn operation_owned_allow_with_null_metadata_is_refused_and_released() {
    operation_owned_hook_is_refused_and_released(
        serde_json::Value::Null,
        true,
        NON_OBJECT_REFUSAL,
        None,
    );
}

#[test]
fn operation_owned_allow_with_array_metadata_is_refused_and_released() {
    operation_owned_hook_is_refused_and_released(
        serde_json::json!(["chio_runtime"]),
        true,
        NON_OBJECT_REFUSAL,
        None,
    );
}

#[test]
fn operation_owned_allow_with_scalar_metadata_is_refused_and_released() {
    operation_owned_hook_is_refused_and_released(
        serde_json::json!(7),
        true,
        NON_OBJECT_REFUSAL,
        None,
    );
}

#[test]
fn operation_owned_deny_with_null_metadata_is_refused_and_released() {
    operation_owned_hook_is_refused_and_released(
        serde_json::Value::Null,
        false,
        NON_OBJECT_REFUSAL,
        None,
    );
}

#[test]
fn operation_owned_deny_with_array_metadata_is_refused_and_released() {
    operation_owned_hook_is_refused_and_released(
        serde_json::json!(["chio_runtime"]),
        false,
        NON_OBJECT_REFUSAL,
        None,
    );
}

#[test]
fn operation_owned_deny_with_scalar_metadata_is_refused_and_released() {
    operation_owned_hook_is_refused_and_released(
        serde_json::json!(7),
        false,
        NON_OBJECT_REFUSAL,
        None,
    );
}
