use alloc::string::ToString;
use alloc::vec;

use serde_json::json;

use crate::economic_continuity::*;
use crate::economic_continuity_tests::{
    digest, head, inline_content, ready_effect_slot, resource_key, schema_validator, transition,
    unsigned_batch,
};
use crate::Keypair;

fn anchor_keypair() -> Keypair {
    Keypair::from_seed(&[0x41; 32])
}

fn pins() -> EconomicStateAnchorPins {
    EconomicStateAnchorPins {
        anchor_id: "anchor-1".to_string(),
        namespace: "economy-prod".to_string(),
        signer_key_id: "anchor-key-1".to_string(),
        signer_key_epoch: 1,
        signer_public_key: anchor_keypair().public_key(),
    }
}

fn signed_view(
    checkpoint_sequence: u64,
    checkpoint_digest: String,
    mut heads: Vec<EconomicResourceHeadV1>,
    mut absent_resource_keys: Vec<EconomicResourceKeyV1>,
    mut request_replays: Vec<EconomicRequestReplayV1>,
    mut absent_request_keys: Vec<EconomicRequestKeyV1>,
) -> Result<EconomicStateAnchorViewV1, EconomicStateAnchorError> {
    heads.sort_by(|left, right| left.resource_key.cmp(&right.resource_key));
    absent_resource_keys.sort_unstable();
    request_replays.sort_by(|left, right| left.request.key().cmp(&right.request.key()));
    absent_request_keys.sort_unstable();
    let mut view = EconomicStateAnchorViewV1 {
        schema: CHIO_ECONOMIC_STATE_ANCHOR_VIEW_SCHEMA.to_string(),
        anchor_id: "anchor-1".to_string(),
        namespace: "economy-prod".to_string(),
        checkpoint_sequence,
        checkpoint_digest,
        heads_root: String::new(),
        heads,
        absent_resource_keys,
        request_replays_root: String::new(),
        request_replays,
        absent_request_keys,
        observed_at: 500,
        signer_key_id: "anchor-key-1".to_string(),
        signer_key_epoch: 1,
        anchor_signature: String::new(),
    };
    view.seal(&anchor_keypair())?;
    Ok(view)
}

#[derive(Debug)]
struct DirectTransitionVerifier;

impl EconomicTransitionProofVerifier for DirectTransitionVerifier {
    fn verify_transition(
        &self,
        _current: Option<&EconomicResourceHeadV1>,
        transition: &EconomicStateTransitionV1,
    ) -> Result<EconomicTransitionAuthorizationV1, EconomicStateAnchorError> {
        if transition.transition_proof_digest == digest("rejected-proof") {
            return Err(EconomicStateAnchorError::TransitionProofRejected(
                transition.resource_key.clone(),
            ));
        }
        Ok(EconomicTransitionAuthorizationV1::Direct)
    }
}

#[test]
fn signed_anchor_view_authenticates_values_absence_and_pins(
) -> Result<(), Box<dyn core::error::Error>> {
    let current = head(resource_key("round-1"), 1, 1, None)?;
    let missing = resource_key("round-2");
    let view = signed_view(
        1,
        digest("checkpoint-1"),
        vec![current],
        vec![missing],
        Vec::new(),
        Vec::new(),
    )?;
    let verified = verify_economic_state_view(view.clone(), &pins())?;
    assert_eq!(verified.view(), &view);

    let mut wrong_namespace = pins();
    wrong_namespace.namespace = "economy-staging".to_string();
    assert!(verify_economic_state_view(view.clone(), &wrong_namespace).is_err());
    let mut wrong_key = pins();
    wrong_key.signer_public_key = Keypair::from_seed(&[0x42; 32]).public_key();
    assert!(verify_economic_state_view(view, &wrong_key).is_err());
    Ok(())
}

fn verified_successor_advance() -> Result<
    (
        VerifiedEconomicStateView,
        VerifiedEconomicStateBatchAdvance,
        EconomicResourceHeadV1,
    ),
    Box<dyn core::error::Error>,
> {
    let current = head(resource_key("round-1"), 1, 1, None)?;
    let current_digest = current.digest()?;
    let current_view = verify_economic_state_view(
        signed_view(
            1,
            digest("checkpoint-1"),
            vec![current],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?,
        &pins(),
    )?;
    let next = head(resource_key("round-1"), 2, 2, Some(current_digest.clone()))?;
    let mut batch = unsigned_batch(vec![transition(next.clone(), Some(current_digest))]);
    batch.checkpoint_sequence = 2;
    batch.previous_checkpoint_digest = Some(current_view.view().checkpoint_digest.clone());
    batch.issued_at = 501;
    batch.seal(&anchor_keypair())?;
    let advance = verify_economic_state_batch_advance(
        &current_view,
        batch,
        &pins(),
        &DirectTransitionVerifier,
    )?;
    Ok((current_view, advance, next))
}

#[test]
fn batch_advance_rechecks_current_heads_sequence_signature_and_consumer_proofs(
) -> Result<(), Box<dyn core::error::Error>> {
    let (current_view, advance, next) = verified_successor_advance()?;
    assert_eq!(advance.batch().checkpoint_sequence, 2);
    reverify_economic_state_batch_advance(&advance, &pins(), &DirectTransitionVerifier)?;

    let committed = verify_economic_state_view(
        signed_view(
            advance.batch().checkpoint_sequence,
            advance.batch().checkpoint_digest.clone(),
            vec![next],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?,
        &pins(),
    )?;
    verify_economic_state_batch_commit(&advance, &committed, &pins())?;

    let unrelated = verify_economic_state_view(
        signed_view(
            advance.batch().checkpoint_sequence,
            digest("unrelated-checkpoint"),
            committed.view().heads.clone(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?,
        &pins(),
    )?;
    assert!(verify_economic_state_batch_commit(&advance, &unrelated, &pins()).is_err());

    let mut stale = advance.batch().clone();
    stale.previous_checkpoint_digest = Some(digest("stale-checkpoint"));
    stale.seal(&anchor_keypair())?;
    assert!(verify_economic_state_batch_advance(
        &current_view,
        stale,
        &pins(),
        &DirectTransitionVerifier,
    )
    .is_err());

    let mut rejected = advance.batch().clone();
    rejected.transitions[0].transition_proof_digest = digest("rejected-proof");
    rejected.seal(&anchor_keypair())?;
    assert!(verify_economic_state_batch_advance(
        &current_view,
        rejected,
        &pins(),
        &DirectTransitionVerifier,
    )
    .is_err());
    Ok(())
}

#[test]
fn retained_request_mapping_rejects_conflict_before_batch_cas(
) -> Result<(), Box<dyn core::error::Error>> {
    let slot = ready_effect_slot()?;
    let retained = EconomicRequestReplayV1 {
        request: slot.request.clone(),
        operation_id: slot.operation_id.clone(),
        effect_slot_ids: vec![slot.slot_id.clone()],
    };
    let view = verify_economic_state_view(
        signed_view(
            1,
            digest("checkpoint-1"),
            Vec::new(),
            vec![resource_key("round-1")],
            vec![retained.clone()],
            Vec::new(),
        )?,
        &pins(),
    )?;
    assert_eq!(
        verify_economic_request_replay(&view, &retained)?,
        EconomicRequestReplayDisposition::Retained(retained.clone())
    );
    let mut conflict = retained.clone();
    conflict.request.request_binding_digest = digest("conflicting-request");
    assert!(matches!(
        verify_economic_request_replay(&view, &conflict),
        Err(EconomicStateAnchorError::RequestReplayConflict(_))
    ));

    let conflicting_view = signed_view(
        1,
        digest("checkpoint-1"),
        Vec::new(),
        vec![resource_key("round-1")],
        vec![conflict],
        Vec::new(),
    )?;
    assert_ne!(
        view.view().request_replays_root,
        conflicting_view.request_replays_root
    );
    Ok(())
}

#[derive(Debug)]
struct FrostTransitionVerifier {
    frost: EconomicFrostBindingV1,
}

impl EconomicTransitionProofVerifier for FrostTransitionVerifier {
    fn verify_transition(
        &self,
        _current: Option<&EconomicResourceHeadV1>,
        _transition: &EconomicStateTransitionV1,
    ) -> Result<EconomicTransitionAuthorizationV1, EconomicStateAnchorError> {
        Ok(EconomicTransitionAuthorizationV1::NOfM {
            frost: self.frost.clone(),
        })
    }
}

#[test]
fn n_of_m_transition_verifier_binds_the_complete_frost_authorization(
) -> Result<(), Box<dyn core::error::Error>> {
    let current = head(resource_key("round-1"), 1, 1, None)?;
    let current_digest = current.digest()?;
    let current_view = verify_economic_state_view(
        signed_view(
            1,
            digest("checkpoint-1"),
            vec![current],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?,
        &pins(),
    )?;
    let frost = EconomicFrostBindingV1 {
        authorization_slot_id: digest("authorization-slot"),
        authorization_id: digest("authorization"),
        action_digest: digest("action"),
        signed_envelope_digest: digest("signed-envelope"),
    };
    let mut next = head(resource_key("round-1"), 2, 2, Some(current_digest.clone()))?;
    next.frost = Some(frost.clone());
    let mut batch = unsigned_batch(vec![transition(next, Some(current_digest))]);
    batch.checkpoint_sequence = 2;
    batch.previous_checkpoint_digest = Some(current_view.view().checkpoint_digest.clone());
    batch.seal(&anchor_keypair())?;
    verify_economic_state_batch_advance(
        &current_view,
        batch.clone(),
        &pins(),
        &FrostTransitionVerifier {
            frost: frost.clone(),
        },
    )?;

    let mut mismatched = frost;
    mismatched.authorization_id = digest("different-authorization");
    assert!(verify_economic_state_batch_advance(
        &current_view,
        batch,
        &pins(),
        &FrostTransitionVerifier { frost: mismatched },
    )
    .is_err());
    Ok(())
}

#[derive(Debug)]
struct MatchingAdmissionHandoff;

impl EconomicAdmissionHandoffVerifier for MatchingAdmissionHandoff {
    fn verify_operation_active(&self, operation_id: &str) -> Result<(), EconomicStateAnchorError> {
        if operation_id == digest("operation-1") {
            Ok(())
        } else {
            Err(EconomicStateAnchorError::AdmissionHandoffRejected)
        }
    }

    fn verify_handoff(
        &self,
        operation_id: &str,
        handoff: &EconomicAdmissionHandoffV1,
    ) -> Result<(), EconomicStateAnchorError> {
        if operation_id == digest("operation-1")
            && handoff.state == EconomicAdmissionHandoffStateV1::MutationSubmitted
            && handoff.operation_version == 4
            && handoff.lifecycle_fence == 9
        {
            Ok(())
        } else {
            Err(EconomicStateAnchorError::AdmissionHandoffRejected)
        }
    }
}

fn dispatch_advance() -> Result<
    (
        VerifiedEconomicEffectDispatchAdvance,
        EconomicEffectSlotV1,
        EconomicResourceHeadV1,
    ),
    Box<dyn core::error::Error>,
> {
    let ready = ready_effect_slot()?;
    let ready_content = inline_content(serde_json::to_value(&ready)?);
    let ready_head = EconomicResourceHeadV1 {
        schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_string(),
        anchor_id: ready.anchor_id.clone(),
        namespace: ready.namespace.clone(),
        resource_key: ready.resource_head_key(),
        head_version: 1,
        resource_version: 1,
        lifecycle_fence: 1,
        lifecycle_state: "ready".to_string(),
        state_digest: ready_content.digest()?,
        state: ready_content,
        operation_id: Some(ready.operation_id.clone()),
        effect_idempotency_key: Some(ready.idempotency_key.clone()),
        frost: None,
        terminal_result: None,
        trusted_clock_high_water: 500,
        predecessor_digest: None,
    };
    let ready_head_digest = ready_head.digest()?;
    let current_view = verify_economic_state_view(
        signed_view(
            1,
            digest("checkpoint-1"),
            vec![ready_head],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?,
        &pins(),
    )?;
    let mut dispatched = ready;
    dispatched.state = EconomicEffectStateV1::DispatchCommitted;
    let dispatched_content = inline_content(serde_json::to_value(&dispatched)?);
    let dispatched_head = EconomicResourceHeadV1 {
        schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_string(),
        anchor_id: dispatched.anchor_id.clone(),
        namespace: dispatched.namespace.clone(),
        resource_key: dispatched.resource_head_key(),
        head_version: 2,
        resource_version: 2,
        lifecycle_fence: 2,
        lifecycle_state: "dispatch_committed".to_string(),
        state_digest: dispatched_content.digest()?,
        state: dispatched_content,
        operation_id: Some(dispatched.operation_id.clone()),
        effect_idempotency_key: Some(dispatched.idempotency_key.clone()),
        frost: None,
        terminal_result: None,
        trusted_clock_high_water: 501,
        predecessor_digest: Some(ready_head_digest.clone()),
    };
    let mut batch = unsigned_batch(vec![transition(
        dispatched_head.clone(),
        Some(ready_head_digest),
    )]);
    batch.checkpoint_sequence = 2;
    batch.previous_checkpoint_digest = Some(current_view.view().checkpoint_digest.clone());
    batch.operation_id = Some(dispatched.operation_id.clone());
    batch.issued_at = 501;
    batch.seal(&anchor_keypair())?;
    let advance = verify_economic_state_batch_advance(
        &current_view,
        batch,
        &pins(),
        &DirectTransitionVerifier,
    )?;
    let dispatch = verify_economic_effect_dispatch_advance(advance, &MatchingAdmissionHandoff)?;
    Ok((dispatch, dispatched, dispatched_head))
}

#[test]
fn only_signed_cas_commit_mints_effect_dispatch_authority(
) -> Result<(), Box<dyn core::error::Error>> {
    let (advance, dispatched, dispatched_head) = dispatch_advance()?;
    let committed_view = verify_economic_state_view(
        signed_view(
            2,
            advance.batch().checkpoint_digest.clone(),
            vec![dispatched_head],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?,
        &pins(),
    )?;
    let commit = EconomicEffectDispatchCommitV1::sign(
        &advance,
        &committed_view,
        digest("cas-nonce"),
        502,
        "anchor-key-1",
        1,
        &anchor_keypair(),
    )?;
    let authority =
        verify_economic_effect_dispatch_commit(advance, &committed_view, commit, &pins())?;
    assert_eq!(authority.slot(), &dispatched);

    let (forged_advance, _, forged_head) = dispatch_advance()?;
    let forged_view = verify_economic_state_view(
        signed_view(
            2,
            forged_advance.batch().checkpoint_digest.clone(),
            vec![forged_head],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?,
        &pins(),
    )?;
    let forged = EconomicEffectDispatchCommitV1::sign(
        &forged_advance,
        &forged_view,
        digest("cas-nonce"),
        502,
        "anchor-key-1",
        1,
        &Keypair::from_seed(&[0x55; 32]),
    )?;
    assert!(
        verify_economic_effect_dispatch_commit(forged_advance, &forged_view, forged, &pins(),)
            .is_err()
    );
    Ok(())
}

#[derive(Debug)]
struct CancellationVerifier {
    kind: EconomicNoEffectKindV1,
}

impl EconomicEffectCancellationProofVerifier for CancellationVerifier {
    fn verify_cancellation(
        &self,
        current: &EconomicEffectSlotV1,
        next: &EconomicEffectSlotV1,
    ) -> Result<EconomicNoEffectKindV1, EconomicStateAnchorError> {
        if current.slot_id != next.slot_id || current.state != EconomicEffectStateV1::Ready {
            return Err(EconomicStateAnchorError::EffectCancellationRejected(
                "cancellation slot binding changed",
            ));
        }
        Ok(self.kind)
    }
}

fn cancellation_advance(
    kind: EconomicNoEffectKindV1,
    admission: &dyn EconomicAdmissionHandoffVerifier,
) -> Result<
    (
        VerifiedEconomicEffectCancellationAdvance,
        EconomicEffectSlotV1,
        EconomicResourceHeadV1,
    ),
    Box<dyn core::error::Error>,
> {
    let ready = ready_effect_slot()?;
    let ready_content = inline_content(serde_json::to_value(&ready)?);
    let ready_head = EconomicResourceHeadV1 {
        schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_string(),
        anchor_id: ready.anchor_id.clone(),
        namespace: ready.namespace.clone(),
        resource_key: ready.resource_head_key(),
        head_version: 1,
        resource_version: 1,
        lifecycle_fence: 1,
        lifecycle_state: "ready".to_string(),
        state_digest: ready_content.digest()?,
        state: ready_content,
        operation_id: Some(ready.operation_id.clone()),
        effect_idempotency_key: Some(ready.idempotency_key.clone()),
        frost: None,
        terminal_result: None,
        trusted_clock_high_water: 500,
        predecessor_digest: None,
    };
    let ready_head_digest = ready_head.digest()?;
    let current_view = verify_economic_state_view(
        signed_view(
            1,
            digest("checkpoint-1"),
            vec![ready_head],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?,
        &pins(),
    )?;
    let proof = inline_content(json!({"cancellation": "anchor-cas"}));
    let mut cancelled = ready;
    cancelled.state = EconomicEffectStateV1::NoEffect;
    cancelled.terminal = Some(EconomicEffectTerminalV1::NoEffect {
        kind,
        proof_id: "anchor-cancellation-1".to_string(),
        proof_digest: proof.digest()?,
        proof,
    });
    let cancelled_content = inline_content(serde_json::to_value(&cancelled)?);
    let cancelled_head = EconomicResourceHeadV1 {
        schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_string(),
        anchor_id: cancelled.anchor_id.clone(),
        namespace: cancelled.namespace.clone(),
        resource_key: cancelled.resource_head_key(),
        head_version: 2,
        resource_version: 2,
        lifecycle_fence: 2,
        lifecycle_state: "no_effect".to_string(),
        state_digest: cancelled_content.digest()?,
        state: cancelled_content,
        operation_id: Some(cancelled.operation_id.clone()),
        effect_idempotency_key: Some(cancelled.idempotency_key.clone()),
        frost: None,
        terminal_result: None,
        trusted_clock_high_water: 501,
        predecessor_digest: Some(ready_head_digest.clone()),
    };
    let mut batch = unsigned_batch(vec![transition(
        cancelled_head.clone(),
        Some(ready_head_digest),
    )]);
    batch.checkpoint_sequence = 2;
    batch.previous_checkpoint_digest = Some(current_view.view().checkpoint_digest.clone());
    batch.operation_id = Some(cancelled.operation_id.clone());
    batch.issued_at = 501;
    batch.seal(&anchor_keypair())?;
    let advance = verify_economic_state_batch_advance(
        &current_view,
        batch,
        &pins(),
        &DirectTransitionVerifier,
    )?;
    let cancellation = verify_economic_effect_cancellation_advance(
        advance,
        &CancellationVerifier { kind },
        admission,
    )?;
    Ok((cancellation, cancelled, cancelled_head))
}

#[test]
fn only_verified_cancellation_cas_mints_no_dispatch_authority(
) -> Result<(), Box<dyn core::error::Error>> {
    let (advance, cancelled, cancelled_head) = cancellation_advance(
        EconomicNoEffectKindV1::PermanentlyNotApplied,
        &MatchingAdmissionHandoff,
    )?;
    let committed = verify_economic_state_view(
        signed_view(
            2,
            advance.batch().checkpoint_digest.clone(),
            vec![cancelled_head.clone()],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?,
        &pins(),
    )?;
    let authority = verify_economic_effect_cancellation_commit(advance, &committed, &pins())?;
    assert_eq!(authority.slot(), &cancelled);
    assert_eq!(
        authority.kind(),
        EconomicNoEffectKindV1::PermanentlyNotApplied
    );
    assert_eq!(
        authority.checkpoint_digest(),
        committed.view().checkpoint_digest
    );
    assert_eq!(authority.expected_head_version(), 1);
    assert_eq!(authority.resulting_head_version(), 2);
    assert_eq!(authority.expected_lifecycle_fence(), 1);
    assert_eq!(authority.resulting_lifecycle_fence(), 2);
    assert_eq!(
        authority.expected_head_digest(),
        cancelled_head
            .predecessor_digest
            .as_deref()
            .ok_or("predecessor")?
    );
    assert_eq!(authority.resulting_head_digest(), cancelled_head.digest()?);

    assert!(cancellation_advance(
        EconomicNoEffectKindV1::VerifiedTransportNotAccepted,
        &RejectingAdmissionHandoff,
    )
    .is_err());
    assert!(cancellation_advance(
        EconomicNoEffectKindV1::PreDispatch,
        &RejectingAdmissionHandoff,
    )
    .is_err());
    Ok(())
}

#[derive(Debug)]
struct RejectingAdmissionHandoff;

impl EconomicAdmissionHandoffVerifier for RejectingAdmissionHandoff {
    fn verify_operation_active(&self, _operation_id: &str) -> Result<(), EconomicStateAnchorError> {
        Err(EconomicStateAnchorError::AdmissionHandoffRejected)
    }

    fn verify_handoff(
        &self,
        _operation_id: &str,
        _handoff: &EconomicAdmissionHandoffV1,
    ) -> Result<(), EconomicStateAnchorError> {
        Err(EconomicStateAnchorError::AdmissionHandoffRejected)
    }
}

#[test]
fn anchor_view_and_dispatch_commit_wire_schemas_match_signed_values(
) -> Result<(), Box<dyn core::error::Error>> {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../spec/schemas/chio-economy")
        .canonicalize()?;
    let view_validator = schema_validator(&root, "anchor-view.v1.json")?;
    let dispatch_validator = schema_validator(&root, "effect-dispatch-commit.v1.json")?;
    let view = signed_view(
        1,
        digest("checkpoint-1"),
        vec![head(resource_key("round-1"), 1, 1, None)?],
        vec![resource_key("round-2")],
        Vec::new(),
        Vec::new(),
    )?;
    let view_json = serde_json::to_value(&view)?;
    assert!(view_validator.is_valid(&view_json));

    let (advance, _, dispatched_head) = dispatch_advance()?;
    let committed_view = verify_economic_state_view(
        signed_view(
            2,
            advance.batch().checkpoint_digest.clone(),
            vec![dispatched_head],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?,
        &pins(),
    )?;
    let commit = EconomicEffectDispatchCommitV1::sign(
        &advance,
        &committed_view,
        digest("cas-nonce"),
        502,
        "anchor-key-1",
        1,
        &anchor_keypair(),
    )?;
    let commit_json = serde_json::to_value(commit)?;
    assert!(dispatch_validator.is_valid(&commit_json));

    let mut unknown_view = view_json;
    unknown_view["schema"] = json!("chio.economy.anchor-view.v2");
    assert!(!view_validator.is_valid(&unknown_view));
    let mut tampered_commit = commit_json;
    tampered_commit["signerKeyEpoch"] = json!(0);
    assert!(!dispatch_validator.is_valid(&tampered_commit));
    Ok(())
}

#[derive(Debug)]
struct TargetEvidenceVerifier;

impl EconomicTargetStatusVerifier for TargetEvidenceVerifier {
    fn verify_status(
        &self,
        slot: &EconomicEffectSlotV1,
        evidence_digest: &str,
    ) -> Result<EconomicEffectTerminalV1, EconomicStateAnchorError> {
        if slot.target.target_id == "settlement-rail" && evidence_digest == digest("target-status")
        {
            let result = inline_content(json!({"transactionId": "tx-1"}));
            Ok(EconomicEffectTerminalV1::Completed {
                result_id: "tx-1".to_string(),
                result_digest: result.digest()?,
                result,
            })
        } else {
            Err(EconomicStateAnchorError::TargetStatusRejected)
        }
    }
}

#[derive(Debug)]
struct IdempotentTargetVerifier;

impl EconomicIdempotentTargetVerifier for IdempotentTargetVerifier {
    fn verify_qualification(
        &self,
        target: &EconomicEffectTargetV1,
        idempotency_key: &str,
    ) -> Result<(), EconomicStateAnchorError> {
        if target.qualification_digest == digest("target-qualification")
            && idempotency_key == digest("idempotency-key")
        {
            Ok(())
        } else {
            Err(EconomicStateAnchorError::IdempotentRecoveryRejected)
        }
    }
}

#[test]
fn target_status_and_idempotent_retry_require_separate_qualification(
) -> Result<(), Box<dyn core::error::Error>> {
    let mut slot = ready_effect_slot()?;
    slot.state = EconomicEffectStateV1::DispatchCommitted;
    let status =
        verify_economic_target_status(&slot, &digest("target-status"), &TargetEvidenceVerifier)?;
    assert_eq!(status.next_slot().state, EconomicEffectStateV1::Completed);
    let retry = verify_economic_idempotent_recovery(&slot, &IdempotentTargetVerifier)?;
    assert_eq!(retry.idempotency_key(), slot.idempotency_key);
    assert_eq!(retry.slot(), &slot);
    assert!(verify_economic_idempotent_recovery(&slot, &TargetEvidenceVerifier).is_err());
    Ok(())
}

impl EconomicIdempotentTargetVerifier for TargetEvidenceVerifier {
    fn verify_qualification(
        &self,
        _target: &EconomicEffectTargetV1,
        _idempotency_key: &str,
    ) -> Result<(), EconomicStateAnchorError> {
        Err(EconomicStateAnchorError::IdempotentRecoveryRejected)
    }
}

#[test]
fn readiness_is_false_for_missing_behind_ahead_and_divergent_views(
) -> Result<(), Box<dyn core::error::Error>> {
    let current = head(resource_key("round-1"), 1, 1, None)?;
    let current_digest = current.digest()?;
    let view = verify_economic_state_view(
        signed_view(
            3,
            digest("checkpoint-3"),
            vec![current],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?,
        &pins(),
    )?;
    let expectation = EconomicStateReadinessExpectation {
        checkpoint_sequence: 3,
        checkpoint_digest: digest("checkpoint-3"),
        heads: vec![EconomicExpectedHead {
            resource_key: resource_key("round-1"),
            head_digest: current_digest,
        }],
    };
    assert_eq!(
        assess_economic_state_readiness(&view, &expectation)?,
        EconomicStateReadiness::Ready
    );
    let mut behind = expectation.clone();
    behind.checkpoint_sequence = 4;
    assert_eq!(
        assess_economic_state_readiness(&view, &behind)?,
        EconomicStateReadiness::Behind
    );
    let mut ahead = expectation.clone();
    ahead.checkpoint_sequence = 2;
    assert_eq!(
        assess_economic_state_readiness(&view, &ahead)?,
        EconomicStateReadiness::Ahead
    );
    let mut divergent = expectation.clone();
    divergent.checkpoint_digest = digest("different-checkpoint");
    assert_eq!(
        assess_economic_state_readiness(&view, &divergent)?,
        EconomicStateReadiness::Divergent
    );
    let mut missing = expectation;
    missing.heads[0].resource_key = resource_key("round-2");
    assert_eq!(
        assess_economic_state_readiness(&view, &missing)?,
        EconomicStateReadiness::Missing
    );
    let oversized = EconomicStateReadinessExpectation {
        checkpoint_sequence: 3,
        checkpoint_digest: digest("checkpoint-3"),
        heads: (0..=MAX_ECONOMIC_TRANSITIONS)
            .map(|index| EconomicExpectedHead {
                resource_key: resource_key(&format!("round-{index:03}")),
                head_digest: digest(&format!("head-{index}")),
            })
            .collect(),
    };
    assert!(assess_economic_state_readiness(&view, &oversized).is_err());
    Ok(())
}
