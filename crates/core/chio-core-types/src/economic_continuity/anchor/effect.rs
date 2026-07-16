use super::*;

pub trait EconomicEffectCancellationProofVerifier: Send + Sync {
    fn verify_cancellation(
        &self,
        current: &EconomicEffectSlotV1,
        next: &EconomicEffectSlotV1,
    ) -> Result<EconomicNoEffectKindV1, EconomicStateAnchorError>;
}

#[derive(Debug)]
pub struct VerifiedEconomicEffectCancellationAdvance {
    advance: VerifiedEconomicStateBatchAdvance,
    slot: EconomicEffectSlotV1,
    kind: EconomicNoEffectKindV1,
}

impl VerifiedEconomicEffectCancellationAdvance {
    pub fn batch(&self) -> &EconomicStateBatchV1 {
        self.advance.batch()
    }

    pub fn slot(&self) -> &EconomicEffectSlotV1 {
        &self.slot
    }

    pub const fn kind(&self) -> EconomicNoEffectKindV1 {
        self.kind
    }
}

pub fn verify_economic_effect_cancellation_advance(
    advance: VerifiedEconomicStateBatchAdvance,
    verifier: &dyn EconomicEffectCancellationProofVerifier,
    admission: &dyn EconomicAdmissionHandoffVerifier,
) -> Result<VerifiedEconomicEffectCancellationAdvance, EconomicStateAnchorError> {
    if advance.batch.transitions.len() != 1
        || !advance.batch.effect_slots.is_empty()
        || !advance.batch.request_replays.is_empty()
        || advance.batch.transitions[0].prepared_effect.is_some()
    {
        return Err(EconomicStateAnchorError::EffectCancellationRejected(
            "cancellation must advance exactly one retained effect slot",
        ));
    }
    let transition = &advance.batch.transitions[0];
    if transition.resource_key.resource_family != "effect_slot" {
        return Err(EconomicStateAnchorError::EffectCancellationRejected(
            "transition is not an effect slot",
        ));
    }
    let current_head = advance
        .current
        .view
        .head(&transition.resource_key)
        .ok_or_else(|| {
            EconomicStateAnchorError::CurrentHeadMissing(transition.resource_key.clone())
        })?;
    let current_slot = economic_effect_slot_from_head(current_head)?;
    let next_slot = economic_effect_slot_from_head(&transition.next_head)?;
    current_slot.validate_successor(&next_slot)?;
    let kind = next_slot
        .terminal
        .as_ref()
        .and_then(EconomicEffectTerminalV1::no_effect_kind)
        .ok_or(EconomicStateAnchorError::EffectCancellationRejected(
            "cancellation did not retain a no-effect proof",
        ))?;
    if current_slot.state != EconomicEffectStateV1::Ready
        || next_slot.state != EconomicEffectStateV1::NoEffect
        || transition.next_head.lifecycle_state != "no_effect"
        || advance.batch.operation_id.as_deref() != Some(next_slot.operation_id.as_str())
    {
        return Err(EconomicStateAnchorError::EffectCancellationRejected(
            "effect slot did not enter no_effect from ready",
        ));
    }
    if verifier.verify_cancellation(&current_slot, &next_slot)? != kind {
        return Err(EconomicStateAnchorError::EffectCancellationRejected(
            "cancellation proof kind changed",
        ));
    }
    if kind == EconomicNoEffectKindV1::PreDispatch {
        admission.verify_operation_active(&next_slot.operation_id)?;
    } else {
        admission.verify_handoff(&next_slot.operation_id, &next_slot.admission_handoff)?;
    }
    Ok(VerifiedEconomicEffectCancellationAdvance {
        advance,
        slot: next_slot,
        kind,
    })
}

pub fn reverify_economic_effect_cancellation_advance(
    advance: &VerifiedEconomicEffectCancellationAdvance,
    pins: &EconomicStateAnchorPins,
    transition_verifier: &dyn EconomicTransitionProofVerifier,
    cancellation_verifier: &dyn EconomicEffectCancellationProofVerifier,
    admission_verifier: &dyn EconomicAdmissionHandoffVerifier,
) -> Result<(), EconomicStateAnchorError> {
    let verified = verify_economic_state_batch_advance(
        advance.advance.current(),
        advance.batch().clone(),
        pins,
        transition_verifier,
    )?;
    let cancellation = verify_economic_effect_cancellation_advance(
        verified,
        cancellation_verifier,
        admission_verifier,
    )?;
    if cancellation.slot != advance.slot || cancellation.kind != advance.kind {
        return Err(EconomicStateAnchorError::EffectCancellationRejected(
            "reverified cancellation changed",
        ));
    }
    Ok(())
}

#[derive(Debug)]
pub struct VerifiedEconomicEffectNotDispatched {
    slot: EconomicEffectSlotV1,
    kind: EconomicNoEffectKindV1,
    expected_head_version: u64,
    expected_head_digest: String,
    expected_lifecycle_fence: u64,
    resulting_head_version: u64,
    resulting_head_digest: String,
    resulting_lifecycle_fence: u64,
    checkpoint_sequence: u64,
    checkpoint_digest: String,
}

impl VerifiedEconomicEffectNotDispatched {
    pub fn slot(&self) -> &EconomicEffectSlotV1 {
        &self.slot
    }

    pub const fn kind(&self) -> EconomicNoEffectKindV1 {
        self.kind
    }

    pub const fn expected_head_version(&self) -> u64 {
        self.expected_head_version
    }

    pub fn expected_head_digest(&self) -> &str {
        &self.expected_head_digest
    }

    pub const fn expected_lifecycle_fence(&self) -> u64 {
        self.expected_lifecycle_fence
    }

    pub const fn resulting_head_version(&self) -> u64 {
        self.resulting_head_version
    }

    pub fn resulting_head_digest(&self) -> &str {
        &self.resulting_head_digest
    }

    pub const fn resulting_lifecycle_fence(&self) -> u64 {
        self.resulting_lifecycle_fence
    }

    pub const fn checkpoint_sequence(&self) -> u64 {
        self.checkpoint_sequence
    }

    pub fn checkpoint_digest(&self) -> &str {
        &self.checkpoint_digest
    }
}

pub fn verify_economic_effect_cancellation_commit(
    advance: VerifiedEconomicEffectCancellationAdvance,
    committed: &VerifiedEconomicStateView,
    pins: &EconomicStateAnchorPins,
) -> Result<VerifiedEconomicEffectNotDispatched, EconomicStateAnchorError> {
    verify_economic_state_batch_commit(&advance.advance, committed, pins)?;
    let transition = &advance.advance.batch.transitions[0];
    let expected = advance
        .advance
        .current
        .view
        .head(&transition.resource_key)
        .ok_or_else(|| {
            EconomicStateAnchorError::CurrentHeadMissing(transition.resource_key.clone())
        })?;
    Ok(VerifiedEconomicEffectNotDispatched {
        slot: advance.slot,
        kind: advance.kind,
        expected_head_version: expected.head_version,
        expected_head_digest: expected.digest()?,
        expected_lifecycle_fence: expected.lifecycle_fence,
        resulting_head_version: transition.next_head.head_version,
        resulting_head_digest: transition.next_head.digest()?,
        resulting_lifecycle_fence: transition.next_head.lifecycle_fence,
        checkpoint_sequence: committed.view().checkpoint_sequence,
        checkpoint_digest: committed.view().checkpoint_digest.clone(),
    })
}
