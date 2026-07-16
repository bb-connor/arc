use std::sync::Arc;

use chio_federation::frost::{
    verify_burned_frost_authorization_slot, FrostAnchoredAuthorizationSlot,
    FrostArtifactTrustStore, FrostAuthorizationSlotCheckpointV1,
};

use super::*;

pub const CLEARING_LIFECYCLE_REPLAY_FORMAT: &str = "chio.clearing.lifecycle-replay.v1";
pub const CLEARING_LIFECYCLE_REPLAY_DESCRIPTOR_KIND: &str = "chio.clearing.lifecycle-replay.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingFinalizationBurnReplayV1 {
    pub finalization: SignedClearingRoundFinalizationV1,
    pub bound_slot: FrostAuthorizationSlotCheckpointV1,
    pub burned_slot: FrostAnchoredAuthorizationSlot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingAbortReplayV1 {
    pub request: ClearingRoundRequestV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_output: Option<SignedClearingRoundOutputV1>,
    pub zero_dispatch_proof: SignedClearingZeroDispatchProofV1,
    pub abort: SignedClearingRoundAbortV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finalization_burn: Option<ClearingFinalizationBurnReplayV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClearingLifecycleReplayEvidenceV1 {
    Proposal {
        request: Box<ClearingRoundRequestV1>,
        signed_output: Box<SignedClearingRoundOutputV1>,
    },
    BeginAbort {
        abort: Box<ClearingAbortReplayV1>,
    },
    Abort {
        preabort_round_head: Box<EconomicResourceHeadV1>,
        begin_abort_proof: Box<ClearingRoundTransitionProofV1>,
        abort: Box<ClearingAbortReplayV1>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingLifecycleReplayV1 {
    pub format: String,
    pub proof: ClearingRoundTransitionProofV1,
    pub evidence: ClearingLifecycleReplayEvidenceV1,
}

impl ClearingLifecycleReplayV1 {
    pub fn validate(&self) -> Result<(), ClearingError> {
        if self.format != CLEARING_LIFECYCLE_REPLAY_FORMAT {
            return Err(ClearingError::InvalidField("lifecycle_replay_format"));
        }
        self.proof.validate()?;
        let matches = matches!(
            (&self.proof.transition, &self.evidence),
            (
                ClearingRoundTransitionV1::Propose { .. },
                ClearingLifecycleReplayEvidenceV1::Proposal { .. }
            ) | (
                ClearingRoundTransitionV1::BeginAbort { .. },
                ClearingLifecycleReplayEvidenceV1::BeginAbort { .. }
            ) | (
                ClearingRoundTransitionV1::Abort { .. },
                ClearingLifecycleReplayEvidenceV1::Abort { .. }
            )
        );
        if !matches {
            return Err(ClearingError::IllegalLifecycleTransition);
        }
        Ok(())
    }

    pub fn proof_digest(&self) -> Result<String, ClearingError> {
        self.validate()?;
        self.proof.digest()
    }

    #[must_use]
    pub fn authorized_at_unix_ms(&self) -> u64 {
        match &self.evidence {
            ClearingLifecycleReplayEvidenceV1::Proposal { request, .. } => {
                request.generated_at_unix_ms
            }
            ClearingLifecycleReplayEvidenceV1::BeginAbort { abort }
            | ClearingLifecycleReplayEvidenceV1::Abort { abort, .. } => {
                abort.abort.body.authorized_at_unix_ms
            }
        }
    }

    #[must_use]
    pub fn admission_checkpoint(&self) -> Option<(&str, u64, &str)> {
        let abort = match &self.evidence {
            ClearingLifecycleReplayEvidenceV1::BeginAbort { abort } => abort,
            ClearingLifecycleReplayEvidenceV1::Proposal { .. }
            | ClearingLifecycleReplayEvidenceV1::Abort { .. } => return None,
        };
        Some((
            &abort.zero_dispatch_proof.body.admission_store_id,
            abort.zero_dispatch_proof.body.admission_commit_sequence,
            &abort.zero_dispatch_proof.body.admission_commit_digest,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClearingLifecycleAuthorityPinsV1 {
    pub clearing_authority_id: String,
    pub clearing_authority_key: PublicKey,
    pub clearing_authority_key_epoch: u64,
    pub participant_authority_id: String,
    pub participant_authority_key: PublicKey,
    pub participant_key_epoch: u64,
    pub obligation_authority_id: String,
    pub obligation_authority_key: PublicKey,
    pub obligation_key_epoch: u64,
    pub zero_dispatch_authority_id: String,
    pub zero_dispatch_authority_key: PublicKey,
    pub zero_dispatch_authority_key_epoch: u64,
    pub admission_store_id: String,
}

impl ClearingLifecycleAuthorityPinsV1 {
    pub fn validate(&self) -> Result<(), ClearingError> {
        self.clearing_trust(1)?.validate()?;
        validate_text(
            "zero_dispatch_authority_id",
            &self.zero_dispatch_authority_id,
        )?;
        validate_positive(
            "zero_dispatch_authority_key_epoch",
            self.zero_dispatch_authority_key_epoch,
        )?;
        validate_text("admission_store_id", &self.admission_store_id)
    }

    fn clearing_trust(
        &self,
        trusted_time_unix_ms: u64,
    ) -> Result<ClearingAuthorityTrustV1, ClearingError> {
        let trust = ClearingAuthorityTrustV1 {
            clearing_authority_id: self.clearing_authority_id.clone(),
            clearing_authority_key: self.clearing_authority_key.clone(),
            clearing_authority_key_epoch: self.clearing_authority_key_epoch,
            participant_authority_id: self.participant_authority_id.clone(),
            participant_authority_key: self.participant_authority_key.clone(),
            participant_key_epoch: self.participant_key_epoch,
            obligation_authority_id: self.obligation_authority_id.clone(),
            obligation_authority_key: self.obligation_authority_key.clone(),
            obligation_key_epoch: self.obligation_key_epoch,
            trusted_time_unix_ms,
        };
        trust.validate()?;
        Ok(trust)
    }

    fn zero_dispatch_trust(
        &self,
        proof: &SignedClearingZeroDispatchProofV1,
        trusted_time_unix_ms: u64,
    ) -> Result<ClearingZeroDispatchTrustV1, ClearingError> {
        let trust = ClearingZeroDispatchTrustV1 {
            authority_id: self.zero_dispatch_authority_id.clone(),
            authority_key: self.zero_dispatch_authority_key.clone(),
            authority_key_epoch: self.zero_dispatch_authority_key_epoch,
            admission_store_id: self.admission_store_id.clone(),
            admission_commit_sequence: proof.body.admission_commit_sequence,
            admission_commit_digest: proof.body.admission_commit_digest.clone(),
            trusted_time_unix_ms,
        };
        trust.validate()?;
        Ok(trust)
    }
}

pub fn verify_clearing_lifecycle_replay(
    current: &VerifiedEconomicStateView,
    batch: &EconomicStateBatchV1,
    replay: &ClearingLifecycleReplayV1,
    pins: &ClearingLifecycleAuthorityPinsV1,
    frost_trust: Option<&FrostArtifactTrustStore>,
) -> Result<EconomicTransitionAuthorizationV1, ClearingError> {
    replay.validate()?;
    pins.validate()?;
    verify_projection(current, batch, &replay.proof)?;
    let round_key = EconomicResourceKeyV1 {
        resource_family: CLEARING_ROUND_RESOURCE_FAMILY.to_owned(),
        scope_id: replay.proof.governance_scope_id.clone(),
        resource_id: replay.proof.round_id.clone(),
    };
    let source_round_head = current
        .view()
        .head(&round_key)
        .ok_or(ClearingError::IncompleteLifecycleProjection)?;
    verify_clearing_lifecycle_replay_authority(source_round_head, replay, pins, frost_trust)
}

pub fn verify_clearing_lifecycle_replay_authority(
    source_round_head: &EconomicResourceHeadV1,
    replay: &ClearingLifecycleReplayV1,
    pins: &ClearingLifecycleAuthorityPinsV1,
    frost_trust: Option<&FrostArtifactTrustStore>,
) -> Result<EconomicTransitionAuthorizationV1, ClearingError> {
    replay.validate()?;
    pins.validate()?;
    if source_round_head
        .digest()
        .map_err(|_| ClearingError::InvalidField("current_round_head"))?
        != replay.proof.source_round_head_digest
    {
        return Err(ClearingError::IncompleteLifecycleProjection);
    }
    match &replay.evidence {
        ClearingLifecycleReplayEvidenceV1::Proposal {
            request,
            signed_output,
        } => verify_proposal(&replay.proof, request, signed_output, pins)?,
        ClearingLifecycleReplayEvidenceV1::BeginAbort { abort } => {
            let verified = verify_abort_replay(source_round_head, abort, pins, frost_trust)?;
            if replay.proof.transition != verified.begin_abort_transition() {
                return Err(ClearingError::AuthorityVerification);
            }
        }
        ClearingLifecycleReplayEvidenceV1::Abort {
            preabort_round_head,
            begin_abort_proof,
            abort,
        } => {
            let verified = verify_abort_replay(preabort_round_head, abort, pins, frost_trust)?;
            if replay.proof.transition
                != verified.abort_transition(source_round_head, begin_abort_proof)?
            {
                return Err(ClearingError::AuthorityVerification);
            }
        }
    }
    Ok(EconomicTransitionAuthorizationV1::Direct)
}

pub struct ClearingLifecycleReplayBatchVerifier {
    replay: ClearingLifecycleReplayV1,
    pins: ClearingLifecycleAuthorityPinsV1,
    frost_trust: Option<Arc<FrostArtifactTrustStore>>,
}

impl ClearingLifecycleReplayBatchVerifier {
    pub fn new(
        replay: ClearingLifecycleReplayV1,
        pins: ClearingLifecycleAuthorityPinsV1,
        frost_trust: Option<Arc<FrostArtifactTrustStore>>,
    ) -> Result<Self, ClearingError> {
        replay.validate()?;
        pins.validate()?;
        Ok(Self {
            replay,
            pins,
            frost_trust,
        })
    }
}

impl EconomicTransitionProofVerifier for ClearingLifecycleReplayBatchVerifier {
    fn verify_transition(
        &self,
        _current: Option<&EconomicResourceHeadV1>,
        transition: &EconomicStateTransitionV1,
    ) -> Result<EconomicTransitionAuthorizationV1, EconomicStateAnchorError> {
        Err(EconomicStateAnchorError::TransitionProofRejected(
            transition.resource_key.clone(),
        ))
    }

    fn verify_batch(
        &self,
        current: &VerifiedEconomicStateView,
        batch: &EconomicStateBatchV1,
    ) -> Result<Vec<EconomicTransitionAuthorizationV1>, EconomicStateAnchorError> {
        let authorization = verify_clearing_lifecycle_replay(
            current,
            batch,
            &self.replay,
            &self.pins,
            self.frost_trust.as_deref(),
        )
        .map_err(|_| rejected_batch(batch))?;
        Ok(vec![authorization; batch.transitions.len()])
    }
}

fn verify_proposal(
    proof: &ClearingRoundTransitionProofV1,
    request: &ClearingRoundRequestV1,
    signed_output: &SignedClearingRoundOutputV1,
    pins: &ClearingLifecycleAuthorityPinsV1,
) -> Result<(), ClearingError> {
    let trust = pins.clearing_trust(request.generated_at_unix_ms)?;
    let output = verify_signed_netting_round(request, &trust, signed_output)?;
    let output_manifest_digest = output.output_manifest.digest()?;
    let authority_digest = signed_output.output_manifest.digest()?;
    let ClearingRoundTransitionV1::Propose {
        output_manifest_digest: expected_output,
        authority_digest: expected_authority,
    } = &proof.transition
    else {
        return Err(ClearingError::IllegalLifecycleTransition);
    };
    if output.core.round_id != proof.round_id
        || output.core.governance_scope_id != proof.governance_scope_id
        || output.core.digest()? != proof.round_core_digest
        || output.core.input_manifest_digest != proof.input_manifest_digest
        || output.core.reservation_root != proof.reservation_root
        || output.core.input_count != proof.reservation_count
        || output_manifest_digest != *expected_output
        || authority_digest != *expected_authority
    {
        return Err(ClearingError::AuthorityVerification);
    }
    Ok(())
}

fn verify_abort_replay(
    preabort_round_head: &EconomicResourceHeadV1,
    replay: &ClearingAbortReplayV1,
    pins: &ClearingLifecycleAuthorityPinsV1,
    frost_trust: Option<&FrostArtifactTrustStore>,
) -> Result<VerifiedClearingRoundAbortV1, ClearingError> {
    let authorized_at = replay.abort.body.authorized_at_unix_ms;
    let clearing_trust = pins.clearing_trust(authorized_at)?;
    let zero_dispatch_trust =
        pins.zero_dispatch_trust(&replay.zero_dispatch_proof, authorized_at)?;
    let zero_dispatch = verify_clearing_zero_dispatch_proof(
        preabort_round_head,
        &replay.request,
        replay.signed_output.as_ref(),
        &replay.zero_dispatch_proof,
        &clearing_trust,
        &zero_dispatch_trust,
    )?;
    match &replay.finalization_burn {
        Some(burn) => {
            let trust = frost_trust.ok_or(ClearingError::AuthorityVerification)?;
            let burned = verify_burned_frost_authorization_slot(
                &burn.bound_slot,
                &burn.burned_slot,
                trust,
                authorized_at,
            )
            .map_err(|_| ClearingError::AuthorityVerification)?;
            verify_clearing_round_abort(
                preabort_round_head,
                &zero_dispatch,
                &replay.abort,
                Some(ClearingFinalizationBurnEvidenceV1::new(
                    &burn.finalization,
                    &burned,
                )),
                &clearing_trust,
            )
        }
        None => verify_clearing_round_abort(
            preabort_round_head,
            &zero_dispatch,
            &replay.abort,
            None,
            &clearing_trust,
        ),
    }
}
