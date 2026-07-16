use std::collections::BTreeMap;
use std::sync::Arc;

use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_core_types::economic_continuity::{
    verify_economic_state_batch_advance, verify_economic_state_batch_commit,
    verify_economic_state_view, EconomicAdmissionHandoffStateV1, EconomicAdmissionHandoffV1,
    EconomicContentV1, EconomicEffectSlotV1, EconomicEffectStateV1, EconomicEffectTargetV1,
    EconomicFrostBindingV1, EconomicRequestBindingV1, EconomicResourceHeadV1,
    EconomicResourceKeyV1, EconomicStateAnchorError, EconomicStateAnchorPins,
    EconomicStateAnchorViewV1, EconomicStateBatchV1, EconomicTransitionAuthorizationV1,
    CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA, CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA,
    CHIO_ECONOMIC_STATE_ANCHOR_VIEW_SCHEMA, CHIO_ECONOMIC_STATE_BATCH_SCHEMA,
};
use chio_core_types::StoreMutationFence;
use chio_credit::clearing::{
    clearing_reservation_root, compose_clearing_dispatch_transition,
    compose_clearing_lifecycle_transition, AnchoredClearingObligationV1,
    ClearingLifecycleAuthorityVerifier, ClearingLifecycleBatchVerifier,
    ClearingLifecycleProofResolver, ClearingObligationInputV1, ClearingRoundLifecycleRecordV1,
    ClearingRoundTransitionProofV1, ClearingRoundTransitionV1, ClearingSettlementIntentV1,
    NettingRoundCoreV1, SignedClearingSettlementIntentV1, CLEARING_ALGORITHM_V1,
    CLEARING_ROUND_CORE_SCHEMA, CLEARING_SETTLEMENT_DISPATCH_EFFECT_KIND,
    CLEARING_SETTLEMENT_INTENT_SCHEMA,
};
use chio_credit::obligation::{
    ObligationAtomInputV1, ObligationAtomV1, ObligationCreditElectionV1,
    ObligationDispositionRecordV1, ObligationDispositionTransitionV1, ObligationDispositionV1,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn digest(value: &str) -> String {
    sha256_hex(value.as_bytes())
}

fn validate_schema(name: &str, artifact: &impl serde::Serialize) -> TestResult {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../spec/schemas/chio-economy")
        .join(name);
    let schema = chio_spec_validate::load_json(&path)?;
    let value = serde_json::to_value(artifact)?;
    chio_spec_validate::validate_value(
        &path,
        &schema,
        &std::path::PathBuf::from("<clearing-lifecycle-artifact>"),
        &value,
    )?;
    Ok(())
}

fn anchor_key() -> Keypair {
    Keypair::from_seed(&[41; 32])
}

fn pins() -> EconomicStateAnchorPins {
    EconomicStateAnchorPins {
        anchor_id: "anchor-1".to_owned(),
        namespace: "economy-prod".to_owned(),
        signer_key_id: "anchor-key-1".to_owned(),
        signer_key_epoch: 1,
        signer_public_key: anchor_key().public_key(),
    }
}

fn reserved_obligation(
    sequence: u64,
) -> Result<ClearingObligationInputV1, Box<dyn std::error::Error>> {
    let atom = ObligationAtomV1::new(ObligationAtomInputV1 {
        economic_intent_digest: digest(&format!("intent-{sequence}")),
        source_receipt_id: format!("receipt-{sequence}"),
        source_receipt_digest: digest(&format!("receipt-{sequence}")),
        debtor_id: format!("debtor-{sequence}"),
        original_creditor_id: format!("creditor-{sequence}"),
        original_settlement_destination_ref: format!("acct:creditor-{sequence}"),
        payee_binding_digest: digest(&format!("payee-{sequence}")),
        amount: MonetaryAmount {
            currency: "USD".to_owned(),
            units: sequence * 100,
        },
        credit_election: ObligationCreditElectionV1::NotCredit,
        pre_action_authority_digest: digest(&format!("produce-{sequence}")),
        created_at_unix_ms: 100,
        due_at_unix_ms: 1_000,
    })?;
    let disposition = ObligationDispositionRecordV1::produced(&atom)?.advance(
        &atom,
        ObligationDispositionTransitionV1::ReserveClearing {
            round_id: "round-1".to_owned(),
            authority_digest: digest(&format!("reserve-{sequence}")),
        },
    )?;
    Ok(ClearingObligationInputV1 {
        source_sequence: sequence,
        atom,
        disposition,
    })
}

fn core(
    obligations: &[ClearingObligationInputV1],
) -> Result<NettingRoundCoreV1, Box<dyn std::error::Error>> {
    Ok(NettingRoundCoreV1 {
        schema: CLEARING_ROUND_CORE_SCHEMA.to_owned(),
        round_id: "round-1".to_owned(),
        epoch: 1,
        governance_scope_id: "clearing-governance".to_owned(),
        clearing_authority_id: "clearing-authority".to_owned(),
        clearing_authority_key_epoch: 1,
        currency: "USD".to_owned(),
        algorithm_version: CLEARING_ALGORITHM_V1.to_owned(),
        participant_snapshot_digest: digest("snapshot"),
        input_manifest_digest: digest("manifest"),
        input_count: u64::try_from(obligations.len())?,
        reservation_root: clearing_reservation_root(obligations)?,
        dispute_window_ends_at_unix_ms: 500,
        generated_at_unix_ms: 100,
    })
}

fn content(value: impl serde::Serialize) -> Result<EconomicContentV1, Box<dyn std::error::Error>> {
    Ok(EconomicContentV1::Inline {
        value: serde_json::to_value(value)?,
    })
}

fn round_head(
    record: &ClearingRoundLifecycleRecordV1,
) -> Result<EconomicResourceHeadV1, Box<dyn std::error::Error>> {
    let state = content(record)?;
    Ok(EconomicResourceHeadV1 {
        schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_owned(),
        anchor_id: "anchor-1".to_owned(),
        namespace: "economy-prod".to_owned(),
        resource_key: EconomicResourceKeyV1 {
            resource_family: "clearing_round".to_owned(),
            scope_id: record.governance_scope_id().to_owned(),
            resource_id: record.round_id().to_owned(),
        },
        head_version: record.row_version(),
        resource_version: record.row_version(),
        lifecycle_fence: record.fence(),
        lifecycle_state: record.state().as_str().to_owned(),
        state_digest: state.digest()?,
        state,
        operation_id: None,
        effect_idempotency_key: None,
        frost: None,
        terminal_result: None,
        trusted_clock_high_water: 500,
        predecessor_digest: None,
    })
}

fn obligation_head(
    input: &ClearingObligationInputV1,
    scope_id: &str,
) -> Result<EconomicResourceHeadV1, Box<dyn std::error::Error>> {
    let state = content(&input.disposition)?;
    Ok(EconomicResourceHeadV1 {
        schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_owned(),
        anchor_id: "anchor-1".to_owned(),
        namespace: "economy-prod".to_owned(),
        resource_key: EconomicResourceKeyV1 {
            resource_family: "obligation_disposition".to_owned(),
            scope_id: scope_id.to_owned(),
            resource_id: input.atom.obligation_id().to_owned(),
        },
        head_version: 1,
        resource_version: input.disposition.version(),
        lifecycle_fence: input.disposition.lifecycle_fence(),
        lifecycle_state: "clearing_reserved".to_owned(),
        state_digest: state.digest()?,
        state,
        operation_id: None,
        effect_idempotency_key: None,
        frost: None,
        terminal_result: None,
        trusted_clock_high_water: 500,
        predecessor_digest: None,
    })
}

fn signed_view(
    sequence: u64,
    checkpoint_digest: String,
    mut heads: Vec<EconomicResourceHeadV1>,
) -> Result<EconomicStateAnchorViewV1, Box<dyn std::error::Error>> {
    heads.sort_by(|left, right| left.resource_key.cmp(&right.resource_key));
    let mut view = EconomicStateAnchorViewV1 {
        schema: CHIO_ECONOMIC_STATE_ANCHOR_VIEW_SCHEMA.to_owned(),
        anchor_id: "anchor-1".to_owned(),
        namespace: "economy-prod".to_owned(),
        checkpoint_sequence: sequence,
        checkpoint_digest,
        heads_root: String::new(),
        heads,
        absent_resource_keys: Vec::new(),
        request_replays_root: String::new(),
        request_replays: Vec::new(),
        absent_request_keys: Vec::new(),
        observed_at: 500 + sequence,
        signer_key_id: "anchor-key-1".to_owned(),
        signer_key_epoch: 1,
        anchor_signature: String::new(),
    };
    view.seal(&anchor_key())?;
    Ok(view)
}

fn signed_batch(
    projection: &chio_credit::clearing::ClearingLifecycleProjectionV1,
    current: &EconomicStateAnchorViewV1,
) -> Result<EconomicStateBatchV1, Box<dyn std::error::Error>> {
    let mut batch = EconomicStateBatchV1 {
        schema: CHIO_ECONOMIC_STATE_BATCH_SCHEMA.to_owned(),
        batch_id: String::new(),
        checkpoint_digest: String::new(),
        anchor_id: "anchor-1".to_owned(),
        namespace: "economy-prod".to_owned(),
        checkpoint_sequence: current.checkpoint_sequence + 1,
        previous_checkpoint_digest: Some(current.checkpoint_digest.clone()),
        expected_heads_root: String::new(),
        next_heads_root: String::new(),
        transitions: projection.transitions().to_vec(),
        effect_slots: projection.effect_slots().to_vec(),
        request_replays: projection.request_replays().to_vec(),
        operation_id: projection.operation_id().map(str::to_owned),
        issued_at: current.observed_at + 1,
        signer_key_id: "anchor-key-1".to_owned(),
        signer_key_epoch: 1,
        anchor_signature: String::new(),
    };
    batch.seal(&anchor_key())?;
    Ok(batch)
}

#[derive(Debug)]
struct Proofs(BTreeMap<String, ClearingRoundTransitionProofV1>);

impl ClearingLifecycleProofResolver for Proofs {
    fn resolve(
        &self,
        proof_digest: &str,
    ) -> Result<ClearingRoundTransitionProofV1, chio_credit::clearing::ClearingError> {
        self.0
            .get(proof_digest)
            .cloned()
            .ok_or(chio_credit::clearing::ClearingError::InvalidField(
                "transition_proof_digest",
            ))
    }
}

#[derive(Debug)]
struct DirectAuthority;

impl ClearingLifecycleAuthorityVerifier for DirectAuthority {
    fn verify(
        &self,
        _proof: &ClearingRoundTransitionProofV1,
    ) -> Result<EconomicTransitionAuthorizationV1, chio_credit::clearing::ClearingError> {
        Ok(EconomicTransitionAuthorizationV1::Direct)
    }
}

#[derive(Debug)]
struct MatchingAuthority;

impl ClearingLifecycleAuthorityVerifier for MatchingAuthority {
    fn verify(
        &self,
        proof: &ClearingRoundTransitionProofV1,
    ) -> Result<EconomicTransitionAuthorizationV1, chio_credit::clearing::ClearingError> {
        match &proof.transition {
            ClearingRoundTransitionV1::Finalize { frost, .. } => {
                Ok(EconomicTransitionAuthorizationV1::NOfM {
                    frost: frost.clone(),
                })
            }
            _ => Ok(EconomicTransitionAuthorizationV1::Direct),
        }
    }
}

fn next_heads(
    projection: &chio_credit::clearing::ClearingLifecycleProjectionV1,
) -> Vec<EconomicResourceHeadV1> {
    projection
        .transitions()
        .iter()
        .map(|transition| transition.next_head.clone())
        .collect()
}

fn anchored_obligations(
    inputs: &[ClearingObligationInputV1],
    heads: &[EconomicResourceHeadV1],
) -> Option<Vec<AnchoredClearingObligationV1>> {
    inputs
        .iter()
        .map(|input| {
            heads
                .iter()
                .find(|head| head.resource_key.resource_id == input.atom.obligation_id())
                .cloned()
                .map(|head| AnchoredClearingObligationV1 {
                    input: input.clone(),
                    head,
                })
        })
        .collect()
}

fn signed_dispatch_intent(
    round_core_digest: &str,
    label: &str,
) -> Result<SignedClearingSettlementIntentV1, Box<dyn std::error::Error>> {
    Ok(SignedClearingSettlementIntentV1::sign(
        ClearingSettlementIntentV1 {
            schema: CLEARING_SETTLEMENT_INTENT_SCHEMA.to_owned(),
            intent_id: format!("intent-{label}"),
            round_core_digest: round_core_digest.to_owned(),
            ordinal: 1,
            debtor_participant_id: "debtor-1".to_owned(),
            creditor_participant_id: "creditor-1".to_owned(),
            creditor_settlement_destination: "acct:creditor-1".to_owned(),
            amount: MonetaryAmount {
                currency: "USD".to_owned(),
                units: 100,
            },
            contributing_reservation_root: digest("contributing-reservations"),
            dispatch_idempotency_key: digest(&format!("dispatch-key-{label}")),
        },
        &Keypair::from_seed(&[51; 32]),
    )?)
}

fn dispatch_slot(
    source_round_head: &EconomicResourceHeadV1,
    intent: &SignedClearingSettlementIntentV1,
    label: &str,
) -> Result<EconomicEffectSlotV1, Box<dyn std::error::Error>> {
    let mut slot = EconomicEffectSlotV1 {
        schema: CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA.to_owned(),
        slot_id: String::new(),
        anchor_id: source_round_head.anchor_id.clone(),
        namespace: source_round_head.namespace.clone(),
        resource_key: source_round_head.resource_key.clone(),
        operation_id: digest(&format!("operation-{label}")),
        effect_kind: CLEARING_SETTLEMENT_DISPATCH_EFFECT_KIND.to_owned(),
        request: EconomicRequestBindingV1 {
            request_namespace_digest: digest("request-namespace"),
            request_id: format!("request-{label}"),
            request_binding_digest: digest(&format!("request-binding-{label}")),
        },
        admission_handoff: EconomicAdmissionHandoffV1 {
            state: EconomicAdmissionHandoffStateV1::DispatchCommitted,
            operation_version: 6,
            lifecycle_fence: 9,
            store_fence: StoreMutationFence {
                store_uuid: "store-1".to_owned(),
                lease_id: "lease-1".to_owned(),
                owner_epoch: 3,
            },
        },
        target: EconomicEffectTargetV1 {
            target_id: "settlement-rail".to_owned(),
            target_key_epoch: 2,
            qualification_digest: digest("settlement-rail-qualification"),
        },
        action_digest: intent.digest()?,
        parameters_digest: intent.body.digest()?,
        resource_head_digest: source_round_head.digest()?,
        frost: None,
        idempotency_key: intent.body.dispatch_idempotency_key.clone(),
        state: EconomicEffectStateV1::Ready,
        terminal: None,
    };
    slot.slot_id = slot.recompute_slot_id()?;
    slot.validate()?;
    Ok(slot)
}

#[test]
fn finalization_and_abort_compete_on_one_complete_external_projection() -> TestResult {
    let inputs = vec![reserved_obligation(1)?, reserved_obligation(2)?];
    let core = core(&inputs)?;
    let reserved = ClearingRoundLifecycleRecordV1::reserved(&core)?;
    validate_schema("clearing-round-lifecycle.v1.json", &reserved)?;
    validate_schema("obligation-atom.v1.json", &inputs[0].atom)?;
    validate_schema("obligation-disposition.v1.json", &inputs[0].disposition)?;
    let reserved_round_head = round_head(&reserved)?;
    let mut anchored = inputs
        .iter()
        .map(|input| {
            Ok(AnchoredClearingObligationV1 {
                input: input.clone(),
                head: obligation_head(input, &core.governance_scope_id)?,
            })
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    let proposed = compose_clearing_lifecycle_transition(
        &reserved_round_head,
        &anchored,
        ClearingRoundTransitionV1::Propose {
            output_manifest_digest: digest("output-manifest"),
            authority_digest: digest("proposal-authority"),
        },
        501,
    )?;
    let proposed_heads = next_heads(&proposed);
    let proposed_round_head = proposed_heads
        .iter()
        .find(|head| head.resource_key.resource_family == "clearing_round")
        .ok_or("missing proposed round head")?
        .clone();
    anchored = anchored_obligations(&inputs, &proposed_heads)
        .ok_or("projection omitted an obligation head")?;

    let finalizing = compose_clearing_lifecycle_transition(
        &proposed_round_head,
        &anchored,
        ClearingRoundTransitionV1::BeginFinalization {
            acceptance_root: digest("acceptances"),
            acceptance_count: 2,
            authority_digest: digest("finalization-authority"),
        },
        502,
    )?;
    let aborting = compose_clearing_lifecycle_transition(
        &proposed_round_head,
        &anchored,
        ClearingRoundTransitionV1::BeginAbort {
            abort_digest: digest("abort"),
            zero_dispatch_proof_digest: digest("zero-dispatch"),
            authority_digest: digest("abort-authority"),
            frost_burn_checkpoint_digest: None,
        },
        502,
    )?;
    validate_schema("clearing-round-transition-proof.v1.json", aborting.proof())?;
    assert_eq!(finalizing.transitions().len(), 3);
    assert_eq!(aborting.transitions().len(), 3);
    assert_eq!(
        finalizing.transitions()[0].expected_head_digest,
        aborting.transitions()[0].expected_head_digest
    );

    let current_view = signed_view(1, digest("checkpoint-1"), proposed_heads)?;
    let verified_current = verify_economic_state_view(current_view.clone(), &pins())?;
    let finalizing_batch = signed_batch(&finalizing, &current_view)?;
    let aborting_batch = signed_batch(&aborting, &current_view)?;
    let mut proofs = BTreeMap::new();
    proofs.insert(finalizing.proof().digest()?, finalizing.proof().clone());
    proofs.insert(aborting.proof().digest()?, aborting.proof().clone());
    let verifier =
        ClearingLifecycleBatchVerifier::new(Arc::new(Proofs(proofs)), Arc::new(DirectAuthority));
    let finalizing_advance = verify_economic_state_batch_advance(
        &verified_current,
        finalizing_batch,
        &pins(),
        &verifier,
    )?;
    verify_economic_state_batch_advance(
        &verified_current,
        aborting_batch.clone(),
        &pins(),
        &verifier,
    )?;

    let committed_view = signed_view(
        finalizing_advance.batch().checkpoint_sequence,
        finalizing_advance.batch().checkpoint_digest.clone(),
        finalizing_advance
            .batch()
            .transitions
            .iter()
            .map(|transition| transition.next_head.clone())
            .collect(),
    )?;
    let verified_committed = verify_economic_state_view(committed_view, &pins())?;
    verify_economic_state_batch_commit(&finalizing_advance, &verified_committed, &pins())?;
    assert!(verify_economic_state_batch_advance(
        &verified_committed,
        aborting_batch,
        &pins(),
        &verifier,
    )
    .is_err());

    let mut omitted = signed_batch(&aborting, &current_view)?;
    omitted.transitions.pop();
    omitted.seal(&anchor_key())?;
    assert!(matches!(
        verify_economic_state_batch_advance(&verified_current, omitted, &pins(), &verifier),
        Err(EconomicStateAnchorError::TransitionProofRejected(_))
    ));
    Ok(())
}

#[test]
fn finalizing_abort_requires_a_burn_and_dispatch_is_effect_fenced() -> TestResult {
    let inputs = vec![reserved_obligation(1)?];
    let core = core(&inputs)?;
    let reserved = ClearingRoundLifecycleRecordV1::reserved(&core)?;
    let reserved_head = round_head(&reserved)?;
    let mut anchored = vec![AnchoredClearingObligationV1 {
        input: inputs[0].clone(),
        head: obligation_head(&inputs[0], &core.governance_scope_id)?,
    }];
    let proposed = compose_clearing_lifecycle_transition(
        &reserved_head,
        &anchored,
        ClearingRoundTransitionV1::Propose {
            output_manifest_digest: digest("output-manifest"),
            authority_digest: digest("proposal-authority"),
        },
        501,
    )?;
    let proposed_heads = next_heads(&proposed);
    let proposed_head = proposed_heads[0].clone();
    anchored = anchored_obligations(&inputs, &proposed_heads)
        .ok_or("projection omitted an obligation head")?;
    let finalizing = compose_clearing_lifecycle_transition(
        &proposed_head,
        &anchored,
        ClearingRoundTransitionV1::BeginFinalization {
            acceptance_root: digest("acceptances"),
            acceptance_count: 1,
            authority_digest: digest("finalization-authority"),
        },
        502,
    )?;
    let finalizing_heads = next_heads(&finalizing);
    let finalizing_head = finalizing_heads[0].clone();
    let EconomicContentV1::Inline { value } = &finalizing_head.state else {
        return Err("finalizing head did not contain inline state".into());
    };
    let mut impossible_record = value.clone();
    impossible_record["participantAcceptanceCount"] = serde_json::json!(1025);
    let impossible_record: ClearingRoundLifecycleRecordV1 =
        serde_json::from_value(impossible_record)?;
    assert!(impossible_record.validate().is_err());
    assert!(validate_schema("clearing-round-lifecycle.v1.json", &impossible_record,).is_err());
    anchored = anchored_obligations(&inputs, &finalizing_heads)
        .ok_or("projection omitted an obligation head")?;
    assert!(compose_clearing_lifecycle_transition(
        &finalizing_head,
        &anchored,
        ClearingRoundTransitionV1::BeginAbort {
            abort_digest: digest("abort"),
            zero_dispatch_proof_digest: digest("zero-dispatch"),
            authority_digest: digest("abort-authority"),
            frost_burn_checkpoint_digest: None,
        },
        503,
    )
    .is_err());

    let finalized = compose_clearing_lifecycle_transition(
        &finalizing_head,
        &anchored,
        ClearingRoundTransitionV1::Finalize {
            finalization_digest: digest("finalization"),
            frost: EconomicFrostBindingV1 {
                authorization_slot_id: digest("authorization-slot"),
                authorization_id: digest("authorization"),
                action_digest: digest("finalization-action"),
                signed_envelope_digest: digest("frost-envelope"),
            },
        },
        503,
    )?;
    let finalized_heads = next_heads(&finalized);
    let finalized_head = finalized_heads[0].clone();
    let finalized_obligations = anchored_obligations(&inputs, &finalized_heads)
        .ok_or("projection omitted an obligation head")?;

    let current_view = signed_view(1, digest("finalizing-checkpoint"), finalizing_heads)?;
    let verified_current = verify_economic_state_view(current_view.clone(), &pins())?;
    let finalized_batch = signed_batch(&finalized, &current_view)?;
    let proof_digest = finalized.proof().digest()?;
    let proofs = BTreeMap::from([(proof_digest, finalized.proof().clone())]);
    let direct_verifier = ClearingLifecycleBatchVerifier::new(
        Arc::new(Proofs(proofs.clone())),
        Arc::new(DirectAuthority),
    );
    assert!(verify_economic_state_batch_advance(
        &verified_current,
        finalized_batch.clone(),
        &pins(),
        &direct_verifier,
    )
    .is_err());
    let matching_verifier =
        ClearingLifecycleBatchVerifier::new(Arc::new(Proofs(proofs)), Arc::new(MatchingAuthority));
    verify_economic_state_batch_advance(
        &verified_current,
        finalized_batch,
        &pins(),
        &matching_verifier,
    )?;

    assert!(compose_clearing_lifecycle_transition(
        &finalized_head,
        &finalized_obligations,
        ClearingRoundTransitionV1::BeginAbort {
            abort_digest: digest("late-abort"),
            zero_dispatch_proof_digest: digest("zero-dispatch"),
            authority_digest: digest("abort-authority"),
            frost_burn_checkpoint_digest: Some(digest("burned-slot")),
        },
        504,
    )
    .is_err());

    let first_intent = signed_dispatch_intent(&core.digest()?, "first")?;
    let first_slot = dispatch_slot(&finalized_head, &first_intent, "first")?;
    let first_dispatch = compose_clearing_dispatch_transition(
        &finalized_head,
        &finalized_obligations,
        &first_intent,
        first_slot.clone(),
        504,
    )?;
    validate_schema(
        "clearing-round-transition-proof.v1.json",
        first_dispatch.proof(),
    )?;
    assert_eq!(first_dispatch.transitions().len(), inputs.len() + 2);
    assert_eq!(
        first_dispatch.effect_slots(),
        std::slice::from_ref(&first_slot)
    );
    assert_eq!(
        first_dispatch.operation_id(),
        Some(first_slot.operation_id.as_str())
    );
    let mut dispatch_view = signed_view(2, digest("finalized-checkpoint"), finalized_heads)?;
    dispatch_view.absent_resource_keys = vec![first_slot.resource_head_key()];
    dispatch_view.absent_request_keys = vec![first_slot.request.key()];
    dispatch_view.seal(&anchor_key())?;
    let verified_dispatch_view = verify_economic_state_view(dispatch_view.clone(), &pins())?;
    let dispatch_batch = signed_batch(&first_dispatch, &dispatch_view)?;
    let dispatch_proofs = BTreeMap::from([(
        first_dispatch.proof().digest()?,
        first_dispatch.proof().clone(),
    )]);
    let dispatch_verifier = ClearingLifecycleBatchVerifier::new(
        Arc::new(Proofs(dispatch_proofs)),
        Arc::new(DirectAuthority),
    );
    verify_economic_state_batch_advance(
        &verified_dispatch_view,
        dispatch_batch.clone(),
        &pins(),
        &dispatch_verifier,
    )?;
    let mut substituted_slot = dispatch_batch.clone();
    substituted_slot.effect_slots[0]
        .request
        .request_binding_digest = digest("substituted-request-binding");
    let substituted_slot_value = serde_json::to_value(&substituted_slot.effect_slots[0])?;
    let substituted_slot_digest = substituted_slot.effect_slots[0].digest()?;
    let substituted_slot_key = substituted_slot.effect_slots[0].resource_head_key();
    substituted_slot.request_replays[0].request = substituted_slot.effect_slots[0].request.clone();
    for transition in &mut substituted_slot.transitions {
        if transition.resource_key == substituted_slot_key {
            transition.next_head.state = EconomicContentV1::Inline {
                value: substituted_slot_value.clone(),
            };
            transition.next_head.state_digest = transition.next_head.state.digest()?;
        }
        if let Some(prepared) = &mut transition.prepared_effect {
            prepared.effect_slot_digest = substituted_slot_digest.clone();
        }
    }
    substituted_slot.seal(&anchor_key())?;
    assert!(verify_economic_state_batch_advance(
        &verified_dispatch_view,
        substituted_slot,
        &pins(),
        &dispatch_verifier,
    )
    .is_err());
    let mut incomplete_dispatch = dispatch_batch;
    incomplete_dispatch
        .transitions
        .retain(|transition| transition.resource_key.resource_id != inputs[0].atom.obligation_id());
    incomplete_dispatch.seal(&anchor_key())?;
    assert!(verify_economic_state_batch_advance(
        &verified_dispatch_view,
        incomplete_dispatch,
        &pins(),
        &dispatch_verifier,
    )
    .is_err());

    let first_dispatch_heads = next_heads(&first_dispatch);
    let dispatching_head = first_dispatch_heads
        .iter()
        .find(|head| head.resource_key.resource_family == "clearing_round")
        .ok_or("missing dispatching round head")?;
    let dispatching_obligations = anchored_obligations(&inputs, &first_dispatch_heads)
        .ok_or("first dispatch omitted an obligation head")?;
    let second_intent = signed_dispatch_intent(&core.digest()?, "second")?;
    let second_slot = dispatch_slot(dispatching_head, &second_intent, "second")?;
    let second_dispatch = compose_clearing_dispatch_transition(
        dispatching_head,
        &dispatching_obligations,
        &second_intent,
        second_slot,
        505,
    )?;
    let second_round_head = second_dispatch
        .transitions()
        .iter()
        .find(|transition| transition.resource_key.resource_family == "clearing_round")
        .map(|transition| &transition.next_head)
        .ok_or("missing second dispatch round head")?;
    let EconomicContentV1::Inline { value } = &second_round_head.state else {
        return Err("second dispatch round state is not inline".into());
    };
    let second_record: ClearingRoundLifecycleRecordV1 = serde_json::from_value(value.clone())?;
    assert_eq!(
        second_record.first_dispatch_operation_id(),
        Some(first_slot.operation_id.as_str())
    );
    let mut reused_operation = dispatch_slot(dispatching_head, &second_intent, "second")?;
    reused_operation.operation_id = first_slot.operation_id.clone();
    reused_operation.slot_id = reused_operation.recompute_slot_id()?;
    assert!(compose_clearing_dispatch_transition(
        dispatching_head,
        &dispatching_obligations,
        &second_intent,
        reused_operation,
        505,
    )
    .is_err());
    Ok(())
}

#[test]
fn aborted_round_releases_every_reservation_in_the_winning_batch() -> TestResult {
    let inputs = vec![reserved_obligation(1)?, reserved_obligation(2)?];
    let core = core(&inputs)?;
    let reserved = ClearingRoundLifecycleRecordV1::reserved(&core)?;
    let reserved_head = round_head(&reserved)?;
    let mut anchored = inputs
        .iter()
        .map(|input| {
            Ok(AnchoredClearingObligationV1 {
                input: input.clone(),
                head: obligation_head(input, &core.governance_scope_id)?,
            })
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    let abort_digest = digest("signed-abort");
    let zero_dispatch_proof_digest = digest("zero-dispatch");
    let authority_digest = digest("abort-authority");
    let aborting = compose_clearing_lifecycle_transition(
        &reserved_head,
        &anchored,
        ClearingRoundTransitionV1::BeginAbort {
            abort_digest: abort_digest.clone(),
            zero_dispatch_proof_digest: zero_dispatch_proof_digest.clone(),
            authority_digest: authority_digest.clone(),
            frost_burn_checkpoint_digest: None,
        },
        501,
    )?;
    let aborting_heads = next_heads(&aborting);
    let aborting_head = aborting_heads[0].clone();
    anchored = anchored_obligations(&inputs, &aborting_heads)
        .ok_or("projection omitted an obligation head")?;
    let aborted = compose_clearing_lifecycle_transition(
        &aborting_head,
        &anchored,
        ClearingRoundTransitionV1::Abort {
            abort_digest,
            zero_dispatch_proof_digest,
            authority_digest,
        },
        502,
    )?;
    assert_eq!(aborted.transitions().len(), inputs.len() + 1);
    for transition in aborted
        .transitions()
        .iter()
        .filter(|transition| transition.resource_key.resource_family == "obligation_disposition")
    {
        let EconomicContentV1::Inline { value } = &transition.next_head.state else {
            return Err("released disposition is not inline".into());
        };
        let disposition: ObligationDispositionRecordV1 = serde_json::from_value(value.clone())?;
        assert!(matches!(
            disposition.disposition(),
            ObligationDispositionV1::PerCall
        ));
    }
    Ok(())
}
