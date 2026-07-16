use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_core_types::economic_continuity::{
    EconomicContentV1, EconomicResourceHeadV1, EconomicResourceKeyV1,
    EconomicTransitionAuthorizationV1, CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA,
};
use chio_credit::clearing::{
    compose_clearing_lifecycle_transition, compute_netting_round, prepare_clearing_round_abort,
    prepare_clearing_round_finalization, prepare_clearing_zero_dispatch_proof,
    sign_clearing_round_abort, sign_clearing_round_finalization, sign_clearing_zero_dispatch_proof,
    sign_netting_round, verify_clearing_lifecycle_replay_authority,
    verify_clearing_participant_acceptances, verify_clearing_round_abort,
    verify_clearing_zero_dispatch_proof, verify_netting_round, verify_signed_netting_round,
    AnchoredClearingObligationV1, ClearingAbortReplayV1, ClearingAuthorityTrustV1,
    ClearingDisputeWindowResolver, ClearingDisputeWindowStatusV1, ClearingInputManifestBodyV1,
    ClearingInputManifestEntryV1, ClearingIntentDispatchStatusV1, ClearingLifecycleAuthorityPinsV1,
    ClearingLifecycleReplayEvidenceV1, ClearingLifecycleReplayV1, ClearingObligationInputV1,
    ClearingParticipantAcceptanceBodyV1, ClearingParticipantBindingV1,
    ClearingParticipantSnapshotAcknowledgementBodyV1, ClearingParticipantSnapshotBodyV1,
    ClearingRoundAbortReasonV1, ClearingRoundLifecycleRecordV1, ClearingRoundRequestV1,
    ClearingRoundTransitionV1, ClearingZeroDispatchTrustV1, SignedClearingInputManifestV1,
    SignedClearingParticipantAcceptanceV1, SignedClearingParticipantSnapshotAcknowledgementV1,
    SignedClearingParticipantSnapshotV1, SignedNettingRoundCoreV1, CLEARING_ALGORITHM_V1,
    CLEARING_INPUT_MANIFEST_SCHEMA, CLEARING_LIFECYCLE_REPLAY_FORMAT,
    CLEARING_PARTICIPANT_ACCEPTANCE_SCHEMA, CLEARING_PARTICIPANT_SNAPSHOT_ACKNOWLEDGEMENT_SCHEMA,
    CLEARING_PARTICIPANT_SNAPSHOT_SCHEMA,
};
use chio_credit::obligation::{
    ObligationAtomInputV1, ObligationAtomV1, ObligationCreditElectionV1,
    ObligationDispositionRecordV1, ObligationDispositionTransitionV1, ObligationDispositionV1,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn validate_schema(name: &str, artifact: &impl serde::Serialize) -> TestResult {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../spec/schemas/chio-economy")
        .join(name);
    let schema = chio_spec_validate::load_json(&path)?;
    let value = serde_json::to_value(artifact)?;
    chio_spec_validate::validate_value(
        &path,
        &schema,
        &std::path::PathBuf::from("<clearing-artifact>"),
        &value,
    )?;
    Ok(())
}

fn digest(value: &str) -> String {
    sha256_hex(value.as_bytes())
}

fn participant_key(participant: &str) -> Keypair {
    let seed = match participant {
        "A" => 10,
        "B" => 11,
        "C" => 12,
        _ => 13,
    };
    Keypair::from_seed(&[seed; 32])
}

fn reserved_obligation(
    sequence: u64,
    debtor_id: &str,
    creditor_id: &str,
    currency: &str,
    units: u64,
) -> Result<ClearingObligationInputV1, Box<dyn std::error::Error>> {
    let atom = ObligationAtomV1::new(ObligationAtomInputV1 {
        economic_intent_digest: digest(&format!("intent-{sequence}")),
        source_receipt_id: format!("receipt-{sequence}"),
        source_receipt_digest: digest(&format!("receipt-{sequence}")),
        debtor_id: debtor_id.to_owned(),
        original_creditor_id: creditor_id.to_owned(),
        original_settlement_destination_ref: format!("acct:{creditor_id}"),
        payee_binding_digest: digest(&format!("payee-{sequence}")),
        amount: MonetaryAmount {
            currency: currency.to_owned(),
            units,
        },
        credit_election: ObligationCreditElectionV1::NotCredit,
        pre_action_authority_digest: digest(&format!("authority-{sequence}")),
        created_at_unix_ms: 100,
        due_at_unix_ms: 10_000,
    })?;
    let disposition = ObligationDispositionRecordV1::produced(&atom)?.advance(
        &atom,
        ObligationDispositionTransitionV1::ReserveClearing {
            round_id: "round-1".to_owned(),
            authority_digest: digest(&format!("reservation-{sequence}")),
        },
    )?;
    Ok(ClearingObligationInputV1 {
        source_sequence: sequence,
        atom,
        disposition,
    })
}

fn signed_request(
    obligations: Vec<ClearingObligationInputV1>,
    participant_authority: &Keypair,
    obligation_authority: &Keypair,
) -> Result<ClearingRoundRequestV1, Box<dyn std::error::Error>> {
    let participant_snapshot = SignedClearingParticipantSnapshotV1::sign(
        ClearingParticipantSnapshotBodyV1 {
            schema: CLEARING_PARTICIPANT_SNAPSHOT_SCHEMA.to_owned(),
            authority_id: "participant-authority".to_owned(),
            key_epoch: 7,
            algorithm_version: CLEARING_ALGORITHM_V1.to_owned(),
            valid_from_unix_ms: 50,
            expires_at_unix_ms: 1_000,
            participants: ["A", "B", "C"]
                .into_iter()
                .map(|participant| ClearingParticipantBindingV1 {
                    participant_id: participant.to_owned(),
                    identities: vec![participant.to_owned()],
                    settlement_destination: format!("acct:{participant}"),
                    acknowledgement_key: participant_key(participant).public_key(),
                    acknowledgement_key_epoch: 1,
                })
                .collect(),
        },
        participant_authority,
    )?;
    let participant_snapshot_digest = participant_snapshot.body.digest()?;
    let participant_acknowledgements = ["A", "B", "C"]
        .into_iter()
        .map(|participant| {
            SignedClearingParticipantSnapshotAcknowledgementV1::sign(
                ClearingParticipantSnapshotAcknowledgementBodyV1 {
                    schema: CLEARING_PARTICIPANT_SNAPSHOT_ACKNOWLEDGEMENT_SCHEMA.to_owned(),
                    participant_snapshot_digest: participant_snapshot_digest.clone(),
                    participant_id: participant.to_owned(),
                    algorithm_version: CLEARING_ALGORITHM_V1.to_owned(),
                    key_epoch: 1,
                    accepted_at_unix_ms: 90,
                    expires_at_unix_ms: 600,
                },
                &participant_key(participant),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let entries = obligations
        .iter()
        .map(ClearingInputManifestEntryV1::from_reserved)
        .collect::<Result<Vec<_>, _>>()?;
    let input_manifest = SignedClearingInputManifestV1::sign(
        ClearingInputManifestBodyV1 {
            schema: CLEARING_INPUT_MANIFEST_SCHEMA.to_owned(),
            authority_id: "obligation-authority".to_owned(),
            key_epoch: 11,
            source_id: "obligations-primary".to_owned(),
            epoch: 3,
            range_start_sequence: 1,
            range_end_sequence: u64::try_from(entries.len())?,
            start_checkpoint_digest: digest("checkpoint-start"),
            end_checkpoint_digest: digest("checkpoint-end"),
            entries,
            has_more: false,
            next_cursor: None,
            issued_at_unix_ms: 80,
            expires_at_unix_ms: 200,
        },
        obligation_authority,
    )?;
    Ok(ClearingRoundRequestV1 {
        round_id: "round-1".to_owned(),
        epoch: 3,
        governance_scope_id: "clearing-governance".to_owned(),
        currency: "USD".to_owned(),
        algorithm_version: CLEARING_ALGORITHM_V1.to_owned(),
        participant_snapshot,
        participant_acknowledgements,
        input_manifest,
        obligations,
        dispute_window_ends_at_unix_ms: 500,
        generated_at_unix_ms: 100,
    })
}

fn trust(
    participant_authority: &Keypair,
    obligation_authority: &Keypair,
) -> ClearingAuthorityTrustV1 {
    ClearingAuthorityTrustV1 {
        clearing_authority_id: "clearing-authority".to_owned(),
        clearing_authority_key: participant_authority.public_key(),
        clearing_authority_key_epoch: 13,
        participant_authority_id: "participant-authority".to_owned(),
        participant_authority_key: participant_authority.public_key(),
        participant_key_epoch: 7,
        obligation_authority_id: "obligation-authority".to_owned(),
        obligation_authority_key: obligation_authority.public_key(),
        obligation_key_epoch: 11,
        trusted_time_unix_ms: 100,
    }
}

fn signed_acceptances(
    output: &chio_credit::clearing::ClearingRoundOutputV1,
) -> Result<Vec<SignedClearingParticipantAcceptanceV1>, Box<dyn std::error::Error>> {
    let output_manifest_digest = output.output_manifest.digest()?;
    output
        .participant_statements
        .iter()
        .map(|statement| {
            Ok(SignedClearingParticipantAcceptanceV1::sign(
                ClearingParticipantAcceptanceBodyV1 {
                    schema: CLEARING_PARTICIPANT_ACCEPTANCE_SCHEMA.to_owned(),
                    round_id: output.core.round_id.clone(),
                    round_core_digest: output.core.digest()?,
                    output_manifest_digest: output_manifest_digest.clone(),
                    participant_statement_digest: statement.digest()?,
                    participant_id: statement.participant_id.clone(),
                    key_epoch: 1,
                    accepted_at_unix_ms: 510,
                    expires_at_unix_ms: 600,
                },
                &participant_key(&statement.participant_id),
            )?)
        })
        .collect()
}

struct DisputeWindow {
    unresolved_dispute_count: u64,
}

impl ClearingDisputeWindowResolver for DisputeWindow {
    fn resolve_closed_window(
        &self,
        round_id: &str,
        round_core_digest: &str,
        output_manifest_digest: &str,
        dispute_window_ends_at_unix_ms: u64,
    ) -> Result<ClearingDisputeWindowStatusV1, chio_credit::clearing::ClearingError> {
        Ok(ClearingDisputeWindowStatusV1 {
            round_id: round_id.to_owned(),
            round_core_digest: round_core_digest.to_owned(),
            output_manifest_digest: output_manifest_digest.to_owned(),
            dispute_window_ends_at_unix_ms,
            observed_through_unix_ms: dispute_window_ends_at_unix_ms,
            unresolved_dispute_count: self.unresolved_dispute_count,
            checkpoint_digest: digest("dispute-window-checkpoint"),
        })
    }
}

fn clearing_head(
    record: &ClearingRoundLifecycleRecordV1,
) -> Result<EconomicResourceHeadV1, Box<dyn std::error::Error>> {
    let state = EconomicContentV1::Inline {
        value: serde_json::to_value(record)?,
    };
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

fn anchored_obligations(
    obligations: &[ClearingObligationInputV1],
    scope_id: &str,
) -> Result<Vec<AnchoredClearingObligationV1>, Box<dyn std::error::Error>> {
    obligations
        .iter()
        .map(|input| {
            let state = EconomicContentV1::Inline {
                value: serde_json::to_value(&input.disposition)?,
            };
            Ok(AnchoredClearingObligationV1 {
                input: input.clone(),
                head: EconomicResourceHeadV1 {
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
                },
            })
        })
        .collect()
}

fn advance_anchored_obligations(
    inputs: &[ClearingObligationInputV1],
    heads: &[EconomicResourceHeadV1],
) -> Result<Vec<AnchoredClearingObligationV1>, Box<dyn std::error::Error>> {
    inputs
        .iter()
        .map(|input| {
            let head = heads
                .iter()
                .find(|head| head.resource_key.resource_id == input.atom.obligation_id())
                .ok_or("missing obligation head")?;
            Ok(AnchoredClearingObligationV1 {
                input: input.clone(),
                head: head.clone(),
            })
        })
        .collect()
}

#[test]
fn acyclic_chain_reduces_to_one_direct_intent() -> TestResult {
    let participant_authority = Keypair::from_seed(&[1; 32]);
    let obligation_authority = Keypair::from_seed(&[2; 32]);
    let obligations = vec![
        reserved_obligation(1, "A", "B", "USD", 100)?,
        reserved_obligation(2, "B", "C", "USD", 100)?,
    ];
    let request = signed_request(
        obligations.clone(),
        &participant_authority,
        &obligation_authority,
    )?;
    let output = compute_netting_round(
        &request,
        &trust(&participant_authority, &obligation_authority),
    )?;

    assert_eq!(output.intents.len(), 1);
    assert_eq!(output.intents[0].debtor_participant_id, "A");
    assert_eq!(output.intents[0].creditor_participant_id, "C");
    assert_eq!(output.intents[0].amount.units, 100);
    verify_netting_round(
        &request,
        &trust(&participant_authority, &obligation_authority),
        &output,
    )?;
    let mut tampered = output.clone();
    tampered.intents[0].amount.units = 101;
    assert!(verify_netting_round(
        &request,
        &trust(&participant_authority, &obligation_authority),
        &tampered,
    )
    .is_err());
    let authority_trust = trust(&participant_authority, &obligation_authority);
    assert!(sign_netting_round(
        &request,
        &tampered,
        &authority_trust,
        &participant_authority,
    )
    .is_err());
    let signed = sign_netting_round(&request, &output, &authority_trust, &participant_authority)?;
    validate_schema(
        "clearing-participant-snapshot.v1.json",
        &request.participant_snapshot,
    )?;
    for acknowledgement in &request.participant_acknowledgements {
        validate_schema(
            "clearing-participant-snapshot-acknowledgement.v1.json",
            acknowledgement,
        )?;
    }
    validate_schema("clearing-input-manifest.v1.json", &request.input_manifest)?;
    validate_schema("clearing-netting-round-core.v1.json", &signed.core)?;
    for statement in &signed.participant_statements {
        validate_schema("clearing-participant-statement.v1.json", statement)?;
    }
    for intent in &signed.intents {
        validate_schema("clearing-settlement-intent.v1.json", intent)?;
    }
    for transformation in &signed.transformations {
        validate_schema("clearing-atom-transformation.v1.json", transformation)?;
    }
    validate_schema("clearing-output-manifest.v1.json", &signed.output_manifest)?;
    assert_eq!(
        verify_signed_netting_round(&request, &authority_trust, &signed)?,
        output
    );
    let mut tampered_signed = signed;
    tampered_signed.intents[0].body.amount.units = 101;
    assert!(verify_signed_netting_round(&request, &authority_trust, &tampered_signed).is_err());
    let mut unknown_field = serde_json::to_value(&tampered_signed.core)?;
    unknown_field["unexpected"] = serde_json::Value::Bool(true);
    assert!(serde_json::from_value::<SignedNettingRoundCoreV1>(unknown_field).is_err());

    let mut missing_acknowledgement = request.clone();
    missing_acknowledgement.participant_acknowledgements.pop();
    assert!(compute_netting_round(&missing_acknowledgement, &authority_trust).is_err());

    let mut shuffled = request;
    shuffled.obligations.reverse();
    let shuffled_output = compute_netting_round(
        &shuffled,
        &trust(&participant_authority, &obligation_authority),
    )?;
    assert_eq!(output, shuffled_output);
    Ok(())
}

#[test]
fn participant_acceptances_bind_every_affected_statement_after_the_dispute_window() -> TestResult {
    let participant_authority = Keypair::from_seed(&[21; 32]);
    let obligation_authority = Keypair::from_seed(&[22; 32]);
    let request = signed_request(
        vec![
            reserved_obligation(1, "A", "B", "USD", 100)?,
            reserved_obligation(2, "B", "C", "USD", 100)?,
        ],
        &participant_authority,
        &obligation_authority,
    )?;
    let mut finalization_trust = trust(&participant_authority, &obligation_authority);
    let admission_trust = finalization_trust.clone();
    let output = compute_netting_round(&request, &admission_trust)?;
    let signed_output =
        sign_netting_round(&request, &output, &admission_trust, &participant_authority)?;
    let acceptances = signed_acceptances(&output)?;
    let closed_dispute_window = DisputeWindow {
        unresolved_dispute_count: 0,
    };
    finalization_trust.trusted_time_unix_ms = 550;

    let verified = verify_clearing_participant_acceptances(
        &request,
        &signed_output,
        &acceptances,
        &closed_dispute_window,
        &finalization_trust,
    )?;
    assert_eq!(verified.acceptance_count(), 3);
    assert_eq!(verified.round_id(), "round-1");
    assert_eq!(
        verified.output_manifest_digest(),
        output.output_manifest.digest()?
    );
    for acceptance in &acceptances {
        validate_schema("clearing-participant-acceptance.v1.json", acceptance)?;
    }
    assert!(matches!(
        verified.begin_finalization_transition(),
        ClearingRoundTransitionV1::BeginFinalization {
            acceptance_count: 3,
            ..
        }
    ));

    let reserved = ClearingRoundLifecycleRecordV1::reserved(&output.core)?;
    let reserved_head = clearing_head(&reserved)?;
    let anchored = anchored_obligations(&request.obligations, &output.core.governance_scope_id)?;
    let proposed = compose_clearing_lifecycle_transition(
        &reserved_head,
        &anchored,
        ClearingRoundTransitionV1::Propose {
            output_manifest_digest: output.output_manifest.digest()?,
            authority_digest: signed_output.output_manifest.digest()?,
        },
        501,
    )?;
    let proposed_heads = proposed
        .transitions()
        .iter()
        .map(|transition| transition.next_head.clone())
        .collect::<Vec<_>>();
    let proposed_head = proposed_heads
        .iter()
        .find(|head| head.resource_key.resource_family == "clearing_round")
        .ok_or("missing proposed round head")?;
    let proposed_obligations = advance_anchored_obligations(&request.obligations, &proposed_heads)?;
    let finalizing = compose_clearing_lifecycle_transition(
        proposed_head,
        &proposed_obligations,
        verified.begin_finalization_transition(),
        502,
    )?;
    let finalizing_head = finalizing
        .transitions()
        .iter()
        .find(|transition| transition.resource_key.resource_family == "clearing_round")
        .map(|transition| &transition.next_head)
        .ok_or("missing finalizing round head")?;
    let finalization_body =
        prepare_clearing_round_finalization(finalizing_head, &verified, &finalization_trust)?;
    let signed_finalization = sign_clearing_round_finalization(
        finalization_body.clone(),
        &finalization_trust,
        &participant_authority,
    )?;
    validate_schema("clearing-round-finalization.v1.json", &signed_finalization)?;
    let action = finalization_body.frost_action_preimage()?;
    assert_eq!(action.resource_id(), "round-1");
    assert_eq!(action.resource_version(), finalizing_head.resource_version);
    assert_eq!(action.resource_fence(), finalizing_head.lifecycle_fence);

    let mut alternate_acceptances = acceptances.clone();
    alternate_acceptances[0] = SignedClearingParticipantAcceptanceV1::sign(
        ClearingParticipantAcceptanceBodyV1 {
            accepted_at_unix_ms: 511,
            ..alternate_acceptances[0].body.clone()
        },
        &participant_key("A"),
    )?;
    let alternate_verified = verify_clearing_participant_acceptances(
        &request,
        &signed_output,
        &alternate_acceptances,
        &closed_dispute_window,
        &finalization_trust,
    )?;
    assert!(prepare_clearing_round_finalization(
        finalizing_head,
        &alternate_verified,
        &finalization_trust,
    )
    .is_err());

    let mut expired_finalization_trust = finalization_trust.clone();
    expired_finalization_trust.trusted_time_unix_ms = 600;
    assert!(prepare_clearing_round_finalization(
        finalizing_head,
        &verified,
        &expired_finalization_trust,
    )
    .is_err());

    let mut incomplete = acceptances.clone();
    incomplete.pop();
    assert!(verify_clearing_participant_acceptances(
        &request,
        &signed_output,
        &incomplete,
        &closed_dispute_window,
        &finalization_trust,
    )
    .is_err());

    let mut wrong_statement = acceptances.clone();
    wrong_statement[0] = SignedClearingParticipantAcceptanceV1::sign(
        ClearingParticipantAcceptanceBodyV1 {
            participant_statement_digest: output.participant_statements[1].digest()?,
            ..wrong_statement[0].body.clone()
        },
        &participant_key("A"),
    )?;
    assert!(verify_clearing_participant_acceptances(
        &request,
        &signed_output,
        &wrong_statement,
        &closed_dispute_window,
        &finalization_trust,
    )
    .is_err());

    let mut expired = acceptances.clone();
    expired[0] = SignedClearingParticipantAcceptanceV1::sign(
        ClearingParticipantAcceptanceBodyV1 {
            expires_at_unix_ms: 550,
            ..expired[0].body.clone()
        },
        &participant_key("A"),
    )?;
    assert!(verify_clearing_participant_acceptances(
        &request,
        &signed_output,
        &expired,
        &closed_dispute_window,
        &finalization_trust,
    )
    .is_err());

    finalization_trust.trusted_time_unix_ms = 499;
    assert!(verify_clearing_participant_acceptances(
        &request,
        &signed_output,
        &acceptances,
        &closed_dispute_window,
        &finalization_trust,
    )
    .is_err());
    finalization_trust.trusted_time_unix_ms = 550;
    assert!(verify_clearing_participant_acceptances(
        &request,
        &signed_output,
        &acceptances,
        &DisputeWindow {
            unresolved_dispute_count: 1,
        },
        &finalization_trust,
    )
    .is_err());
    Ok(())
}

#[test]
fn signed_abort_releases_only_after_complete_zero_dispatch_and_the_winning_fence() -> TestResult {
    let participant_authority = Keypair::from_seed(&[31; 32]);
    let obligation_authority = Keypair::from_seed(&[32; 32]);
    let admission_authority = Keypair::from_seed(&[33; 32]);
    let request = signed_request(
        vec![
            reserved_obligation(1, "A", "B", "USD", 100)?,
            reserved_obligation(2, "B", "C", "USD", 100)?,
        ],
        &participant_authority,
        &obligation_authority,
    )?;
    let mut clearing_trust = trust(&participant_authority, &obligation_authority);
    let output = compute_netting_round(&request, &clearing_trust)?;
    let signed_output =
        sign_netting_round(&request, &output, &clearing_trust, &participant_authority)?;
    let reserved = ClearingRoundLifecycleRecordV1::reserved(&output.core)?;
    let reserved_head = clearing_head(&reserved)?;
    let anchored = anchored_obligations(&request.obligations, &output.core.governance_scope_id)?;
    let proposed = compose_clearing_lifecycle_transition(
        &reserved_head,
        &anchored,
        ClearingRoundTransitionV1::Propose {
            output_manifest_digest: output.output_manifest.digest()?,
            authority_digest: signed_output.output_manifest.digest()?,
        },
        501,
    )?;
    let proposed_heads = proposed
        .transitions()
        .iter()
        .map(|transition| transition.next_head.clone())
        .collect::<Vec<_>>();
    let proposed_head = proposed_heads
        .iter()
        .find(|head| head.resource_key.resource_family == "clearing_round")
        .ok_or("missing proposed round head")?;
    let proposed_obligations = advance_anchored_obligations(&request.obligations, &proposed_heads)?;

    clearing_trust.trusted_time_unix_ms = 520;
    let proof_trust = ClearingZeroDispatchTrustV1 {
        authority_id: "admission-authority".to_owned(),
        authority_key: admission_authority.public_key(),
        authority_key_epoch: 9,
        admission_store_id: "admission-store-primary".to_owned(),
        admission_commit_sequence: 12,
        admission_commit_digest: digest("admission-commit"),
        trusted_time_unix_ms: 520,
    };
    let statuses = output
        .intents
        .iter()
        .map(ClearingIntentDispatchStatusV1::absent)
        .collect::<Result<Vec<_>, _>>()?;
    let proof_body = prepare_clearing_zero_dispatch_proof(
        proposed_head,
        &request,
        Some(&signed_output),
        statuses.clone(),
        &clearing_trust,
        &proof_trust,
        560,
    )?;
    let signed_proof =
        sign_clearing_zero_dispatch_proof(proof_body, &proof_trust, &admission_authority)?;
    validate_schema("clearing-zero-dispatch-proof.v1.json", &signed_proof)?;
    let verified_proof = verify_clearing_zero_dispatch_proof(
        proposed_head,
        &request,
        Some(&signed_output),
        &signed_proof,
        &clearing_trust,
        &proof_trust,
    )?;
    let mut advanced_checkpoint = proof_trust.clone();
    advanced_checkpoint.admission_commit_sequence += 1;
    advanced_checkpoint.admission_commit_digest = digest("advanced-admission-commit");
    assert!(verify_clearing_zero_dispatch_proof(
        proposed_head,
        &request,
        Some(&signed_output),
        &signed_proof,
        &clearing_trust,
        &advanced_checkpoint,
    )
    .is_err());

    clearing_trust.trusted_time_unix_ms = 525;
    let abort_body = prepare_clearing_round_abort(
        proposed_head,
        &verified_proof,
        ClearingRoundAbortReasonV1::OperatorCancelled,
        digest("abort-authority"),
        None,
        &clearing_trust,
    )?;
    let signed_abort =
        sign_clearing_round_abort(abort_body, &clearing_trust, &obligation_authority)?;
    validate_schema("clearing-round-abort.v1.json", &signed_abort)?;
    let verified_abort = verify_clearing_round_abort(
        proposed_head,
        &verified_proof,
        &signed_abort,
        None,
        &clearing_trust,
    )?;
    let aborting = compose_clearing_lifecycle_transition(
        proposed_head,
        &proposed_obligations,
        verified_abort.begin_abort_transition(),
        525,
    )?;
    let aborting_heads = aborting
        .transitions()
        .iter()
        .map(|transition| transition.next_head.clone())
        .collect::<Vec<_>>();
    let aborting_head = aborting_heads
        .iter()
        .find(|head| head.resource_key.resource_family == "clearing_round")
        .ok_or("missing aborting round head")?;
    let aborting_obligations = advance_anchored_obligations(&request.obligations, &aborting_heads)?;
    let aborted = compose_clearing_lifecycle_transition(
        aborting_head,
        &aborting_obligations,
        verified_abort.abort_transition(aborting_head, aborting.proof())?,
        526,
    )?;
    let aborted_round = aborted
        .transitions()
        .iter()
        .find(|transition| transition.resource_key.resource_family == "clearing_round")
        .ok_or("missing aborted round head")?;
    assert_eq!(aborted_round.next_head.lifecycle_state, "aborted");
    let replay_pins = ClearingLifecycleAuthorityPinsV1 {
        clearing_authority_id: clearing_trust.clearing_authority_id.clone(),
        clearing_authority_key: clearing_trust.clearing_authority_key.clone(),
        clearing_authority_key_epoch: clearing_trust.clearing_authority_key_epoch,
        participant_authority_id: clearing_trust.participant_authority_id.clone(),
        participant_authority_key: clearing_trust.participant_authority_key.clone(),
        participant_key_epoch: clearing_trust.participant_key_epoch,
        obligation_authority_id: clearing_trust.obligation_authority_id.clone(),
        obligation_authority_key: clearing_trust.obligation_authority_key.clone(),
        obligation_key_epoch: clearing_trust.obligation_key_epoch,
        zero_dispatch_authority_id: proof_trust.authority_id.clone(),
        zero_dispatch_authority_key: proof_trust.authority_key.clone(),
        zero_dispatch_authority_key_epoch: proof_trust.authority_key_epoch,
        admission_store_id: proof_trust.admission_store_id.clone(),
    };
    let proposal_replay = ClearingLifecycleReplayV1 {
        format: CLEARING_LIFECYCLE_REPLAY_FORMAT.to_owned(),
        proof: proposed.proof().clone(),
        evidence: ClearingLifecycleReplayEvidenceV1::Proposal {
            request: Box::new(request.clone()),
            signed_output: Box::new(signed_output.clone()),
        },
    };
    assert_eq!(
        verify_clearing_lifecycle_replay_authority(
            &reserved_head,
            &proposal_replay,
            &replay_pins,
            None,
        )?,
        EconomicTransitionAuthorizationV1::Direct
    );
    let abort_replay = ClearingAbortReplayV1 {
        request: request.clone(),
        signed_output: Some(signed_output.clone()),
        zero_dispatch_proof: signed_proof.clone(),
        abort: signed_abort.clone(),
        finalization_burn: None,
    };
    let begin_replay = ClearingLifecycleReplayV1 {
        format: CLEARING_LIFECYCLE_REPLAY_FORMAT.to_owned(),
        proof: aborting.proof().clone(),
        evidence: ClearingLifecycleReplayEvidenceV1::BeginAbort {
            abort: Box::new(abort_replay.clone()),
        },
    };
    assert_eq!(
        verify_clearing_lifecycle_replay_authority(
            proposed_head,
            &begin_replay,
            &replay_pins,
            None,
        )?,
        EconomicTransitionAuthorizationV1::Direct
    );
    assert_eq!(
        begin_replay.admission_checkpoint(),
        Some((
            proof_trust.admission_store_id.as_str(),
            proof_trust.admission_commit_sequence,
            proof_trust.admission_commit_digest.as_str(),
        ))
    );
    let completion_replay = ClearingLifecycleReplayV1 {
        format: CLEARING_LIFECYCLE_REPLAY_FORMAT.to_owned(),
        proof: aborted.proof().clone(),
        evidence: ClearingLifecycleReplayEvidenceV1::Abort {
            preabort_round_head: Box::new(proposed_head.clone()),
            begin_abort_proof: Box::new(aborting.proof().clone()),
            abort: Box::new(abort_replay),
        },
    };
    assert_eq!(
        verify_clearing_lifecycle_replay_authority(
            aborting_head,
            &completion_replay,
            &replay_pins,
            None,
        )?,
        EconomicTransitionAuthorizationV1::Direct
    );
    let canonical_replay = canonical_json_bytes(&completion_replay)?;
    let decoded_replay: ClearingLifecycleReplayV1 = serde_json::from_slice(&canonical_replay)?;
    assert_eq!(decoded_replay, completion_replay);
    let mut substituted_replay = completion_replay;
    let ClearingLifecycleReplayEvidenceV1::Abort {
        begin_abort_proof, ..
    } = &mut substituted_replay.evidence
    else {
        return Err("completion replay used the wrong evidence".into());
    };
    begin_abort_proof.source_round_head_digest = digest("substituted-source");
    assert!(verify_clearing_lifecycle_replay_authority(
        aborting_head,
        &substituted_replay,
        &replay_pins,
        None,
    )
    .is_err());
    for transition in aborted
        .transitions()
        .iter()
        .filter(|transition| transition.resource_key.resource_family == "obligation_disposition")
    {
        let EconomicContentV1::Inline { value } = &transition.next_head.state else {
            return Err("released obligation did not contain inline state".into());
        };
        let disposition: ObligationDispositionRecordV1 = serde_json::from_value(value.clone())?;
        assert_eq!(disposition.disposition(), &ObligationDispositionV1::PerCall);
    }

    let mut incomplete = statuses;
    incomplete.pop();
    assert!(prepare_clearing_zero_dispatch_proof(
        proposed_head,
        &request,
        Some(&signed_output),
        incomplete,
        &clearing_trust,
        &proof_trust,
        560,
    )
    .is_err());
    assert!(sign_clearing_round_abort(
        signed_abort.body.clone(),
        &clearing_trust,
        &participant_authority,
    )
    .is_err());
    assert!(verified_abort
        .abort_transition(proposed_head, aborting.proof())
        .is_err());
    let mut substituted_proof = aborting.proof().clone();
    let ClearingRoundTransitionV1::BeginAbort {
        zero_dispatch_proof_digest,
        ..
    } = &mut substituted_proof.transition
    else {
        return Err("aborting proof used the wrong transition".into());
    };
    *zero_dispatch_proof_digest = digest("substituted-zero-dispatch");
    assert!(verified_abort
        .abort_transition(aborting_head, &substituted_proof)
        .is_err());
    let mut expired_trust = clearing_trust;
    expired_trust.trusted_time_unix_ms = 560;
    assert!(prepare_clearing_round_abort(
        proposed_head,
        &verified_proof,
        ClearingRoundAbortReasonV1::OperatorCancelled,
        digest("abort-authority"),
        None,
        &expired_trust,
    )
    .is_err());
    Ok(())
}

#[test]
fn reverse_bilateral_flows_cancel_before_matching() -> TestResult {
    let participant_authority = Keypair::from_seed(&[3; 32]);
    let obligation_authority = Keypair::from_seed(&[4; 32]);
    let request = signed_request(
        vec![
            reserved_obligation(1, "A", "B", "USD", 100)?,
            reserved_obligation(2, "B", "A", "USD", 40)?,
        ],
        &participant_authority,
        &obligation_authority,
    )?;
    let output = compute_netting_round(
        &request,
        &trust(&participant_authority, &obligation_authority),
    )?;

    assert_eq!(output.intents.len(), 1);
    assert_eq!(output.intents[0].debtor_participant_id, "A");
    assert_eq!(output.intents[0].creditor_participant_id, "B");
    assert_eq!(output.intents[0].amount.units, 60);
    Ok(())
}

#[test]
fn balanced_cycle_emits_no_settlement_intent() -> TestResult {
    let participant_authority = Keypair::from_seed(&[7; 32]);
    let obligation_authority = Keypair::from_seed(&[8; 32]);
    let request = signed_request(
        vec![
            reserved_obligation(1, "A", "B", "USD", 100)?,
            reserved_obligation(2, "B", "C", "USD", 100)?,
            reserved_obligation(3, "C", "A", "USD", 100)?,
        ],
        &participant_authority,
        &obligation_authority,
    )?;
    let output = compute_netting_round(
        &request,
        &trust(&participant_authority, &obligation_authority),
    )?;

    assert!(output.intents.is_empty());
    assert_eq!(output.output_manifest.settlement_intent_count, 0);
    assert!(output
        .participant_statements
        .iter()
        .all(|statement| statement.net_balance.units == 0));
    Ok(())
}

#[test]
fn aggregate_that_cannot_fit_the_wire_amount_rejects() -> TestResult {
    let participant_authority = Keypair::from_seed(&[9; 32]);
    let obligation_authority = Keypair::from_seed(&[14; 32]);
    let obligations = (1..=2)
        .map(|sequence| reserved_obligation(sequence, "A", "B", "USD", (1_u64 << 53) - 1))
        .collect::<Result<Vec<_>, _>>()?;
    let request = signed_request(obligations, &participant_authority, &obligation_authority)?;

    assert!(compute_netting_round(
        &request,
        &trust(&participant_authority, &obligation_authority)
    )
    .is_err());
    Ok(())
}

#[test]
fn duplicate_mixed_currency_and_incomplete_inputs_reject() -> TestResult {
    let participant_authority = Keypair::from_seed(&[5; 32]);
    let obligation_authority = Keypair::from_seed(&[6; 32]);
    let first = reserved_obligation(1, "A", "B", "USD", 100)?;
    let mut second = first.clone();
    second.source_sequence = 2;
    let duplicate = signed_request(
        vec![first, second],
        &participant_authority,
        &obligation_authority,
    )?;
    assert!(compute_netting_round(
        &duplicate,
        &trust(&participant_authority, &obligation_authority)
    )
    .is_err());

    let mixed = signed_request(
        vec![
            reserved_obligation(1, "A", "B", "USD", 100)?,
            reserved_obligation(2, "B", "C", "EUR", 100)?,
        ],
        &participant_authority,
        &obligation_authority,
    )?;
    assert!(compute_netting_round(
        &mixed,
        &trust(&participant_authority, &obligation_authority)
    )
    .is_err());

    let mut incomplete = signed_request(
        vec![reserved_obligation(1, "A", "B", "USD", 100)?],
        &participant_authority,
        &obligation_authority,
    )?;
    incomplete.input_manifest.body.has_more = true;
    incomplete.input_manifest.body.next_cursor = Some("cursor-2".to_owned());
    incomplete.input_manifest = SignedClearingInputManifestV1::sign(
        incomplete.input_manifest.body.clone(),
        &obligation_authority,
    )?;
    assert!(compute_netting_round(
        &incomplete,
        &trust(&participant_authority, &obligation_authority)
    )
    .is_err());
    Ok(())
}
