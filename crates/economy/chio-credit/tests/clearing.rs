use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_credit::clearing::{
    compute_netting_round, sign_netting_round, verify_netting_round, verify_signed_netting_round,
    ClearingAuthorityTrustV1, ClearingInputManifestBodyV1, ClearingInputManifestEntryV1,
    ClearingObligationInputV1, ClearingParticipantBindingV1,
    ClearingParticipantSnapshotAcknowledgementBodyV1, ClearingParticipantSnapshotBodyV1,
    ClearingRoundRequestV1, SignedClearingInputManifestV1,
    SignedClearingParticipantSnapshotAcknowledgementV1, SignedClearingParticipantSnapshotV1,
    SignedNettingRoundCoreV1, CLEARING_ALGORITHM_V1, CLEARING_INPUT_MANIFEST_SCHEMA,
    CLEARING_PARTICIPANT_SNAPSHOT_ACKNOWLEDGEMENT_SCHEMA, CLEARING_PARTICIPANT_SNAPSHOT_SCHEMA,
};
use chio_credit::obligation::{
    ObligationAtomInputV1, ObligationAtomV1, ObligationCreditElectionV1,
    ObligationDispositionRecordV1, ObligationDispositionTransitionV1,
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
    let obligations = (1..=2_051)
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
