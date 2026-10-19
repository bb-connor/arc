use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_finding::{
    compute_enforcement_id, compute_snapshot_id, verify_signed_challenge_enforcement,
    verify_signed_finalized_bond_snapshot, FindingEffectIntentBinding, FindingEffectIntentKind,
    FindingError, FindingFinalizedBondSnapshot, FindingObservedFinality,
};
use serde_json::{json, Value};

use super::helpers::*;

#[test]
fn enforcement_destinations_sum_exactly_to_the_total() -> TestResult {
    let enforcement = enforcement_body()?;
    (enforcement.validate())?;

    let mut short = enforcement_body()?;
    short.destinations[0].amount = usd(89_999);
    short.enforcement_id = compute_enforcement_id(&short)?;
    assert_eq!(
        short.validate(),
        Err(FindingError::InvalidField("destinations"))
    );

    let mut long = enforcement_body()?;
    long.destinations[1].amount = usd(30_001);
    long.enforcement_id = compute_enforcement_id(&long)?;
    assert_eq!(
        long.validate(),
        Err(FindingError::InvalidField("destinations"))
    );

    let mut mixed_currency = enforcement_body()?;
    mixed_currency.destinations[1].amount = MonetaryAmount {
        units: 30_000,
        currency: "EUR".to_string(),
    };
    mixed_currency.enforcement_id = compute_enforcement_id(&mixed_currency)?;
    assert_eq!(
        mixed_currency.validate(),
        Err(FindingError::CurrencyMismatch("destinations[]"))
    );

    let mut duplicated = enforcement_body()?;
    duplicated.destinations[1].destination = duplicated.destinations[0].destination.clone();
    duplicated.destinations[1].amount = usd(30_000);
    duplicated.enforcement_id = compute_enforcement_id(&duplicated)?;
    assert_eq!(
        duplicated.validate(),
        Err(FindingError::DuplicateEntry("destinations[]"))
    );

    let mut empty = enforcement_body()?;
    empty.destinations.clear();
    empty.enforcement_id = compute_enforcement_id(&empty)?;
    assert_eq!(
        empty.validate(),
        Err(FindingError::MissingEntry("destinations"))
    );
    Ok(())
}

#[test]
fn enforcement_requires_every_pre_dispatch_intent() -> TestResult {
    let mut missing_retraction = enforcement_body()?;
    missing_retraction
        .effect_intents
        .retain(|intent| intent.kind != FindingEffectIntentKind::Retraction);
    missing_retraction.enforcement_id = compute_enforcement_id(&missing_retraction)?;
    assert_eq!(
        missing_retraction.validate(),
        Err(FindingError::MissingEntry("effect_intents[]"))
    );

    let mut duplicated = enforcement_body()?;
    duplicated.effect_intents.push(FindingEffectIntentBinding {
        kind: FindingEffectIntentKind::SellerImpair,
        intent_id: HEX64_THIRD.to_string(),
    });
    duplicated.enforcement_id = compute_enforcement_id(&duplicated)?;
    assert_eq!(
        duplicated.validate(),
        Err(FindingError::DuplicateEntry("effect_intents[]"))
    );

    let mut with_optional = enforcement_body()?;
    with_optional
        .effect_intents
        .push(FindingEffectIntentBinding {
            kind: FindingEffectIntentKind::ChallengeBond,
            intent_id: HEX64_ALT.to_string(),
        });
    with_optional.enforcement_id = compute_enforcement_id(&with_optional)?;
    (with_optional.validate())?;
    Ok(())
}

#[test]
fn enforcement_signs_and_verifies_under_the_finalization_authority() -> TestResult {
    let finalization_authority = keypair(44);
    let evaluator = keypair(43);

    let signed = SignedExportEnvelope::sign(enforcement_body()?, &finalization_authority)?;
    (verify_signed_challenge_enforcement(&signed, &finalization_authority.public_key()))?;

    // Role separation: the evaluator key cannot authorize enforcement.
    let forged = SignedExportEnvelope::sign(enforcement_body()?, &evaluator)?;
    assert_eq!(
        verify_signed_challenge_enforcement(&forged, &finalization_authority.public_key()),
        Err(FindingError::AuthorityMismatch("challenge_enforcement"))
    );

    let mut misbound = enforcement_body()?;
    misbound.finalization_key = keypair(45).public_key();
    misbound.enforcement_id = compute_enforcement_id(&misbound)?;
    let misbound = SignedExportEnvelope::sign(misbound, &finalization_authority)?;
    assert_eq!(
        verify_signed_challenge_enforcement(&misbound, &finalization_authority.public_key()),
        Err(FindingError::AuthorityMismatch(
            "challenge_enforcement.finalization_key"
        ))
    );
    Ok(())
}

#[test]
fn enforcement_conforms_to_its_schema() -> TestResult {
    let finalization_authority = keypair(44);
    let signed = SignedExportEnvelope::sign(enforcement_body()?, &finalization_authority)?;
    let value: Value = serde_json::to_value(&signed)?;
    validate_family_schema("challenge-enforcement", &value)?;

    let mut missing_intent = value.clone();
    missing_intent["body"]["effect_intents"] = json!([
        { "kind": "seller_impair", "intent_id": HEX64 },
        { "kind": "root_intent", "intent_id": HEX64_ALT },
        { "kind": "fee", "intent_id": HEX64_THIRD },
    ]);
    assert_family_schema_rejects(
        "challenge-enforcement",
        &missing_intent,
        "missing retraction intent",
    )?;

    let mut publisher_state = value.clone();
    publisher_state["body"]["assigned_sequence"] = json!(7);
    assert_family_schema_rejects(
        "challenge-enforcement",
        &publisher_state,
        "publisher-only sequence member",
    )?;

    let mut zero_destination = value;
    zero_destination["body"]["destinations"][0]["amount"]["units"] = json!(0);
    assert_family_schema_rejects(
        "challenge-enforcement",
        &zero_destination,
        "zero destination amount",
    )?;
    Ok(())
}

#[test]
fn bond_snapshot_arithmetic_is_checked() -> TestResult {
    let seller = keypair(45);
    let snapshot = bond_snapshot_body(&seller)?;
    (snapshot.validate())?;
    assert_eq!(snapshot.live_allocated_collateral()?, 380_000);

    let mut overcommitted = bond_snapshot_body(&seller)?;
    overcommitted.slashed_amount = 400_000;
    overcommitted.snapshot_id = compute_snapshot_id(&overcommitted)?;
    assert_eq!(
        overcommitted.validate(),
        Err(FindingError::InvalidField("held_amount"))
    );

    let mut exactly_full = bond_snapshot_body(&seller)?;
    exactly_full.slashed_amount = 380_000;
    exactly_full.snapshot_id = compute_snapshot_id(&exactly_full)?;
    (exactly_full.validate())?;
    assert_eq!(exactly_full.live_allocated_collateral()?, 0);

    let mut zero_block = bond_snapshot_body(&seller)?;
    zero_block.block_number = 0;
    zero_block.snapshot_id = compute_snapshot_id(&zero_block)?;
    assert_eq!(
        zero_block.validate(),
        Err(FindingError::NonZeroRequired("block_number"))
    );

    let mut malformed_hash = bond_snapshot_body(&seller)?;
    malformed_hash.block_hash = "0xNOTAHASH".to_string();
    malformed_hash.snapshot_id = compute_snapshot_id(&malformed_hash)?;
    assert_eq!(
        malformed_hash.validate(),
        Err(FindingError::MalformedDigest("block_hash"))
    );

    // The prefix is optional, the shape is not.
    let mut bare_hash = bond_snapshot_body(&seller)?;
    bare_hash.block_hash = HEX64.to_string();
    bare_hash.snapshot_id = compute_snapshot_id(&bare_hash)?;
    (bare_hash.validate())?;

    let mut zero_depth = bond_snapshot_body(&seller)?;
    zero_depth.observed_finality = FindingObservedFinality::Confirmations { depth: 0 };
    zero_depth.snapshot_id = compute_snapshot_id(&zero_depth)?;
    assert_eq!(
        zero_depth.validate(),
        Err(FindingError::NonZeroRequired("observed_finality.depth"))
    );

    // `require_nonzero` also enforces the I-JSON maximum. Keep every
    // nonzero integer that the registered schema bounds covered explicitly,
    // so a future helper refactor cannot admit Rust values schema consumers
    // must reject.
    type SnapshotMutation = fn(&mut FindingFinalizedBondSnapshot);
    let out_of_range_cases: [(&'static str, SnapshotMutation); 5] = [
        ("locked_amount", |snapshot| {
            snapshot.locked_amount = ABOVE_I_JSON_MAX;
        }),
        ("block_number", |snapshot| {
            snapshot.block_number = ABOVE_I_JSON_MAX;
        }),
        ("operator_key_epoch", |snapshot| {
            snapshot.operator_key_epoch = ABOVE_I_JSON_MAX;
        }),
        ("observed_at", |snapshot| {
            snapshot.observed_at = ABOVE_I_JSON_MAX;
        }),
        ("observed_finality.depth", |snapshot| {
            snapshot.observed_finality = FindingObservedFinality::Confirmations {
                depth: ABOVE_I_JSON_MAX,
            };
        }),
    ];
    for (field, mutate) in out_of_range_cases {
        let mut snapshot = bond_snapshot_body(&seller)?;
        mutate(&mut snapshot);
        snapshot.snapshot_id = compute_snapshot_id(&snapshot)?;
        assert_eq!(
            snapshot.validate(),
            Err(FindingError::IJsonIntegerOutOfRange(field)),
            "{field} must match the registered schema's I-JSON bound"
        );
    }
    Ok(())
}

#[test]
fn bond_snapshot_signs_and_conforms_to_its_schema() -> TestResult {
    let seller = keypair(45);
    let observer = keypair(46);
    let interloper = keypair(9);

    let signed = SignedExportEnvelope::sign(bond_snapshot_body(&seller)?, &observer)?;
    (verify_signed_finalized_bond_snapshot(&signed, &observer.public_key()))?;
    assert_eq!(
        verify_signed_finalized_bond_snapshot(&signed, &interloper.public_key()),
        Err(FindingError::AuthorityMismatch("finalized_bond_snapshot"))
    );

    let value: Value = serde_json::to_value(&signed)?;
    validate_family_schema("finalized-bond-snapshot", &value)?;

    let mut finalized = bond_snapshot_body(&seller)?;
    finalized.observed_finality = FindingObservedFinality::Finalized;
    finalized.snapshot_id = compute_snapshot_id(&finalized)?;
    (finalized.validate())?;
    let signed_finalized = SignedExportEnvelope::sign(finalized, &observer)?;
    validate_family_schema(
        "finalized-bond-snapshot",
        &serde_json::to_value(&signed_finalized)?,
    )?;

    let mut zero_locked = value.clone();
    zero_locked["body"]["locked_amount"] = json!(0);
    assert_family_schema_rejects(
        "finalized-bond-snapshot",
        &zero_locked,
        "zero locked amount",
    )?;

    let mut bad_hash = value.clone();
    bad_hash["body"]["block_hash"] = json!("0xzz");
    assert_family_schema_rejects("finalized-bond-snapshot", &bad_hash, "malformed block hash")?;

    let mut unknown_finality = value;
    unknown_finality["body"]["observed_finality"] = json!("probably");
    assert_family_schema_rejects(
        "finalized-bond-snapshot",
        &unknown_finality,
        "unknown finality",
    )?;
    Ok(())
}
