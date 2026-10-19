use chio_core_types::canonical_json_bytes;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_finding::{
    derive_outcome_id, signed_envelope_sha256, verdict_for_replay_predicate,
    verify_outcome_challenge_binding, verify_signed_challenge_outcome,
    FindingChallengeEvidenceKind, FindingChallengeFacet, FindingChallengeVerdict, FindingError,
    FindingEvidenceInvalidFacet, FindingEvidenceInvalidity, FindingPenaltyCalculation,
    FindingReplayPredicateResult,
};
use serde_json::{json, Value};

use super::helpers::*;

#[test]
fn outcome_id_derivation_is_stable_and_domain_separated() -> TestResult {
    let challenger = keypair(41);
    let signed_challenge =
        SignedExportEnvelope::sign(buyer_digest_mismatch_challenge(&challenger)?, &challenger)?;
    let challenge_envelope_sha256 = signed_envelope_sha256(&signed_challenge)?;
    let outcome = outcome_body(
        &challenge_envelope_sha256,
        FindingChallengeVerdict::Upheld,
        digest_mismatch_facet(),
    )?;
    (outcome.validate())?;
    assert_eq!(derive_outcome_id(&outcome)?, outcome.outcome_id);

    // The derivation is domain-separated: a plain content address over the
    // same body is a different value.
    let mut cleared = outcome.clone();
    cleared.outcome_id = String::new();
    let plain = chio_core_types::crypto::sha256_hex(&canonical_json_bytes(&cleared)?);
    assert_ne!(plain, outcome.outcome_id);

    let mut tampered = outcome.clone();
    tampered.reason = "a different reason".to_string();
    assert_eq!(
        tampered.validate(),
        Err(FindingError::ArtifactIdMismatch("outcome_id"))
    );
    Ok(())
}

#[test]
fn outcome_binds_the_challenge_envelope_not_its_body() -> TestResult {
    let challenger = keypair(41);
    let challenge = buyer_digest_mismatch_challenge(&challenger)?;
    let signed_challenge = SignedExportEnvelope::sign(challenge.clone(), &challenger)?;
    let envelope_digest = signed_envelope_sha256(&signed_challenge)?;
    let body_digest = chio_core_types::crypto::sha256_hex(&canonical_json_bytes(&challenge)?);
    assert_ne!(envelope_digest, body_digest);

    let outcome = outcome_body(
        &envelope_digest,
        FindingChallengeVerdict::Upheld,
        digest_mismatch_facet(),
    )?;
    (verify_outcome_challenge_binding(&outcome, &signed_challenge))?;

    let body_bound = outcome_body(
        &body_digest,
        FindingChallengeVerdict::Upheld,
        digest_mismatch_facet(),
    )?;
    assert_eq!(
        verify_outcome_challenge_binding(&body_bound, &signed_challenge),
        Err(FindingError::ArtifactIdMismatch(
            "challenge_envelope_sha256"
        ))
    );
    Ok(())
}

#[test]
fn replay_predicate_maps_onto_every_verdict() -> TestResult {
    assert_eq!(
        verdict_for_replay_predicate(FindingReplayPredicateResult::ConfirmedContradiction),
        FindingChallengeVerdict::Upheld
    );
    assert_eq!(
        verdict_for_replay_predicate(FindingReplayPredicateResult::Consistent),
        FindingChallengeVerdict::Rejected
    );
    assert_eq!(
        verdict_for_replay_predicate(FindingReplayPredicateResult::Indeterminate),
        FindingChallengeVerdict::Indeterminate
    );

    // Total in both directions: every verdict is reachable exactly once.
    let mut verdicts: Vec<FindingChallengeVerdict> = [
        FindingReplayPredicateResult::ConfirmedContradiction,
        FindingReplayPredicateResult::Consistent,
        FindingReplayPredicateResult::Indeterminate,
    ]
    .into_iter()
    .map(verdict_for_replay_predicate)
    .collect();
    verdicts.dedup();
    assert_eq!(verdicts.len(), 3);

    // The nested result and the top-level verdict must agree in the body.
    let outcome = outcome_body(
        HEX64,
        FindingChallengeVerdict::Rejected,
        replay_facet(FindingReplayPredicateResult::Consistent),
    )?;
    (outcome.validate())?;

    let contradictory = outcome_body(
        HEX64,
        FindingChallengeVerdict::Rejected,
        replay_facet(FindingReplayPredicateResult::ConfirmedContradiction),
    )?;
    assert_eq!(
        contradictory.validate(),
        Err(FindingError::InvalidField("replay_contradiction.verdict"))
    );
    Ok(())
}

#[test]
fn outcome_reserves_the_penalty_calculation_for_upheld_verdicts() -> TestResult {
    let indeterminate = outcome_body(
        HEX64,
        FindingChallengeVerdict::Indeterminate,
        replay_facet(FindingReplayPredicateResult::Indeterminate),
    )?;
    (indeterminate.validate())?;
    assert!(indeterminate.penalty_calculation.is_none());

    let mut upheld_without_calculation = outcome_body(
        HEX64,
        FindingChallengeVerdict::Upheld,
        digest_mismatch_facet(),
    )?;
    upheld_without_calculation.penalty_calculation = None;
    upheld_without_calculation.outcome_id = derive_outcome_id(&upheld_without_calculation)?;
    assert_eq!(
        upheld_without_calculation.validate(),
        Err(FindingError::MissingEntry("penalty_calculation"))
    );

    let mut rejected_with_calculation = outcome_body(
        HEX64,
        FindingChallengeVerdict::Rejected,
        replay_facet(FindingReplayPredicateResult::Consistent),
    )?;
    rejected_with_calculation.penalty_calculation = Some(FindingPenaltyCalculation {
        base_finding_stake_units: 1,
        open_per_sale_encumbrance_units: 1,
        computed_exposure_units: 2,
        listing_required_amount_units: 2,
        live_allocated_collateral_units: 2,
        penalty_amount: usd(2),
    });
    rejected_with_calculation.outcome_id = derive_outcome_id(&rejected_with_calculation)?;
    assert_eq!(
        rejected_with_calculation.validate(),
        Err(FindingError::InvalidField("penalty_calculation"))
    );
    Ok(())
}

#[test]
fn outcome_retry_deadline_is_future_and_indeterminate_only() -> TestResult {
    let mut retryable = outcome_body(
        HEX64,
        FindingChallengeVerdict::Indeterminate,
        replay_facet(FindingReplayPredicateResult::Indeterminate),
    )?;
    retryable.retry_deadline = Some(retryable.evaluated_at + 60);
    retryable.outcome_id = derive_outcome_id(&retryable)?;
    (retryable.validate())?;

    let mut terminal = outcome_body(
        HEX64,
        FindingChallengeVerdict::Rejected,
        replay_facet(FindingReplayPredicateResult::Consistent),
    )?;
    terminal.retry_deadline = Some(terminal.evaluated_at + 60);
    terminal.outcome_id = derive_outcome_id(&terminal)?;
    assert_eq!(
        terminal.validate(),
        Err(FindingError::InvalidField("retry_deadline"))
    );

    let mut elapsed = retryable.clone();
    elapsed.retry_deadline = Some(elapsed.evaluated_at);
    elapsed.outcome_id = derive_outcome_id(&elapsed)?;
    assert_eq!(
        elapsed.validate(),
        Err(FindingError::InvalidField("retry_deadline"))
    );

    let mut unsafe_deadline = retryable;
    unsafe_deadline.retry_deadline = Some(1_u64 << 53);
    unsafe_deadline.outcome_id = derive_outcome_id(&unsafe_deadline)?;
    assert_eq!(
        unsafe_deadline.validate(),
        Err(FindingError::IJsonIntegerOutOfRange("retry_deadline"))
    );
    Ok(())
}

#[test]
fn outcome_penalty_calculation_is_checked_against_its_own_formula() -> TestResult {
    let mut wrong_sum = outcome_body(
        HEX64,
        FindingChallengeVerdict::Upheld,
        digest_mismatch_facet(),
    )?;
    if let Some(calculation) = wrong_sum.penalty_calculation.as_mut() {
        calculation.computed_exposure_units = 110_000;
    }
    wrong_sum.outcome_id = derive_outcome_id(&wrong_sum)?;
    assert_eq!(
        wrong_sum.validate(),
        Err(FindingError::InvalidField(
            "penalty_calculation.computed_exposure_units"
        ))
    );

    let mut above_ceiling = outcome_body(
        HEX64,
        FindingChallengeVerdict::Upheld,
        digest_mismatch_facet(),
    )?;
    if let Some(calculation) = above_ceiling.penalty_calculation.as_mut() {
        calculation.listing_required_amount_units = 100_000;
    }
    above_ceiling.outcome_id = derive_outcome_id(&above_ceiling)?;
    assert_eq!(
        above_ceiling.validate(),
        Err(FindingError::InvalidField(
            "penalty_calculation.listing_required_amount_units"
        ))
    );

    // The penalty is the minimum of live collateral and computed exposure,
    // never the promise alone.
    let mut capped = outcome_body(
        HEX64,
        FindingChallengeVerdict::Upheld,
        digest_mismatch_facet(),
    )?;
    if let Some(calculation) = capped.penalty_calculation.as_mut() {
        calculation.live_allocated_collateral_units = 90_000;
        calculation.penalty_amount = usd(90_000);
    }
    capped.outcome_id = derive_outcome_id(&capped)?;
    (capped.validate())?;

    let mut overstated = outcome_body(
        HEX64,
        FindingChallengeVerdict::Upheld,
        digest_mismatch_facet(),
    )?;
    if let Some(calculation) = overstated.penalty_calculation.as_mut() {
        calculation.live_allocated_collateral_units = 90_000;
    }
    overstated.outcome_id = derive_outcome_id(&overstated)?;
    assert_eq!(
        overstated.validate(),
        Err(FindingError::InvalidField(
            "penalty_calculation.penalty_amount"
        ))
    );
    Ok(())
}

#[test]
fn outcome_rejects_policy_transform_denials_and_facet_substitution() -> TestResult {
    let mut transformed = outcome_body(
        HEX64,
        FindingChallengeVerdict::Upheld,
        digest_mismatch_facet(),
    )?;
    if let FindingChallengeFacet::DigestMismatch(facet) = &mut transformed.facet {
        facet.transform_profile = "redact_pii_v1".to_string();
    }
    transformed.outcome_id = derive_outcome_id(&transformed)?;
    assert_eq!(
        transformed.validate(),
        Err(FindingError::InvalidField(
            "digest_mismatch.transform_profile"
        ))
    );

    // A digest mismatch that matches is not a mismatch.
    let mut equal_digests = outcome_body(
        HEX64,
        FindingChallengeVerdict::Upheld,
        digest_mismatch_facet(),
    )?;
    if let FindingChallengeFacet::DigestMismatch(facet) = &mut equal_digests.facet {
        facet.delivered_output_sha256 = facet.committed_payload_sha256.clone();
    }
    equal_digests.outcome_id = derive_outcome_id(&equal_digests)?;
    assert_eq!(
        equal_digests.validate(),
        Err(FindingError::InvalidField("digest_mismatch.verdict"))
    );

    // The facet must belong to the class the outcome names.
    let mut substituted = outcome_body(
        HEX64,
        FindingChallengeVerdict::Upheld,
        digest_mismatch_facet(),
    )?;
    substituted.evidence_kind = FindingChallengeEvidenceKind::EvidenceInvalid;
    substituted.outcome_id = derive_outcome_id(&substituted)?;
    assert_eq!(
        substituted.validate(),
        Err(FindingError::InvalidField("facet"))
    );

    // Unavailable inputs are indeterminate, never a rejection of the buyer.
    let unavailable = outcome_body(
        HEX64,
        FindingChallengeVerdict::Indeterminate,
        FindingChallengeFacet::EvidenceInvalid(FindingEvidenceInvalidFacet {
            challenged_receipt_ids: vec!["evidence-receipt-1".to_string()],
            invalidity: FindingEvidenceInvalidity::InputsUnavailable,
        }),
    )?;
    (unavailable.validate())?;
    assert_eq!(
        FindingEvidenceInvalidity::InputsUnavailable.verdict(),
        FindingChallengeVerdict::Indeterminate
    );
    assert_eq!(
        FindingEvidenceInvalidity::NoAffirmativeInvalidity.verdict(),
        FindingChallengeVerdict::Rejected
    );
    Ok(())
}

#[test]
fn outcome_signs_and_verifies_under_its_pinned_evaluator() -> TestResult {
    let evaluator = keypair(43);
    let interloper = keypair(9);
    let outcome = outcome_body(
        HEX64,
        FindingChallengeVerdict::Upheld,
        digest_mismatch_facet(),
    )?;

    let signed = SignedExportEnvelope::sign(outcome.clone(), &evaluator)?;
    (verify_signed_challenge_outcome(&signed, &evaluator.public_key()))?;
    let mut misattributed = outcome.clone();
    misattributed.evaluator_key = interloper.public_key();
    misattributed.outcome_id = derive_outcome_id(&misattributed)?;
    let misattributed = SignedExportEnvelope::sign(misattributed, &evaluator)?;
    assert_eq!(
        verify_signed_challenge_outcome(&misattributed, &evaluator.public_key()),
        Err(FindingError::AuthorityMismatch(
            "challenge_outcome.evaluator_key"
        ))
    );
    let forged = SignedExportEnvelope::sign(outcome, &interloper)?;
    assert_eq!(
        verify_signed_challenge_outcome(&forged, &evaluator.public_key()),
        Err(FindingError::AuthorityMismatch("challenge_outcome"))
    );
    Ok(())
}

#[test]
fn outcome_conforms_to_its_schema() -> TestResult {
    let evaluator = keypair(43);
    let signed = SignedExportEnvelope::sign(
        outcome_body(
            HEX64,
            FindingChallengeVerdict::Upheld,
            digest_mismatch_facet(),
        )?,
        &evaluator,
    )?;
    let value: Value = serde_json::to_value(&signed)?;
    validate_family_schema("challenge-outcome", &value)?;

    let rejected = SignedExportEnvelope::sign(
        outcome_body(
            HEX64,
            FindingChallengeVerdict::Rejected,
            replay_facet(FindingReplayPredicateResult::Consistent),
        )?,
        &evaluator,
    )?;
    validate_family_schema("challenge-outcome", &serde_json::to_value(&rejected)?)?;

    let mut retryable = outcome_body(
        HEX64,
        FindingChallengeVerdict::Indeterminate,
        replay_facet(FindingReplayPredicateResult::Indeterminate),
    )?;
    retryable.retry_deadline = Some(retryable.evaluated_at + 60);
    retryable.outcome_id = derive_outcome_id(&retryable)?;
    let signed_retryable = SignedExportEnvelope::sign(retryable, &evaluator)?;
    validate_family_schema(
        "challenge-outcome",
        &serde_json::to_value(&signed_retryable)?,
    )?;

    let mut deadline_on_rejected = serde_json::to_value(&rejected)?;
    deadline_on_rejected["body"]["retry_deadline"] = json!(1_750_000_560_u64);
    assert_family_schema_rejects(
        "challenge-outcome",
        &deadline_on_rejected,
        "retry deadline on a rejected verdict",
    )?;

    let mut unsafe_retry_deadline = serde_json::to_value(&signed_retryable)?;
    unsafe_retry_deadline["body"]["retry_deadline"] = json!(1_u64 << 53);
    assert_family_schema_rejects(
        "challenge-outcome",
        &unsafe_retry_deadline,
        "retry deadline above the I-JSON safe integer",
    )?;

    let mut unknown_verdict = value.clone();
    unknown_verdict["body"]["verdict"] = json!("maybe");
    assert_family_schema_rejects("challenge-outcome", &unknown_verdict, "unknown verdict")?;

    let mut spent = value.clone();
    spent["body"]["facet"]["digest_mismatch"]["realized_spend_units"] = json!(1);
    assert_family_schema_rejects("challenge-outcome", &spent, "nonzero realized spend")?;

    let mut transformed = value.clone();
    transformed["body"]["facet"]["digest_mismatch"]["transform_profile"] = json!("redact_pii_v1");
    assert_family_schema_rejects("challenge-outcome", &transformed, "policy transform")?;

    let mut penalty_without_upheld = serde_json::to_value(&rejected)?;
    penalty_without_upheld["body"]["penalty_calculation"] = json!({
        "base_finding_stake_units": 1,
        "open_per_sale_encumbrance_units": 1,
        "computed_exposure_units": 2,
        "listing_required_amount_units": 2,
        "live_allocated_collateral_units": 2,
        "penalty_amount": { "units": 2, "currency": "USD" },
    });
    assert_family_schema_rejects(
        "challenge-outcome",
        &penalty_without_upheld,
        "penalty calculation on a rejected verdict",
    )?;

    let mut unknown = value;
    unknown["body"]["surprise"] = json!(true);
    assert_family_schema_rejects("challenge-outcome", &unknown, "unknown body member")?;
    Ok(())
}
