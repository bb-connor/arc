use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_finding::{
    audit_epoch_precommitment_sha256, compute_snapshot_id, signed_envelope_sha256,
    verify_signed_authority_status, FindingAuditRoundAuthorization, FindingAuthorityStatus,
    FindingChallengeVerdict, FindingError, FindingObservedFinality, FindingPenaltyCalculation,
    FindingRecipePhaseKind, FindingReplayPredicateResult,
    FINDING_AUDIT_ROUND_AUTHORIZATION_SCHEMA_V1, FINDING_AUTHORITY_STATUS_SCHEMA_V1,
};
use serde_json::Value;
use std::collections::BTreeSet;

use super::helpers::*;

/// Artifact validation and the registered schema are two independent gates
/// over the same bytes, and a signed artifact has to clear both. Anything
/// the validator accepts is round-tripped through its canonical encoding and
/// put to the schema here, so a member the schema constrains more tightly
/// than the validator cannot reach a signature and then strand at the first
/// verifier that reads the registry.
#[test]
fn every_challenge_family_round_trips_its_registered_schema() -> TestResult {
    let challenger = keypair(41);
    let audit_authority = keypair(42);
    let evaluator = keypair(43);
    let finalization_authority = keypair(44);
    let seller = keypair(45);
    let observer = keypair(46);
    let mut documents: Vec<(&'static str, Value)> = Vec::new();

    let buyer_challenge = buyer_digest_mismatch_challenge(&challenger)?;
    (buyer_challenge.validate())?;
    documents.push((
        "challenge",
        canonical_document(&SignedExportEnvelope::sign(buyer_challenge, &challenger)?)?,
    ));

    let venue_challenge = venue_replay_challenge()?;
    (venue_challenge.validate())?;
    documents.push((
        "challenge",
        canonical_document(&SignedExportEnvelope::sign(
            venue_challenge,
            &audit_authority,
        )?)?,
    ));

    for (verdict, facet) in [
        (FindingChallengeVerdict::Upheld, digest_mismatch_facet()),
        (
            FindingChallengeVerdict::Rejected,
            replay_facet(FindingReplayPredicateResult::Consistent),
        ),
        (
            FindingChallengeVerdict::Indeterminate,
            replay_facet(FindingReplayPredicateResult::Indeterminate),
        ),
    ] {
        let outcome = outcome_body(HEX64, verdict, facet)?;
        (outcome.validate())?;
        documents.push((
            "challenge-outcome",
            canonical_document(&SignedExportEnvelope::sign(outcome, &evaluator)?)?,
        ));
    }

    // The smallest calculation the formula admits: one unit of exposure fully
    // covered by one unit of live collateral.
    let minimal_penalty = upheld_outcome_with_penalty(FindingPenaltyCalculation {
        base_finding_stake_units: 1,
        open_per_sale_encumbrance_units: 0,
        computed_exposure_units: 1,
        listing_required_amount_units: 1,
        live_allocated_collateral_units: 1,
        penalty_amount: usd(1),
    })?;
    (minimal_penalty.validate())?;
    documents.push((
        "challenge-outcome",
        canonical_document(&SignedExportEnvelope::sign(minimal_penalty, &evaluator)?)?,
    ));

    let enforcement = enforcement_body()?;
    (enforcement.validate())?;
    documents.push((
        "challenge-enforcement",
        canonical_document(&SignedExportEnvelope::sign(
            enforcement,
            &finalization_authority,
        )?)?,
    ));

    for finality in [
        FindingObservedFinality::Finalized,
        FindingObservedFinality::Confirmations { depth: 96 },
    ] {
        let mut snapshot = bond_snapshot_body(&seller)?;
        snapshot.observed_finality = finality;
        snapshot.snapshot_id = compute_snapshot_id(&snapshot)?;
        (snapshot.validate())?;
        documents.push((
            "finalized-bond-snapshot",
            canonical_document(&SignedExportEnvelope::sign(snapshot, &observer)?)?,
        ));
    }

    let epoch = audit_epoch_body()?;
    (epoch.validate())?;
    let signed_epoch = SignedExportEnvelope::sign(epoch, &audit_authority)?;
    documents.push(("audit-epoch", canonical_document(&signed_epoch)?));

    let authorization = FindingAuditRoundAuthorization {
        schema: FINDING_AUDIT_ROUND_AUTHORIZATION_SCHEMA_V1.to_string(),
        epoch_precommitment_sha256: audit_epoch_precommitment_sha256(&signed_epoch.body)?,
        authorized_at: signed_epoch.body.committed_at - 100,
        expires_at: signed_epoch.body.committed_at + 100,
    };
    (authorization.validate())?;
    documents.push((
        "audit-round-authorization",
        canonical_document(&SignedExportEnvelope::sign(
            authorization,
            &finalization_authority,
        )?)?,
    ));

    let report = audit_report_body(&signed_envelope_sha256(&signed_epoch)?)?;
    (report.validate())?;
    documents.push((
        "audit-report",
        canonical_document(&SignedExportEnvelope::sign(report, &audit_authority)?)?,
    ));

    for phase in [
        FindingRecipePhaseKind::Baseline,
        FindingRecipePhaseKind::Candidate,
    ] {
        let observation = observation_body(HEX64, HEX64_ALT, phase, "replay-run-42");
        (observation.validate())?;
        documents.push(("replay-observation", canonical_document(&observation)?));
    }

    let mut covered = BTreeSet::new();
    for (family, document) in &documents {
        validate_family_schema(family, document)?;
        covered.insert(*family);
    }
    assert_eq!(
        covered,
        CHALLENGE_LANE_FAMILIES.into_iter().collect::<BTreeSet<_>>()
    );
    Ok(())
}

#[test]
fn authority_status_round_trips_registered_schema_and_external_pin() -> TestResult {
    let status_authority = keypair(51);
    let role_key = keypair(52).public_key();
    let signed = SignedExportEnvelope::sign(
        FindingAuthorityStatus {
            schema: FINDING_AUTHORITY_STATUS_SCHEMA_V1.to_string(),
            status_ref: "revocations/failed-delivery".to_string(),
            authority_id: "failed-delivery".to_string(),
            key: role_key,
            key_epoch: 7,
            revoked_from: None,
            observed_at: 1_745_000_500,
        },
        &status_authority,
    )?;

    verify_signed_authority_status(&signed, &status_authority.public_key())?;
    validate_family_schema("authority-status", &canonical_document(&signed)?)?;
    assert_eq!(
        refusal(verify_signed_authority_status(
            &signed,
            &keypair(53).public_key()
        )),
        FindingError::AuthorityMismatch("authority_status")
    );
    Ok(())
}

/// The penalty calculation is the one place where the outcome carries raw
/// unit members rather than a monetary amount alone, so its bounds are
/// pinned against the registered schema in both directions.
#[test]
fn penalty_calculation_bounds_match_the_registered_schema() -> TestResult {
    let evaluator = keypair(43);

    // Live collateral exhausted by an earlier hold: the formula yields zero,
    // which authorizes no sanction and which no monetary member may carry.
    let exhausted_collateral = upheld_outcome_with_penalty(FindingPenaltyCalculation {
        base_finding_stake_units: 50,
        open_per_sale_encumbrance_units: 0,
        computed_exposure_units: 50,
        listing_required_amount_units: 5_000,
        live_allocated_collateral_units: 0,
        penalty_amount: usd(0),
    })?;
    assert_eq!(
        exhausted_collateral.validate(),
        Err(FindingError::NonZeroRequired(
            "penalty_calculation.penalty_amount"
        ))
    );
    let signed = SignedExportEnvelope::sign(exhausted_collateral, &evaluator)?;
    assert_family_schema_rejects(
        "challenge-outcome",
        &canonical_document(&signed)?,
        "zero penalty amount",
    )?;

    // A unit member above the I-JSON safe integer would round in any
    // consumer that parses the canonical bytes as a double.
    let unsafe_requirement = upheld_outcome_with_penalty(FindingPenaltyCalculation {
        base_finding_stake_units: 1,
        open_per_sale_encumbrance_units: 0,
        computed_exposure_units: 1,
        listing_required_amount_units: u64::MAX,
        live_allocated_collateral_units: 1,
        penalty_amount: usd(1),
    })?;
    assert_eq!(
        unsafe_requirement.validate(),
        Err(FindingError::IJsonIntegerOutOfRange(
            "penalty_calculation.listing_required_amount_units"
        ))
    );
    let signed = SignedExportEnvelope::sign(unsafe_requirement, &evaluator)?;
    assert_family_schema_rejects(
        "challenge-outcome",
        &canonical_document(&signed)?,
        "listing requirement above the I-JSON safe integer",
    )?;

    let unsafe_collateral = upheld_outcome_with_penalty(FindingPenaltyCalculation {
        base_finding_stake_units: 1,
        open_per_sale_encumbrance_units: 0,
        computed_exposure_units: 1,
        listing_required_amount_units: 1,
        live_allocated_collateral_units: u64::MAX,
        penalty_amount: usd(1),
    })?;
    assert_eq!(
        unsafe_collateral.validate(),
        Err(FindingError::IJsonIntegerOutOfRange(
            "penalty_calculation.live_allocated_collateral_units"
        ))
    );
    Ok(())
}
