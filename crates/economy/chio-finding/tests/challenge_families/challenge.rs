use chio_core_types::canonical_json_string;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_finding::{
    compute_challenge_id, ensure_challenge_class_compatibility, verify_signed_challenge,
    FindingChallenge, FindingChallengeAuthorization, FindingChallengeEvidence,
    FindingChallengeEvidenceKind, FindingChallengeStanding, FindingError, FindingEvidenceClass,
    FindingGuaranteeClass, FindingRecipePhaseKind,
};
use serde_json::{json, Value};

use super::helpers::*;

#[test]
fn challenge_content_address_is_stable_and_detects_tampering() -> TestResult {
    let challenger = keypair(41);
    let challenge = buyer_digest_mismatch_challenge(&challenger)?;
    (challenge.validate())?;
    assert_eq!(compute_challenge_id(&challenge)?, challenge.challenge_id);

    let mut tampered = buyer_digest_mismatch_challenge(&challenger)?;
    tampered.listing_id = "finding-listing-02".to_string();
    assert_eq!(
        tampered.validate(),
        Err(FindingError::ArtifactIdMismatch("challenge_id"))
    );

    let mut tampered = buyer_digest_mismatch_challenge(&challenger)?;
    tampered.filed_at += 1;
    assert_eq!(
        tampered.validate(),
        Err(FindingError::ArtifactIdMismatch("challenge_id"))
    );
    Ok(())
}

#[test]
fn challenge_authorization_union_rejects_cross_branch_members() -> TestResult {
    let challenger = keypair(41);
    let challenge = buyer_digest_mismatch_challenge(&challenger)?;
    let mut value: Value = serde_json::to_value(&challenge)?;
    value["authorization"]["buyer_submission"]["audit_epoch_envelope_sha256"] = json!(HEX64);
    assert_eq!(
    refusal(serde_json::from_value::<FindingChallenge>(value.clone())).to_string(),
    "unknown field `audit_epoch_envelope_sha256`, expected one of `challenger`, `dispute_fee_terminal`, `dispute_lock_ref`, `standing`"
);

    let venue = venue_replay_challenge()?;
    let mut value: Value = serde_json::to_value(&venue)?;
    value["authorization"]["venue_audit"]["challenger"] = json!(HEX64);
    assert_eq!(
    refusal(serde_json::from_value::<FindingChallenge>(value)).to_string(),
    "unknown field `challenger`, expected one of `audit_epoch_envelope_sha256`, `selection_digest`, `authorization_digest`"
);

    let mut value: Value = serde_json::to_value(&venue)?;
    value["authorization"]["venue_audit"]["dispute_lock_ref"] = json!({
        "lock_id": "dispute-lock-42",
        "class": "dispute",
        "fee_schedule_envelope_sha256": HEX64,
        "amount": { "units": 1, "currency": "USD" },
        "expiry": 1,
    });
    assert_eq!(
    refusal(serde_json::from_value::<FindingChallenge>(value)).to_string(),
    "unknown field `dispute_lock_ref`, expected one of `audit_epoch_envelope_sha256`, `selection_digest`, `authorization_digest`"
);

    // Both branches at once is not a union.
    let mut value: Value = serde_json::to_value(&challenge)?;
    value["authorization"]["venue_audit"] = json!({
        "audit_epoch_envelope_sha256": HEX64,
        "selection_digest": HEX64_ALT,
        "authorization_digest": HEX64_THIRD,
    });
    assert_eq!(
        refusal(serde_json::from_value::<FindingChallenge>(value)).to_string(),
        "invalid value: map, expected map with a single key"
    );
    Ok(())
}

#[test]
fn challenge_evidence_union_rejects_cross_class_members() -> TestResult {
    let challenger = keypair(41);
    let challenge = buyer_digest_mismatch_challenge(&challenger)?;
    let mut value: Value = serde_json::to_value(&challenge)?;
    value["evidence"]["digest_mismatch"]["purchase_record_envelope_sha256"] = json!(HEX64);
    assert_eq!(
    refusal(serde_json::from_value::<FindingChallenge>(value)).to_string(),
    "unknown field `purchase_record_envelope_sha256`, expected one of `failed_delivery_envelope_sha256`, `deny_receipt_ref`, `deny_checkpoint_ref`"
);

    let mut value: Value = serde_json::to_value(&challenge)?;
    value["evidence"]["digest_mismatch"]["recipe_preimage"] = json!("{}");
    assert_eq!(
    refusal(serde_json::from_value::<FindingChallenge>(value)).to_string(),
    "unknown field `recipe_preimage`, expected one of `failed_delivery_envelope_sha256`, `deny_receipt_ref`, `deny_checkpoint_ref`"
);

    let venue = venue_replay_challenge()?;
    let mut value: Value = serde_json::to_value(&venue)?;
    value["evidence"]["replay_contradiction"]["failed_delivery_envelope_sha256"] = json!(HEX64);
    assert_eq!(
    refusal(serde_json::from_value::<FindingChallenge>(value)).to_string(),
    "unknown field `failed_delivery_envelope_sha256`, expected one of `reproduction`, `recipe_preimage`, `purchase_record_envelope_sha256`"
);

    let mut value: Value = serde_json::to_value(&venue)?;
    value["evidence"]["digest_mismatch"] = json!({
        "failed_delivery_envelope_sha256": HEX64,
        "deny_receipt_ref": { "receipt_id": "deny-receipt-42", "receipt_sha256": HEX64 },
        "deny_checkpoint_ref": {
            "checkpoint_ref": "checkpoints/venue-wedge/9001",
            "checkpoint_sha256": HEX64_ALT,
        },
    });
    assert_eq!(
        refusal(serde_json::from_value::<FindingChallenge>(value)).to_string(),
        "invalid value: map, expected map with a single key"
    );
    Ok(())
}

#[test]
fn challenge_schema_closes_both_unions() -> TestResult {
    let challenger = keypair(41);
    let signed =
        SignedExportEnvelope::sign(buyer_digest_mismatch_challenge(&challenger)?, &challenger)?;
    let value: Value = serde_json::to_value(&signed)?;
    validate_family_schema("challenge", &value)?;

    let mut cross_authorization = value.clone();
    cross_authorization["body"]["authorization"]["buyer_submission"]
        ["audit_epoch_envelope_sha256"] = json!(HEX64);
    assert_family_schema_rejects(
        "challenge",
        &cross_authorization,
        "audit member inside a buyer submission",
    )?;

    let mut both_branches = value.clone();
    both_branches["body"]["authorization"]["venue_audit"] = json!({
        "audit_epoch_envelope_sha256": HEX64,
        "selection_digest": HEX64_ALT,
        "authorization_digest": HEX64_THIRD,
    });
    assert_family_schema_rejects("challenge", &both_branches, "two authorization branches")?;

    let mut cross_evidence = value.clone();
    cross_evidence["body"]["evidence"]["digest_mismatch"]["purchase_record_envelope_sha256"] =
        json!(HEX64);
    assert_family_schema_rejects(
        "challenge",
        &cross_evidence,
        "purchase member inside a digest mismatch",
    )?;

    let mut both_classes = value.clone();
    both_classes["body"]["evidence"]["evidence_invalid"] = json!({
        "challenged_evidence_receipt_refs": [
            { "receipt_id": "evidence-receipt-1", "receipt_sha256": HEX64 }
        ],
        "challenged_checkpoint_ref": {
            "checkpoint_ref": "checkpoints/venue-wedge/9001",
            "checkpoint_sha256": HEX64_ALT,
        },
        "purchase_record_envelope_sha256": HEX64_ALT,
    });
    assert_family_schema_rejects("challenge", &both_classes, "two evidence branches")?;

    let mut unknown = value.clone();
    unknown["body"]["surprise"] = json!(true);
    assert_family_schema_rejects("challenge", &unknown, "unknown body member")?;

    let mut wrong_schema = value;
    wrong_schema["body"]["schema"] = json!("chio.finding.challenge.v9");
    assert_family_schema_rejects("challenge", &wrong_schema, "wrong schema const")?;
    Ok(())
}

#[test]
fn challenge_requires_standing_matching_its_evidence_class() -> TestResult {
    let challenger = keypair(41);

    let mismatched = challenge_body(
        buyer_authorization(&challenger, purchase_standing()),
        digest_mismatch_evidence(),
    )?;
    assert_eq!(
        mismatched.validate(),
        Err(FindingError::InvalidField("standing"))
    );

    let mismatched = challenge_body(
        buyer_authorization(&challenger, failed_delivery_standing()),
        evidence_invalid_evidence(),
    )?;
    assert_eq!(
        mismatched.validate(),
        Err(FindingError::InvalidField("standing"))
    );

    // Right branch, wrong artifact digest.
    let wrong_digest = challenge_body(
        buyer_authorization(
            &challenger,
            FindingChallengeStanding::FinalizedPurchase {
                purchase_key: HEX64.to_string(),
                purchase_record_envelope_sha256: HEX64_THIRD.to_string(),
            },
        ),
        evidence_invalid_evidence(),
    )?;
    assert_eq!(
        wrong_digest.validate(),
        Err(FindingError::InvalidField("standing"))
    );

    let aligned = challenge_body(
        buyer_authorization(&challenger, purchase_standing()),
        evidence_invalid_evidence(),
    )?;
    (aligned.validate())?;

    // A buyer needs at least one affected delivery; a venue audit does not.
    let mut without_standing_receipt = aligned.clone();
    without_standing_receipt.affected_deliveries.clear();
    without_standing_receipt.challenge_id = compute_challenge_id(&without_standing_receipt)?;
    assert_eq!(
        without_standing_receipt.validate(),
        Err(FindingError::MissingEntry("affected_deliveries"))
    );

    let mut audit = venue_replay_challenge()?;
    audit.affected_deliveries.clear();
    audit.challenge_id = compute_challenge_id(&audit)?;
    (audit.validate())?;
    Ok(())
}

#[test]
fn challenge_nonzero_integers_enforce_the_i_json_maximum() -> TestResult {
    let challenger = keypair(41);
    type ChallengeMutation = fn(&mut FindingChallenge);
    let out_of_range_cases: [(&'static str, ChallengeMutation); 4] = [
        ("filed_at", |challenge| {
            challenge.filed_at = ABOVE_I_JSON_MAX;
        }),
        ("dispute_fee_terminal.amount", |challenge| {
            if let FindingChallengeAuthorization::BuyerSubmission(submission) =
                &mut challenge.authorization
            {
                submission.dispute_fee_terminal.amount.units = ABOVE_I_JSON_MAX;
            }
        }),
        ("dispute_lock_ref.amount", |challenge| {
            if let FindingChallengeAuthorization::BuyerSubmission(submission) =
                &mut challenge.authorization
            {
                submission.dispute_lock_ref.amount.units = ABOVE_I_JSON_MAX;
            }
        }),
        ("dispute_lock_ref.expiry", |challenge| {
            if let FindingChallengeAuthorization::BuyerSubmission(submission) =
                &mut challenge.authorization
            {
                submission.dispute_lock_ref.expiry = ABOVE_I_JSON_MAX;
            }
        }),
    ];

    for (field, mutate) in out_of_range_cases {
        let mut challenge = buyer_digest_mismatch_challenge(&challenger)?;
        mutate(&mut challenge);
        challenge.challenge_id = compute_challenge_id(&challenge)?;
        assert_eq!(
            challenge.validate(),
            Err(FindingError::IJsonIntegerOutOfRange(field)),
            "{field} must match the registered schema's I-JSON bound"
        );
    }
    Ok(())
}

#[test]
fn replay_evidence_binds_one_run_and_the_committed_recipe() -> TestResult {
    let challenge = venue_replay_challenge()?;
    (challenge.validate())?;

    // Two runs cannot be spliced into one reproduction set.
    let recipe = recipe_body(HEX64_THIRD);
    let recipe_digest = recipe.canonical_sha256()?;
    let mut spliced = challenge.clone();
    if let FindingChallengeEvidence::ReplayContradiction { reproduction, .. } =
        &mut spliced.evidence
    {
        reproduction[1].observation_bytes = canonical_json_string(&observation_body(
            &recipe_digest,
            HEX64_THIRD,
            FindingRecipePhaseKind::Candidate,
            "replay-run-43",
        ))?;
    }
    spliced.challenge_id = compute_challenge_id(&spliced)?;
    assert_eq!(
        spliced.validate(),
        Err(FindingError::InvalidField(
            "replay_contradiction.reproduction[].observation_bytes"
        ))
    );

    // An observation about another recipe cannot ride along.
    let mut foreign = challenge.clone();
    if let FindingChallengeEvidence::ReplayContradiction { reproduction, .. } =
        &mut foreign.evidence
    {
        reproduction[0].observation_bytes = canonical_json_string(&observation_body(
            HEX64,
            HEX64_THIRD,
            FindingRecipePhaseKind::Baseline,
            "replay-run-42",
        ))?;
    }
    foreign.challenge_id = compute_challenge_id(&foreign)?;
    assert_eq!(
        foreign.validate(),
        Err(FindingError::InvalidField(
            "replay_contradiction.reproduction[].observation_bytes"
        ))
    );

    // A recipe committing another profile cannot ride along.
    let mut foreign_profile = challenge.clone();
    let other_recipe = recipe_body(HEX64);
    if let FindingChallengeEvidence::ReplayContradiction {
        recipe_preimage, ..
    } = &mut foreign_profile.evidence
    {
        *recipe_preimage = canonical_json_string(&other_recipe)?;
    }
    foreign_profile.challenge_id = compute_challenge_id(&foreign_profile)?;
    assert_eq!(
        foreign_profile.validate(),
        Err(FindingError::InvalidField(
            "replay_contradiction.recipe_preimage"
        ))
    );

    // Non-canonical carried bytes reject before anything reads them.
    let mut non_canonical = challenge;
    if let FindingChallengeEvidence::ReplayContradiction {
        recipe_preimage, ..
    } = &mut non_canonical.evidence
    {
        *recipe_preimage = format!(" {recipe_preimage}");
    }
    non_canonical.challenge_id = compute_challenge_id(&non_canonical)?;
    assert_eq!(
        non_canonical.validate(),
        Err(FindingError::NonCanonicalBytes(
            "replay_contradiction.recipe_preimage"
        ))
    );
    Ok(())
}

#[test]
fn compatibility_matrix_admits_exactly_the_closed_pairings() -> TestResult {
    let guarantee_classes = [
        FindingGuaranteeClass::DeterministicReplay,
        FindingGuaranteeClass::MeteredAttested,
        FindingGuaranteeClass::Asserted,
    ];
    let evidence_classes = [
        FindingEvidenceClass::Asserted,
        FindingEvidenceClass::Observed,
        FindingEvidenceClass::Verified,
    ];
    let evidence_kinds = [
        FindingChallengeEvidenceKind::DigestMismatch,
        FindingChallengeEvidenceKind::EvidenceInvalid,
        FindingChallengeEvidenceKind::ReplayContradiction,
    ];

    let mut admitted = 0_usize;
    for kind in evidence_kinds {
        for guarantee_class in guarantee_classes {
            for evidence_class in evidence_classes {
                let expected = match kind {
                    FindingChallengeEvidenceKind::DigestMismatch => true,
                    FindingChallengeEvidenceKind::EvidenceInvalid => {
                        evidence_class != FindingEvidenceClass::Asserted
                    }
                    FindingChallengeEvidenceKind::ReplayContradiction => {
                        guarantee_class == FindingGuaranteeClass::DeterministicReplay
                            && evidence_class == FindingEvidenceClass::Verified
                    }
                };
                let result =
                    ensure_challenge_class_compatibility(kind, guarantee_class, evidence_class);
                assert_eq!(
                    result.is_ok(),
                    expected,
                    "{kind:?} with {guarantee_class:?}/{evidence_class:?}"
                );
                if expected {
                    admitted += 1;
                }
            }
        }
    }
    // Nine digest-mismatch cells, six evidence-invalid cells, one replay cell.
    assert_eq!(admitted, 16);

    assert_eq!(
        ensure_challenge_class_compatibility(
            FindingChallengeEvidenceKind::ReplayContradiction,
            FindingGuaranteeClass::MeteredAttested,
            FindingEvidenceClass::Verified,
        ),
        Err(FindingError::InvalidField(
            "replay_contradiction.guarantee_class"
        ))
    );
    assert_eq!(
        ensure_challenge_class_compatibility(
            FindingChallengeEvidenceKind::EvidenceInvalid,
            FindingGuaranteeClass::MeteredAttested,
            FindingEvidenceClass::Asserted,
        ),
        Err(FindingError::InvalidField(
            "evidence_invalid.evidence_class"
        ))
    );
    Ok(())
}

#[test]
fn challenge_signing_binds_the_challenger_or_the_pinned_audit_authority() -> TestResult {
    let challenger = keypair(41);
    let interloper = keypair(9);
    let audit_authority = keypair(42);

    let signed =
        SignedExportEnvelope::sign(buyer_digest_mismatch_challenge(&challenger)?, &challenger)?;
    (verify_signed_challenge(&signed, &audit_authority.public_key()))?;

    let forged =
        SignedExportEnvelope::sign(buyer_digest_mismatch_challenge(&challenger)?, &interloper)?;
    assert_eq!(
        verify_signed_challenge(&forged, &audit_authority.public_key()),
        Err(FindingError::AuthorityMismatch("challenge"))
    );

    let audit = SignedExportEnvelope::sign(venue_replay_challenge()?, &audit_authority)?;
    (verify_signed_challenge(&audit, &audit_authority.public_key()))?;

    let buyer_signed_audit = SignedExportEnvelope::sign(venue_replay_challenge()?, &challenger)?;
    assert_eq!(
        verify_signed_challenge(&buyer_signed_audit, &audit_authority.public_key()),
        Err(FindingError::AuthorityMismatch("challenge"))
    );
    Ok(())
}
