use chio_core_types::canonical_json_bytes;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_finding::{
    audit_epoch_precommitment_sha256, compute_audit_report_id, derive_audit_seed_commitment,
    signed_envelope_sha256, verify_audit_report_epoch_binding, verify_signed_audit_epoch,
    verify_signed_audit_report, verify_signed_audit_round_authorization,
    FindingAuditRoundAuthorization, FindingError, FindingMissedAudit, FindingRecipePhaseKind,
    FINDING_AUDIT_ROUND_AUTHORIZATION_SCHEMA_V1,
};
use serde_json::{json, Value};

use super::helpers::*;

#[test]
fn audit_seed_commitment_reproduces_in_both_directions() -> TestResult {
    let commitment = derive_audit_seed_commitment(SEED);
    assert_eq!(commitment.len(), 64);
    assert_eq!(commitment, derive_audit_seed_commitment(SEED));
    assert_ne!(commitment, derive_audit_seed_commitment(HEX64));
    // The commitment is domain-separated from a plain digest of the seed.
    assert_ne!(
        commitment,
        chio_core_types::crypto::sha256_hex(SEED.as_bytes())
    );

    let audit_authority = keypair(42);
    let epoch = audit_epoch_body()?;
    (epoch.validate())?;
    assert_eq!(epoch.seed_commitment, commitment);

    let signed_epoch = SignedExportEnvelope::sign(epoch, &audit_authority)?;
    let epoch_envelope_sha256 = signed_envelope_sha256(&signed_epoch)?;
    let report = audit_report_body(&epoch_envelope_sha256)?;
    (report.validate())?;
    (verify_audit_report_epoch_binding(&report, &signed_epoch))?;

    let mut wrong_seed = audit_report_body(&epoch_envelope_sha256)?;
    wrong_seed.revealed_seed = HEX64.to_string();
    wrong_seed.audit_report_id = compute_audit_report_id(&wrong_seed)?;
    assert_eq!(
        verify_audit_report_epoch_binding(&wrong_seed, &signed_epoch),
        Err(FindingError::ArtifactIdMismatch("revealed_seed"))
    );

    let mut wrong_epoch = audit_report_body(HEX64)?;
    wrong_epoch.audit_report_id = compute_audit_report_id(&wrong_epoch)?;
    assert_eq!(
        verify_audit_report_epoch_binding(&wrong_epoch, &signed_epoch),
        Err(FindingError::ArtifactIdMismatch(
            "audit_epoch_envelope_sha256"
        ))
    );
    Ok(())
}

#[test]
fn audit_epoch_integer_bounds_match_the_registered_schema() -> TestResult {
    const FIRST_UNSAFE_I_JSON_INTEGER: u64 = 9_007_199_254_740_992;
    let audit_authority = keypair(42);
    let base = audit_epoch_body()?;
    let mut cases = Vec::new();

    let mut epoch = base.clone();
    epoch.epoch_index = FIRST_UNSAFE_I_JSON_INTEGER;
    cases.push(("epoch_index", epoch));
    let mut epoch = base.clone();
    epoch.seed_witnessed_at = FIRST_UNSAFE_I_JSON_INTEGER;
    cases.push(("seed_witnessed_at", epoch));
    let mut epoch = base.clone();
    epoch.eligible_snapshot_at = FIRST_UNSAFE_I_JSON_INTEGER;
    cases.push(("eligible_snapshot_at", epoch));
    let mut epoch = base.clone();
    epoch.eligible_listing_count = FIRST_UNSAFE_I_JSON_INTEGER;
    cases.push(("eligible_listing_count", epoch));
    let mut epoch = base.clone();
    epoch.published_rate_bps = FIRST_UNSAFE_I_JSON_INTEGER;
    cases.push(("published_rate_bps", epoch));
    let mut epoch = base.clone();
    epoch.available_budget.units = FIRST_UNSAFE_I_JSON_INTEGER;
    cases.push(("available_budget", epoch));
    let mut epoch = base;
    epoch.committed_at = FIRST_UNSAFE_I_JSON_INTEGER;
    cases.push(("committed_at", epoch));

    for (field, epoch) in cases {
        assert_eq!(
            epoch.validate(),
            Err(FindingError::IJsonIntegerOutOfRange(field)),
            "Rust validation must enforce the same I-JSON bound as the schema for {field}"
        );
        let value = serde_json::to_value(SignedExportEnvelope::sign(epoch, &audit_authority)?)?;
        assert_family_schema_rejects("audit-epoch", &value, field)?;
    }
    Ok(())
}

#[test]
fn audit_report_accounts_for_every_selection() -> TestResult {
    let mut unselected_miss = audit_report_body(HEX64)?;
    unselected_miss.missed_attempts[0].finding_id = HEX64_THIRD.to_string();
    unselected_miss.audit_report_id = compute_audit_report_id(&unselected_miss)?;
    assert_eq!(
        unselected_miss.validate(),
        Err(FindingError::InvalidField("missed_attempts[]"))
    );

    let mut no_attempts = audit_report_body(HEX64)?;
    no_attempts.attempt_envelope_sha256s.clear();
    no_attempts.audit_report_id = compute_audit_report_id(&no_attempts)?;
    assert_eq!(
        no_attempts.validate(),
        Err(FindingError::MissingEntry("attempt_envelope_sha256s"))
    );

    // Every selection missed is a complete account with no attempts.
    let mut all_missed = audit_report_body(HEX64)?;
    all_missed.attempt_envelope_sha256s.clear();
    all_missed.missed_attempts.push(FindingMissedAudit {
        finding_id: HEX64.to_string(),
        reason: "runner unavailable for the whole window".to_string(),
    });
    all_missed.audit_report_id = compute_audit_report_id(&all_missed)?;
    (all_missed.validate())?;

    let mut duplicated = audit_report_body(HEX64)?;
    duplicated.selected_finding_ids.push(HEX64.to_string());
    duplicated.audit_report_id = compute_audit_report_id(&duplicated)?;
    assert_eq!(
        duplicated.validate(),
        Err(FindingError::DuplicateEntry("selected_finding_ids[]"))
    );
    Ok(())
}

#[test]
fn audit_artifacts_sign_and_conform_to_their_schemas() -> TestResult {
    let audit_authority = keypair(42);
    let seed_witness = keypair(43);
    let governance_authority = keypair(44);
    let interloper = keypair(9);

    let signed_epoch = SignedExportEnvelope::sign(audit_epoch_body()?, &audit_authority)?;
    (verify_signed_audit_epoch(
        &signed_epoch,
        &audit_authority.public_key(),
        &seed_witness.public_key(),
    ))?;
    assert_eq!(
        verify_signed_audit_epoch(
            &signed_epoch,
            &interloper.public_key(),
            &seed_witness.public_key(),
        ),
        Err(FindingError::AuthorityMismatch("audit_epoch"))
    );
    assert_eq!(
        verify_signed_audit_epoch(
            &signed_epoch,
            &audit_authority.public_key(),
            &interloper.public_key(),
        ),
        Err(FindingError::AuthorityMismatch("audit_seed_witness"))
    );
    let epoch_value: Value = serde_json::to_value(&signed_epoch)?;
    validate_family_schema("audit-epoch", &epoch_value)?;

    let mut seeded = epoch_value.clone();
    seeded["body"]["revealed_seed"] = json!(SEED);
    assert_family_schema_rejects("audit-epoch", &seeded, "seed inside the precommitment")?;

    let mut over_rate = epoch_value;
    over_rate["body"]["published_rate_bps"] = json!(10_001);
    assert_family_schema_rejects("audit-epoch", &over_rate, "rate above one hundred percent")?;

    let authorization = FindingAuditRoundAuthorization {
        schema: FINDING_AUDIT_ROUND_AUTHORIZATION_SCHEMA_V1.to_string(),
        epoch_precommitment_sha256: audit_epoch_precommitment_sha256(&signed_epoch.body)?,
        authorized_at: signed_epoch.body.committed_at - 100,
        expires_at: signed_epoch.body.committed_at + 100,
    };
    (authorization.validate())?;
    let mut invalid_authorization = authorization.clone();
    invalid_authorization.expires_at = ABOVE_I_JSON_MAX;
    assert_eq!(
        invalid_authorization.validate(),
        Err(FindingError::IJsonIntegerOutOfRange("expires_at"))
    );
    let signed_authorization = SignedExportEnvelope::sign(authorization, &governance_authority)?;
    (verify_signed_audit_round_authorization(
        &signed_authorization,
        &governance_authority.public_key(),
    ))?;
    assert_eq!(
        verify_signed_audit_round_authorization(&signed_authorization, &interloper.public_key(),),
        Err(FindingError::AuthorityMismatch("audit_round_authorization"))
    );
    let authorization_value = serde_json::to_value(&signed_authorization)?;
    validate_family_schema("audit-round-authorization", &authorization_value)?;

    let mut out_of_range = authorization_value;
    out_of_range["body"]["expires_at"] = json!(ABOVE_I_JSON_MAX);
    assert_family_schema_rejects(
        "audit-round-authorization",
        &out_of_range,
        "expiry above the I-JSON maximum",
    )?;

    let epoch_envelope_sha256 = signed_envelope_sha256(&signed_epoch)?;
    let signed_report =
        SignedExportEnvelope::sign(audit_report_body(&epoch_envelope_sha256)?, &audit_authority)?;
    (verify_signed_audit_report(&signed_report, &audit_authority.public_key()))?;
    let report_value: Value = serde_json::to_value(&signed_report)?;
    validate_family_schema("audit-report", &report_value)?;

    let mut unknown = report_value;
    unknown["body"]["surprise"] = json!(true);
    assert_family_schema_rejects("audit-report", &unknown, "unknown body member")?;
    Ok(())
}

#[test]
fn replay_observation_digest_is_the_receipt_binding() -> TestResult {
    let observation = observation_body(HEX64, HEX64_ALT, FindingRecipePhaseKind::Baseline, "run-1");
    (observation.validate())?;
    let digest = observation.canonical_sha256()?;
    assert_eq!(digest.len(), 64);
    assert_eq!(
        digest,
        chio_core_types::crypto::sha256_hex(&canonical_json_bytes(&observation)?)
    );

    let mut other_phase = observation.clone();
    other_phase.phase_id = FindingRecipePhaseKind::Candidate;
    assert_ne!(other_phase.canonical_sha256()?, digest);

    let mut out_of_range = observation.clone();
    out_of_range.exit_code = 4_096;
    assert_eq!(
        out_of_range.validate(),
        Err(FindingError::InvalidField("exit_code"))
    );

    let mut foreign_schema = observation.clone();
    foreign_schema.schema = "chio.finding.replay-observation.v9".to_string();
    assert!(matches!(
        foreign_schema.validate(),
        Err(FindingError::UnsupportedSchema(_))
    ));

    let value: Value = serde_json::to_value(&observation)?;
    validate_family_schema("replay-observation", &value)?;

    let mut unknown = value.clone();
    unknown["surprise"] = json!(true);
    assert_family_schema_rejects("replay-observation", &unknown, "unknown member")?;

    let mut unknown_terminal = value.clone();
    unknown_terminal["terminal_result"] = json!("mostly_completed");
    assert_family_schema_rejects("replay-observation", &unknown_terminal, "unknown terminal")?;

    let mut unknown_phase = value;
    unknown_phase["phase_id"] = json!("warmup");
    assert_family_schema_rejects("replay-observation", &unknown_phase, "unknown phase")?;
    Ok(())
}

#[test]
fn market_penalty_schema_mirrors_the_frozen_camel_case_shape() -> TestResult {
    let value = market_penalty_envelope()?;
    validate_family_schema("market-penalty", &value)?;

    // The frozen body tolerates unknown members, so its schema must too.
    let mut extended = value.clone();
    extended["body"]["futureMember"] = json!("tolerated");
    validate_family_schema("market-penalty", &extended)?;

    // The envelope itself is strict.
    let mut unknown_envelope_member = value.clone();
    unknown_envelope_member["surprise"] = json!(true);
    assert_family_schema_rejects(
        "market-penalty",
        &unknown_envelope_member,
        "unknown envelope member",
    )?;

    // snake_case member names belong to the finding families, not this one.
    let mut snake_case = value.clone();
    let body = snake_case["body"]
        .as_object_mut()
        .ok_or_else(|| std::io::Error::other("penalty body is an object"))?;
    body.remove("penaltyId");
    body.insert("penalty_id".to_string(), json!("market-penalty-42"));
    assert_family_schema_rejects("market-penalty", &snake_case, "snake_case member name")?;

    let mut wrong_schema = value.clone();
    wrong_schema["body"]["schema"] = json!("chio.registry.market-penalty.v9");
    assert_family_schema_rejects("market-penalty", &wrong_schema, "wrong schema const")?;

    let mut unknown_abuse_class = value.clone();
    unknown_abuse_class["body"]["abuseClass"] = json!("mildly_annoying");
    assert_family_schema_rejects(
        "market-penalty",
        &unknown_abuse_class,
        "unknown abuse class",
    )?;

    let mut no_evidence = value;
    no_evidence["body"]["evidenceRefs"] = json!([]);
    assert_family_schema_rejects("market-penalty", &no_evidence, "empty evidence refs")?;
    Ok(())
}
