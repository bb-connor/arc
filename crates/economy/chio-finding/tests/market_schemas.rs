//! JSON Schema conformance and golden-fixture coverage for the seven
//! market artifact families. Behavioral wire-type coverage lives in
//! `market_families.rs`; this file pins the registered schemas and the
//! committed fixtures, written by `chio proof fixture regenerate`, against
//! both the schema and the Rust verify paths.

use std::error::Error;
use std::path::PathBuf;

use chio_core_types::crypto::Keypair;
use chio_core_types::{canonical_json_bytes, canonical_json_bytes_from_str};
use chio_finding::{
    signed_envelope_sha256, verify_signed_admission, verify_signed_bond_backing,
    verify_signed_market_terms, verify_signed_seller_authorization, verify_signed_verifier_report,
    FindingReplayRecipeInput, SignedFindingAdmission, SignedFindingBondBacking,
    SignedFindingChallengeVerifierProfile, SignedFindingMarketTerms,
    SignedFindingSellerAuthorization, SignedFindingVerifierReport, MAX_FINDING_ARTIFACT_ITEMS,
    MAX_FINDING_IDENTIFIER_BYTES, MAX_FINDING_TEXT_BYTES,
};
use serde_json::{json, Value};

type TestResult = Result<(), Box<dyn Error>>;

const HEX64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// One market family: its registered schema file and its golden fixture.
struct Family {
    schema: &'static str,
    fixture_dir: &'static str,
    fixture_file: &'static str,
}

const PROFILE: Family = Family {
    schema: "challenge-verifier-profile",
    fixture_dir: "verifier-profile-basic",
    fixture_file: "profile.json",
};
const TERMS: Family = Family {
    schema: "market-terms",
    fixture_dir: "market-terms-basic",
    fixture_file: "terms.json",
};
const AUTHORIZATION: Family = Family {
    schema: "seller-authorization",
    fixture_dir: "seller-authorization-basic",
    fixture_file: "authorization.json",
};
const BACKING: Family = Family {
    schema: "bond-backing",
    fixture_dir: "bond-backing-basic",
    fixture_file: "backing.json",
};
const REPORT: Family = Family {
    schema: "verifier-report",
    fixture_dir: "verifier-report-basic",
    fixture_file: "report.json",
};
const ADMISSION: Family = Family {
    schema: "admission",
    fixture_dir: "venue-admission-basic",
    fixture_file: "admission.json",
};
const RECIPE: Family = Family {
    schema: "replay-recipe-input",
    fixture_dir: "replay-recipe-basic",
    fixture_file: "recipe.json",
};

const GOLDEN_PROFILE_RAW: &str =
    include_str!("../../../../fixtures/proof-room/finding/verifier-profile-basic/profile.json");
const GOLDEN_TERMS_RAW: &str =
    include_str!("../../../../fixtures/proof-room/finding/market-terms-basic/terms.json");
const GOLDEN_AUTHORIZATION_RAW: &str = include_str!(
    "../../../../fixtures/proof-room/finding/seller-authorization-basic/authorization.json"
);
const GOLDEN_BACKING_RAW: &str =
    include_str!("../../../../fixtures/proof-room/finding/bond-backing-basic/backing.json");
const GOLDEN_REPORT_RAW: &str =
    include_str!("../../../../fixtures/proof-room/finding/verifier-report-basic/report.json");
const QUALIFIED_DELIVERY_REPORT_RAW: &str = include_str!(
    "../../../../fixtures/proof-room/finding/cognition-market-qualified-profile/report.json"
);
const GOLDEN_ADMISSION_RAW: &str =
    include_str!("../../../../fixtures/proof-room/finding/venue-admission-basic/admission.json");
const GOLDEN_RECIPE_RAW: &str =
    include_str!("../../../../fixtures/proof-room/finding/replay-recipe-basic/recipe.json");

const GOLDEN_PROFILE_ID: &str = "9cdfc597044c13602ce86b8acaba8c919daa0faf63545c9ec5e4b9e3464ca987";
const GOLDEN_PROFILE_ENVELOPE_SHA256: &str =
    "e0db940832af2936ea63f99b5ffbe8de4f9e720089019571d4a1b2c89921211b";
const GOLDEN_TERMS_ID: &str = "00e03f40ee7e96c48fa13cf05f8f0d932b47cc4524d5fdd06c524d8aa1142e77";
const GOLDEN_TERMS_ENVELOPE_SHA256: &str =
    "9263180b432ae0f32957f839df0b6f3c8dcb12f33b251fb8efffed3963c497a2";
const GOLDEN_AUTHORIZATION_ID: &str =
    "cd595cde853c1d2c42732748e9894cf0166b99bf85df47031eb89d4cf58a2af4";
const GOLDEN_AUTHORIZATION_ENVELOPE_SHA256: &str =
    "f8ee7c2311e258893f26fd9a6c58990012bad7441a31429687c17700bb5a0ecb";
const GOLDEN_ALLOCATION_ID: &str =
    "2586e92a398e6dbbea299408add0610a881a847ec3523e839ef9eb9e175ef482";
const GOLDEN_BACKING_ENVELOPE_SHA256: &str =
    "5d27cba919f0e463eea4a9091c5c2ee11770bd6e87f11c3645494ab78958b228";
const GOLDEN_REPORT_ID: &str = "fca3e0c0e15921c334ab431c40010ecc8e881423c529b29766513c3b39fcc186";
const GOLDEN_REPORT_ENVELOPE_SHA256: &str =
    "bc50ee7fd6e8269af82d5a62f851e637036062760bc84bba6665d94d1f5c05c3";
const GOLDEN_ADMISSION_ID: &str =
    "5953afeb3fefbb921a3b61db01a5c494f4a85f30da87ca6a607c517b928fe3de";
const GOLDEN_ADMISSION_ENVELOPE_SHA256: &str =
    "73aa9ccfb34cdf0b26fb2bc0e2b58c24f84c9b7411f246a08c386d8a69a3229c";
const GOLDEN_RECIPE_SHA256: &str =
    "9ac1ef84a974f386b07ced3f0284da47744770e7ea119041c06b837c95e8ddf7";

fn fixture_path(family: &Family) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../fixtures/proof-room/finding")
        .join(family.fixture_dir)
        .join(family.fixture_file)
}

fn schema_path(family: &Family) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../spec/schemas/chio-finding/v1")
        .join(format!("{}.schema.json", family.schema))
}

fn validate_family_schema(
    family: &Family,
    value: &Value,
) -> Result<(), chio_spec_validate::ValidateError> {
    let path = schema_path(family);
    let schema = chio_spec_validate::load_json(&path)?;
    chio_spec_validate::validate_value(&path, &schema, &fixture_path(family), value)
}

fn assert_family_schema_rejects(family: &Family, value: &Value, case: &str) -> TestResult {
    match validate_family_schema(family, value) {
        Err(chio_spec_validate::ValidateError::SchemaViolation(_, _, _)) => Ok(()),
        Err(err) => Err(err.into()),
        Ok(()) => Err(std::io::Error::other(format!(
            "{} schema accepted invalid case: {case}",
            family.schema
        ))
        .into()),
    }
}

fn keypair(seed: u8) -> Keypair {
    Keypair::from_seed(&[seed; 32])
}

fn signed_profile() -> Result<SignedFindingChallengeVerifierProfile, Box<dyn Error>> {
    Ok(serde_json::from_str(GOLDEN_PROFILE_RAW)?)
}

fn signed_terms() -> Result<SignedFindingMarketTerms, Box<dyn Error>> {
    Ok(serde_json::from_str(GOLDEN_TERMS_RAW)?)
}

fn signed_authorization() -> Result<SignedFindingSellerAuthorization, Box<dyn Error>> {
    Ok(serde_json::from_str(GOLDEN_AUTHORIZATION_RAW)?)
}

fn signed_backing() -> Result<SignedFindingBondBacking, Box<dyn Error>> {
    Ok(serde_json::from_str(GOLDEN_BACKING_RAW)?)
}

fn signed_report() -> Result<SignedFindingVerifierReport, Box<dyn Error>> {
    Ok(serde_json::from_str(GOLDEN_REPORT_RAW)?)
}

fn signed_admission() -> Result<SignedFindingAdmission, Box<dyn Error>> {
    Ok(serde_json::from_str(GOLDEN_ADMISSION_RAW)?)
}

fn recipe_body() -> Result<FindingReplayRecipeInput, Box<dyn Error>> {
    Ok(serde_json::from_str(GOLDEN_RECIPE_RAW)?)
}

#[test]
fn profile_envelope_conforms_to_schema() -> TestResult {
    validate_family_schema(&PROFILE, &serde_json::to_value(signed_profile()?)?)?;
    Ok(())
}

#[test]
fn profile_schema_rejects_unknown_top_level_member() -> TestResult {
    let mut value = serde_json::to_value(signed_profile()?)?;
    value["surprise"] = json!(true);
    assert_family_schema_rejects(&PROFILE, &value, "unknown top-level member")
}

#[test]
fn profile_schema_rejects_wrong_schema_const() -> TestResult {
    let mut value = serde_json::to_value(signed_profile()?)?;
    value["body"]["schema"] = json!("chio.finding.challenge-verifier-profile.v999");
    assert_family_schema_rejects(&PROFILE, &value, "wrong schema const")
}

#[test]
fn profile_schema_rejects_missing_receipt_role() -> TestResult {
    let mut value = serde_json::to_value(signed_profile()?)?;
    if let Some(signers) = value["body"]["receipt_signers"].as_array_mut() {
        signers.pop();
    }
    assert_family_schema_rejects(&PROFILE, &value, "two receipt signer roles")
}

#[test]
fn terms_envelope_conforms_to_schema() -> TestResult {
    validate_family_schema(&TERMS, &serde_json::to_value(signed_terms()?)?)?;
    Ok(())
}

#[test]
fn terms_schema_rejects_unknown_top_level_member() -> TestResult {
    let mut value = serde_json::to_value(signed_terms()?)?;
    value["surprise"] = json!(true);
    assert_family_schema_rejects(&TERMS, &value, "unknown top-level member")
}

#[test]
fn terms_schema_rejects_wrong_schema_const() -> TestResult {
    let mut value = serde_json::to_value(signed_terms()?)?;
    value["body"]["schema"] = json!("chio.finding.market-terms.v999");
    assert_family_schema_rejects(&TERMS, &value, "wrong schema const")
}

#[test]
fn terms_schema_rejects_zero_base_finding_stake() -> TestResult {
    let mut value = serde_json::to_value(signed_terms()?)?;
    value["body"]["backing_requirement"]["base_finding_stake"]["units"] = json!(0);
    assert_family_schema_rejects(&TERMS, &value, "zero base finding stake")
}

#[test]
fn terms_schema_rejects_unknown_payout_policy() -> TestResult {
    let mut value = serde_json::to_value(signed_terms()?)?;
    value["body"]["payout_policy"] = json!("winner_takes_all_v1");
    assert_family_schema_rejects(&TERMS, &value, "unknown payout policy")
}

#[test]
fn authorization_envelope_conforms_to_schema() -> TestResult {
    validate_family_schema(
        &AUTHORIZATION,
        &serde_json::to_value(signed_authorization()?)?,
    )?;
    Ok(())
}

#[test]
fn authorization_schema_rejects_unknown_top_level_member() -> TestResult {
    let mut value = serde_json::to_value(signed_authorization()?)?;
    value["surprise"] = json!(true);
    assert_family_schema_rejects(&AUTHORIZATION, &value, "unknown top-level member")
}

#[test]
fn authorization_schema_rejects_wrong_schema_const() -> TestResult {
    let mut value = serde_json::to_value(signed_authorization()?)?;
    value["body"]["schema"] = json!("chio.finding.seller-authorization.v999");
    assert_family_schema_rejects(&AUTHORIZATION, &value, "wrong schema const")
}

#[test]
fn authorization_schema_rejects_uppercase_finding_id() -> TestResult {
    let mut value = serde_json::to_value(signed_authorization()?)?;
    value["body"]["finding_id"] = json!(HEX64.to_uppercase());
    assert_family_schema_rejects(&AUTHORIZATION, &value, "uppercase finding_id digest")
}

#[test]
fn backing_envelope_conforms_to_schema() -> TestResult {
    validate_family_schema(&BACKING, &serde_json::to_value(signed_backing()?)?)?;
    Ok(())
}

#[test]
fn backing_schema_rejects_unknown_top_level_member() -> TestResult {
    let mut value = serde_json::to_value(signed_backing()?)?;
    value["surprise"] = json!(true);
    assert_family_schema_rejects(&BACKING, &value, "unknown top-level member")
}

#[test]
fn backing_schema_rejects_wrong_schema_const() -> TestResult {
    let mut value = serde_json::to_value(signed_backing()?)?;
    value["body"]["schema"] = json!("chio.finding.bond-backing.v999");
    assert_family_schema_rejects(&BACKING, &value, "wrong schema const")
}

#[test]
fn backing_schema_rejects_zero_claim_horizon() -> TestResult {
    let mut value = serde_json::to_value(signed_backing()?)?;
    value["body"]["claim_horizon_secs"] = json!(0);
    assert_family_schema_rejects(&BACKING, &value, "zero claim horizon")
}

#[test]
fn report_envelope_conforms_to_schema() -> TestResult {
    validate_family_schema(&REPORT, &serde_json::to_value(signed_report()?)?)?;
    Ok(())
}

#[test]
fn report_schema_rejects_unknown_top_level_member() -> TestResult {
    let mut value = serde_json::to_value(signed_report()?)?;
    value["surprise"] = json!(true);
    assert_family_schema_rejects(&REPORT, &value, "unknown top-level member")
}

#[test]
fn report_schema_rejects_wrong_schema_const() -> TestResult {
    let mut value = serde_json::to_value(signed_report()?)?;
    value["body"]["schema"] = json!("chio.finding.verifier-report.v999");
    assert_family_schema_rejects(&REPORT, &value, "wrong schema const")
}

#[test]
fn report_schema_rejects_unknown_facet_outcome() -> TestResult {
    let mut value = serde_json::to_value(signed_report()?)?;
    value["body"]["facets"][0]["outcome"] = json!("maybe");
    assert_family_schema_rejects(&REPORT, &value, "unknown facet outcome token")
}

#[test]
fn admission_envelope_conforms_to_schema() -> TestResult {
    validate_family_schema(&ADMISSION, &serde_json::to_value(signed_admission()?)?)?;
    Ok(())
}

#[test]
fn admission_schema_rejects_unknown_top_level_member() -> TestResult {
    let mut value = serde_json::to_value(signed_admission()?)?;
    value["surprise"] = json!(true);
    assert_family_schema_rejects(&ADMISSION, &value, "unknown top-level member")
}

#[test]
fn admission_schema_rejects_wrong_schema_const() -> TestResult {
    let mut value = serde_json::to_value(signed_admission()?)?;
    value["body"]["schema"] = json!("chio.finding.admission.v999");
    assert_family_schema_rejects(&ADMISSION, &value, "wrong schema const")
}

#[test]
fn admission_schema_rejects_malformed_capability_scope() -> TestResult {
    let mut value = serde_json::to_value(signed_admission()?)?;
    value["body"]["capability_scope"] = json!("finding:not-a-digest");
    assert_family_schema_rejects(&ADMISSION, &value, "malformed capability scope")
}

#[test]
fn market_family_schemas_reject_oversized_string_fields() -> TestResult {
    let oversized_id = "i".repeat(MAX_FINDING_IDENTIFIER_BYTES + 1);
    let oversized_text = "t".repeat(MAX_FINDING_TEXT_BYTES + 1);

    let mut admission = serde_json::to_value(signed_admission()?)?;
    admission["body"]["venue_id"] = json!(oversized_id.clone());
    assert_family_schema_rejects(&ADMISSION, &admission, "oversized venue id")?;

    let mut authorization = serde_json::to_value(signed_authorization()?)?;
    authorization["body"]["revocation_status_ref"] = json!(oversized_id.clone());
    assert_family_schema_rejects(
        &AUTHORIZATION,
        &authorization,
        "oversized revocation status ref",
    )?;

    let mut backing = serde_json::to_value(signed_backing()?)?;
    backing["body"]["vault"]["venue_ledger"]["ledger_account"] = json!(oversized_id.clone());
    assert_family_schema_rejects(&BACKING, &backing, "oversized ledger account")?;

    let mut terms = serde_json::to_value(signed_terms()?)?;
    terms["body"]["payout_policy"] = json!(oversized_id.clone());
    assert_family_schema_rejects(&TERMS, &terms, "oversized payout policy")?;

    let mut profile = serde_json::to_value(signed_profile()?)?;
    profile["body"]["operator"] = json!(oversized_id);
    assert_family_schema_rejects(&PROFILE, &profile, "oversized operator")?;

    let mut report = serde_json::to_value(signed_report()?)?;
    report["body"]["facets"][0]["reason"] = json!(oversized_text);
    assert_family_schema_rejects(&REPORT, &report, "oversized facet reason")
}

#[test]
fn market_family_schemas_reject_oversized_collections() -> TestResult {
    let mut admission = serde_json::to_value(signed_admission()?)?;
    let terminal = admission["body"]["fee_terminals"][0].clone();
    admission["body"]["fee_terminals"] = json!((0..=MAX_FINDING_ARTIFACT_ITEMS)
        .map(|index| {
            let mut item = terminal.clone();
            if index > 0 {
                item["event"] = json!({
                    "participation_epoch": {
                        "epoch_index": index - 1
                    }
                });
            }
            item
        })
        .collect::<Vec<_>>());
    assert_family_schema_rejects(&ADMISSION, &admission, "too many fee terminals")?;

    let mut terms = serde_json::to_value(signed_terms()?)?;
    terms["body"]["decision_rule_refs"] = json!((0..=MAX_FINDING_ARTIFACT_ITEMS)
        .map(|index| format!("decision/rule-{index}"))
        .collect::<Vec<_>>());
    assert_family_schema_rejects(&TERMS, &terms, "too many decision rules")?;

    let mut profile = serde_json::to_value(signed_profile()?)?;
    let checkpoint = profile["body"]["checkpoint_logs"][0].clone();
    profile["body"]["checkpoint_logs"] = json!((0..=MAX_FINDING_ARTIFACT_ITEMS)
        .map(|index| {
            let mut item = checkpoint.clone();
            item["log_id"] = json!(format!("checkpoint-{index}"));
            item
        })
        .collect::<Vec<_>>());
    assert_family_schema_rejects(&PROFILE, &profile, "too many checkpoint logs")?;

    let mut report = serde_json::to_value(signed_report()?)?;
    report["body"]["facets"][0]["evidence_refs"] = json!((0..=MAX_FINDING_ARTIFACT_ITEMS)
        .map(|index| format!("receipt-{index}"))
        .collect::<Vec<_>>());
    assert_family_schema_rejects(&REPORT, &report, "too many evidence refs")
}

#[test]
fn recipe_conforms_to_schema() -> TestResult {
    validate_family_schema(&RECIPE, &serde_json::to_value(recipe_body()?)?)?;
    Ok(())
}

#[test]
fn recipe_schema_rejects_unknown_top_level_member() -> TestResult {
    let mut value = serde_json::to_value(recipe_body()?)?;
    value["surprise"] = json!(true);
    assert_family_schema_rejects(&RECIPE, &value, "unknown top-level member")
}

#[test]
fn recipe_schema_rejects_wrong_schema_const() -> TestResult {
    let mut value = serde_json::to_value(recipe_body()?)?;
    value["schema"] = json!("chio.finding.replay-recipe-input.v999");
    assert_family_schema_rejects(&RECIPE, &value, "wrong schema const")
}

#[test]
fn recipe_schema_rejects_swapped_phase_order() -> TestResult {
    let mut value = serde_json::to_value(recipe_body()?)?;
    if let Some(phases) = value["phases"].as_array_mut() {
        phases.swap(0, 1);
    }
    assert_family_schema_rejects(&RECIPE, &value, "candidate phase before baseline")
}

#[test]
fn recipe_schema_rejects_unknown_payload_application() -> TestResult {
    let mut value = serde_json::to_value(recipe_body()?)?;
    value["phases"][1]["payload_application"] = json!("replace_tree_v1");
    assert_family_schema_rejects(&RECIPE, &value, "unknown payload application")
}

#[test]
fn golden_verifier_profile_fixture_validates() -> TestResult {
    let strict_canonical = canonical_json_bytes_from_str(GOLDEN_PROFILE_RAW)?;
    let value: Value = serde_json::from_str(GOLDEN_PROFILE_RAW)?;
    validate_family_schema(&PROFILE, &value)?;
    let signed: SignedFindingChallengeVerifierProfile = serde_json::from_str(GOLDEN_PROFILE_RAW)?;
    assert_eq!(strict_canonical, canonical_json_bytes(&signed)?);
    signed.body.validate()?;
    chio_finding::verify_signed_profile(&signed, &keypair(1).public_key())?;
    assert_eq!(signed.body.profile_id, GOLDEN_PROFILE_ID);
    assert_eq!(
        signed_envelope_sha256(&signed)?,
        GOLDEN_PROFILE_ENVELOPE_SHA256
    );
    Ok(())
}

#[test]
fn golden_market_terms_fixture_validates() -> TestResult {
    let strict_canonical = canonical_json_bytes_from_str(GOLDEN_TERMS_RAW)?;
    let value: Value = serde_json::from_str(GOLDEN_TERMS_RAW)?;
    validate_family_schema(&TERMS, &value)?;
    let signed: SignedFindingMarketTerms = serde_json::from_str(GOLDEN_TERMS_RAW)?;
    assert_eq!(strict_canonical, canonical_json_bytes(&signed)?);
    verify_signed_market_terms(&signed)?;
    assert_eq!(signed.body.seller, keypair(2).public_key());
    assert_eq!(signed.body.terms_id, GOLDEN_TERMS_ID);
    assert_eq!(
        signed_envelope_sha256(&signed)?,
        GOLDEN_TERMS_ENVELOPE_SHA256
    );
    Ok(())
}

#[test]
fn golden_seller_authorization_fixture_validates() -> TestResult {
    let strict_canonical = canonical_json_bytes_from_str(GOLDEN_AUTHORIZATION_RAW)?;
    let value: Value = serde_json::from_str(GOLDEN_AUTHORIZATION_RAW)?;
    validate_family_schema(&AUTHORIZATION, &value)?;
    let signed: SignedFindingSellerAuthorization = serde_json::from_str(GOLDEN_AUTHORIZATION_RAW)?;
    assert_eq!(strict_canonical, canonical_json_bytes(&signed)?);
    verify_signed_seller_authorization(&signed)?;
    assert_eq!(signed.body.issuer, keypair(3).public_key());
    assert_eq!(signed.body.authorization_id, GOLDEN_AUTHORIZATION_ID);
    assert_eq!(
        signed_envelope_sha256(&signed)?,
        GOLDEN_AUTHORIZATION_ENVELOPE_SHA256
    );
    Ok(())
}

#[test]
fn golden_bond_backing_fixture_validates() -> TestResult {
    let strict_canonical = canonical_json_bytes_from_str(GOLDEN_BACKING_RAW)?;
    let value: Value = serde_json::from_str(GOLDEN_BACKING_RAW)?;
    validate_family_schema(&BACKING, &value)?;
    let signed: SignedFindingBondBacking = serde_json::from_str(GOLDEN_BACKING_RAW)?;
    assert_eq!(strict_canonical, canonical_json_bytes(&signed)?);
    verify_signed_bond_backing(&signed, &keypair(4).public_key())?;
    assert_eq!(signed.body.allocation_id, GOLDEN_ALLOCATION_ID);
    assert_eq!(
        signed_envelope_sha256(&signed)?,
        GOLDEN_BACKING_ENVELOPE_SHA256
    );
    Ok(())
}

#[test]
fn golden_verifier_report_fixture_validates() -> TestResult {
    let strict_canonical = canonical_json_bytes_from_str(GOLDEN_REPORT_RAW)?;
    let value: Value = serde_json::from_str(GOLDEN_REPORT_RAW)?;
    validate_family_schema(&REPORT, &value)?;
    let signed: SignedFindingVerifierReport = serde_json::from_str(GOLDEN_REPORT_RAW)?;
    assert_eq!(strict_canonical, canonical_json_bytes(&signed)?);
    verify_signed_verifier_report(&signed, &keypair(15).public_key())?;
    assert_eq!(signed.body.report_id, GOLDEN_REPORT_ID);
    assert_eq!(
        signed_envelope_sha256(&signed)?,
        GOLDEN_REPORT_ENVELOPE_SHA256
    );
    Ok(())
}

#[test]
fn qualified_delivery_verifier_report_conforms_to_schema() -> TestResult {
    let strict_canonical = canonical_json_bytes_from_str(QUALIFIED_DELIVERY_REPORT_RAW)?;
    let value: Value = serde_json::from_str(QUALIFIED_DELIVERY_REPORT_RAW)?;
    validate_family_schema(&REPORT, &value)?;
    let signed: SignedFindingVerifierReport = serde_json::from_str(QUALIFIED_DELIVERY_REPORT_RAW)?;
    assert_eq!(strict_canonical, canonical_json_bytes(&signed)?);
    verify_signed_verifier_report(&signed, &signed.body.verifier_authority)?;
    assert!(signed.body.finding_delivery.is_some());
    Ok(())
}

#[test]
fn signed_verifier_report_rejects_explicit_null_optionals() -> TestResult {
    for field in [
        "replay_recipe_input_sha256",
        "status_proof_input_sha256",
        "finding_delivery_receipt_id",
        "finding_delivery",
        "backing_allocation_id",
    ] {
        let mut value: Value = serde_json::from_str(GOLDEN_REPORT_RAW)?;
        let body = value
            .get_mut("body")
            .and_then(Value::as_object_mut)
            .ok_or("signed verifier report body")?;
        body.insert(field.to_string(), Value::Null);
        assert!(
            serde_json::from_value::<SignedFindingVerifierReport>(value).is_err(),
            "explicit null was accepted for {field}"
        );
    }
    Ok(())
}

#[test]
fn golden_venue_admission_fixture_validates() -> TestResult {
    let strict_canonical = canonical_json_bytes_from_str(GOLDEN_ADMISSION_RAW)?;
    let value: Value = serde_json::from_str(GOLDEN_ADMISSION_RAW)?;
    validate_family_schema(&ADMISSION, &value)?;
    let signed: SignedFindingAdmission = serde_json::from_str(GOLDEN_ADMISSION_RAW)?;
    assert_eq!(strict_canonical, canonical_json_bytes(&signed)?);
    verify_signed_admission(&signed, &keypair(6).public_key(), "venue-wedge")?;
    assert_eq!(signed.body.admission_id, GOLDEN_ADMISSION_ID);
    assert_eq!(
        signed_envelope_sha256(&signed)?,
        GOLDEN_ADMISSION_ENVELOPE_SHA256
    );
    Ok(())
}

#[test]
fn golden_replay_recipe_fixture_validates() -> TestResult {
    let strict_canonical = canonical_json_bytes_from_str(GOLDEN_RECIPE_RAW)?;
    let value: Value = serde_json::from_str(GOLDEN_RECIPE_RAW)?;
    validate_family_schema(&RECIPE, &value)?;
    let recipe: FindingReplayRecipeInput = serde_json::from_str(GOLDEN_RECIPE_RAW)?;
    assert_eq!(strict_canonical, canonical_json_bytes(&recipe)?);
    recipe.validate()?;
    assert_eq!(recipe.canonical_sha256()?, GOLDEN_RECIPE_SHA256);
    Ok(())
}
