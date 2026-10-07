use crate::{
    common::{self, Result},
    funded_work::work_consent as consent,
};
use chio_core_types::{canonical_json_bytes, sha256_hex};

fn intent(f: &super::native::Fixture) -> Result<consent::Intent> {
    Ok(consent::Intent {
        schema: consent::INTENT_SCHEMA.into(),
        policy_sha256: common::digest(&f.native.policy)?,
        request_id: "separate-consent".into(),
        input_sha256: sha256_hex(b"{}"),
        work: f.agreement.body.work.clone(),
    })
}

#[test]
fn separate_consent_preserves_original_request_and_replays_without_buyer_seed() -> Result<()> {
    let f = super::native::fixture()?;
    let intent = intent(&f)?;
    let proposal = consent::propose(&f.native, &intent, "{}")?;
    let buyer = tempfile::tempdir()?;
    std::fs::write(buyer.path().join("key.seed"), f.buyer.seed_hex())?;
    let accepted = consent::accept(buyer.path(), &intent, &proposal)?;
    let (agreement, request) = consent::original(&f.native, &accepted)?;
    agreement.validate(&f.native.policy, &request)?;
    assert_eq!(
        canonical_json_bytes(&consent::propose(&f.native, &intent, "{}")?)?,
        canonical_json_bytes(&proposal)?
    );
    std::fs::remove_file(buyer.path().join("key.seed"))?;
    assert_eq!(
        canonical_json_bytes(&consent::accept(buyer.path(), &intent, &proposal)?)?,
        canonical_json_bytes(&accepted)?
    );
    assert!(serde_json::to_value(&proposal)?.get("capability").is_none());
    Ok(())
}

#[test]
fn buyer_intent_and_provider_custody_reject_substituted_consent() -> Result<()> {
    let f = super::native::fixture()?;
    let intent = intent(&f)?;
    let proposal = consent::propose(&f.native, &intent, "{}")?;
    let buyer = tempfile::tempdir()?;
    std::fs::write(buyer.path().join("key.seed"), f.buyer.seed_hex())?;
    let mut changed = proposal.clone();
    changed.input.push(' ');
    assert!(consent::accept(buyer.path(), &intent, &changed).is_err());
    assert!(!buyer.path().join("buyer-consent.json").exists());
    let mut changed = intent.clone();
    changed.work.amount = "101".into();
    assert!(consent::accept(buyer.path(), &changed, &proposal).is_err());
    assert!(consent::propose(&f.native, &changed, "{}").is_err());
    let accepted = consent::accept(buyer.path(), &intent, &proposal)?;
    let mut changed = accepted.clone();
    changed.body.proposal_sha256 = "ab".repeat(32);
    assert!(consent::original(&f.native, &changed).is_err());
    Ok(())
}

#[test]
fn lost_consent_components_cannot_silently_mint_replacements() -> Result<()> {
    let f = super::native::fixture()?;
    let intent = intent(&f)?;
    let proposal = consent::propose(&f.native, &intent, "{}")?;
    std::fs::remove_file(f.directory.path().join("provider-intent.json"))?;
    assert!(consent::propose(&f.native, &intent, "{}").is_err());
    assert!(
        !f.directory.path().join("provider-intent.json").exists(),
        "lost enrollment marker must remain absent"
    );
    let buyer = tempfile::tempdir()?;
    std::fs::write(buyer.path().join("key.seed"), f.buyer.seed_hex())?;
    consent::accept(buyer.path(), &intent, &proposal)?;
    std::fs::remove_file(buyer.path().join("buyer-consent.json"))?;
    assert!(
        consent::accept(buyer.path(), &intent, &proposal).is_err(),
        "lost first consent must not be re-signed"
    );
    assert!(!buyer.path().join("buyer-consent.json").exists());
    Ok(())
}

#[test]
fn buyer_seed_and_exact_work_terms_are_checked_before_consent_custody() -> Result<()> {
    let f = super::native::fixture()?;
    let intent = intent(&f)?;
    let proposal = consent::propose(&f.native, &intent, "{}")?;
    let buyer = tempfile::tempdir()?;
    common::init(buyer.path())?;
    assert!(consent::accept(buyer.path(), &intent, &proposal).is_err());
    assert!(!buyer.path().join("buyer-intent.json").exists());
    std::fs::write(buyer.path().join("key.seed"), f.buyer.seed_hex())?;
    for field in [
        "payer",
        "beneficiary",
        "verifier",
        "amount",
        "submitBy",
        "challengeUntil",
        "resolveBy",
        "refundAfter",
    ] {
        let mut changed = serde_json::to_value(&proposal)?;
        let value = &mut changed["agreement"]["work"][field];
        *value = if let Some(n) = value.as_u64() {
            serde_json::json!(n + 1)
        } else {
            serde_json::json!("ab")
        };
        let changed: consent::Proposal = serde_json::from_value(changed)?;
        assert!(
            consent::accept(buyer.path(), &intent, &changed).is_err(),
            "{field}"
        );
        assert!(!buyer.path().join("buyer-intent.json").exists());
    }
    let response = consent::accept(buyer.path(), &intent, &proposal)?;
    let raw = canonical_json_bytes(&response)?;
    let duplicate = [b"{\"body\":{},".as_slice(), &raw[1..]].concat();
    assert!(crate::funded_work::evidence::decode::<consent::Acceptance>(&duplicate).is_err());
    let trailing = [raw.as_slice(), b"\n"].concat();
    assert!(crate::funded_work::evidence::decode::<consent::Acceptance>(&trailing).is_err());
    Ok(())
}
