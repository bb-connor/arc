use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn signed_policy_registry_rejects_exact_record_under_wrong_key() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("policies.json");
    let key = chio_core::Keypair::from_seed(&[41; 32]);
    let document = chio_credentials::create_signed_passport_verifier_policy(
        &key,
        "owned-policy",
        "verifier",
        1,
        100,
        chio_credentials::PassportVerifierPolicy::default(),
    )?;
    let mut registry = VerifierPolicyRegistry::default();
    registry
        .policies
        .insert(document.body.policy_id.clone(), document.clone());
    registry.save(&path)?;
    assert_eq!(
        VerifierPolicyRegistry::load(&path)?.get("owned-policy"),
        Some(&document)
    );
    registry.policies.clear();
    registry.policies.insert("foreign-policy".into(), document);
    registry.save(&path)?;
    assert!(matches!(
        VerifierPolicyRegistry::load(&path),
        Err(CliError::RecordBinding("policy_id"))
    ));
    Ok(())
}

#[test]
fn signed_registry_rejects_duplicate_map_entries_before_verification() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("policies.json");
    fs::write(
        &path,
        br#"{"version":"chio.passport-verifier-policies.v1","policies":{}}"#,
    )?;
    assert!(VerifierPolicyRegistry::load(&path)?.policies.is_empty());
    fs::write(&path, br#"{"version":"chio.passport-verifier-policies.v1","policies":{"shadow":{}},"policies":{}}"#)?;
    assert!(matches!(
        VerifierPolicyRegistry::load(&path),
        Err(CliError::SignedJson(
            chio_core::canonical::UntrustedJsonError::SignedInput(_)
        ))
    ));
    Ok(())
}

#[test]
fn stored_challenge_cannot_substitute_another_valid_identifier_after_reopen() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("challenges.sqlite");
    let challenge = chio_credentials::create_passport_presentation_challenge(
        "https://rp.example.com",
        "owned-nonce",
        1_710_000_010,
        1_710_000_310,
        chio_credentials::PassportPresentationOptions::default(),
        None,
    )?;
    let id = challenge_identifier(&challenge).into_owned();
    let store = PassportVerifierChallengeStore::open(&path)?;
    store.register(&challenge)?;
    assert_eq!(store.fetch_active(&id, 1_710_000_020)?, challenge);
    drop(store);
    let store = PassportVerifierChallengeStore::open(&path)?;
    assert_eq!(store.fetch_active(&id, 1_710_000_020)?, challenge);
    let foreign = chio_credentials::create_passport_presentation_challenge(
        "https://rp.example.com",
        "foreign-nonce",
        1_710_000_010,
        1_710_000_310,
        chio_credentials::PassportPresentationOptions::default(),
        None,
    )?;
    verify_passport_presentation_challenge(&foreign, 1_710_000_020)?;
    store.connection()?.execute(
        "UPDATE passport_verifier_challenges SET challenge_json = ?1 WHERE challenge_id = ?2",
        params![serde_json::to_string(&foreign)?, id],
    )?;
    assert!(matches!(
        store.fetch_active(&id, 1_710_000_020),
        Err(CliError::RecordBinding("challenge_id/expires_at"))
    ));
    Ok(())
}
