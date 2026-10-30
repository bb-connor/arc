use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn signed_policy_registry_rejects_exact_record_under_wrong_key() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
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
    let directory = chio_test_support::private_tempdir()?;
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
