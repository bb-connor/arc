//! Adjacent registries use the same lock-owned persistence boundary as status
//! registries. Busy and refused operations never replace the current file.

use super::test_fixtures::passport_issued_at;
use super::*;
use std::sync::{Arc, Barrier};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const ISSUED_AT: u64 = 1_730_000_000;

fn signed_policy(id: &str) -> Result<SignedPassportVerifierPolicy, CliError> {
    Ok(chio_credentials::create_signed_passport_verifier_policy(
        &Keypair::from_seed(&[81; 32]),
        id,
        "verifier",
        ISSUED_AT,
        ISSUED_AT + 3_600,
        chio_credentials::PassportVerifierPolicy::default(),
    )?)
}

#[test]
fn unrelated_policy_update_preserves_a_deletion_after_busy_retry_and_reopen() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("policies.json");
    VerifierPolicyRegistry::update(&path, |registry| registry.upsert(signed_policy("removed")?))?;
    let inside = Arc::new(Barrier::new(2));
    let attempted = Arc::new(Barrier::new(2));
    let deleter = {
        let (path, inside, attempted) = (path.clone(), Arc::clone(&inside), Arc::clone(&attempted));
        std::thread::spawn(move || {
            VerifierPolicyRegistry::update(&path, |registry| {
                let deleted = registry.remove("removed");
                inside.wait();
                attempted.wait();
                Ok::<_, CliError>(deleted)
            })
            .map_err(|error| format!("{error:?}"))
        })
    };
    inside.wait();
    let before = fs::read(&path)?;
    assert!(matches!(
        VerifierPolicyRegistry::update(&path, |registry| registry
            .upsert(signed_policy("unrelated")?)),
        Err(RegistryTransactionError::Registry(
            RegistryUpdateError::Busy
        ))
    ));
    assert_eq!(fs::read(&path)?, before);
    attempted.wait();
    assert!(deleter.join().map_err(|_| "policy deleter panicked")??);
    VerifierPolicyRegistry::update(&path, |registry| {
        registry.upsert(signed_policy("unrelated")?)
    })?;
    let reopened = VerifierPolicyRegistry::load(&path)?;
    assert!(reopened.get("removed").is_none());
    assert_eq!(
        reopened.get("unrelated"),
        Some(&signed_policy("unrelated")?)
    );
    Ok(())
}

#[test]
fn unrelated_offer_update_preserves_consumption_after_busy_retry_and_reopen() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("offers.json");
    let metadata =
        chio_credentials::default_oid4vci_passport_issuer_metadata("https://issuer.example.test")?;
    let passport = passport_issued_at(122, ISSUED_AT)?;
    let offered = PassportIssuanceOfferRegistry::update_for_issuance(&path, |registry| {
        registry.issue_offer(&metadata, passport, None, 3_600, ISSUED_AT)
    })?;
    let request = Oid4vciTokenRequest {
        grant_type: chio_credentials::OID4VCI_PRE_AUTHORIZED_GRANT_TYPE.to_string(),
        pre_authorized_code: offered.offer.pre_authorized_code()?.to_string(),
    };
    let inside = Arc::new(Barrier::new(2));
    let attempted = Arc::new(Barrier::new(2));
    let redeemer = {
        let (path, inside, attempted, metadata, request) = (
            path.clone(),
            Arc::clone(&inside),
            Arc::clone(&attempted),
            metadata.clone(),
            request.clone(),
        );
        std::thread::spawn(move || {
            PassportIssuanceOfferRegistry::update(&path, |registry| {
                let response =
                    registry.redeem_pre_authorized_code(&metadata, &request, ISSUED_AT, 300)?;
                inside.wait();
                attempted.wait();
                Ok::<_, CliError>(response)
            })
            .map_err(|error| format!("{error:?}"))
        })
    };
    inside.wait();
    let fresh = passport_issued_at(123, ISSUED_AT)?;
    let before = fs::read(&path)?;
    let create = || {
        PassportIssuanceOfferRegistry::update_for_issuance(&path, |registry| {
            registry.issue_offer(&metadata, fresh.clone(), None, 3_600, ISSUED_AT)
        })
    };
    assert!(matches!(
        create(),
        Err(RegistryTransactionError::Registry(
            RegistryUpdateError::Busy
        ))
    ));
    assert_eq!(fs::read(&path)?, before);
    attempted.wait();
    let token = redeemer.join().map_err(|_| "offer redeemer panicked")??;
    let unrelated = create()?;
    let reopened = PassportIssuanceOfferRegistry::load(&path)?;
    let consumed = reopened
        .offers
        .get(&offered.offer_id)
        .ok_or("consumed offer disappeared")?;
    assert_eq!(consumed.state, PassportIssuanceOfferState::TokenIssued);
    assert_eq!(
        consumed.access_token.as_deref(),
        Some(token.access_token.as_str())
    );
    assert!(reopened.offers.contains_key(&unrelated.offer_id));
    let before = fs::read(&path)?;
    assert!(matches!(
        PassportIssuanceOfferRegistry::update(&path, |registry| {
            registry.redeem_pre_authorized_code(&metadata, &request, ISSUED_AT, 300)
        }),
        Err(RegistryTransactionError::Refused(_))
    ));
    assert_eq!(fs::read(&path)?, before);
    Ok(())
}

#[test]
fn a_typed_operation_refusal_does_not_commit_and_the_next_update_progresses() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("policies.json");
    VerifierPolicyRegistry::update(&path, |registry| registry.upsert(signed_policy("kept")?))?;
    let before = fs::read(&path)?;
    let outcome = VerifierPolicyRegistry::update(&path, |registry| {
        registry.remove("kept");
        Err::<(), _>("operator refusal")
    });
    assert!(matches!(
        outcome,
        Err(RegistryTransactionError::Refused("operator refusal"))
    ));
    assert_eq!(fs::read(&path)?, before);
    VerifierPolicyRegistry::update(&path, |registry| registry.upsert(signed_policy("next")?))?;
    let reopened = VerifierPolicyRegistry::load(&path)?;
    assert!(reopened.get("kept").is_some());
    assert!(reopened.get("next").is_some());
    Ok(())
}

#[test]
fn invalid_current_signed_policy_refuses_before_the_change_runs() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("policies.json");
    let mut invalid = VerifierPolicyRegistry::default();
    invalid
        .policies
        .insert("wrong-storage-key".to_string(), signed_policy("owned")?);
    fs::write(&path, serde_json::to_vec(&invalid)?)?;
    let before = fs::read(&path)?;
    let mut changed = false;
    let result = VerifierPolicyRegistry::update(&path, |_| {
        changed = true;
        Ok::<_, CliError>(())
    });
    assert!(matches!(
        result,
        Err(RegistryTransactionError::Registry(
            RegistryUpdateError::Load(CliError::RecordBinding("policy_id"))
        ))
    ));
    assert!(!changed);
    assert_eq!(fs::read(&path)?, before);
    Ok(())
}
