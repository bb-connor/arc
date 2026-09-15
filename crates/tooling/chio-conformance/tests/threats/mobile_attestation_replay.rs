// Threat test for threat ID `mobile_attestation_replay`.
//
// Coverage strategy: present a production-shaped App Attest assertion whose
// counter does not advance beyond the previously accepted value. The
// production verifier must reject the replay before certificate processing.
//
// Revert-to-prove-it-fails recipe: replace `enforce_counter` in
// `crates/trust/chio-custody-hw/src/attestation/app_attest.rs` with `Ok(())`.
// The replay assertion then advances to the intentionally incomplete
// certificate-chain fixture instead of returning `CounterRollback`, and the
// typed deny-arm assertion below fails.

use std::error::Error;
use std::sync::Arc;

use chio_custody_hw::{
    verify_app_attest, AppAttestVerificationInput, AttestationError, InMemoryMobileChallengeStore,
    MobileAttestationBinding, MobileChallengeAuthority, MobileChallengeError, MobileChallengeStore,
};

use crate::mobile_attestation_common::{encoded_key_id, webauthn_fixture, APP_ID, CHALLENGE};

#[test]
fn mobile_attestation_replay_is_rejected_by_app_attest_counter() -> Result<(), Box<dyn Error>> {
    let credential_id = b"credential-id-mobile-replay";
    let fixture = webauthn_fixture(APP_ID, credential_id, CHALLENGE)?;
    let key_id = encoded_key_id(credential_id);
    let app_attest_error = verify_app_attest(AppAttestVerificationInput {
        attestation_cbor: &fixture,
        key_id: &key_id,
        challenge: CHALLENGE,
        app_id: APP_ID,
        previous_counter: Some(1),
        production: true,
        allow_development_fixture: false,
    })
    .err()
    .ok_or("expected App Attest replay rejection")?;
    assert_eq!(app_attest_error, AttestationError::CounterRollback);
    assert_eq!(
        app_attest_error.urn(),
        "urn:chio:error:custody:app-attest-counter-rollback"
    );

    let later_error = verify_app_attest(AppAttestVerificationInput {
        attestation_cbor: &fixture,
        key_id: &key_id,
        challenge: CHALLENGE,
        app_id: APP_ID,
        previous_counter: Some(0),
        production: true,
        allow_development_fixture: false,
    })
    .err()
    .ok_or("expected incomplete certificate fixture to fail closed")?;
    assert_eq!(
        later_error,
        AttestationError::MissingField("attStmt.x5c"),
        "an advancing counter must pass the replay gate and reach the later certificate gate"
    );
    Ok(())
}

#[test]
fn mobile_challenge_authority_atomically_advances_app_attest_counter() -> Result<(), Box<dyn Error>>
{
    let store = Arc::new(InMemoryMobileChallengeStore::new());
    let authority = MobileChallengeAuthority::new(store.clone());
    let binding = MobileAttestationBinding::AppAttest {
        key_id: "app-attest-conformance-key".to_string(),
        app_id: APP_ID.to_string(),
        audience: "urn:chio:mobile:production".to_string(),
    };

    let enrollment = authority.issue(binding.clone(), 1_000)?;
    let enrollment_snapshot = store.load_active(&enrollment.challenge_id, 1_001)?;
    store.consume_verified(&enrollment_snapshot, Some(0), 1_002)?;
    assert!(matches!(
        store.load_active(&enrollment.challenge_id, 1_003),
        Err(MobileChallengeError::Replayed { .. })
    ));

    let first_assertion = authority.issue(binding.clone(), 1_100)?;
    let stale_assertion = authority.issue(binding, 1_100)?;
    let first_snapshot = store.load_active(&first_assertion.challenge_id, 1_101)?;
    let stale_snapshot = store.load_active(&stale_assertion.challenge_id, 1_101)?;
    assert_eq!(first_snapshot.previous_app_attest_counter(), Some(0));
    assert_eq!(stale_snapshot.previous_app_attest_counter(), Some(0));
    store.consume_verified(&first_snapshot, Some(1), 1_102)?;
    assert!(matches!(
        store.consume_verified(&stale_snapshot, Some(2), 1_103),
        Err(MobileChallengeError::Invalid(_))
    ));
    Ok(())
}
