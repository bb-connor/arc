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

use chio_custody_hw::{verify_app_attest, AppAttestVerificationInput, AttestationError};

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
