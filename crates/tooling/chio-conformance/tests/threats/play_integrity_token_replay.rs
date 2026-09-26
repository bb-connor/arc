// Threat test for threat ID `play_integrity_token_replay`.
//
// Coverage strategy: present three Play Integrity tokens that fail
// distinct gates: replayed nonce, stale exp, and audience mismatch.
// The production verifier must reject each.
//
// Revert-to-prove-it-fails recipes (per branch) inside
// `verify_play_integrity` in
// `crates/trust/chio-custody-hw/src/attestation/play_integrity.rs`:
//   (a) drop the nonce comparison that returns
//       `Err(AttestationError::PlayIntegrityNonceMismatch)`. The
//       replayed-nonce deny-arm assertion below fails.
//   (b) drop the `exp` claim check that returns
//       `Err(AttestationError::PlayIntegrityInvalidToken)`. The
//       expired-token deny-arm assertion below fails.
//   (c) drop the audience-claim check that returns
//       `Err(AttestationError::PlayIntegrityInvalidToken)`. The
//       audience-mismatch deny-arm assertion below fails.

use std::error::Error;
use std::sync::Arc;

use chio_custody_hw::attestation::google_root::play_integrity_jwks_json;
use chio_custody_hw::{
    verify_play_integrity, AttestationError, InMemoryMobileChallengeStore,
    MobileAttestationBinding, MobileChallengeAuthority, MobileChallengeError,
    PlayIntegrityVerificationInput, VerifiedMobileAttestationEvidence, MEETS_DEVICE_INTEGRITY,
};

use crate::mobile_attestation_common::{
    future_exp, signed_play_integrity_token, AUDIENCE, NONCE, PACKAGE,
};

#[test]
fn play_integrity_token_replay_fails_nonce_expiry_and_audience_gates() -> Result<(), Box<dyn Error>>
{
    let token =
        signed_play_integrity_token(NONCE, AUDIENCE, &[MEETS_DEVICE_INTEGRITY], future_exp()?)?;
    let valid = verify_play_integrity(PlayIntegrityVerificationInput {
        token: &token,
        expected_nonce: NONCE,
        expected_package_name: PACKAGE,
        expected_audience: AUDIENCE,
        jwks_json: &play_integrity_jwks_json(),
        allow_caller_supplied_jwks: false,
    })?;
    assert_eq!(valid.nonce, NONCE);
    assert_eq!(valid.package_name, PACKAGE);

    let nonce_error = verify_play_integrity(PlayIntegrityVerificationInput {
        token: &token,
        expected_nonce: "already-used-nonce",
        expected_package_name: PACKAGE,
        expected_audience: AUDIENCE,
        jwks_json: &play_integrity_jwks_json(),
        allow_caller_supplied_jwks: false,
    })
    .err()
    .ok_or("expected nonce replay rejection")?;
    assert_eq!(nonce_error, AttestationError::PlayIntegrityNonceMismatch);

    let expired = signed_play_integrity_token(NONCE, AUDIENCE, &[MEETS_DEVICE_INTEGRITY], 1)?;
    let expired_error = verify_play_integrity(PlayIntegrityVerificationInput {
        token: &expired,
        expected_nonce: NONCE,
        expected_package_name: PACKAGE,
        expected_audience: AUDIENCE,
        jwks_json: &play_integrity_jwks_json(),
        allow_caller_supplied_jwks: false,
    })
    .err()
    .ok_or("expected stale token rejection")?;
    assert!(matches!(
        expired_error,
        AttestationError::PlayIntegrityInvalidToken(_)
    ));

    let wrong_audience = signed_play_integrity_token(
        NONCE,
        "other-mobile-issuer",
        &[MEETS_DEVICE_INTEGRITY],
        future_exp()?,
    )?;
    let audience_error = verify_play_integrity(PlayIntegrityVerificationInput {
        token: &wrong_audience,
        expected_nonce: NONCE,
        expected_package_name: PACKAGE,
        expected_audience: AUDIENCE,
        jwks_json: &play_integrity_jwks_json(),
        allow_caller_supplied_jwks: false,
    })
    .err()
    .ok_or("expected audience rejection")?;
    assert!(matches!(
        audience_error,
        AttestationError::PlayIntegrityInvalidToken(_)
    ));
    Ok(())
}

#[test]
fn play_integrity_challenge_is_issuer_owned_and_single_use() -> Result<(), Box<dyn Error>> {
    let store = Arc::new(InMemoryMobileChallengeStore::new());
    let authority = MobileChallengeAuthority::new(store);
    let binding = MobileAttestationBinding::PlayIntegrity {
        package_name: PACKAGE.to_string(),
        audience: AUDIENCE.to_string(),
    };
    let challenge = authority.issue(binding.clone(), 2_000)?;
    let token = signed_play_integrity_token(
        &challenge.nonce,
        AUDIENCE,
        &[MEETS_DEVICE_INTEGRITY],
        future_exp()?,
    )?;
    let verified =
        authority.verify_play_integrity_and_consume(&challenge.challenge_id, &token, 2_001)?;
    assert!(matches!(
        verified.evidence(),
        VerifiedMobileAttestationEvidence::PlayIntegrity(_)
    ));
    assert_eq!(verified.challenge_id(), challenge.challenge_id);
    assert_eq!(verified.binding(), &binding);
    assert!(matches!(
        authority.verify_play_integrity_and_consume(&challenge.challenge_id, &token, 2_002),
        Err(MobileChallengeError::Replayed { .. })
    ));
    Ok(())
}
