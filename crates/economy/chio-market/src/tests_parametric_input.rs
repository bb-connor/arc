use super::*;

#[test]
fn parametric_policy_verification_fails_closed_on_signer_schema_and_encoding() {
    let fixture = sample_parametric_fixture();
    let mut tampered = fixture.signed_policy();
    tampered.body.max_checkpoint_lag_seconds += 1;
    assert_eq!(
        require_err(
            VerifiedParametricPolicy::verify(tampered, &fixture.context()),
            "tampered policy",
        ),
        ParametricContractError::InvalidSignature
    );

    let rogue_signer = crate::crypto::Keypair::from_seed(&[40; 32]);
    let rogue_policy = require_ok(
        SignedParametricPolicy::sign(fixture.policy.clone(), &rogue_signer),
        "sign rogue policy",
    );
    assert_eq!(
        require_err(
            VerifiedParametricPolicy::verify(rogue_policy, &fixture.context()),
            "rogue policy signer",
        ),
        ParametricContractError::UntrustedPolicySigner
    );

    let mut unknown = fixture.policy.clone();
    unknown.schema = "chio.parametric.policy.v9".to_string();
    let unknown = require_ok(
        SignedParametricPolicy::sign(unknown, &fixture.policy_signer),
        "sign unknown schema",
    );
    assert_eq!(
        require_err(
            VerifiedParametricPolicy::verify(unknown, &fixture.context()),
            "unknown policy schema",
        ),
        ParametricContractError::UnknownSchema("chio.parametric.policy.v9".to_string())
    );

    let verified = require_ok(
        VerifiedParametricPolicy::verify(fixture.signed_policy(), &fixture.context()),
        "verify canonical policy",
    );
    let canonical = require_ok(verified.canonical_bytes(), "encode canonical policy");
    let round_trip = require_ok(
        VerifiedParametricPolicy::from_canonical_bytes(&canonical, &fixture.context()),
        "decode canonical policy",
    );
    assert_eq!(round_trip.envelope_digest(), verified.envelope_digest());

    let mut padded = vec![b' '];
    padded.extend_from_slice(&canonical);
    assert!(matches!(
        VerifiedParametricPolicy::from_canonical_bytes(&padded, &fixture.context()),
        Err(ParametricContractError::Input(source))
            if source.code() == "urn:chio:error:attest:signed-json-noncanonical"
    ));
}
