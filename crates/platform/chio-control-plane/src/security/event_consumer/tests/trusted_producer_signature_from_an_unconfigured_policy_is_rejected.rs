use super::*;

#[test]
fn trusted_producer_signature_from_an_unconfigured_policy_is_rejected() {
    let keypair = Keypair::from_seed(&[72_u8; 32]);
    let verifier = verifier(&keypair);
    let mut event = signed_event(&keypair);
    let control = verifier
        .verify(&event)
        .unwrap_or_else(|error| panic!("valid control: {error}"));
    assert_eq!(control.event_id, event.event_id);
    let signed: SignedSecurityEvent = serde_json::from_slice(event.source_evidence.as_bytes())
        .unwrap_or_else(|error| panic!("decode signed event: {error}"));
    let mut body = signed.body().clone();
    body.policy_version = record("policy-v2");
    let canonical_body = canonical_json_bytes(&body)
        .unwrap_or_else(|error| panic!("canonical policy-v2 body: {error}"));
    let resigned =
        SignedSecurityEvent::sign_with_backend(body, &Ed25519Backend::new(keypair.clone()))
            .unwrap_or_else(|error| panic!("sign policy-v2 event: {error}"));
    assert!(resigned
        .verify_trusted_producer(
            &producer(),
            &record("detector-key-v1"),
            &keypair.public_key()
        )
        .unwrap_or_else(|error| panic!("correctly signed wrong binding: {error}")));
    event.canonical_body = CanonicalBody::new(canonical_body.clone())
        .unwrap_or_else(|error| panic!("policy-v2 body: {error}"));
    event.body_hash = Digest32::new(*chio_core::sha256(&canonical_body).as_bytes());
    event.source_evidence = CanonicalBody::new(
        canonical_json_bytes(&resigned)
            .unwrap_or_else(|error| panic!("canonical policy-v2 envelope: {error}")),
    )
    .unwrap_or_else(|error| panic!("policy-v2 envelope: {error}"));

    let error = verifier
        .verify(&event)
        .err()
        .unwrap_or_else(|| panic!("accepted wrong policy"));
    assert_eq!(
        error.kind(),
        chio_security_types::ports::PortErrorKind::IntegrityFailure
    );
    assert_eq!(error.code().as_str(), "store.integrity_failure");
}
