use super::*;

#[test]
fn attenuation_witness_rejects_noncanonical_scope_even_with_matching_hash(
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    use std::error::Error as _;
    let scope = make_scope(vec![make_grant("srv", "tool", vec![Operation::Invoke])]);
    let mut witness = compute_attenuation_witness(&scope, &scope)?;
    let hash = scope_hash(&scope)?;
    verify_attenuation_witness(&hash, &hash, &witness)?;
    witness.normalized_parent_scope.insert(1, ' ');
    let substituted_hash = crate::sha256_hex(witness.normalized_parent_scope.as_bytes());
    let error = verify_attenuation_witness(&substituted_hash, &hash, &witness)
        .err()
        .ok_or("accepted noncanonical witness")?;
    let crate::Error::UntrustedInput(cause) = &error else {
        return Err("wrong rejection class".into());
    };
    assert_eq!(
        cause.code(),
        "urn:chio:error:attest:signed-json-noncanonical"
    );
    assert!(error.source().is_some());
    Ok(())
}

#[test]
fn attenuation_witness_roundtrip_and_forgery_rejection() {
    let parent = make_scope(vec![make_grant(
        "srv",
        "tool",
        vec![Operation::Invoke, Operation::ReadResult],
    )]);
    let child = make_scope(vec![make_grant("srv", "tool", vec![Operation::Invoke])]);

    let witness = compute_attenuation_witness(&parent, &child).unwrap();
    let parent_hash = scope_hash(&parent).unwrap();
    let child_hash = scope_hash(&child).unwrap();

    verify_attenuation_witness(&parent_hash, &child_hash, &witness).unwrap();
    let forged = "00".repeat(32);
    assert!(matches!(
        verify_attenuation_witness(&forged, &child_hash, &witness),
        Err(crate::Error::AttenuationViolation { .. })
    ));
}
