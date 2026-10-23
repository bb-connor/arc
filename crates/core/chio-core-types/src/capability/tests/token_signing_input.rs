use super::*;

#[test]
fn capability_token_without_schema_is_refused() {
    let kp = Keypair::generate();
    let body = CapabilityTokenBody {
        id: "cap-no-schema".to_string(),
        issuer: kp.public_key(),
        subject: Keypair::generate().public_key(),
        scope: make_scope(vec![make_grant(
            "srv-a",
            "file_read",
            vec![Operation::Invoke],
        )]),
        issued_at: 1000,
        expires_at: 2000,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };
    let token = CapabilityToken::sign(body, &kp).unwrap();
    let mut value = serde_json::to_value(&token).unwrap();
    assert_eq!(value["schema"], CHIO_CAPABILITY_SCHEMA);
    value.as_object_mut().unwrap().remove("schema");

    let error = serde_json::from_value::<CapabilityToken>(value)
        .unwrap_err()
        .to_string();
    assert!(error.contains("missing field `schema`"), "{error}");
}

#[test]
fn plain_body_signature_is_refused() -> Result<()> {
    let kp = Keypair::generate();
    let body = CapabilityTokenBody {
        id: "cap-plain-body".to_string(),
        issuer: kp.public_key(),
        subject: Keypair::generate().public_key(),
        scope: make_scope(vec![make_grant(
            "srv-a",
            "file_read",
            vec![Operation::Invoke],
        )]),
        issued_at: 1000,
        expires_at: 2000,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };
    let signature = kp.sign_wrapped(
        CHIO_CAPABILITY_SCHEMA,
        &crate::canonical::CanonicalBytes::from_serializable(&body)?,
    )?;
    let token = CapabilityToken {
        schema: CHIO_CAPABILITY_SCHEMA.to_string(),
        id: body.id,
        issuer: body.issuer,
        subject: body.subject,
        scope: body.scope,
        issued_at: body.issued_at,
        expires_at: body.expires_at,
        delegation_chain: body.delegation_chain,
        caveats: Vec::new(),
        scope_attenuations: None,
        attenuation_proof: None,
        budget_share_bps: None,
        aggregate_invocation_budget: None,
        signature,
    };

    assert!(!token.verify_signature()?);
    assert!(matches!(
        token.verify_signature_with_floor(CapabilityCryptoFloor::AllowClassical),
        Ok(false)
    ));
    Ok(())
}
