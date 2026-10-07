//! Old canonical formats retain data and cannot invent a fresh release binding.
use super::*;

#[test]
fn legacy_raw_security_formats_decode_without_fresh_release_authority(
) -> Result<(), Box<dyn std::error::Error>> {
    let operation = committed_operation("legacy-original-dispatch");
    let signer = Keypair::generate();
    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "capability-1".into(),
            issuer: signer.public_key(),
            subject: signer.public_key(),
            scope: ChioScope::default(),
            issued_at: 1,
            expires_at: 2,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &signer,
    )?;
    let request: ToolCallRequest = serde_json::from_value(json!({
        "request_id": "legacy-original-dispatch", "capability": capability,
        "agent_id": signer.public_key().to_hex(), "arguments": {},
        "server_id": "server-1", "tool_name": "tool-1"
    }))?;
    let context = SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
        TenantId::new("legacy-tenant")?,
        SessionId::new("legacy-session")?,
        PrincipalId::new(request.agent_id.clone())?,
        IsolationEpochId::new("legacy-epoch")?,
        LineageId::new(request.capability.id.clone())?,
        1,
    ));
    let mut persisted = raw_for(&operation, json!({"retained": true})).to_persisted();
    persisted.schema = RAW_INVOCATION_OUTCOME_WITH_SECURITY_CONTEXT_SCHEMA.into();
    persisted.request_canonical_json = Some(String::from_utf8(canonical_json_bytes(&request)?)?);
    persisted.security_invocation_context = Some(context);
    let contextual = RawInvocationOutcomeV1::from_persisted(persisted)?;
    let required = contextual.clone().with_security_release_requirement(true)?;
    let signing =
        required
            .clone()
            .with_receipt_signing_identity(FrozenReceiptSigningIdentityV1::new(
                signer.public_key(),
                chio_core::receipt::crypto_floor::ReceiptCryptoFloor::AllowClassical,
            )?)?;
    for legacy in [contextual, required, signing] {
        let bytes = legacy.canonical_blob()?.bytes().to_vec();
        let decoded = RawInvocationOutcomeV1::from_canonical_bytes(&bytes)?;
        assert_eq!(decoded.canonical_blob()?.bytes(), bytes);
        assert_eq!(decoded.to_persisted().schema, legacy.to_persisted().schema);
        assert!(decoded.original_security_dispatch_binding().is_none());
        assert!(matches!(
            decoded.security_dispatch_commitment_id(),
            Err(ToolOutcomeError::Binding(
                "security_release.original_dispatch"
            ))
        ));
    }
    Ok(())
}
