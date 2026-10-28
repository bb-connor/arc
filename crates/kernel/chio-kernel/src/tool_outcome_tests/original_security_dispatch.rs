//! Complete canonical returns bind the request and its security release evidence.
use super::*;
use crate::admission_operation::NativeSecurityDispatchRequestBindingV1;

#[test]
fn complete_raw_security_envelope_roundtrips_canonical_bytes(
) -> Result<(), Box<dyn std::error::Error>> {
    let operation = committed_operation("original-dispatch");
    let signer = Keypair::from_seed(&[0x61; 32]);
    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: operation.binding().capability_id().as_str().to_owned(),
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
        "request_id": operation.binding().request_id(), "capability": capability,
        "agent_id": signer.public_key().to_hex(), "arguments": {},
        "server_id": "server-1", "tool_name": "tool-1"
    }))?;
    let context = SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
        TenantId::new("tenant")?,
        SessionId::new("session")?,
        PrincipalId::new(request.agent_id.clone())?,
        IsolationEpochId::new("epoch")?,
        LineageId::new(request.capability.id.clone())?,
        1,
    ));
    let live = NativeSecurityDispatchRequestBindingV1::from_live_request(&request, &context)?;
    let raw = RawInvocationOutcomeV1::from_committed_dispatch(
        &operation,
        operation.dispatch_commit().ok_or("committed fixture")?,
        id("server-1"),
        id("tool-1"),
        provider_attempt(&operation, "attempt-1"),
        admission_digest("transport-terminal"),
        0,
        7,
        stream_limits(),
        InvocationOutputV1::Value {
            value: json!({"retained": true}),
        },
        Some(MonetaryAmount {
            units: 25,
            currency: "USD".to_owned(),
        }),
        None,
        crate::kernel::PreInvocationGuardOutput::default(),
        RawInvocationContext {
            request: &request,
            security_invocation_context: Some(context.clone()),
            federation_context_json: None,
            security_release_required: true,
            receipt_signing_identity: FrozenReceiptSigningIdentityV1::new(
                signer.public_key(),
                chio_core::receipt::crypto_floor::ReceiptCryptoFloor::AllowClassical,
            )?,
            caller_delivery_evidence: None,
            original_security_dispatch_binding: Some(Box::new(
                OriginalSecurityDispatchBindingV1::new(&live)?,
            )),
        },
    )?;
    wire_shape::verify(&raw, &operation, &request, &context)?;
    Ok(())
}

#[path = "original_security_dispatch/wire_shape.rs"]
mod wire_shape;
