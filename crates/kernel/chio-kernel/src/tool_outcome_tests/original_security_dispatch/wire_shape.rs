//! Reuse the real signed legacy fixture to pin the new complete raw envelope.
use super::*;
use crate::admission_operation::NativeSecurityDispatchRequestBindingV1;
use chio_core::canonical::UntrustedJsonError;
use std::error::Error;

pub(super) fn verify(
    signing: &RawInvocationOutcomeV1,
    operation: &AdmissionOperationV1,
    request: &ToolCallRequest,
    context: &SecurityInvocationContext,
) -> Result<(), Box<dyn std::error::Error>> {
    let live = NativeSecurityDispatchRequestBindingV1::from_live_request(request, context)?;
    let binding = OriginalSecurityDispatchBindingV1::new(&live)?;
    let request_bytes = canonical_json_bytes(request)?;
    let expected_binding = json!({
        "dispatch_commitment_id": live.dispatch_commitment_id(),
        "live_request_digest": sha256_hex(&request_bytes),
        "schema": "chio.original-security-dispatch-binding.v1",
    });
    assert_eq!(
        canonical_json_bytes(&binding)?,
        canonical_json_bytes(&expected_binding)?
    );
    let raw = signing
        .clone()
        .with_original_security_dispatch_binding(Some(Box::new(binding)))?;
    let commit = operation.dispatch_commit().ok_or("committed fixture")?;
    let expected = json!({
        "schema": "chio.raw-invocation-outcome-with-original-security-dispatch.v1",
        "operation_id": operation.binding().operation_id(),
        "request_id": "legacy-original-dispatch",
        "dispatch_operation_version": commit.committed_version,
        "dispatch_fence": 9,
        "tool_server": "server-1",
        "tool_name": "tool-1",
        "provider_attempt": {
            "operation_id": operation.binding().operation_id(),
            "attempt_id": "attempt-1", "transport_id": "qualified-release-provider",
            "transport_key_epoch": 7,
        },
        "transport_terminal_evidence_digest": sha256_hex(b"transport-terminal"),
        "matched_grant_index": 0,
        "elapsed_millis": 7,
        "stream_limits": {"max_total_bytes":1024,"max_chunks":16,"max_duration_secs":30},
        "output": {"kind":"value","value":{"retained":true}},
        "reported_cost": {"units":25,"currency":"USD"},
        "receipt_metadata_snapshot": null,
        "pre_invocation_guard_evidence": [],
        "request_canonical_json": String::from_utf8(request_bytes)?,
        "security_invocation_context": {
            "version": "v1",
            "context": {
                "tenantId":"legacy-tenant", "sessionId":"legacy-session",
                "principalId": request.agent_id, "isolationEpochId":"legacy-epoch",
                "lineageRootId":"capability-1", "contextGeneration":1,
                "flowStateGeneration":null,
            },
        },
        "security_release_required": true,
        "receipt_signing_identity": {
            "public_key": request.capability.issuer,
            "crypto_floor": "allow_classical",
        },
        "original_security_dispatch_binding": expected_binding,
    });
    let expected_bytes = canonical_json_bytes(&expected)?;
    let blob = raw.canonical_blob()?;
    assert_eq!(blob.bytes(), expected_bytes);
    let restored = RawInvocationOutcomeV1::from_canonical_bytes(&expected_bytes)?;
    assert_eq!(restored.canonical_blob()?.bytes(), expected_bytes);
    assert_eq!(
        restored.security_dispatch_commitment_id()?,
        live.dispatch_commitment_id().clone()
    );

    // Field presence and schema travel together. A historical schema with
    // new authority-shaped data, or a new schema without it, must refuse.
    let mut missing = expected.clone();
    missing
        .as_object_mut()
        .ok_or("raw object")?
        .remove("original_security_dispatch_binding");
    assert!(matches!(
        RawInvocationOutcomeV1::from_canonical_bytes(&canonical_json_bytes(&missing)?),
        Err(ToolOutcomeError::Binding(
            "raw.original_security_dispatch_binding"
        ))
    ));
    let mut historical = expected.clone();
    historical["schema"] = json!("chio.raw-invocation-outcome-with-signing-identity.v1");
    assert!(matches!(
        RawInvocationOutcomeV1::from_canonical_bytes(&canonical_json_bytes(&historical)?),
        Err(ToolOutcomeError::Binding(
            "raw.original_security_dispatch_binding"
        ))
    ));
    let mut unknown = expected.clone();
    unknown["original_security_dispatch_binding"]["authority"] = json!("invented");
    match RawInvocationOutcomeV1::from_canonical_bytes(&canonical_json_bytes(&unknown)?) {
        Err(ToolOutcomeError::UntrustedInput(shared)) => {
            assert_eq!(
                shared.code(),
                "urn:chio:error:attest:signed-json-invalid-shape"
            );
            match shared
                .source()
                .and_then(|cause| cause.downcast_ref::<UntrustedJsonError>())
            {
                Some(UntrustedJsonError::Decode(error)) => {
                    assert_eq!(error.classify(), serde_json::error::Category::Data);
                    assert!(error
                        .to_string()
                        .starts_with("unknown field `authority`, expected "));
                }
                _ => panic!("unknown binding field must preserve its typed Serde data cause"),
            }
        }
        Err(error) => panic!("unknown binding field changed error owner: {error:?}"),
        Ok(_) => panic!("raw wire accepted an unknown binding field"),
    }
    let mut wrong_binding_schema = expected;
    wrong_binding_schema["original_security_dispatch_binding"]["schema"] =
        json!("chio.original-security-dispatch-binding.v0");
    assert!(matches!(
        RawInvocationOutcomeV1::from_canonical_bytes(&canonical_json_bytes(&wrong_binding_schema)?),
        Err(ToolOutcomeError::Binding(
            "raw.original_security_dispatch_binding"
        ))
    ));
    Ok(())
}
