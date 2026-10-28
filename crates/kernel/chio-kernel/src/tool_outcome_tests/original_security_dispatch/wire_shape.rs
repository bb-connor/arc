//! Canonical wire bytes require explicit evidence fields and consistent release binding.
use super::*;
use crate::admission_operation::NativeSecurityDispatchRequestBindingV1;
use chio_core::canonical::UntrustedJsonError;
use std::error::Error;

pub(super) fn verify(
    raw: &RawInvocationOutcomeV1,
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
    let commit = operation.dispatch_commit().ok_or("committed fixture")?;
    let expected = json!({
        "schema": "chio.raw-invocation-outcome.v1",
        "operation_id": operation.binding().operation_id(),
        "request_id": "original-dispatch",
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
        "pre_invocation_guard_output": {"evidence": [], "witness": null},
        "request_canonical_json": String::from_utf8(request_bytes)?,
        "security_invocation_context": {
            "version": "v1",
            "context": {
                "tenantId":"tenant", "sessionId":"session",
                "principalId": request.agent_id, "isolationEpochId":"epoch",
                "lineageRootId":"capability-1", "contextGeneration":1,
                "flowStateGeneration":null,
            },
        },
        "federation_context_json": null,
        "security_release_required": true,
        "receipt_signing_identity": {
            "public_key": request.capability.issuer,
            "crypto_floor": "allow_classical",
        },
        "caller_delivery_evidence": null,
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

    let mut null_binding = expected.clone();
    null_binding["original_security_dispatch_binding"] = Value::Null;
    assert_eq!(
        RawInvocationOutcomeV1::from_canonical_bytes(&canonical_json_bytes(&null_binding)?),
        Err(ToolOutcomeError::Binding(
            "raw.original_security_dispatch_binding"
        ))
    );
    let mut release_not_required = expected.clone();
    release_not_required["security_release_required"] = json!(false);
    assert_eq!(
        RawInvocationOutcomeV1::from_canonical_bytes(&canonical_json_bytes(&release_not_required)?),
        Err(ToolOutcomeError::Binding(
            "raw.original_security_dispatch_binding"
        ))
    );
    let mut null_context = expected.clone();
    null_context["security_invocation_context"] = Value::Null;
    assert_eq!(
        RawInvocationOutcomeV1::from_canonical_bytes(&canonical_json_bytes(&null_context)?),
        Err(ToolOutcomeError::Binding(
            "raw.security_release_requirement"
        ))
    );
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
    assert_eq!(
        RawInvocationOutcomeV1::from_canonical_bytes(&canonical_json_bytes(&wrong_binding_schema)?),
        Err(ToolOutcomeError::Binding(
            "raw.original_security_dispatch_binding"
        ))
    );
    Ok(())
}
