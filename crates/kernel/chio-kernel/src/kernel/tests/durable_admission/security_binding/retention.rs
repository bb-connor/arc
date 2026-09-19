//! Exact typed storage compatibility and stable security binding semantics.

use super::*;
use crate::admission_operation::{AdmissionSecurityBindingV1, RetainedToolAdmissionRequestV1};
use chio_core::canonical::canonical_json_bytes;

#[test]
fn retained_v2_binds_security_but_not_mutable_flow_generation() -> TestResult {
    let (_, request, _, _) = durable_admission_fixture("retained-security");
    let original = context(&request, 1)?;
    let binding = AdmissionSecurityBindingV1::from_trusted_context(Some(&original), false, false)?;
    let matching = matching(&request)?;
    let retained =
        RetainedToolAdmissionRequestV1::from_admission(&request, &matching, &[], binding.as_ref())?;
    let decoded = RetainedToolAdmissionRequestV1::from_canonical_bytes(retained.canonical_bytes())?;
    decoded.validate_security_binding(binding.as_ref())?;
    decoded.validate_request_material(&request)?;
    let encoded: serde_json::Value = serde_json::from_slice(retained.canonical_bytes())?;
    assert_eq!(encoded["schema"], "chio.retained-tool-admission-request.v2");
    assert!(encoded["security_binding"]["context"]
        .get("flow_state_generation")
        .is_none());
    let advanced =
        SecurityInvocationContext::v1(original.as_v1().clone().with_flow_state_generation(2));
    let live = AdmissionSecurityBindingV1::from_trusted_context(Some(&advanced), false, false)?;
    assert_eq!(live, binding);
    assert!(decoded.validate_security_binding(None).is_err());
    let changed = AdmissionSecurityBindingV1::from_trusted_context(
        Some(&context(&request, 2)?),
        false,
        false,
    )?;
    assert!(decoded.validate_security_binding(changed.as_ref()).is_err());
    Ok(())
}

#[test]
fn retained_security_decoder_rejects_schema_downgrade_unknown_fields_and_invalid_generations(
) -> TestResult {
    let (_, request, _, _) = durable_admission_fixture("security-codec");
    let binding =
        AdmissionSecurityBindingV1::from_trusted_context(Some(&context(&request, 1)?), true, true)?;
    let retained = RetainedToolAdmissionRequestV1::from_admission(
        &request,
        &matching(&request)?,
        &[],
        binding.as_ref(),
    )?;
    let original: serde_json::Value = serde_json::from_slice(retained.canonical_bytes())?;
    for variant in 0..8 {
        let mut candidate = original.clone();
        match variant {
            0 => candidate["schema"] = serde_json::json!("chio.retained-tool-admission-request.v1"),
            1 => {
                candidate
                    .as_object_mut()
                    .ok_or("object")?
                    .remove("security_binding");
            }
            2 => candidate["security_binding"]["schema"] = serde_json::json!("unknown-version"),
            3 => {
                candidate["security_binding"]["context"]["context_generation"] =
                    serde_json::json!(0)
            }
            4 => {
                candidate["security_binding"]["context"]["flow_state_generation"] =
                    serde_json::json!(2)
            }
            5 => candidate["security_binding"]["context"]["tenant_id"] = serde_json::json!(""),
            6 => candidate["security_binding"] = serde_json::Value::Null,
            _ => candidate["security_binding"]["unrecognized_authority"] = serde_json::json!(true),
        }
        assert!(
            RetainedToolAdmissionRequestV1::from_canonical_bytes(&canonical_json_bytes(
                &candidate
            )?)
            .is_err(),
            "variant {variant}"
        );
    }
    assert!(AdmissionSecurityBindingV1::from_trusted_context(
        Some(&context(&request, u64::MAX)?),
        false,
        false
    )
    .is_err());
    Ok(())
}

#[test]
fn unbound_retained_v1_keeps_its_exact_hash_and_bytes() -> TestResult {
    let (_, request, _, _) = durable_admission_fixture("legacy-security-compatibility");
    let matching = matching(&request)?;
    let retained = RetainedToolAdmissionRequestV1::from_admission(&request, &matching, &[], None)?;
    let encoded: serde_json::Value = serde_json::from_slice(retained.canonical_bytes())?;
    assert_eq!(encoded["schema"], "chio.retained-tool-admission-request.v1");
    assert!(encoded.get("security_binding").is_none());
    let independent_v1 = serde_json::json!({
        "schema": "chio.tool-admission-request.v1",
        "server_id": request.server_id, "tool_name": request.tool_name,
        "agent_id": request.agent_id, "arguments": request.arguments,
        "governed_intent": request.governed_intent, "model_metadata": request.model_metadata,
        "federated_origin_kernel_id": request.federated_origin_kernel_id,
        "matching_grants": [{"index": 0, "grant": &request.capability.scope.grants[0]}],
        "post_return_steps": [],
    });
    let hash =
        crate::admission_operation::immutable_tool_request_hash(&request, &matching, &[], None)?;
    assert_eq!(
        hash.as_str(),
        sha256_hex(&canonical_json_bytes(&independent_v1)?)
    );
    Ok(())
}
