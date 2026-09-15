use super::*;
use crate::admission_operation::{
    immutable_tool_request_hash, AdmissionSecurityBindingV1, RetainedToolAdmissionRequestV1,
};
use chio_core::canonical::canonical_json_bytes;

#[test]
fn native_retained_codec_is_strict_and_hash_domain_is_versioned() -> TestResult {
    let (_, request, _, _) = durable_admission_fixture("native-codec");
    let context = context(&request, 1)?;
    let selected = binding("native-store", "source", b"initialization")?;
    let security = AdmissionSecurityBindingV1::from_trusted_selection(
        Some(&context),
        true,
        true,
        Some(selected.clone()),
    )?;
    let matching = matching(&request)?;
    let retained = RetainedToolAdmissionRequestV1::from_admission(
        &request,
        &matching,
        &[],
        security.as_ref(),
    )?;
    retained.validate_native_security_context(&context)?;
    retained.validate_native_security_authority(&selected)?;
    let original: serde_json::Value = serde_json::from_slice(retained.canonical_bytes())?;
    assert_eq!(
        original["schema"],
        "chio.retained-tool-admission-request.v3"
    );
    let unbound = immutable_tool_request_hash(&request, &matching, &[], None)?;
    let independent = serde_json::json!({"schema": "chio.tool-admission-request.v3", "unbound_request_hash": unbound, "security_binding": original["security_binding"]});
    assert_eq!(
        immutable_tool_request_hash(&request, &matching, &[], security.as_ref())?.as_str(),
        sha256_hex(&canonical_json_bytes(&independent)?)
    );
    for variant in 0..14 {
        let mut candidate = original.clone();
        match variant {
            0 => candidate["schema"] = "chio.retained-tool-admission-request.v2".into(),
            1 => {
                candidate["security_binding"]["schema"] =
                    "chio.admission-security-binding.v1".into()
            }
            2 => candidate["security_binding"]["native_authority"] = serde_json::Value::Null,
            3 => {
                candidate["security_binding"]
                    .as_object_mut()
                    .ok_or("object")?
                    .remove("native_authority");
            }
            4 => {
                candidate["security_binding"]["native_authority"]["schema"] =
                    "unknown-version".into()
            }
            5 => candidate["security_binding"]["native_authority"]["store_uuid"] = "".into(),
            6 => {
                candidate["security_binding"]["native_authority"]["security_authority_id"] =
                    " padded ".into()
            }
            7 => {
                candidate["security_binding"]["native_authority"]["initialization_digest"] =
                    "not-a-digest".into()
            }
            8 => candidate["security_binding"]["native_authority"]["owner_epoch"] = 9.into(),
            9 => candidate["security_binding"]["pre_dispatch_required"] = false.into(),
            10 => candidate["security_binding"]["pre_dispatch_hook_installed"] = false.into(),
            11 => candidate["security_binding"]["context"] = serde_json::Value::Null,
            12 => {
                candidate["security_binding"]["native_authority"]["store_uuid"] =
                    "x".repeat(513).into()
            }
            _ => {
                candidate["security_binding"]["native_authority"]
                    .as_object_mut()
                    .ok_or("object")?
                    .remove("initialization_digest");
            }
        }
        assert!(
            RetainedToolAdmissionRequestV1::from_canonical_bytes(&canonical_json_bytes(
                &candidate
            )?)
            .is_err(),
            "variant {variant}"
        );
    }
    Ok(())
}

#[test]
fn context_only_v2_keeps_its_exact_historical_bytes_and_hash() -> TestResult {
    let (_, request, _, _) = durable_admission_fixture("native-v2-compatibility");
    let context = context(&request, 1)?;
    let security = AdmissionSecurityBindingV1::from_trusted_context(Some(&context), true, true)?;
    let matching = matching(&request)?;
    let retained = RetainedToolAdmissionRequestV1::from_admission(
        &request,
        &matching,
        &[],
        security.as_ref(),
    )?;
    let mut independent: serde_json::Value = serde_json::from_slice(retained.canonical_bytes())?;
    let context = context.as_v1();
    independent["security_binding"] = serde_json::json!({
        "schema": "chio.admission-security-binding.v1",
        "context": { "tenant_id": context.tenant_id(), "session_id": context.session_id(),
            "principal_id": context.principal_id(), "isolation_epoch_id": context.isolation_epoch_id(),
            "lineage_root_id": context.lineage_root_id(), "context_generation": context.context_generation() },
        "pre_dispatch_required": true, "pre_dispatch_hook_installed": true
    });
    independent["schema"] = "chio.retained-tool-admission-request.v2".into();
    assert_eq!(
        retained.canonical_bytes(),
        canonical_json_bytes(&independent)?
    );
    let hash = serde_json::json!({"schema": "chio.tool-admission-request.v2",
        "unbound_request_hash": immutable_tool_request_hash(&request, &matching, &[], None)?,
        "security_binding": independent["security_binding"]});
    assert_eq!(
        immutable_tool_request_hash(&request, &matching, &[], security.as_ref())?.as_str(),
        sha256_hex(&canonical_json_bytes(&hash)?)
    );
    assert!(retained.native_security_authority_binding().is_none());
    assert!(retained
        .validate_native_security_authority(&binding("native-store", "source", b"initialization")?)
        .is_err());
    Ok(())
}
