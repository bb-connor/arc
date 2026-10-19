use super::*;
use chio_core::canonical::UntrustedJsonError;
use std::error::Error;

#[test]
fn raw_v1_requires_complete_envelope_fields() -> Result<(), Box<dyn Error>> {
    let operation = committed_operation("required-raw-envelope");
    let raw = raw_for(&operation, json!({"retained": true}));
    let original = serde_json::to_value(raw.to_persisted())?;
    for field in [
        "reported_cost",
        "receipt_metadata_snapshot",
        "request_canonical_json",
        "receipt_signing_identity",
        "security_invocation_context",
        "security_release_required",
        "federation_context_json",
        "caller_delivery_evidence",
        "original_security_dispatch_binding",
    ] {
        let mut omitted = original.clone();
        omitted.as_object_mut().ok_or("raw envelope")?.remove(field);
        omitted["schema"] = json!("chio.raw-invocation-outcome.v1");
        let result = RawInvocationOutcomeV1::from_canonical_bytes(&canonical_json_bytes(&omitted)?);
        let Err(ToolOutcomeError::UntrustedInput(error)) = result else {
            return Err(
                format!("missing {field} did not refuse with signed JSON shape error").into(),
            );
        };
        assert_eq!(
            error.code(),
            "urn:chio:error:attest:signed-json-invalid-shape"
        );
        let Some(UntrustedJsonError::Decode(source)) = error
            .source()
            .and_then(|source| source.downcast_ref::<UntrustedJsonError>())
        else {
            return Err("missing field lost its Serde data cause".into());
        };
        assert_eq!(source.classify(), serde_json::error::Category::Data);
        assert!(source
            .to_string()
            .starts_with(&format!("missing field `{field}`")));
    }
    Ok(())
}

#[test]
fn raw_envelope_rejects_other_schema_ids() {
    let operation = committed_operation("single-raw-schema");
    let raw = raw_for(&operation, json!({"retained": true}));
    for schema in [
        "chio.raw-invocation-outcome-with-request.v1",
        "chio.raw-invocation-outcome-with-security-context.v1",
        "chio.raw-invocation-outcome-with-federation-context.v1",
        "chio.raw-invocation-outcome-with-security-release.v1",
        "chio.raw-invocation-outcome-with-signing-identity.v1",
        "chio.raw-invocation-outcome-with-caller-delivery.v1",
        "chio.raw-invocation-outcome-with-original-security-dispatch.v1",
    ] {
        let mut invalid = raw.to_persisted();
        invalid.schema = schema.to_owned();
        assert_eq!(
            RawInvocationOutcomeV1::from_persisted(invalid),
            Err(ToolOutcomeError::Invalid("raw.schema")),
            "{schema}"
        );
    }
}

#[test]
fn raw_v1_rejects_unknown_fields() -> Result<(), Box<dyn Error>> {
    let operation = committed_operation("unknown-raw-field");
    let raw = raw_for(&operation, json!({"retained": true}));
    let mut value = serde_json::to_value(raw.to_persisted())?;
    value["unbound_authority"] = json!(true);
    let result = RawInvocationOutcomeV1::from_canonical_bytes(&canonical_json_bytes(&value)?);
    let Err(ToolOutcomeError::UntrustedInput(error)) = result else {
        return Err("unknown field did not refuse with signed JSON shape error".into());
    };
    assert_eq!(
        error.code(),
        "urn:chio:error:attest:signed-json-invalid-shape"
    );
    let Some(UntrustedJsonError::Decode(source)) = error
        .source()
        .and_then(|source| source.downcast_ref::<UntrustedJsonError>())
    else {
        return Err("unknown field lost its Serde data cause".into());
    };
    assert_eq!(source.classify(), serde_json::error::Category::Data);
    assert!(source
        .to_string()
        .starts_with("unknown field `unbound_authority`"));
    Ok(())
}

#[test]
fn raw_v1_serializes_nullable_contexts_explicitly() -> Result<(), Box<dyn Error>> {
    let operation = committed_operation("nullable-raw-contexts");
    let raw = raw_for(&operation, json!({"retained": true}));
    let value = serde_json::to_value(raw.to_persisted())?;
    let fields = value.as_object().ok_or("raw envelope")?;
    for field in [
        "security_invocation_context",
        "federation_context_json",
        "caller_delivery_evidence",
        "original_security_dispatch_binding",
    ] {
        assert_eq!(fields.get(field), Some(&Value::Null), "{field}");
    }
    assert_eq!(fields.get("security_release_required"), Some(&json!(false)));
    assert_eq!(
        RawInvocationOutcomeV1::from_canonical_bytes(raw.canonical_blob()?.bytes())?,
        raw
    );
    Ok(())
}

#[test]
fn raw_v1_rejects_incomplete_v1_shape() -> Result<(), Box<dyn Error>> {
    let operation = committed_operation("incomplete-v1-envelope");
    let raw = raw_for(&operation, json!({"retained": true}));
    let mut value = serde_json::to_value(raw.to_persisted())?;
    let fields = value.as_object_mut().ok_or("raw envelope")?;
    for field in [
        "request_canonical_json",
        "receipt_signing_identity",
        "security_invocation_context",
        "security_release_required",
        "federation_context_json",
        "caller_delivery_evidence",
        "original_security_dispatch_binding",
    ] {
        fields.remove(field);
    }
    let result = RawInvocationOutcomeV1::from_canonical_bytes(&canonical_json_bytes(&value)?);
    let Err(ToolOutcomeError::UntrustedInput(error)) = result else {
        return Err("incomplete v1 shape did not refuse during decoding".into());
    };
    assert_eq!(
        error.code(),
        "urn:chio:error:attest:signed-json-invalid-shape"
    );
    let Some(UntrustedJsonError::Decode(source)) = error
        .source()
        .and_then(|source| source.downcast_ref::<UntrustedJsonError>())
    else {
        return Err("incomplete shape lost its Serde data cause".into());
    };
    assert_eq!(source.to_string(), "missing field `request_canonical_json`");
    Ok(())
}
