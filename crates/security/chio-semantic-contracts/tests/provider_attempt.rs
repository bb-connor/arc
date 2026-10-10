//! Nominal provider attempts retain the established protected wire encoding.
use chio_core_types::canonical_json_bytes;
use chio_security_types::{recovery::*, semantic::*};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn provider_attempt_preserves_the_established_utf8_wire_codec() -> TestResult {
    for value in [
        "native-attempt",
        "provider attempt/opaque?=1",
        "étape:東京/🙂",
        "embedded\u{0}control\ntext",
    ] {
        let old = ProtectedText::<128>::new(value)?;
        let attempt = SemanticProviderAttemptId::new(value)?;
        assert_eq!(attempt.as_str(), old.as_str());
        let old_wire = canonical_json_bytes(&old)?;
        assert_eq!(canonical_json_bytes(&attempt)?, old_wire);
        let decoded: SemanticProviderAttemptId = serde_json::from_slice(&old_wire)?;
        assert_eq!(decoded.as_str(), value);
        assert!(!format!("{attempt:?}").contains(value));
    }
    Ok(())
}

#[test]
fn provider_attempt_byte_boundaries_and_shape_refusals_match_the_established_codec() -> TestResult {
    for value in ["x".repeat(128), "🙂".repeat(32)] {
        assert_eq!(value.len(), 128);
        let old = ProtectedText::<128>::new(&value)?;
        let attempt = SemanticProviderAttemptId::new(&value)?;
        assert_eq!(canonical_json_bytes(&old)?, canonical_json_bytes(&attempt)?);
        let wire = canonical_json_bytes(&value)?;
        let decoded: SemanticProviderAttemptId = serde_json::from_slice(&wire)?;
        assert_eq!(decoded.as_str(), value);
    }
    for value in [String::new(), "x".repeat(129), "🙂".repeat(33)] {
        assert!(ProtectedText::<128>::new(&value).is_err());
        assert!(SemanticProviderAttemptId::new(&value).is_err());
        let wire = canonical_json_bytes(&value)?;
        assert!(serde_json::from_slice::<ProtectedText<128>>(&wire).is_err());
        assert!(serde_json::from_slice::<SemanticProviderAttemptId>(&wire).is_err());
    }
    for wire in [b"null".as_slice(), b"0", b"true", b"{}", b"[]"] {
        assert!(serde_json::from_slice::<ProtectedText<128>>(wire).is_err());
        assert!(serde_json::from_slice::<SemanticProviderAttemptId>(wire).is_err());
    }
    Ok(())
}

#[test]
fn nominal_provider_attempt_preserves_full_request_and_response_canonical_bytes() -> TestResult {
    let value = "provider attempt/opaque?=étape:東京/🙂\u{0}\n";
    let payload = SemanticPayloadV1 {
        fields: NonEmptyBoundedList::new(vec![SemanticFieldV1 {
            field: SemanticFieldId::new("title")?,
            value: SemanticValueV1::Text {
                value: ProtectedText::new("stable payload")?,
            },
        }])?,
    };
    let request = SemanticProviderRequestV1 {
        domain_version: VersionV1,
        kind: SemanticOperationKindV1::IssueWrite,
        provider: ProviderId::new("provider")?,
        account: ProviderAccountId::new("account")?,
        resource: ProviderResourceId::new("resource")?,
        provider_version: ProtectedText::new("resource version")?,
        operation: OperationId::new("operation")?,
        attempt: SemanticProviderAttemptId::new(value)?,
        payload: payload.clone(),
    };
    let response = SemanticProviderResponseV1 {
        provider: request.provider.clone(),
        account: request.account.clone(),
        resource: request.resource.clone(),
        checked_provider_version: request.provider_version.clone(),
        operation: request.operation.clone(),
        attempt: request.attempt.clone(),
        payload,
    };
    let old_attempt = ProtectedText::<128>::new(value)?;
    let old_request = serde_json::json!({
        "domain_version": 1,
        "kind": "issue_write",
        "provider": "provider",
        "account": "account",
        "resource": "resource",
        "provider_version": "resource version",
        "operation": "operation",
        "attempt": &old_attempt,
        "payload": {"fields": [{"field": "title", "value": {"kind": "text", "value": "stable payload"}}]}
    });
    let old_response = serde_json::json!({
        "provider": "provider",
        "account": "account",
        "resource": "resource",
        "checked_provider_version": "resource version",
        "operation": "operation",
        "attempt": &old_attempt,
        "payload": {"fields": [{"field": "title", "value": {"kind": "text", "value": "stable payload"}}]}
    });
    let request_wire = canonical_json_bytes(&old_request)?;
    let response_wire = canonical_json_bytes(&old_response)?;
    assert_eq!(canonical_json_bytes(&request)?, request_wire);
    assert_eq!(canonical_json_bytes(&response)?, response_wire);
    let decoded_request: SemanticProviderRequestV1 = serde_json::from_slice(&request_wire)?;
    let decoded_response: SemanticProviderResponseV1 = serde_json::from_slice(&response_wire)?;
    assert_eq!(decoded_request, request);
    assert_eq!(decoded_response, response);
    Ok(())
}
