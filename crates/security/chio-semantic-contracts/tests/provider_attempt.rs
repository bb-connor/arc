use chio_core_types::{canonical_json_bytes, recovery::decode_contract};
use chio_security_types::recovery::{
    ContractError, NonEmptyBoundedList, OperationId, ProtectedText, ProviderAccountId, ProviderId,
    ProviderResourceId, SemanticFieldId, VersionV1,
};
use chio_security_types::semantic::{
    SemanticFieldV1, SemanticOperationKindV1, SemanticPayloadV1, SemanticProviderAttemptId,
    SemanticProviderRequestV1, SemanticProviderResponseV1, SemanticValueV1,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn provider_attempt_uses_a_redacted_utf8_string_encoding() -> TestResult {
    for value in [
        "native-attempt",
        "provider attempt/opaque?=1",
        "étape:東京/🙂",
        "embedded\u{0}control\ntext",
    ] {
        let attempt = SemanticProviderAttemptId::new(value)?;
        let wire = canonical_json_bytes(&value)?;
        assert_eq!(attempt.as_str(), value);
        assert_eq!(canonical_json_bytes(&attempt)?, wire);
        assert_eq!(
            decode_contract::<SemanticProviderAttemptId>(&wire)?.as_str(),
            value
        );
        assert!(!format!("{attempt:?}").contains(value));
    }
    Ok(())
}

#[test]
fn provider_attempt_requires_one_to_128_utf8_bytes_and_refuses_other_shapes() -> TestResult {
    for value in ["x".repeat(128), "🙂".repeat(32)] {
        assert_eq!(value.len(), 128);
        let attempt = SemanticProviderAttemptId::new(&value)?;
        let wire = canonical_json_bytes(&value)?;
        assert_eq!(canonical_json_bytes(&attempt)?, wire);
        assert_eq!(
            decode_contract::<SemanticProviderAttemptId>(&wire)?.as_str(),
            value
        );
    }
    for value in [String::new(), "x".repeat(129), "🙂".repeat(33)] {
        assert_eq!(
            SemanticProviderAttemptId::new(&value).err(),
            Some(ContractError::LimitExceeded)
        );
        assert_eq!(
            decode_contract::<SemanticProviderAttemptId>(&canonical_json_bytes(&value)?).err(),
            Some(ContractError::Malformed)
        );
    }
    for wire in [b"null".as_slice(), b"0", b"true", b"{}", b"[]"] {
        assert_eq!(
            decode_contract::<SemanticProviderAttemptId>(wire).err(),
            Some(ContractError::Malformed)
        );
    }
    Ok(())
}

#[test]
fn provider_request_and_response_bind_the_exact_attempt_bytes() -> TestResult {
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
    let expected_request = serde_json::json!({
        "domain_version": 1, "kind": "issue_write", "provider": "provider",
        "account": "account", "resource": "resource", "provider_version": "resource version",
        "operation": "operation", "attempt": value,
        "payload": {"fields": [{"field": "title", "value": {"kind": "text", "value": "stable payload"}}]}
    });
    let expected_response = serde_json::json!({
        "provider": "provider", "account": "account", "resource": "resource",
        "checked_provider_version": "resource version", "operation": "operation", "attempt": value,
        "payload": {"fields": [{"field": "title", "value": {"kind": "text", "value": "stable payload"}}]}
    });
    let request_wire = canonical_json_bytes(&expected_request)?;
    let response_wire = canonical_json_bytes(&expected_response)?;
    assert_eq!(canonical_json_bytes(&request)?, request_wire);
    assert_eq!(canonical_json_bytes(&response)?, response_wire);
    assert_eq!(
        decode_contract::<SemanticProviderRequestV1>(&request_wire)?,
        request
    );
    assert_eq!(
        decode_contract::<SemanticProviderResponseV1>(&response_wire)?,
        response
    );
    Ok(())
}
