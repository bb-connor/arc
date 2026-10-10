use super::*;

#[test]
fn adapter_preserves_identity_locations_and_payload_binding() {
    let classifier = RegexStructuredClassifier::new(
        "classifier.local",
        "1",
        vec![RegexClassificationRule::new("pii.email", "@", 9_000)
            .unwrap_or_else(|error| panic!("rule: {error}"))],
    )
    .unwrap_or_else(|error| panic!("classifier: {error}"));
    let adapter = StructuredClassificationAdapter::new(Arc::new(classifier));
    let request = request(b"a@b");
    let result = adapter
        .classify(&request)
        .unwrap_or_else(|error| panic!("classification: {error}"));
    assert_eq!(result.request_id, request.request_id);
    assert_eq!(result.payload_digest, request.payload_digest);
    assert_eq!(result.classifier_id.as_str(), "classifier.local");
    assert_eq!(result.classifier_version.as_str(), "1");
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings.as_slice()[0].category.as_str(), "pii.email");
    assert_eq!(
        result.findings.as_slice()[0].byte_range,
        Some(chio_security_types::ports::ByteRange { start: 1, end: 2 })
    );
}
