//! Threat test for threat ID `pii_phi_exposure`.
//!
//! Coverage strategy: run the default post-invocation `SanitizerHook` against
//! definite PHI/PII markers and assert that the raw identifiers never reach
//! the agent and that receipt evidence names each detector without the raw
//! values.

use chio_guards::{sanitize_json, PostInvocationPipeline, PostInvocationVerdict, SanitizerHook};

#[test]
fn threat_pii_phi_exposure_is_covered() {
    // covers: pii_phi_exposure
    let payload = serde_json::json!({
        "patient": "Jane Doe",
        "mrn": "MRN 123456789",
        "ssn": "123-45-6789"
    });
    let raw_identifiers = ["123-45-6789", "MRN 123456789", "123456789"];

    let mut pipeline = PostInvocationPipeline::new();
    pipeline.add(Box::new(SanitizerHook::new()));

    let benign = serde_json::json!({"message": "operation completed successfully"});
    let clean = pipeline.evaluate_with_evidence("tool", &benign);
    assert!(matches!(clean.verdict, PostInvocationVerdict::Allow));
    assert!(clean.evidence.is_empty());

    let outcome = pipeline.evaluate_with_evidence("tool", &payload);
    match &outcome.verdict {
        PostInvocationVerdict::Redact(redacted) => {
            let rendered = redacted.to_string();
            for raw in raw_identifiers {
                assert!(!rendered.contains(raw), "{raw} leaked: {rendered}");
            }
        }
        other => panic!("PHI payload must redact, got {other:?}"),
    }
    assert_eq!(outcome.evidence.len(), 1);
    let details = outcome.evidence[0].details.as_deref().unwrap_or("");
    assert!(details.contains("pii_mrn:"), "got: {details}");
    assert!(details.contains("pii_ssn:"), "got: {details}");
    for raw in raw_identifiers {
        assert!(!details.contains(raw), "{raw} leaked into evidence");
    }

    let hook = SanitizerHook::new();
    let (_, result) = sanitize_json(hook.sanitizer(), &payload);
    assert!(result.redactions.len() >= 2);
    assert!(result
        .findings
        .iter()
        .any(|finding| finding.id == "pii_mrn"));
    assert!(result
        .findings
        .iter()
        .any(|finding| finding.id == "pii_ssn"));
}
