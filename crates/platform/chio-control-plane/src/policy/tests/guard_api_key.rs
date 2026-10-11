use super::*;

#[test]
fn external_guard_policy_debug_never_discloses_configured_api_keys() {
    let policy = parse_policy(
        r#"
guards:
  cloud_guardrails:
    azure_content_safety:
      endpoint: "https://example.cognitiveservices.azure.com"
      api_key: "azure-policy-secret-sentinel"
  threat_intel:
    safe_browsing:
      api_key: "safe-browsing-policy-secret-sentinel"
"#,
    )
    .test_expect("secret-bearing policy fixture");

    for guards in [&policy.guards, &policy.guards.clone()] {
        let diagnostic = format!("{guards:#?}");
        assert!(!diagnostic.contains("azure-policy-secret-sentinel"));
        assert!(!diagnostic.contains("safe-browsing-policy-secret-sentinel"));
        assert!(diagnostic.contains("[REDACTED]"));
        assert_eq!(
            build_guard_pipeline(guards)
                .test_expect("redaction retains usable guard credentials")
                .len(),
            2,
        );
    }
}
