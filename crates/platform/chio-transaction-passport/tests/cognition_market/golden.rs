use super::*;

#[test]
fn persisted_cognition_market_golden_verifies() -> TestResult {
    let root = workspace_root().join(GOLDEN_RELATIVE);
    let mut bundle = build_bundle()?;
    let persisted_profile = std::fs::read(root.join("deployment/verifier-profile.json"))?;
    assert_eq!(
        persisted_profile,
        canonical_json_bytes(&bundle.trust.trusted_verifier_profile)?,
        "deployment profile fixture must match the profile pinned by the golden report"
    );
    bundle.passport =
        serde_json::from_slice(&std::fs::read(root.join("transaction-passport.json"))?)?;
    bundle.evidence_graph_bytes = std::fs::read(root.join("evidence-graph.json"))?;
    bundle.evidence_graph = serde_json::from_slice(&bundle.evidence_graph_bytes)?;
    bundle.verifier_policy_bytes = std::fs::read(root.join("verifier-policy.json"))?;
    bundle.artifacts = BTreeMap::from([
        (
            "claim-set.json".to_string(),
            std::fs::read(root.join("claim-set.json"))?,
        ),
        (
            "verifier-policy.json".to_string(),
            bundle.verifier_policy_bytes.clone(),
        ),
        (
            "report.json".to_string(),
            std::fs::read(root.join("report.json"))?,
        ),
        (
            "purchase-record.json".to_string(),
            std::fs::read(root.join("purchase-record.json"))?,
        ),
        (
            "finding.json".to_string(),
            std::fs::read(root.join("finding.json"))?,
        ),
        (
            "attachments/replay-recipe-input.json".to_string(),
            std::fs::read(root.join("attachments/replay-recipe-input.json"))?,
        ),
        (
            "attachments/status-proof-input.json".to_string(),
            std::fs::read(root.join("attachments/status-proof-input.json"))?,
        ),
    ]);
    verify(&bundle)
}
