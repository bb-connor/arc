use chio_test_support::prelude::*;

use chio_transaction_passport::{
    validate_transaction_evidence_graph, validate_verifier_policy_artifact,
    TransactionPassportError,
};

fn graph(extra: &str) -> String {
    format!(
        r#"{{"schema":"chio.transaction.evidence-graph.v1","id":"graph","issued_at":"2026-06-10T00:00:00Z","nodes":[{{"id":"{digest}","sha256":"{digest}"}}],"edges":[]{extra}}}"#,
        digest = "a".repeat(64),
    )
}

#[test]
fn original_graph_duplicates_cannot_disappear_before_validation() {
    assert_eq!(
        validate_transaction_evidence_graph(graph("").as_bytes()),
        Ok(())
    );
    let original = graph(r#", "extension":{"private-marker":1,"private-marker":2}"#);
    let error = validate_transaction_evidence_graph(original.as_bytes())
        .test_expect_err("original duplicates must reject");
    assert!(matches!(&error, TransactionPassportError::Input(_)));
    assert!(std::error::Error::source(&error).is_some());
    assert!(!format!("{error:?} {error}").contains("private-marker"));
}

#[test]
fn original_graph_keeps_native_integers_but_rejects_lossy_tokens() {
    assert_eq!(
        validate_transaction_evidence_graph(
            graph(r#", "counter":18446744073709551615"#).as_bytes()
        ),
        Ok(())
    );
    assert!(matches!(
        validate_transaction_evidence_graph(
            graph(r#", "counter":18446744073709551616"#).as_bytes()
        ),
        Err(TransactionPassportError::Input(_))
    ));
}

#[test]
fn policy_size_is_bounded_before_typed_projection() {
    let policy = br#"{"schema":"chio.transaction.verifier-policy.v1","id":"policy","issued_at":"2026-06-10T00:00:00Z","required_claims":["claim.transaction.passport_root_verified"],"omitted_claims":[]}"#;
    assert_eq!(validate_verifier_policy_artifact(policy), Ok(()));
    let mut padded = vec![b' '; 16 * 1024 * 1024];
    padded.extend_from_slice(policy);
    assert!(matches!(
        validate_verifier_policy_artifact(&padded),
        Err(TransactionPassportError::Input(_))
    ));
}

#[test]
fn original_deep_graph_is_validated_without_recursive_stack_growth() {
    let count = 4096;
    let nodes: Vec<_> = (0..count)
        .map(|n| {
            serde_json::json!({
                "id": format!("{n:064x}"), "sha256": format!("{n:064x}"),
            })
        })
        .collect();
    let edges: Vec<_> = (1..count)
        .map(|n| {
            serde_json::json!({
                "from": format!("{:064x}", n-1), "to": format!("{n:064x}"),
            })
        })
        .collect();
    let mut value: serde_json::Value =
        serde_json::from_str(&graph("")).test_expect("fixture parses");
    value["nodes"] = nodes.into();
    value["edges"] = edges.into();
    let bytes = serde_json::to_vec(&value).test_expect("graph serializes");
    assert_eq!(validate_transaction_evidence_graph(&bytes), Ok(()));
    value["nodes"]
        .as_array_mut()
        .test_expect("nodes is array")
        .push(serde_json::json!({
            "id": "over-limit", "sha256": "a".repeat(64),
        }));
    let bytes = serde_json::to_vec(&value).test_expect("graph serializes");
    assert_eq!(
        validate_transaction_evidence_graph(&bytes),
        Err(TransactionPassportError::EvidenceLimit)
    );
}

#[test]
fn transparency_inspection_budgets_all_artifacts_before_hashing() {
    use chio_transaction_passport::transaction_evidence_graph_transparency_state_with_anchors;
    let mut artifacts = std::collections::BTreeMap::new();
    let original = graph("");
    transaction_evidence_graph_transparency_state_with_anchors(
        original.as_bytes(),
        &artifacts,
        chio_transaction_passport::TransactionTrustAnchors {
            passport_root_signers: &[],
            checkpoint_signers: &[],
        },
    )
    .test_expect("positive inspection control");
    artifacts.insert("oversized".into(), vec![0; 16 * 1024 * 1024 + 1]);
    assert_eq!(
        transaction_evidence_graph_transparency_state_with_anchors(
            original.as_bytes(),
            &artifacts,
            chio_transaction_passport::TransactionTrustAnchors {
                passport_root_signers: &[],
                checkpoint_signers: &[]
            }
        ),
        Err(TransactionPassportError::EvidenceLimit)
    );
}
