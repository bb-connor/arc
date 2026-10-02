use super::support::write_minimal_evidence_graph;
use chio_test_support::prelude::*;
use std::path::Path;

pub(super) fn add_unknown_role_artifact(bundle_dir: &Path) {
    let unsupported_artifact = serde_json::json!({
        "schema": "chio.transaction.future-evidence.v1",
        "id": "future-evidence"
    });
    let unsupported_artifact_bytes =
        serde_json::to_vec(&unsupported_artifact).test_expect("serialize unsupported artifact");
    std::fs::write(
        bundle_dir.join("future-evidence.json"),
        &unsupported_artifact_bytes,
    )
    .test_expect("write unsupported artifact");

    let evidence_graph_path = bundle_dir.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&evidence_graph_path).test_expect("read evidence graph"),
    )
    .test_expect("parse evidence graph");
    evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("evidence graph nodes")
        .push(serde_json::json!({
            "id": "future-evidence",
            "schema": "chio.transaction.future-evidence.v1",
            "path": "future-evidence.json",
            "sha256": chio_core::sha256_hex(&unsupported_artifact_bytes),
            "role": "future-unsupported-role"
        }));
    write_minimal_evidence_graph(bundle_dir, evidence_graph);
}
