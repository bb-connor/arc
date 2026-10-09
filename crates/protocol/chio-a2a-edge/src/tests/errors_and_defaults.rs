use crate::config::A2aEdgeConfig;
use crate::edge::ChioA2aEdge;
use crate::error::A2aEdgeError;
use crate::tests::{kernel_for_server, test_manifest, test_server, text_message};
use crate::types::TaskStatus;
use chio_cross_protocol::semantic_hints::BridgeFidelity;
use chio_test_support::prelude::*;
use serde_json::json;

// ---- Error type tests ----

#[test]
fn error_display_tool_not_found() {
    let err = A2aEdgeError::ToolNotFound("missing".into());
    assert!(format!("{err}").contains("missing"));
}

#[test]
fn error_display_invalid_request() {
    let err = A2aEdgeError::InvalidRequest("bad".into());
    assert!(format!("{err}").contains("bad"));
}

#[test]
fn error_display_kernel() {
    let err = A2aEdgeError::Kernel("denied".into());
    assert!(format!("{err}").contains("denied"));
}

// ---- Duplicate skill handling ----

#[test]
fn duplicate_skills_across_manifests_receive_qualified_ids() {
    let m1 = test_manifest();
    let m2 = test_manifest(); // Same tool names
    let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![m1, m2]).test_unwrap();
    assert_eq!(edge.skill_ids().len(), 4);
    assert!(edge.skill("test-srv::echo").is_some());
    assert!(edge.skill("test-srv::echo#2").is_some());
    assert!(edge.skill("test-srv::write").is_some());
    assert!(edge.skill("test-srv::write#2").is_some());
    assert_eq!(
        edge.bridge_fidelity("echo"),
        Some(&BridgeFidelity::Unsupported {
            reason: "skill id collides across manifests; use one of the qualified ids: test-srv::echo, test-srv::echo#2".to_string()
        })
    );
}

#[test]
fn ambiguous_unqualified_skill_id_returns_guidance() {
    let m1 = test_manifest();
    let m2 = test_manifest(); // Same tool names
    let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![m1, m2]).test_unwrap();
    let (kernel, execution) = kernel_for_server(test_server());
    let error = edge
        .handle_send_message("echo", &text_message("hello"), &kernel, &execution)
        .test_expect_err("ambiguous unqualified A2A skill id must fail");

    let A2aEdgeError::InvalidRequest(message) = error else {
        panic!("expected invalid request");
    };
    assert!(message.contains("ambiguous"));
    assert!(message.contains("test-srv::echo"));
    assert!(message.contains("test-srv::echo#2"));
}

// ---- Default config tests ----

#[test]
fn default_config_has_reasonable_values() {
    let config = A2aEdgeConfig::default();
    assert!(!config.agent_name.is_empty());
    assert_eq!(config.protocol_binding, "JSONRPC");
}

// ---- TaskStatus serde ----

#[test]
fn task_status_serializes_correctly() {
    let json = serde_json::to_value(TaskStatus::Completed).test_unwrap();
    assert_eq!(json, "completed");
    let json = serde_json::to_value(TaskStatus::Failed).test_unwrap();
    assert_eq!(json, "failed");
}

#[test]
fn bridge_fidelity_serializes_correctly() {
    let json = serde_json::to_value(BridgeFidelity::Lossless).test_unwrap();
    assert_eq!(json, json!({"kind": "lossless"}));
    let json = serde_json::to_value(BridgeFidelity::Adapted {
        caveats: vec!["stream collated".to_string()],
    })
    .test_unwrap();
    assert_eq!(
        json,
        json!({"kind": "adapted", "caveats": ["stream collated"]})
    );
    let json = serde_json::to_value(BridgeFidelity::Unsupported {
        reason: "needs cancellation".to_string(),
    })
    .test_unwrap();
    assert_eq!(
        json,
        json!({"kind": "unsupported", "reason": "needs cancellation"})
    );
}
