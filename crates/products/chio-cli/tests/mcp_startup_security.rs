#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::process::Command;

use chio_core::Keypair;
use chio_manifest::{
    sign_manifest, ToolAnnotations, ToolDefinition, ToolFlowDeclaration, ToolManifest,
};

#[test]
fn mcp_serve_rejects_flow_before_store_acquisition_and_launch_policy_loading() {
    // The absent launch policy is a downstream sentinel, not an expected
    // authorization failure for the constrained profile. Ordinary end-to-end
    // launches are exercised separately by the mcp_serve integration suite.
    for flow in [None, Some(ToolFlowDeclaration::public_egress())] {
        let requires_flow = flow.is_some();
        let directory = tempfile::tempdir().expect("private startup directory");
        let policy_path = directory.path().join("policy.yaml");
        std::fs::write(&policy_path, "capabilities:\n  default:\n    tools: []\n")
            .expect("write valid policy");
        let signer = Keypair::from_seed(&[71; 32]);
        let manifest = ToolManifest {
            schema: chio_manifest::TOOL_MANIFEST_SCHEMA.to_string(),
            server_id: "startup-fixture".to_string(),
            name: "Startup fixture".to_string(),
            description: None,
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "send".to_string(),
                description: "Counted startup fixture".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                annotations: ToolAnnotations::default(),
                latency_hint: None,
                flow,
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: signer.public_key().to_hex(),
        };
        let manifest_path = directory.path().join("signed-manifest.json");
        std::fs::write(
            &manifest_path,
            serde_json::to_vec(&sign_manifest(&manifest, &signer).expect("sign manifest"))
                .expect("serialize signed manifest"),
        )
        .expect("write signed manifest");
        let admission_path = directory.path().join("admission.sqlite3");
        let receipt_path = directory.path().join("receipts.sqlite3");
        let output = Command::new(env!("CARGO_BIN_EXE_chio"))
            .current_dir(directory.path())
            .env_remove("CHIO_CONTROL_TOKEN")
            .arg("--session-db")
            .arg(&admission_path)
            .arg("--receipt-db")
            .arg(&receipt_path)
            .args(["mcp", "serve", "--policy"])
            .arg(&policy_path)
            .args(["--server-id", "startup-fixture", "--signed-manifest"])
            .arg(&manifest_path)
            .args(["--manifest-public-key", &signer.public_key().to_hex()])
            .arg("--cage-policy")
            .arg(directory.path().join("absent-cage-policy.json"))
            .args(["--cage-policy-signer", &signer.public_key().to_hex(), "--"])
            .arg(env!("CARGO_BIN_EXE_chio"))
            .output()
            .expect("invoke public MCP serve startup");
        assert!(!output.status.success());
        let error = String::from_utf8_lossy(&output.stderr);
        if requires_flow {
            assert!(
                error.contains(
                    "MCP serve requires an active-defense host for flow-required manifests"
                ),
                "{error}"
            );
            assert!(!admission_path.exists());
            assert!(!receipt_path.exists());
        } else {
            assert!(
                error.contains("failed to read cage launch policy"),
                "{error}"
            );
            assert!(admission_path.exists());
            assert!(receipt_path.exists());
        }
    }
}
