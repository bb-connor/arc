use super::super::util::runtime_hash_for_hushspec;
use super::*;
use chio_core::capability::threshold_approval::{
    ThresholdApprovalRequirement, ThresholdApproverIdentity,
};
use chio_core::{sha256_hex, Keypair};

// The profile token is supplied by the guard crate, whose independent
// fixtures own its bytes. Every policy preimage field is literal here.
const KERNEL: &str = r#"{"allow_elicitation":false,"allow_ephemeral_receipt_log":false,"allow_ephemeral_revocation_store":false,"allow_sampling":false,"allow_sampling_tool_use":false,"allow_unsafe_durable_admission_off":false,"checkpoint_batch_size":8,"delegation_depth_limit":2,"durable_admission_mode":"side_effecting","max_capability_ttl":63,"require_swarm_admission":true,"require_web3_evidence":false}"#;
const GUARDS: &str = r#"{"cloud_guardrails":null,"content_review":null,"egress_allowlist":null,"forbidden_path":null,"internal_network":null,"patch_integrity":null,"path_allowlist":null,"query_result":null,"secret_patterns":null,"shell_command":null,"sql_query":null,"threat_intel":null,"tool_access":null,"vector_db":null,"warehouse_cost":null}"#;

fn policy() -> ChioPolicy {
    parse_policy("kernel:\n  max_capability_ttl: 63\n  delegation_depth_limit: 2\n  checkpoint_batch_size: 8\n  require_swarm_admission: true\n").test_unwrap()
}

#[test]
fn runtime_policy_v3_chio_yaml_hash_pins_complete_canonical_preimage() {
    let profile = chio_guards::default_runtime_guard_profile_identity().test_unwrap();
    let bytes = format!("{{\"default_capabilities\":[],\"default_guard_profile\":\"{profile}\",\"format\":\"chio_yaml\",\"guards\":{GUARDS},\"kernel\":{KERNEL},\"schema\":\"chio.runtime-policy.v3\"}}").into_bytes();
    let value: serde_json::Value = serde_json::from_slice(&bytes).test_unwrap();
    assert_eq!(
        chio_core::canonical::canonical_json_bytes(&value).test_unwrap(),
        bytes
    );
    let actual = runtime_hash_for_chio_yaml(&policy(), &[]).test_unwrap();
    assert_eq!(actual, sha256_hex(&bytes));
    let previous = String::from_utf8(bytes)
        .test_unwrap()
        .replace("chio.runtime-policy.v3", "chio.runtime-policy.v2");
    assert_ne!(actual, sha256_hex(previous.as_bytes()));
}

#[test]
fn runtime_policy_v3_hushspec_hash_pins_approval_material_without_circular_hash() {
    let kernel = policy().kernel;
    let spec = chio_policy::HushSpec::parse("hushspec: '0.1.0'\n").test_unwrap();
    let profile = chio_guards::default_runtime_guard_profile_identity().test_unwrap();
    let key = Keypair::from_seed(&[11; 32]).public_key();
    let mut approval = ThresholdApprovalRequirement::new(
        "a".repeat(64),
        1,
        vec![ThresholdApproverIdentity {
            identifier: "operator-a".into(),
            public_key: key.clone(),
        }],
        "directory-7".into(),
        60,
    )
    .test_unwrap();
    let key_hex = key.to_hex();
    let eligible_digest = &approval.eligible_set_digest;
    let bytes = format!("{{\"auxiliary_assets\":[],\"default_capabilities\":[],\"default_guard_profile\":\"{profile}\",\"format\":\"hushspec\",\"issuance_policy\":null,\"kernel\":{KERNEL},\"resolved_policy\":{{\"hushspec\":\"0.1.0\"}},\"runtime_assurance_policy\":null,\"schema\":\"chio.runtime-policy.v3\",\"threshold_approval\":{{\"directory_version\":\"directory-7\",\"eligible_approvers\":[{{\"identifier\":\"operator-a\",\"public_key\":\"{key_hex}\"}}],\"eligible_set_digest\":\"{eligible_digest}\",\"threshold\":1,\"timeout_seconds\":60}}}}").into_bytes();
    let value: serde_json::Value = serde_json::from_slice(&bytes).test_unwrap();
    assert_eq!(
        chio_core::canonical::canonical_json_bytes(&value).test_unwrap(),
        bytes
    );
    let actual = runtime_hash_for_hushspec(&kernel, &[], &spec, &[], None, None, Some(&approval))
        .test_unwrap();
    assert_eq!(actual, sha256_hex(&bytes));
    approval.policy_hash = "b".repeat(64);
    assert_eq!(
        runtime_hash_for_hushspec(&kernel, &[], &spec, &[], None, None, Some(&approval))
            .test_unwrap(),
        actual
    );
}
