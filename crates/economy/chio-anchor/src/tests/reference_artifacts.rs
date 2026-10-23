use super::*;
use chio_core::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    metadata::GuardEvidence,
};
use chio_core::web3::identity::{
    SignedWeb3IdentityBinding, Web3IdentityBindingCertificate, Web3KeyBindingPurpose,
    CHIO_KEY_BINDING_CERTIFICATE_SCHEMA,
};

use crate::{
    prepare_functions_batch_verification, ChainlinkFunctionsTarget, FunctionsVerificationPolicy,
    FunctionsVerificationPurpose,
};

const REFERENCE_ARTIFACTS_DIR: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../../docs/standards");

fn operator_keypair() -> Keypair {
    Keypair::from_seed(&[7u8; 32])
}

fn secondary_kernel_keypair() -> Keypair {
    Keypair::from_seed(&[8u8; 32])
}

fn operator_binding() -> SignedWeb3IdentityBinding {
    let operator = operator_keypair();
    let public_key = operator.public_key();
    let certificate = Web3IdentityBindingCertificate {
        schema: CHIO_KEY_BINDING_CERTIFICATE_SCHEMA.to_string(),
        chio_identity: format!("did:chio:{}", public_key.to_hex()),
        chio_public_key: public_key,
        chain_scope: vec!["eip155:8453".to_string(), "eip155:42161".to_string()],
        purpose: vec![Web3KeyBindingPurpose::Anchor, Web3KeyBindingPurpose::Settle],
        settlement_address: "0x1111111111111111111111111111111111111111".to_string(),
        issued_at: 1_743_292_800,
        expires_at: 1_774_828_800,
        nonce: "0123456789abcdef0123456789abcdef".to_string(),
    };
    let signature = chio_core::canonical::CanonicalBytes::from_serializable(&certificate)
        .and_then(|canonical| {
            operator.sign_wrapped(CHIO_KEY_BINDING_CERTIFICATE_SCHEMA, &canonical)
        })
        .test_unwrap();
    SignedWeb3IdentityBinding {
        certificate,
        signature,
    }
}

fn functions_receipt(keypair: &Keypair, id: &str, timestamp: u64) -> ChioReceipt {
    let body = ChioReceiptBody {
        id: id.to_string(),
        timestamp,
        capability_id: "cap-web3".to_string(),
        tool_server: "srv-web3".to_string(),
        tool_name: "settle".to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({
            "chain_id": "eip155:8453",
            "method": "release"
        }))
        .test_unwrap(),
        decision: Some(Decision::Allow),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash: chio_core::crypto::sha256_hex(br#"{"released":true}"#),
        policy_hash: "abc123".to_string(),
        evidence: vec![GuardEvidence {
            guard_name: "BudgetGuard".to_string(),
            verdict: true,
            details: Some("bounded".to_string()),
        }],
        metadata: Some(serde_json::json!({
            "financial": { "units": 42, "currency": "USD" }
        })),
        trust_level: chio_core::receipt::kinds::TrustLevel::default(),
        tenant_id: None,
        kernel_key: keypair.public_key(),
        bbs_projection_version: None,
    };
    ChioReceipt::sign(body, keypair).test_unwrap()
}

fn reference_discovery() -> crate::AnchorDiscoveryArtifact {
    build_anchor_discovery_artifact(
        &sample_discovery_config(
            "0x1111111111111111111111111111111111111111".to_string(),
            true,
        ),
        &operator_binding(),
    )
    .test_unwrap()
}

fn reference_functions_request() -> crate::PreparedFunctionsVerificationRequest {
    let receipts = vec![
        functions_receipt(&operator_keypair(), "rcpt-001", 1_744_000_000),
        functions_receipt(&secondary_kernel_keypair(), "rcpt-002", 1_744_000_030),
    ];
    prepare_functions_batch_verification(
        ChainlinkFunctionsTarget {
            chain_id: "eip155:8453".to_string(),
            router_address: "0x1000000000000000000000000000000000000001".to_string(),
            consumer_address: "0x1000000000000000000000000000000000000002".to_string(),
            don_id: "fun-base-mainnet".to_string(),
            subscription_id: 42,
            callback_gas_limit: 250_000,
        },
        FunctionsVerificationPurpose::AnchorAuditBatch,
        &receipts,
        50_000,
        FunctionsVerificationPolicy::default(),
        Some("batch anchor audit".to_string()),
    )
    .test_unwrap()
}

fn reference_artifact_bytes<T: serde::Serialize>(artifact: &T) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(artifact).test_unwrap();
    bytes.push(b'\n');
    bytes
}

/// The proof bundle wraps the committed `CHIO_ANCHOR_INCLUSION_PROOF_EXAMPLE.json`,
/// so the chio-web3 reference artifact generator runs first.
fn generated_reference_artifacts() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        (
            "CHIO_ANCHOR_DISCOVERY_EXAMPLE.json",
            reference_artifact_bytes(&reference_discovery()),
        ),
        (
            "CHIO_ANCHOR_PROOF_BUNDLE_EXAMPLE.json",
            reference_artifact_bytes(&sample_bitcoin_bundle()),
        ),
        (
            "CHIO_FUNCTIONS_REQUEST_EXAMPLE.json",
            reference_artifact_bytes(&reference_functions_request()),
        ),
    ]
}

/// Set `CHIO_WRITE_WEB3_REFERENCE_ARTIFACTS=1` to rewrite the committed
/// reference artifacts from this generator.
#[test]
fn reference_artifacts_are_the_generator_output() {
    let write = std::env::var_os("CHIO_WRITE_WEB3_REFERENCE_ARTIFACTS").is_some();
    for (name, bytes) in generated_reference_artifacts() {
        let path = std::path::Path::new(REFERENCE_ARTIFACTS_DIR).join(name);
        if write {
            std::fs::write(&path, &bytes).test_unwrap();
        }
        assert_eq!(std::fs::read(&path).test_unwrap(), bytes, "{name}");
    }
}
