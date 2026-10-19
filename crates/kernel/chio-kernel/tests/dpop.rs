//! DPoP verification and volatile source-retention boundaries.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use chio_core::capability::{
    scope::ChioScope,
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::{sha256_hex, Keypair};
use chio_kernel::dpop::authority::DpopReplayAuthority;
use chio_kernel::dpop::{DpopError, MAX_DPOP_REPLAY_IDENTITY_PART_BYTES};
use chio_kernel::{
    verify_dpop_proof_stateless, DpopNonceStore, DpopProof, DpopProofBody, KernelError, DPOP_SCHEMA,
};

const NOW: u64 = 1_800_000_000;

fn authority() -> DpopReplayAuthority {
    serde_json::from_value(serde_json::json!({
        "destination_store_uuid": "018f9878-7047-7abc-8c98-120dc65700ea",
        "dpop_authority_id": "configured-dpop",
        "expectation_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "proof_ttl_secs": 300,
        "max_clock_skew_secs": 30
    }))
    .unwrap()
}

fn make_capability(agent: &Keypair) -> CapabilityToken {
    let issuer = Keypair::generate();
    CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-dpop-test-01".into(),
            issuer: issuer.public_key(),
            subject: agent.public_key(),
            scope: ChioScope::default(),
            issued_at: NOW,
            expires_at: NOW + 3600,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        },
        &issuer,
    )
    .unwrap()
}

fn make_proof_body(capability: &CapabilityToken, agent: &Keypair) -> DpopProofBody {
    DpopProofBody {
        replay_authority: authority(),
        schema: DPOP_SCHEMA.into(),
        capability_id: capability.id.clone(),
        tool_server: "srv-a".into(),
        tool_name: "read_file".into(),
        action_hash: sha256_hex(b"{}"),
        nonce: "nonce-abc-123".into(),
        issued_at: NOW,
        agent_key: agent.public_key(),
    }
}

#[test]
fn dpop_identity_byte_limit_is_shared_by_verification_and_source_retention() {
    let key = Keypair::generate();
    let capability = make_capability(&key);
    let source = DpopNonceStore::new(8, Duration::from_secs(60)).unwrap();
    for (nonce, admitted) in [
        ("é".repeat(MAX_DPOP_REPLAY_IDENTITY_PART_BYTES / 2), true),
        (
            "é".repeat(MAX_DPOP_REPLAY_IDENTITY_PART_BYTES / 2) + "x",
            false,
        ),
    ] {
        let mut body = make_proof_body(&capability, &key);
        body.nonce = nonce.clone();
        let proof = DpopProof::sign(body, &key).unwrap();
        let verified = verify_dpop_proof_stateless(
            &proof,
            &capability,
            "srv-a",
            "read_file",
            &sha256_hex(b"{}"),
            &authority(),
            NOW,
        );
        assert_eq!(verified.is_ok(), admitted);
        assert_eq!(
            source.check_and_insert(&nonce, &capability.id).is_ok(),
            admitted
        );
    }
    assert_eq!(source.utilization().unwrap().0, 1);
}

#[test]
fn dpop_oversized_identity_is_refused_before_signature_canonicalization() {
    let key = Keypair::generate();
    let capability = make_capability(&key);
    let mut proof = DpopProof::sign(make_proof_body(&capability, &key), &key).unwrap();
    proof.body.nonce = "n".repeat(MAX_DPOP_REPLAY_IDENTITY_PART_BYTES + 1);
    assert!(matches!(
        verify_dpop_proof_stateless(
            &proof,
            &capability,
            "srv-a",
            "read_file",
            &sha256_hex(b"{}"),
            &authority(),
            NOW
        ),
        Err(KernelError::Dpop(DpopError::IdentityLimit))
    ));
}

#[test]
fn dpop_valid_proof_yields_repeatable_evidence_without_replay_custody() {
    let key = Keypair::generate();
    let capability = make_capability(&key);
    let proof = DpopProof::sign(make_proof_body(&capability, &key), &key).unwrap();
    for _ in 0..2 {
        let verified = verify_dpop_proof_stateless(
            &proof,
            &capability,
            "srv-a",
            "read_file",
            &sha256_hex(b"{}"),
            &authority(),
            NOW,
        )
        .unwrap();
        assert_eq!(verified.authority(), &authority());
        assert_eq!(verified.valid_through_unix_secs(), NOW + 300);
    }
}

fn assert_binding_mismatch(field: usize, expected: DpopError) {
    let key = Keypair::generate();
    let capability = make_capability(&key);
    let mut body = make_proof_body(&capability, &key);
    match field {
        0 => body.capability_id = "another-capability".into(),
        1 => body.tool_server = "another-server".into(),
        2 => body.tool_name = "another-tool".into(),
        3 => body.action_hash = sha256_hex(b"changed"),
        4 => body.agent_key = Keypair::generate().public_key(),
        _ => unreachable!(),
    }
    let proof = DpopProof::sign(body, &key).unwrap();
    let error = verify_dpop_proof_stateless(
        &proof,
        &capability,
        "srv-a",
        "read_file",
        &sha256_hex(b"{}"),
        &authority(),
        NOW,
    )
    .unwrap_err();
    assert!(matches!(error, KernelError::Dpop(_)));
    assert_eq!(error.report().code, expected.code());
}

#[test]
fn dpop_wrong_capability_id_rejected() {
    assert_binding_mismatch(0, DpopError::Capability);
}
#[test]
fn dpop_wrong_tool_server_rejected() {
    assert_binding_mismatch(1, DpopError::Server);
}
#[test]
fn dpop_wrong_tool_name_rejected() {
    assert_binding_mismatch(2, DpopError::Tool);
}
#[test]
fn dpop_wrong_action_hash_rejected() {
    assert_binding_mismatch(3, DpopError::Action);
}
#[test]
fn dpop_wrong_agent_key_rejected() {
    assert_binding_mismatch(4, DpopError::Sender);
}

#[test]
fn dpop_expired_proof_rejected() {
    let key = Keypair::generate();
    let capability = make_capability(&key);
    let mut body = make_proof_body(&capability, &key);
    body.issued_at = 0;
    let proof = DpopProof::sign(body, &key).unwrap();
    assert!(matches!(
        verify_dpop_proof_stateless(
            &proof,
            &capability,
            "srv-a",
            "read_file",
            &sha256_hex(b"{}"),
            &authority(),
            NOW
        ),
        Err(KernelError::Dpop(DpopError::Expired))
    ));
}

#[test]
fn volatile_source_rejects_duplicate_markers_within_its_retention_window() {
    let source = DpopNonceStore::new(8, Duration::from_secs(3600)).unwrap();
    assert!(source.check_and_insert("nonce", "capability").unwrap());
    assert!(!source.check_and_insert("nonce", "capability").unwrap());
    assert_eq!(source.utilization().unwrap().0, 1);
}

#[test]
fn volatile_source_signed_horizon_is_not_shortened_by_its_local_ttl() {
    let source = DpopNonceStore::with_clock(
        8,
        8,
        chio_kernel::dpop::DEFAULT_DPOP_IDENTITY_BYTE_CAPACITY,
        Duration::ZERO,
        std::sync::Arc::new(chio_security_types::clock::FixedClock::new(NOW)),
    )
    .unwrap();
    let now = NOW;
    assert!(source
        .check_and_insert_through("nonce", "capability", now + 300)
        .unwrap());
    assert!(!source
        .check_and_insert_through("nonce", "capability", now + 300)
        .unwrap());
}

#[test]
fn dpop_required_field_roundtrip() {
    use chio_core::capability::scope::{Operation, ToolGrant};

    // Some(true) must survive a JSON roundtrip and appear in the output.
    let grant_required = ToolGrant {
        server_id: "srv".to_string(),
        tool_name: "tool".to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: Some(true),
    };

    let json = serde_json::to_string(&grant_required).expect("serialize");
    assert!(
        json.contains("dpop_required"),
        "dpop_required must appear in JSON when Some(true)"
    );

    let restored: ToolGrant = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(restored.dpop_required, Some(true));

    // None must be omitted from JSON.
    let grant_none = ToolGrant {
        server_id: "srv".to_string(),
        tool_name: "tool".to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    };
    let json_none = serde_json::to_string(&grant_none).expect("serialize");
    assert!(
        !json_none.contains("dpop_required"),
        "dpop_required must be absent from JSON when None"
    );

    let restored_none: ToolGrant = serde_json::from_str(&json_none).expect("deserialize");
    assert_eq!(restored_none.dpop_required, None);
}

#[test]
fn dpop_issued_at_u64_max_rejected_with_window_overflow() {
    let key = Keypair::generate();
    let capability = make_capability(&key);
    let mut body = make_proof_body(&capability, &key);
    body.issued_at = u64::MAX;
    let proof = DpopProof::sign(body, &key).unwrap();
    assert!(matches!(
        verify_dpop_proof_stateless(
            &proof,
            &capability,
            "srv-a",
            "read_file",
            &sha256_hex(b"{}"),
            &authority(),
            NOW
        ),
        Err(KernelError::Dpop(DpopError::WindowOverflow))
    ));
}
