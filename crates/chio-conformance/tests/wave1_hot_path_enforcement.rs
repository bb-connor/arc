//! Wave 1.5 hot-path enforcement test.
//!
//! Exercises the three Wave 1 attack scenarios (W1.1 inflated parent
//! scope, W1.3 v2-token-to-v1-only-peer downgrade, W1.2 oversubscribed
//! siblings) through the REAL chio-kernel hot path
//! (`ChioKernel::evaluate_portable_verdict`) where possible, or
//! through the same `verify_capability_full` entry point that the hot
//! path delegates to. The point is to lock the wiring in place: any
//! future PR that breaks the chain-binding, schema-ceiling, or
//! sibling-sum hooks on the public hot-path entry point will fail this
//! test fail-closed.
//!
//! Layout:
//!
//! - `kernel_hot_path_rejects_inflated_parent_scope` -- W1.1 chain-binding.
//! - `kernel_hot_path_rejects_v2_token_to_v1_only_peer` -- W1.3 schema ceiling.
//! - `kernel_hot_path_rejects_oversubscribed_siblings` -- W1.2 sibling sum.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core::capability::{
    compute_attenuation_witness, scope_hash, AttenuationProof, CapabilityCryptoFloor,
    CapabilityNegotiation, CapabilityToken, CapabilityTokenBody, CapabilityTokenV2Body, ChioScope,
    DelegationLink, DelegationLinkBody, Operation, ToolGrant, CHIO_CAPABILITY_V1_SCHEMA,
};
use chio_core::crypto::Keypair;
use chio_kernel::{
    ChioKernel, KernelConfig, DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_kernel_core::{
    verify_capability_full, CapabilityError, FixedClock, InMemoryBudgetRegistry,
    PortableToolCallRequest, Verdict,
};

fn grant(operations: Vec<Operation>) -> ToolGrant {
    ToolGrant {
        server_id: "srv".to_string(),
        tool_name: "tool".to_string(),
        operations,
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    }
}

fn scope_with(grants: Vec<ToolGrant>) -> ChioScope {
    ChioScope {
        grants,
        ..ChioScope::default()
    }
}

/// Build a fresh `ChioKernel` whose primary keypair is the supplied
/// `issuer`. Because `trusted_issuer_keys` always includes the
/// kernel's own public key, this keeps the test issuer in the trusted
/// set without needing to mutate `ca_public_keys` post-construction.
fn make_kernel(issuer: Keypair) -> ChioKernel {
    let config = KernelConfig {
        keypair: issuer,
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "wave1-hot-path-test-policy".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
    };
    ChioKernel::new(config)
}

fn portable_request(request_id: &str, capability: &CapabilityToken) -> PortableToolCallRequest {
    PortableToolCallRequest {
        request_id: request_id.to_string(),
        tool_name: "tool".to_string(),
        server_id: "srv".to_string(),
        agent_id: capability.subject.to_hex(),
        arguments: serde_json::Value::Null,
    }
}

#[test]
fn kernel_hot_path_rejects_inflated_parent_scope() {
    // W1.1 chain-binding: a v2 token whose attenuation_proof claims
    // parent_scope_hash == H(scope_BIGGER) but whose issuer's true
    // authority is scope_X must be denied by the kernel hot path.
    let scope_x = scope_with(vec![grant(vec![Operation::Invoke, Operation::Delegate])]);
    let scope_bigger = scope_with(vec![grant(vec![
        Operation::Invoke,
        Operation::Delegate,
        Operation::ReadResult,
    ])]);
    // child <= scope_bigger but NOT <= scope_x (requires ReadResult).
    let scope_child = scope_with(vec![grant(vec![Operation::Invoke, Operation::ReadResult])]);

    let issuer = Keypair::generate();
    let subject = Keypair::generate();

    // Honest witness: child <= scope_bigger. Attacker supplies it; the
    // verifier without chain-binding would accept.
    let witness = compute_attenuation_witness(&scope_bigger, &scope_child).unwrap();
    let proof = AttenuationProof {
        parent_scope_hash: scope_hash(&scope_bigger).unwrap(),
        child_scope_hash: scope_hash(&scope_child).unwrap(),
        normalized_subset_proof: witness,
    };

    let body = CapabilityTokenBody {
        id: "cap-v2-inflated-parent-hot-path".to_string(),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope: scope_child,
        issued_at: 100,
        expires_at: 200,
        delegation_chain: vec![],
    };
    let token = CapabilityToken::sign_v2(
        CapabilityTokenV2Body {
            body,
            caveats: vec![],
            scope_attenuations: vec![],
            attenuation_proof: proof,
            budget_share_bps: None,
        },
        &issuer,
    )
    .expect("inflated-parent token signs (verifier must catch this)");

    // Build a kernel whose primary keypair is the issuer (so the
    // issuer is in the trusted set) and whose registered trust-root
    // authority is scope_X (the issuer's TRUE authority).
    let kernel = make_kernel(issuer.clone())
        .with_capability_trust_roots(vec![(issuer.public_key(), scope_hash(&scope_x).unwrap())]);

    let request = portable_request("req-w1.1-inflated", &token);
    let clock = FixedClock::new(150);
    let guards: &[&dyn chio_kernel_core::Guard] = &[];

    let verdict = kernel.evaluate_portable_verdict(&token, &request, guards, &clock, None);

    assert_eq!(
        verdict.verdict,
        Verdict::Deny,
        "W1.1 chain-binding must DENY the inflated parent_scope_hash attack at the kernel hot path; got verdict {:?} reason {:?}",
        verdict.verdict, verdict.reason
    );
    let reason = verdict.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("chain")
            || reason.contains("parent_scope_hash")
            || reason.contains("trust-root"),
        "expected chain-binding diagnostic, got: {reason}"
    );
}

#[test]
fn kernel_hot_path_rejects_v2_token_to_v1_only_peer() {
    // W1.3 schema ceiling: a v2 token presented across a peer
    // negotiation profile capped at v1 must be denied before any
    // signature work. We exercise this through the same
    // `verify_capability_full` entry point the kernel hot path uses
    // (via chio_kernel_core directly, with a pinned v1-only peer
    // profile that the local kernel would not normally use).
    let scope = scope_with(vec![grant(vec![Operation::Invoke])]);
    let issuer = Keypair::generate();
    let subject = Keypair::generate();

    let witness = compute_attenuation_witness(&scope, &scope).unwrap();
    let proof = AttenuationProof {
        parent_scope_hash: scope_hash(&scope).unwrap(),
        child_scope_hash: scope_hash(&scope).unwrap(),
        normalized_subset_proof: witness,
    };
    let body = CapabilityTokenBody {
        id: "cap-v2-downgrade".to_string(),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope: scope.clone(),
        issued_at: 100,
        expires_at: 200,
        delegation_chain: vec![],
    };
    let token = CapabilityToken::sign_v2(
        CapabilityTokenV2Body {
            body,
            caveats: vec![],
            scope_attenuations: vec![],
            attenuation_proof: proof,
            budget_share_bps: None,
        },
        &issuer,
    )
    .expect("v2 token signs");

    let mut peer_v1_only = CapabilityNegotiation::t1_default();
    peer_v1_only.max_capability_schema = CHIO_CAPABILITY_V1_SCHEMA.to_string();
    let trust_resolver = |k: &chio_core::PublicKey| -> Option<chio_core::capability::ScopeHash> {
        if k == &issuer.public_key() {
            Some(scope_hash(&scope).unwrap())
        } else {
            None
        }
    };
    let mut budgets = InMemoryBudgetRegistry::new();
    let clock = FixedClock::new(150);
    let err = verify_capability_full(
        &token,
        &[issuer.public_key()],
        &clock,
        CapabilityCryptoFloor::AllowClassical,
        &peer_v1_only,
        &trust_resolver,
        &mut budgets,
    )
    .expect_err("W1.3 schema ceiling must reject v2 token presented across a v1-only peer");

    match err {
        CapabilityError::SchemaExceedsNegotiatedCeiling {
            token_schema,
            peer_max,
        } => {
            assert!(
                token_schema.contains("v2") || token_schema.contains("V2"),
                "token_schema should mention v2: {token_schema}"
            );
            assert!(
                peer_max.contains("v1") || peer_max.contains("V1"),
                "peer_max should mention v1: {peer_max}"
            );
        }
        other => panic!("expected SchemaExceedsNegotiatedCeiling, got: {other:?}"),
    }
}

#[test]
fn kernel_hot_path_rejects_oversubscribed_siblings() {
    // W1.2 sibling-sum enforcement: a parent at 5000 bps cannot back
    // two children at 4000 bps each. The second child must DENY at
    // the kernel hot path, even though each per-token share is inside
    // the 10000-bps cap.
    let parent_scope = scope_with(vec![grant(vec![
        Operation::Invoke,
        Operation::Delegate,
        Operation::ReadResult,
    ])]);
    let child_scope = scope_with(vec![grant(vec![Operation::Invoke])]);

    let issuer = Keypair::generate();
    let subject_a = Keypair::generate();
    let subject_b = Keypair::generate();

    let parent_id = "cap-parent-w1.2";

    let mk_chain = |delegatee: chio_core::PublicKey| {
        let body = DelegationLinkBody {
            capability_id: parent_id.to_string(),
            delegator: issuer.public_key(),
            delegatee,
            attenuations: vec![],
            timestamp: 100,
            scope_hash: Some(scope_hash(&parent_scope).unwrap()),
        };
        vec![DelegationLink::sign(body, &issuer).expect("delegation link signs")]
    };

    let mk_child = |id: &str, delegatee: chio_core::PublicKey, share: u16| {
        let witness = compute_attenuation_witness(&parent_scope, &child_scope).unwrap();
        let proof = AttenuationProof {
            parent_scope_hash: scope_hash(&parent_scope).unwrap(),
            child_scope_hash: scope_hash(&child_scope).unwrap(),
            normalized_subset_proof: witness,
        };
        let body = CapabilityTokenBody {
            id: id.to_string(),
            issuer: issuer.public_key(),
            subject: delegatee.clone(),
            scope: child_scope.clone(),
            issued_at: 100,
            expires_at: 200,
            delegation_chain: mk_chain(delegatee),
        };
        CapabilityToken::sign_v2(
            CapabilityTokenV2Body {
                body,
                caveats: vec![],
                scope_attenuations: vec![],
                attenuation_proof: proof,
                budget_share_bps: Some(share),
            },
            &issuer,
        )
        .expect("child token signs")
    };

    let child_a = mk_child("cap-child-a-w1.2", subject_a.public_key(), 4_000);
    let child_b = mk_child("cap-child-b-w1.2", subject_b.public_key(), 4_000);

    // Build kernel using the issuer keypair as the kernel's primary so
    // the issuer is in the trusted set, register the trust root for
    // the chain-binding rule, and seed the budget registry with the
    // parent share.
    let kernel = make_kernel(issuer.clone()).with_capability_trust_roots(vec![(
        issuer.public_key(),
        scope_hash(&parent_scope).unwrap(),
    )]);
    kernel
        .register_budget_parent(parent_id.to_string(), 5_000)
        .expect("register parent");

    let clock = FixedClock::new(150);
    let guards: &[&dyn chio_kernel_core::Guard] = &[];

    // First child: 4000 of 5000 admits.
    let req_a = portable_request("req-w1.2-child-a", &child_a);
    let verdict_a = kernel.evaluate_portable_verdict(&child_a, &req_a, guards, &clock, None);
    assert_eq!(
        verdict_a.verdict,
        Verdict::Allow,
        "first child must be admitted (4000 bps fits 5000 bps parent share); got verdict {:?} reason {:?}",
        verdict_a.verdict, verdict_a.reason
    );

    // Second child: 4000 + 4000 = 8000 > 5000. Must be DENY.
    let req_b = portable_request("req-w1.2-child-b", &child_b);
    let verdict_b = kernel.evaluate_portable_verdict(&child_b, &req_b, guards, &clock, None);
    assert_eq!(
        verdict_b.verdict,
        Verdict::Deny,
        "W1.2 sibling-sum must DENY oversubscribed second child at the kernel hot path; got verdict {:?} reason {:?}",
        verdict_b.verdict, verdict_b.reason
    );
    let reason = verdict_b.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("budget")
            || reason.contains("oversubscrib")
            || reason.contains("budget_split"),
        "expected sibling-sum diagnostic, got: {reason}"
    );
}
