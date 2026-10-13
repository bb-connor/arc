use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::capability::{
    attenuation::{DelegationLink, DelegationLinkBody},
    scope::{ChioScope, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::Keypair;
use chio_core::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    kinds::TrustLevel,
};
use chio_kernel::budget_store::{BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest};
use chio_kernel::{BudgetStore, ReceiptStore, RevocationStore};
use chio_store_sqlite::{SqliteBudgetStore, SqliteReceiptStore, SqliteRevocationStore};

use chio_test_support::prelude::*;

fn charge(store: &SqliteBudgetStore, hold_id: &str, event_id: &str, cost_units: u64) -> bool {
    matches!(
        store
            .authorize_budget_hold(BudgetAuthorizeHoldRequest {
                capability_id: "cap-budget".to_string(),
                grant_index: 0,
                max_invocations: None,
                invocation_quotas: Vec::new(),
                cumulative_approval: None,
                admission_binding: None,
                requested_exposure_units: cost_units,
                max_cost_per_invocation: Some(100),
                max_total_cost_units: Some(100),
                hold_id: hold_id.to_string(),
                event_id: event_id.to_string(),
                authority: None,
            })
            .test_unwrap(),
        BudgetAuthorizeHoldDecision::Authorized(_)
    )
}

fn temp_path(prefix: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .test_unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
}

fn capability(id: &str, subject: &Keypair) -> CapabilityToken {
    let issuer = Keypair::generate();
    let body = CapabilityTokenBody {
        id: id.to_string(),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope: ChioScope {
            grants: vec![ToolGrant {
                server_id: "srv".to_string(),
                tool_name: "read".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![],
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..ChioScope::default()
        },
        issued_at: 1,
        expires_at: 100,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };
    CapabilityToken::sign(body, &issuer).test_unwrap()
}

fn delegated_capability(
    id: &str,
    subject: &Keypair,
    delegator: &Keypair,
    parent: &CapabilityToken,
) -> CapabilityToken {
    let mut body = parent.body();
    body.id = id.to_string();
    body.issuer = delegator.public_key();
    body.subject = subject.public_key();
    body.issued_at = body.issued_at.saturating_add(1);
    body.delegation_chain.push(
        DelegationLink::sign(
            DelegationLinkBody {
                capability_id: parent.id.clone(),
                delegator: delegator.public_key(),
                delegatee: subject.public_key(),
                attenuations: Vec::new(),
                timestamp: body.issued_at,
                scope_hash: None,
                aggregate_budget: None,
                cumulative_approval: None,
            },
            delegator,
        )
        .test_unwrap(),
    );
    CapabilityToken::sign(body, delegator).test_unwrap()
}

fn receipt(id: &str, capability_id: &str) -> ChioReceipt {
    let keypair = Keypair::generate();
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp: 1,
            capability_id: capability_id.to_string(),
            tool_server: "srv".to_string(),
            tool_name: "read".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({"path": "/app/a"}))
                .test_unwrap(),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: "0".repeat(64),
            policy_hash: "policy".to_string(),
            evidence: vec![],
            metadata: None,
            trust_level: TrustLevel::Mediated,
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        &keypair,
    )
    .test_unwrap()
}

#[test]
fn sqlite_revocation_projection_preserves_token_and_ancestor_membership() {
    let path = temp_path("formal-revocation-projection");
    {
        let store = SqliteRevocationStore::open(&path).test_unwrap();
        assert!(store.revoke("cap-token").test_unwrap());
        assert!(store.revoke("cap-ancestor").test_unwrap());
    }

    let reopened = SqliteRevocationStore::open(&path).test_unwrap();
    assert!(reopened.is_revoked("cap-token").test_unwrap());
    assert!(reopened.is_revoked("cap-ancestor").test_unwrap());
    assert!(!reopened.is_revoked("cap-other").test_unwrap());
}

#[test]
fn sqlite_budget_projection_atomic_commits_do_not_overspend() {
    let path = temp_path("formal-budget-projection");
    let store = SqliteBudgetStore::open(&path).test_unwrap();

    assert!(charge(&store, "hold-1", "event-1", 70));
    assert!(!charge(&store, "hold-2", "event-2", 40));

    let usage = store.get_usage("cap-budget", 0).test_unwrap().test_unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_eq!(usage.total_cost_exposed, 70);
}

#[test]
fn sqlite_budget_projection_idempotent_retry_does_not_double_charge() {
    let path = temp_path("formal-budget-idempotent");
    let store = SqliteBudgetStore::open(&path).test_unwrap();

    assert!(charge(&store, "hold-1", "event-1", 25));
    assert!(charge(&store, "hold-1", "event-1", 25));

    let usage = store.get_usage("cap-budget", 0).test_unwrap().test_unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_eq!(usage.total_cost_exposed, 25);
}

#[test]
fn sqlite_receipt_projection_persists_signed_receipts() {
    let path = temp_path("formal-receipt-projection");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let receipt = receipt("rcpt-projection", "cap-projection");

    store.append_chio_receipt(&receipt).test_unwrap();

    let reopened = SqliteReceiptStore::open(&path).test_unwrap();
    assert_eq!(reopened.tool_receipt_count().test_unwrap(), 1);
}

#[test]
fn sqlite_lineage_projection_preserves_root_first_chain() {
    let path = temp_path("formal-lineage-projection");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let subject = Keypair::generate();
    let root = capability("cap-root", &subject);
    let child = delegated_capability("cap-child", &subject, &subject, &root);

    store.record_capability_snapshot(&root, None).test_unwrap();
    store
        .record_capability_snapshot(&child, Some("cap-root"))
        .test_unwrap();

    let chain = store.get_delegation_chain("cap-child").test_unwrap();
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[0].capability_id, "cap-root");
    assert_eq!(chain[1].capability_id, "cap-child");
    assert_eq!(chain[1].parent_capability_id.as_deref(), Some("cap-root"));
}
