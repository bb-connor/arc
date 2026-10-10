//! Subject refresh from capability lineage rows appended after publication:
//! a row is used only as the canonical local lineage reader accepts it.
use std::time::{Duration, Instant};

use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_core::crypto::Keypair;
use chio_kernel::receipt_query::ReceiptQuery;
use rusqlite::params;

use super::super::service::{
    ReceiptQuerySnapshotConfig, ReceiptQuerySnapshotState, ReceiptQuerySnapshots,
};
use super::service::{config, ready};
use super::support::{keypair, Fixture, Spec};

const CAPABILITY: &str = "cap-lineage";

/// A Ready snapshot holding archived receipts of `CAPABILITY` that carry no
/// signed attribution and have no lineage row. Returns one receipt's id.
fn unattributed_archived() -> (Fixture, ReceiptQuerySnapshots, String) {
    let fixture = Fixture::new(4);
    let spec = |index: u64| {
        let mut spec = Spec::new(format!("unattributed-{index}"), 1_700_000_000 + index);
        spec.capability = CAPABILITY.into();
        spec
    };
    for index in 0..4 {
        fixture.append(&spec(index));
    }
    let deadline = Instant::now() + Duration::from_secs(60);
    while fixture.rotate(1_700_000_100) == 0 {
        assert!(
            Instant::now() < deadline,
            "the receipts were never archived"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let service = ready(
        &fixture,
        ReceiptQuerySnapshotConfig {
            invalid_retry_backoff: Duration::from_secs(3),
            ..config()
        },
    );
    (fixture, service, spec(0).sign(&keypair()).id)
}

fn by_subject(subject: &str) -> ReceiptQuery {
    ReceiptQuery {
        limit: 100,
        agent_subject: Some(subject.into()),
        ..ReceiptQuery::default().local_operator_admin()
    }
}

fn token(subject: &Keypair, issuer: &Keypair) -> CapabilityToken {
    let body = CapabilityTokenBody {
        id: CAPABILITY.to_string(),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope: ChioScope {
            grants: vec![ToolGrant {
                server_id: "shell".to_string(),
                tool_name: "bash".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![],
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            resource_grants: vec![],
            prompt_grants: vec![],
        },
        issued_at: 1_700_000_000,
        expires_at: 4_000_000_000,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };
    CapabilityToken::sign(body, issuer).unwrap()
}

/// Insert a lineage row directly, as an out-of-band SQL writer could.
fn insert_row(
    fixture: &Fixture,
    subject: &str,
    issuer: &str,
    grants: &str,
    provenance: &str,
    signed: Option<&str>,
) {
    fixture
        .tamper()
        .execute(
            "INSERT INTO capability_lineage (capability_id, subject_key, issuer_key, issued_at,
                expires_at, grants_json, delegation_depth, provenance, signed_capability_json)
             VALUES (?1, ?2, ?3, 1700000000, 4000000000, ?4, 0, ?5, ?6)",
            params![CAPABILITY, subject, issuer, grants, provenance, signed],
        )
        .unwrap();
}

/// Wait until extension has acted on the new lineage row: either `served`
/// holds for the receipt under `subject`, or the snapshot left Ready.
fn await_refresh(
    service: &ReceiptQuerySnapshots,
    subject: &str,
    id: &str,
) -> (bool, ReceiptQuerySnapshotState) {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(page) = service.query_receipts(&by_subject(subject)) {
            if page.receipts.iter().any(|row| row.receipt.id == id) {
                return (true, service.status().state);
            }
        }
        let state = service.status().state;
        if !matches!(state, ReceiptQuerySnapshotState::Ready) {
            return (false, state);
        }
        assert!(
            Instant::now() < deadline,
            "extension never acted on the lineage row"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// A row the canonical reader refuses never attributes a receipt: the
/// snapshot is refused instead, as the build and recertification of the
/// same receipts would be.
fn refused_row_is_never_used(insert: impl FnOnce(&Fixture) -> String) {
    let (fixture, service, id) = unattributed_archived();
    let subject = insert(&fixture);
    assert!(
        fixture.store.get_lineage(CAPABILITY).is_err(),
        "the canonical reader accepts the row"
    );
    let (served, state) = await_refresh(&service, &subject, &id);
    assert!(
        !served,
        "a receipt was served under the subject of a lineage row the local reader refuses"
    );
    assert!(
        matches!(&state, ReceiptQuerySnapshotState::Invalid { reason } if reason.contains("refused by the local reader")),
        "{state:?}"
    );
    service.shutdown();
}

#[test]
fn a_signed_token_lineage_row_without_its_token_never_attributes_a_receipt() {
    refused_row_is_never_used(|fixture| {
        let subject = Keypair::from_seed(&[0x51; 32]).public_key().to_hex();
        let issuer = keypair().public_key().to_hex();
        insert_row(fixture, &subject, &issuer, "{}", "signed_token", None);
        subject
    });
}

#[test]
fn a_signed_token_lineage_row_with_another_subject_never_attributes_a_receipt() {
    refused_row_is_never_used(|fixture| {
        let issuer = keypair();
        let signed = token(&Keypair::from_seed(&[0x52; 32]), &issuer);
        let forged = Keypair::from_seed(&[0x53; 32]).public_key().to_hex();
        insert_row(
            fixture,
            &forged,
            &issuer.public_key().to_hex(),
            &serde_json::to_string(&signed.scope).unwrap(),
            "signed_token",
            Some(&serde_json::to_string(&signed).unwrap()),
        );
        forged
    });
}

#[test]
fn a_malformed_synthetic_anchor_lineage_row_never_attributes_a_receipt() {
    refused_row_is_never_used(|fixture| {
        let subject = Keypair::from_seed(&[0x54; 32]).public_key().to_hex();
        let issuer = keypair().public_key().to_hex();
        insert_row(fixture, &subject, &issuer, "{}", "synthetic_anchor", None);
        subject
    });
}

#[test]
fn a_signed_lineage_row_still_attributes_a_receipt() {
    let (fixture, service, id) = unattributed_archived();
    let subject = Keypair::from_seed(&[0x55; 32]);
    fixture
        .store
        .record_capability_snapshot(&token(&subject, &keypair()), None)
        .unwrap();
    assert!(fixture.store.get_lineage(CAPABILITY).unwrap().is_some());
    let (served, state) = await_refresh(&service, &subject.public_key().to_hex(), &id);
    assert!(
        served,
        "a valid signed lineage row did not attribute: {state:?}"
    );
    assert_eq!(state, ReceiptQuerySnapshotState::Ready);
    service.shutdown();
}

#[test]
fn a_legacy_lineage_row_still_attributes_a_receipt() {
    let (fixture, service, id) = unattributed_archived();
    insert_row(
        &fixture,
        "legacy-subject",
        "legacy-issuer",
        "[]",
        "legacy_projection",
        None,
    );
    assert!(fixture.store.get_lineage(CAPABILITY).unwrap().is_some());
    let (served, state) = await_refresh(&service, "legacy-subject", &id);
    assert!(served, "a legacy lineage row did not attribute: {state:?}");
    assert_eq!(state, ReceiptQuerySnapshotState::Ready);
    service.shutdown();
}
