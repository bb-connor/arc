use super::*;
use chio_core::receipt::{body::ChioReceiptBody, decision::ToolCallAction};
use chio_test_support::prelude::*;
use serde_json::json;

fn receipt(key: &Keypair, index: u64) -> ChioReceipt {
    ChioReceipt::sign(
        ChioReceiptBody {
            id: String::new(),
            timestamp: 100,
            capability_id: "shared-capability".into(),
            tool_server: "certificate-fixture".into(),
            tool_name: "read".into(),
            action: ToolCallAction::from_parameters(json!({ "index": index })).test_unwrap(),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: "content".into(),
            policy_hash: "policy".into(),
            evidence: Vec::new(),
            metadata: Some(json!({ "receipt_context": { "session_id": "target" } })),
            trust_level: Default::default(),
            kernel_key: key.public_key(),
            bbs_projection_version: None,
            tenant_id: Some("tenant-a".into()),
        },
        key,
    )
    .test_unwrap()
}

fn fixture(
    count: u64,
) -> (
    tempfile::TempDir,
    std::path::PathBuf,
    SqliteReceiptStore,
    Keypair,
) {
    let directory = tempfile::tempdir().test_unwrap();
    let path = directory.path().join("live.db");
    let key = Keypair::from_seed(&[42; 32]);
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    for index in 1..=count {
        store
            .append_chio_receipt_returning_seq(&receipt(&key, index))
            .test_unwrap();
    }
    store
        .create_next_receipt_checkpoint(count, &key)
        .test_unwrap();
    (directory, path, store, key)
}

fn collect(
    path: &Path,
    key: &Keypair,
    limits: SessionReadLimits,
) -> Result<RetainedSessionReceipts, ReceiptStoreError> {
    collect_with_limits(
        path,
        "target",
        &ReceiptReadContext::local_operator_admin_all(),
        &key.public_key(),
        limits,
        |_| Ok(()),
    )
}

#[test]
fn session_certificate_production_budgets_accept_exact_limits_and_refuse_one_over() {
    let mut count = SessionBudget::new(SessionReadLimits::default());
    for _ in 0..MAX_SESSION_RECEIPTS {
        count.charge(1).test_unwrap();
    }
    assert!(count
        .charge(1)
        .test_unwrap_err()
        .to_string()
        .contains("session receipt limit"));
    let mut bytes = SessionBudget::new(SessionReadLimits::default());
    for _ in 0..MAX_SESSION_BYTES / MAX_RECEIPT_BYTES {
        bytes.charge(MAX_RECEIPT_BYTES).test_unwrap();
    }
    assert!(bytes
        .charge(1)
        .test_unwrap_err()
        .to_string()
        .contains("session byte limit"));
    assert!(SessionBudget::new(SessionReadLimits::default())
        .charge(MAX_RECEIPT_BYTES + 1)
        .is_err());
}

#[test]
fn session_certificate_real_store_count_and_original_byte_exhaustion_never_return_a_prefix() {
    let (_directory, path, _store, key) = fixture(2);
    let connection = Connection::open(&path).test_unwrap();
    let bytes: i64 = connection
        .query_row(
            "SELECT SUM(length(CAST(raw_json AS BLOB))) FROM claim_receipt_log_entries",
            [],
            |row| row.get(0),
        )
        .test_unwrap();
    let bytes = usize::try_from(bytes).test_unwrap();
    let exact = SessionReadLimits {
        receipts: 2,
        bytes,
        ..SessionReadLimits::default()
    };
    assert_eq!(collect(&path, &key, exact).test_unwrap().receipts.len(), 2);
    assert!(collect(
        &path,
        &key,
        SessionReadLimits {
            receipts: 1,
            ..exact
        }
    )
    .test_unwrap_err()
    .to_string()
    .contains("session receipt limit"));
    assert!(collect(
        &path,
        &key,
        SessionReadLimits {
            bytes: bytes - 1,
            ..exact
        }
    )
    .test_unwrap_err()
    .to_string()
    .contains("session byte limit"));
}

#[test]
fn session_certificate_authentication_row_byte_and_sql_work_limits_refuse() {
    let (_directory, path, _store, key) = fixture(64);
    for (limits, message) in [
        (
            SessionReadLimits {
                authentication_rows: 1,
                ..SessionReadLimits::default()
            },
            "authentication row limit",
        ),
        (
            SessionReadLimits {
                authentication_bytes: 1,
                ..SessionReadLimits::default()
            },
            "authentication byte limit",
        ),
        (
            SessionReadLimits {
                sql_steps: 1,
                ..SessionReadLimits::default()
            },
            "SQL work budget",
        ),
    ] {
        assert!(collect(&path, &key, limits)
            .test_unwrap_err()
            .to_string()
            .contains(message));
    }
}

#[test]
fn session_certificate_membership_overflow_is_rejected_before_allocation() {
    let (_directory, path, _store, key) = fixture(1);
    let connection = Connection::open(&path).test_unwrap();
    connection.execute_batch("DROP TRIGGER chio_tool_receipts_reject_update; UPDATE chio_tool_receipts SET raw_json = CAST(zeroblob(16777217) AS TEXT)").test_unwrap();
    let error = collect(&path, &key, SessionReadLimits::default()).test_unwrap_err();
    assert!(error
        .to_string()
        .contains("authentication source byte limit"));
}

#[test]
fn session_certificate_invalid_utf8_retains_the_native_decoding_cause() {
    let (_directory, path, _store, key) = fixture(1);
    let connection = Connection::open(&path).test_unwrap();
    connection
        .execute_batch("DROP TRIGGER chio_tool_receipts_reject_update; UPDATE chio_tool_receipts SET raw_json = CAST(X'FF' AS TEXT)")
        .test_unwrap();
    let error = collect(&path, &key, SessionReadLimits::default()).test_unwrap_err();
    assert!(std::error::Error::source(&error)
        .is_some_and(|source| source.downcast_ref::<std::str::Utf8Error>().is_some()));
    assert!(!format!("{error} {error:?}").contains("FF"));
}

#[test]
fn session_certificate_dense_membership_is_bounded_before_json_tree_allocation() {
    let (_directory, path, _store, key) = fixture(1);
    let connection = Connection::open(&path).test_unwrap();
    connection
        .execute_batch("DROP TRIGGER claim_receipt_log_entries_reject_update;")
        .test_unwrap();
    let dense = format!("[{}0]", "0,".repeat(MAX_MEMBERSHIP_NODES + 1));
    assert!(dense.len() < MAX_MEMBERSHIP_BYTES);
    connection
        .execute(
            "UPDATE claim_receipt_log_entries SET raw_json = ?1",
            [dense],
        )
        .test_unwrap();
    assert!(collect(&path, &key, SessionReadLimits::default())
        .test_unwrap_err()
        .to_string()
        .contains("membership structure limit"));
}

#[test]
fn session_certificate_later_checkpointed_append_cannot_change_the_pinned_snapshot() {
    let (_directory, path, store, key) = fixture(1);
    let first = collect_with_limits(
        &path,
        "target",
        &ReceiptReadContext::local_operator_admin_all(),
        &key.public_key(),
        SessionReadLimits::default(),
        |_| {
            store.append_chio_receipt_returning_seq(&receipt(&key, 2))?;
            store.create_next_receipt_checkpoint(1, &key)?;
            Ok(())
        },
    )
    .test_unwrap();
    assert_eq!(first.receipts.len(), 1);
    assert_eq!(first.coverage.snapshot_end_entry_seq, 1);
    let next = collect(&path, &key, SessionReadLimits::default()).test_unwrap();
    assert_eq!(next.receipts.len(), 2);
    assert_eq!(next.coverage.snapshot_end_entry_seq, 2);
    assert_ne!(first.coverage.checkpoint, next.coverage.checkpoint);
}

#[test]
fn session_certificate_same_archive_inode_mutation_is_isolated_until_next_read() {
    let (directory, path, store, key) = fixture(1);
    let archive = directory.path().join("archive.db");
    store
        .archive_receipts_before(101, archive.to_str().test_unwrap())
        .test_unwrap();
    let attacker = Connection::open(&archive).test_unwrap();
    attacker
        .pragma_update(None, "journal_mode", "WAL")
        .test_unwrap();
    let first = collect_with_limits(
        &path,
        "target",
        &ReceiptReadContext::local_operator_admin_all(),
        &key.public_key(),
        SessionReadLimits::default(),
        |_| {
            attacker.execute_batch("DROP TABLE chio_tool_receipts")?;
            Ok(())
        },
    )
    .test_unwrap();
    assert_eq!(first.receipts.len(), 1);
    assert_eq!(first.coverage.archived_through_entry_seq, 1);
    assert!(collect(&path, &key, SessionReadLimits::default()).is_err());
}

#[test]
fn session_certificate_preserves_source_and_claim_sequences_across_child_interleaving() {
    use chio_core::receipt::lineage::{ChildRequestReceipt, ChildRequestReceiptBody};
    use chio_core::session::{OperationKind, RequestId, SessionId};
    let (_directory, path, store, key) = fixture(1);
    store
        .append_child_receipt(
            &ChildRequestReceipt::sign(
                ChildRequestReceiptBody {
                    id: String::new(),
                    timestamp: 100,
                    session_id: SessionId::new("target"),
                    parent_request_id: RequestId::new("parent"),
                    request_id: RequestId::new("child"),
                    operation_kind: OperationKind::CreateMessage,
                    terminal_state: OperationTerminalState::Completed,
                    outcome_hash: "child-outcome".into(),
                    policy_hash: "policy".into(),
                    metadata: None,
                    kernel_key: key.public_key(),
                },
                &key,
            )
            .test_unwrap(),
        )
        .test_unwrap();
    store
        .append_chio_receipt_returning_seq(&receipt(&key, 2))
        .test_unwrap();
    store.create_next_receipt_checkpoint(2, &key).test_unwrap();
    let collected = collect(&path, &key, SessionReadLimits::default()).test_unwrap();
    assert_eq!(
        collected
            .receipts
            .iter()
            .map(|row| (row.seq, row.entry_seq))
            .collect::<Vec<_>>(),
        [(1, 1), (2, 3)]
    );
    assert_eq!(collected.coverage.snapshot_end_entry_seq, 3);
}

#[test]
fn session_certificate_commits_nonauthorizing_protocol_refusal_rows() {
    use chio_core::receipt::kinds::{
        BoundaryClass, ObservationOutcome, ReceiptKind, ToolOrigin, TrustLevel,
    };
    let (_directory, path, store, key) = fixture(1);
    let mut body = receipt(&key, 2).body();
    body.decision = None;
    body.receipt_kind = ReceiptKind::TraceObservation;
    body.boundary_class = BoundaryClass::DetectOnly;
    body.observation_outcome = Some(ObservationOutcome::Observed);
    body.tool_origin = ToolOrigin::CallerExecuted;
    body.trust_level = TrustLevel::Verified;
    body.metadata = Some(json!({ "protocol_refusal": {
        "schema": "chio.session.protocol-refusal.v1", "session_id": "target"
    }}));
    store
        .append_chio_receipt_returning_seq(&ChioReceipt::sign(body, &key).test_unwrap())
        .test_unwrap();
    store.create_next_receipt_checkpoint(1, &key).test_unwrap();
    let collected = collect(&path, &key, SessionReadLimits::default()).test_unwrap();
    assert_eq!(collected.receipts.len(), 2);
    assert_eq!(collected.receipts[1].receipt.decision, None);
    assert_eq!(
        collected.receipts[1].receipt.boundary_class,
        BoundaryClass::DetectOnly
    );
}

#[test]
fn session_certificate_read_context_is_validated_and_membership_has_no_index_authority() {
    let (_directory, path, _store, key) = fixture(1);
    for context in [
        ReceiptReadContext::authenticated_tenant("foreign"),
        ReceiptReadContext::authenticated_tenant(" "),
    ] {
        assert!(collect_retained_session_receipts_read_only(
            &path,
            "target",
            &context,
            &key.public_key()
        )
        .is_err());
    }
    for metadata in [
        json!({ "receipt_context": { "session_id": true } }),
        json!({ "protocol_refusal": { "schema": "wrong", "session_id": "target" } }),
        json!({ "protocol_refusal": { "schema": "chio.session.protocol-refusal.v1", "session_id": "foreign" }, "receipt_context": { "session_id": "target" } }),
    ] {
        assert!(signed_membership(Some(&metadata)).is_err());
    }
}
