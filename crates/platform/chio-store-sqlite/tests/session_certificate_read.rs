//! Exercise the certificate reader against the actual retained receipt store.

use chio_core::crypto::Keypair;
use chio_core::receipt::{
    body::{ChioReceipt, ChioReceiptBody},
    decision::{Decision, ToolCallAction},
};
use chio_kernel::{build_checkpoint, ReceiptReadContext, ReceiptStoreError};
use chio_store_sqlite::{collect_retained_session_receipts_read_only, SqliteReceiptStore};
use chio_test_support::prelude::*;
use serde_json::json;

fn receipt(key: &Keypair, index: u64, session: &str, timestamp: u64) -> ChioReceipt {
    ChioReceipt::sign(
        ChioReceiptBody {
            id: String::new(),
            timestamp,
            capability_id: "same-capability-for-every-session".into(),
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
            metadata: Some(json!({ "receipt_context": { "session_id": session } })),
            trust_level: Default::default(),
            kernel_key: key.public_key(),
            bbs_projection_version: None,
            tenant_id: Some("tenant-a".into()),
        },
        key,
    )
    .test_unwrap()
}

fn checkpoint(store: &SqliteReceiptStore, key: &Keypair, end: u64) {
    let bytes = store
        .receipts_canonical_bytes_range(1, end)
        .test_unwrap()
        .into_iter()
        .map(|(_, bytes)| bytes)
        .collect::<Vec<_>>();
    store
        .store_checkpoint(&build_checkpoint(1, 1, end, &bytes, key).test_unwrap())
        .test_unwrap();
}

#[test]
fn session_certificate_reads_authenticated_interleaved_archive_and_live_history() {
    let directory = tempfile::tempdir().test_unwrap();
    let path = directory.path().join("live.db");
    let archive = directory.path().join("archive.db");
    let key = Keypair::from_seed(&[42; 32]);
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    for (index, session) in [(1, "target_%"), (2, "other"), (3, "target_%"), (4, "other")] {
        store
            .append_chio_receipt_returning_seq(&receipt(&key, index, session, 100))
            .test_unwrap();
    }
    checkpoint(&store, &key, 4);
    assert_eq!(
        store
            .archive_receipts_before(101, archive.to_str().test_unwrap())
            .test_unwrap(),
        4
    );
    store
        .append_chio_receipt_returning_seq(&receipt(&key, 5, "target_%", 200))
        .test_unwrap();
    store.create_next_receipt_checkpoint(1, &key).test_unwrap();
    let next = store.load_checkpoint_by_seq(2).test_unwrap().test_unwrap();

    let collected = collect_retained_session_receipts_read_only(
        &path,
        "target_%",
        &ReceiptReadContext::authenticated_tenant("tenant-a"),
        &key.public_key(),
    )
    .test_unwrap();
    assert_eq!(
        collected
            .receipts()
            .iter()
            .map(|row| (row.seq, row.entry_seq))
            .collect::<Vec<_>>(),
        [(1, 1), (3, 3), (5, 5)]
    );
    assert_eq!(collected.coverage().snapshot_end_entry_seq, 5);
    assert_eq!(collected.coverage().archived_through_entry_seq, 4);
    assert_eq!(collected.coverage().checkpoint, next);
    assert_eq!(collected.coverage().tenant_id.as_deref(), Some("tenant-a"));
}

#[test]
fn session_certificate_refuses_uncheckpointed_tail_instead_of_certifying_a_subset() {
    let directory = tempfile::tempdir().test_unwrap();
    let path = directory.path().join("live.db");
    let key = Keypair::from_seed(&[42; 32]);
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    store
        .append_chio_receipt_returning_seq(&receipt(&key, 1, "target", 100))
        .test_unwrap();
    checkpoint(&store, &key, 1);
    // Even an unrelated-session append changes the whole snapshot boundary.
    store
        .append_chio_receipt_returning_seq(&receipt(&key, 2, "other", 200))
        .test_unwrap();
    assert!(matches!(
        collect_retained_session_receipts_read_only(
            &path,
            "target",
            &ReceiptReadContext::local_operator_admin_all(),
            &key.public_key(),
        ),
        Err(ReceiptStoreError::ReadBoundary(_))
    ));
}

#[test]
fn session_certificate_reader_never_creates_or_migrates_a_database() {
    let directory = tempfile::tempdir().test_unwrap();
    let path = directory.path().join("missing.db");
    let key = Keypair::from_seed(&[42; 32]);
    assert!(collect_retained_session_receipts_read_only(
        &path,
        "target",
        &ReceiptReadContext::local_operator_admin_all(),
        &key.public_key(),
    )
    .is_err());
    assert!(!path.exists());

    let connection = rusqlite::Connection::open(&path).test_unwrap();
    connection
        .execute_batch(
            "CREATE TABLE untouched (value TEXT); INSERT INTO untouched VALUES ('sentinel');",
        )
        .test_unwrap();
    let before = std::fs::read(&path).test_unwrap();
    assert!(collect_retained_session_receipts_read_only(
        &path,
        "target",
        &ReceiptReadContext::local_operator_admin_all(),
        &key.public_key(),
    )
    .is_err());
    assert_eq!(std::fs::read(&path).test_unwrap(), before);
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .test_unwrap(),
        1
    );
}

#[test]
fn session_certificate_cannot_ignore_the_collectors_legacy_mutable_history() {
    let directory = tempfile::tempdir().test_unwrap();
    let path = directory.path().join("live.db");
    let key = Keypair::from_seed(&[42; 32]);
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    store
        .append_chio_receipt_returning_seq(&receipt(&key, 1, "target", 100))
        .test_unwrap();
    checkpoint(&store, &key, 1);
    let connection = rusqlite::Connection::open(&path).test_unwrap();
    connection.execute_batch("CREATE TABLE chio_receipts (json_data TEXT); INSERT INTO chio_receipts VALUES ('legacy mutable receipt');").test_unwrap();
    assert!(collect_retained_session_receipts_read_only(
        &path,
        "target",
        &ReceiptReadContext::local_operator_admin_all(),
        &key.public_key(),
    )
    .is_err());
}

#[test]
fn session_certificate_reads_4097_selected_receipts_without_portable_bundle_truncation() {
    let directory = tempfile::tempdir().test_unwrap();
    let path = directory.path().join("live.db");
    let key = Keypair::from_seed(&[42; 32]);
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    for index in 1..=4_097 {
        store
            .append_chio_receipt_returning_seq(&receipt(&key, index, "target", index))
            .test_unwrap();
    }
    checkpoint(&store, &key, 4_097);
    let collected = collect_retained_session_receipts_read_only(
        &path,
        "target",
        &ReceiptReadContext::local_operator_admin_all(),
        &key.public_key(),
    )
    .test_unwrap();
    assert_eq!(collected.receipts().len(), 4_097);
    assert_eq!(collected.receipts()[0].seq, 1);
    assert_eq!(collected.receipts()[4_096].seq, 4_097);
    assert_eq!(collected.coverage().snapshot_end_entry_seq, 4_097);
}

#[test]
fn session_certificate_refuses_conflicting_signed_membership() {
    let directory = tempfile::tempdir().test_unwrap();
    let path = directory.path().join("live.db");
    let key = Keypair::from_seed(&[42; 32]);
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let mut body = receipt(&key, 1, "target", 100).body();
    body.metadata = Some(json!({
        "acp": { "sessionId": "foreign" },
        "receipt_context": { "session_id": "target" }
    }));
    let conflicting = ChioReceipt::sign(body, &key).test_unwrap();
    store
        .append_chio_receipt_returning_seq(&conflicting)
        .test_unwrap();
    checkpoint(&store, &key, 1);
    let error = collect_retained_session_receipts_read_only(
        &path,
        "target",
        &ReceiptReadContext::local_operator_admin_all(),
        &key.public_key(),
    )
    .test_unwrap_err();
    assert!(error.to_string().contains("membership fields conflict"));
}

#[test]
fn session_certificate_refuses_original_duplicate_membership_before_projection() {
    let directory = tempfile::tempdir().test_unwrap();
    let path = directory.path().join("live.db");
    let key = Keypair::from_seed(&[42; 32]);
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    store
        .append_chio_receipt_returning_seq(&receipt(&key, 1, "target", 100))
        .test_unwrap();
    checkpoint(&store, &key, 1);
    let connection = rusqlite::Connection::open(&path).test_unwrap();
    connection
        .execute_batch("DROP TRIGGER claim_receipt_log_entries_reject_update")
        .test_unwrap();
    let raw: String = connection
        .query_row(
            "SELECT raw_json FROM claim_receipt_log_entries",
            [],
            |row| row.get(0),
        )
        .test_unwrap();
    let duplicate = raw.replace(
        "\"session_id\":\"target\"",
        "\"session_id\":\"foreign\",\"session_id\":\"target\"",
    );
    assert_ne!(duplicate, raw);
    connection
        .execute(
            "UPDATE claim_receipt_log_entries SET raw_json = ?1",
            [duplicate],
        )
        .test_unwrap();
    assert!(collect_retained_session_receipts_read_only(
        &path,
        "target",
        &ReceiptReadContext::local_operator_admin_all(),
        &key.public_key(),
    )
    .is_err());
}

#[test]
fn session_certificate_does_not_trust_unsigned_session_or_tenant_indexes() {
    let directory = tempfile::tempdir().test_unwrap();
    let path = directory.path().join("live.db");
    let key = Keypair::from_seed(&[42; 32]);
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    store
        .append_chio_receipt_returning_seq(&receipt(&key, 1, "target", 100))
        .test_unwrap();
    checkpoint(&store, &key, 1);
    let connection = rusqlite::Connection::open(&path).test_unwrap();
    connection.execute_batch("CREATE TABLE unsigned_sessions (session_id TEXT, source_seq INTEGER); INSERT INTO unsigned_sessions VALUES ('foreign', 1);").test_unwrap();
    let collected = collect_retained_session_receipts_read_only(
        &path,
        "target",
        &ReceiptReadContext::local_operator_admin_all(),
        &key.public_key(),
    )
    .test_unwrap();
    assert_eq!(collected.receipts().len(), 1);
    connection.execute_batch("DROP TRIGGER chio_tool_receipts_reject_update; UPDATE chio_tool_receipts SET tenant_id = 'foreign'").test_unwrap();
    assert!(collect_retained_session_receipts_read_only(
        &path,
        "target",
        &ReceiptReadContext::authenticated_tenant("tenant-a"),
        &key.public_key(),
    )
    .is_err());
}

#[test]
fn session_certificate_refuses_an_untrusted_foreign_session_checkpoint() {
    let directory = tempfile::tempdir().test_unwrap();
    let path = directory.path().join("live.db");
    let key = Keypair::from_seed(&[42; 32]);
    let foreign = Keypair::from_seed(&[43; 32]);
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    store
        .append_chio_receipt_returning_seq(&receipt(&key, 1, "target", 100))
        .test_unwrap();
    checkpoint(&store, &key, 1);
    store
        .append_chio_receipt_returning_seq(&receipt(&foreign, 2, "foreign", 200))
        .test_unwrap();
    store
        .create_next_receipt_checkpoint(1, &foreign)
        .test_unwrap();
    assert!(collect_retained_session_receipts_read_only(
        &path,
        "target",
        &ReceiptReadContext::local_operator_admin_all(),
        &key.public_key(),
    )
    .is_err());
}

#[test]
fn session_certificate_refuses_missing_or_replaced_authenticated_archive() {
    let directory = tempfile::tempdir().test_unwrap();
    let path = directory.path().join("live.db");
    let archive = directory.path().join("archive.db");
    let key = Keypair::from_seed(&[42; 32]);
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    store
        .append_chio_receipt_returning_seq(&receipt(&key, 1, "target", 100))
        .test_unwrap();
    checkpoint(&store, &key, 1);
    assert_eq!(
        store
            .archive_receipts_before(101, archive.to_str().test_unwrap())
            .test_unwrap(),
        1
    );
    let saved = archive.with_extension("saved");
    std::fs::rename(&archive, &saved).test_unwrap();
    assert!(collect_retained_session_receipts_read_only(
        &path,
        "target",
        &ReceiptReadContext::local_operator_admin_all(),
        &key.public_key(),
    )
    .is_err());
    assert!(!archive.exists());
    let replacement = SqliteReceiptStore::open(&archive).test_unwrap();
    replacement
        .append_chio_receipt_returning_seq(&receipt(&key, 2, "foreign", 100))
        .test_unwrap();
    checkpoint(&replacement, &key, 1);
    assert!(collect_retained_session_receipts_read_only(
        &path,
        "target",
        &ReceiptReadContext::local_operator_admin_all(),
        &key.public_key(),
    )
    .is_err());
}

#[test]
fn session_certificate_isolates_bounded_foreign_oversize_but_refuses_selected_original_oversize() {
    let directory = tempfile::tempdir().test_unwrap();
    let path = directory.path().join("live.db");
    let key = Keypair::from_seed(&[42; 32]);
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    store
        .append_chio_receipt_returning_seq(&receipt(&key, 1, "target", 100))
        .test_unwrap();
    let mut body = receipt(&key, 2, "foreign", 100).body();
    body.metadata = Some(
        json!({ "receipt_context": { "session_id": "foreign" }, "padding": "x".repeat(1024 * 1024 + 1) }),
    );
    store
        .append_chio_receipt_returning_seq(&ChioReceipt::sign(body, &key).test_unwrap())
        .test_unwrap();
    checkpoint(&store, &key, 2);
    assert_eq!(
        collect_retained_session_receipts_read_only(
            &path,
            "target",
            &ReceiptReadContext::local_operator_admin_all(),
            &key.public_key(),
        )
        .test_unwrap()
        .receipts()
        .len(),
        1
    );
    assert!(collect_retained_session_receipts_read_only(
        &path,
        "foreign",
        &ReceiptReadContext::local_operator_admin_all(),
        &key.public_key(),
    )
    .is_err());

    // The canonical signed bytes still fit. Original stored whitespace must
    // not be discarded before the selected byte ceiling is enforced.
    let connection = rusqlite::Connection::open(&path).test_unwrap();
    connection
        .execute_batch("DROP TRIGGER claim_receipt_log_entries_reject_update; DROP TRIGGER chio_tool_receipts_reject_update;")
        .test_unwrap();
    let raw: String = connection
        .query_row(
            "SELECT raw_json FROM claim_receipt_log_entries WHERE entry_seq = 1",
            [],
            |row| row.get(0),
        )
        .test_unwrap();
    let exact = format!("{raw}{}", " ".repeat(1024 * 1024 - raw.len()));
    connection
        .execute(
            "UPDATE chio_tool_receipts SET raw_json = ?1 WHERE seq = 1",
            [&exact],
        )
        .test_unwrap();
    connection
        .execute(
            "UPDATE claim_receipt_log_entries SET raw_json = ?1 WHERE entry_seq = 1",
            [&exact],
        )
        .test_unwrap();
    assert_eq!(
        collect_retained_session_receipts_read_only(
            &path,
            "target",
            &ReceiptReadContext::local_operator_admin_all(),
            &key.public_key(),
        )
        .test_unwrap()
        .receipts()
        .len(),
        1
    );
    let padded = format!("{exact} ");
    assert_eq!(padded.len(), 1024 * 1024 + 1);
    connection
        .execute(
            "UPDATE claim_receipt_log_entries SET raw_json = ?1 WHERE entry_seq = 1",
            [padded],
        )
        .test_unwrap();
    let error = collect_retained_session_receipts_read_only(
        &path,
        "target",
        &ReceiptReadContext::local_operator_admin_all(),
        &key.public_key(),
    )
    .test_unwrap_err();
    assert!(error.to_string().contains("selected receipt byte limit"));
}

#[test]
fn session_certificate_actual_store_accepts_128_mib_and_refuses_one_more_selected_row() {
    // Keep the large real-SQLite byte fixture off the near-full source volume.
    let directory = tempfile::tempdir_in("/dev/shm").test_unwrap();
    let path = directory.path().join("live.db");
    let key = Keypair::from_seed(&[42; 32]);
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    for index in 1..=128 {
        store
            .append_chio_receipt_returning_seq(&receipt(&key, index, "target", 100))
            .test_unwrap();
    }
    // This untouched head permits a genuine later writer append after padding
    // the earlier records without changing their signed canonical commitments.
    store
        .append_chio_receipt_returning_seq(&receipt(&key, 129, "foreign", 100))
        .test_unwrap();
    checkpoint(&store, &key, 129);
    let mut connection = rusqlite::Connection::open(&path).test_unwrap();
    connection.execute_batch("DROP TRIGGER chio_tool_receipts_reject_update; DROP TRIGGER claim_receipt_log_entries_reject_update;").test_unwrap();
    let transaction = connection.transaction().test_unwrap();
    for sequence in 1..=128 {
        let raw: String = transaction
            .query_row(
                "SELECT raw_json FROM claim_receipt_log_entries WHERE entry_seq = ?1",
                [sequence],
                |row| row.get(0),
            )
            .test_unwrap();
        let padded = format!("{raw}{}", " ".repeat(1024 * 1024 - raw.len()));
        transaction
            .execute(
                "UPDATE chio_tool_receipts SET raw_json = ?1 WHERE seq = ?2",
                rusqlite::params![padded, sequence],
            )
            .test_unwrap();
        transaction
            .execute(
                "UPDATE claim_receipt_log_entries SET raw_json = ?1 WHERE entry_seq = ?2",
                rusqlite::params![padded, sequence],
            )
            .test_unwrap();
    }
    transaction.commit().test_unwrap();
    let exact = collect_retained_session_receipts_read_only(
        &path,
        "target",
        &ReceiptReadContext::local_operator_admin_all(),
        &key.public_key(),
    )
    .test_unwrap();
    assert_eq!(exact.receipts().len(), 128);
    assert_eq!(exact.coverage().snapshot_end_entry_seq, 129);

    store
        .append_chio_receipt_returning_seq(&receipt(&key, 130, "target", 100))
        .test_unwrap();
    store.create_next_receipt_checkpoint(1, &key).test_unwrap();
    let error = collect_retained_session_receipts_read_only(
        &path,
        "target",
        &ReceiptReadContext::local_operator_admin_all(),
        &key.public_key(),
    )
    .test_unwrap_err();
    assert!(error.to_string().contains("session byte limit"));
}
