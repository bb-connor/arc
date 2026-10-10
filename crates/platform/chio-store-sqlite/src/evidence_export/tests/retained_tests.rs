use super::*;
use chio_kernel::ReceiptQuery;

fn copy_archive_tail(connection: &Connection, source: &str, source_seq: i64, entry_seq: i64) {
    for (table, seq, cutoff) in [
        ("chio_tool_receipts", "seq", source_seq),
        ("claim_receipt_log_entries", "entry_seq", entry_seq),
    ] {
        // Archive and upgraded live schema column order can differ. Copy the
        // named projection just as the real archive writer does.
        let mut statement = connection
            .prepare(&format!("PRAGMA table_info({table})"))
            .unwrap();
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .join(", ");
        connection.execute(&format!("INSERT INTO {table} ({columns}) SELECT {columns} FROM {source}.{table} WHERE {seq} >= ?1"), [cutoff]).unwrap();
    }
}

fn retained_fixture() -> (tempfile::TempDir, SqliteReceiptStore, std::path::PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let live = directory.path().join("live.db");
    let archive = directory.path().join("archive.db");
    let store = SqliteReceiptStore::open(&live).unwrap();
    for (index, tenant) in [(1, "a"), (2, "b")] {
        store
            .append_chio_receipt_returning_seq(&receipt_with_ts_and_tenant(
                &format!("old-{index}"),
                "cap",
                100,
                Some(tenant),
            ))
            .unwrap();
    }
    store
        .append_child_receipt(&child_receipt_with_ts_and_key(
            "child",
            100,
            &evidence_receipt_keypair(),
        ))
        .unwrap();
    let canonical = store.receipts_canonical_bytes_range(1, 3).unwrap();
    let checkpoint = build_checkpoint(
        1,
        1,
        3,
        &canonical.into_iter().map(|(_, b)| b).collect::<Vec<_>>(),
        &evidence_receipt_keypair(),
    )
    .unwrap();
    store.store_checkpoint(&checkpoint).unwrap();
    assert_eq!(
        store
            .archive_receipts_before(101, archive.to_str().unwrap())
            .unwrap(),
        2
    );
    store
        .append_chio_receipt_returning_seq(&receipt_with_ts_and_tenant(
            "live",
            "cap",
            102,
            Some("a"),
        ))
        .unwrap();
    (directory, store, archive)
}

#[path = "retained_tests/source_sequences.rs"]
mod source_sequences;

#[test]
fn retained_pages_preserve_sequence_scope_children_and_proofs() {
    let (_directory, store, _archive) = retained_fixture();
    let mut query = ReceiptQuery {
        limit: 1,
        ..ReceiptQuery::default().local_operator_admin()
    };
    let mut ids = Vec::new();
    loop {
        let page = store.query_receipts(&query).unwrap();
        assert_eq!(page.total_count, 3);
        ids.extend(page.receipts.into_iter().map(|row| row.seq));
        let Some(cursor) = page.next_cursor else {
            break;
        };
        query.cursor = Some(cursor);
    }
    assert_eq!(ids, vec![1, 2, 3]);
    let tenant = store
        .query_receipts(&ReceiptQuery::default().authenticated_tenant("a"))
        .unwrap();
    assert_eq!(tenant.total_count, 2);
    assert!(tenant
        .receipts
        .iter()
        .all(|r| r.receipt.tenant_id.as_deref() == Some("a")));
    let bundle = store
        .build_evidence_export_bundle(&EvidenceExportQuery::admin_all())
        .unwrap();
    assert_eq!(bundle.tool_receipts.len(), 3);
    assert_eq!(bundle.child_receipts.len(), 1);
    assert_eq!(bundle.inclusion_proofs.len(), 2);
    assert_eq!(bundle.uncheckpointed_receipts.len(), 1);
    for proof in &bundle.inclusion_proofs {
        let receipt = &bundle
            .tool_receipts
            .iter()
            .find(|r| r.seq == proof.receipt_seq)
            .unwrap()
            .receipt;
        let bytes = chio_core::canonical_json_bytes(receipt).unwrap();
        assert!(proof.verify(&bytes, &bundle.checkpoints[0].body.merkle_root));
    }
    assert!(store.query_receipts(&ReceiptQuery::default()).is_err());
}

#[test]
fn retained_queries_ignore_copied_but_uncommitted_archive_tail() {
    let (directory, store, archive) = retained_fixture();
    let connection = Connection::open(&archive).unwrap();
    connection
        .execute(
            "ATTACH DATABASE ?1 AS live",
            [directory.path().join("live.db").to_str().unwrap()],
        )
        .unwrap();
    copy_archive_tail(&connection, "live", 0, 0);
    let page = store
        .query_receipts(&ReceiptQuery {
            limit: 10,
            ..ReceiptQuery::default().local_operator_admin()
        })
        .unwrap();
    assert_eq!(page.total_count, 3);
    assert_eq!(page.receipts.len(), 3);
    let bundle = store
        .build_evidence_export_bundle(&EvidenceExportQuery::admin_all())
        .unwrap();
    assert_eq!(bundle.tool_receipts.len(), 3);
    assert_eq!(bundle.inclusion_proofs.len(), 2);
}

#[test]
fn retained_query_and_export_refuse_missing_or_corrupt_archive() {
    let (_directory, store, archive) = retained_fixture();
    let moved = archive.with_extension("saved");
    std::fs::rename(&archive, &moved).unwrap();
    assert!(store
        .query_receipts(&ReceiptQuery::default().local_operator_admin())
        .is_err());
    assert!(store
        .build_evidence_export_bundle(&EvidenceExportQuery::admin_all())
        .is_err());
    std::fs::rename(&moved, &archive).unwrap();
    let connection = Connection::open(&archive).unwrap();
    connection
        .execute_batch("DROP TABLE chio_tool_receipts")
        .unwrap();
    assert!(store
        .query_receipts(&ReceiptQuery::default().local_operator_admin())
        .is_err());
    assert!(store
        .build_evidence_export_bundle(&EvidenceExportQuery::admin_all())
        .is_err());
}

#[test]
fn retained_export_refuses_legacy_rows_without_decoding_or_resigning_them() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("legacy.db");
    let store = SqliteReceiptStore::open(&path).unwrap();
    let connection = Connection::open(&path).unwrap();
    connection.execute_batch("CREATE TABLE http_receipts (raw_json TEXT); INSERT INTO http_receipts VALUES (zeroblob(2000000));").unwrap();
    let error = store
        .build_evidence_export_bundle(&EvidenceExportQuery::admin_all())
        .unwrap_err();
    assert!(error.to_string().contains("legacy mutable receipt history"));
    assert_eq!(
        connection
            .query_row("SELECT length(raw_json) FROM http_receipts", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        2000000
    );
}

#[test]
fn retained_snapshot_reads_the_same_archive_inode_version_it_authenticated() {
    let (_directory, store, archive) = retained_fixture();
    let attacker = Connection::open(&archive).unwrap();
    attacker.pragma_update(None, "journal_mode", "WAL").unwrap();
    let read: Result<_, ReceiptStoreError> = store.with_retained_snapshot(|snapshot| {
        // A concurrent writer changes this very inode after authentication.
        // The ongoing operation must use its pinned snapshot, while the next
        // operation must reject the now-incomplete archive.
        attacker.execute_batch("DROP TABLE chio_tool_receipts")?;
        snapshot.query_receipts(&ReceiptQuery::default().local_operator_admin())
    });
    assert_eq!(read.unwrap().total_count, 3);
    assert!(store
        .query_receipts(&ReceiptQuery::default().local_operator_admin())
        .is_err());
}

#[test]
fn retained_point_reads_recover_archived_receipts_with_exact_tenant_authority() {
    let (_directory, store, _archive) = retained_fixture();
    let query = ReceiptQuery::default().authenticated_tenant("a");
    let old = store
        .query_receipts(&query)
        .unwrap()
        .receipts
        .remove(0)
        .receipt;
    let context = chio_kernel::ReceiptReadContext::authenticated_tenant("a");
    let loaded = store
        .load_chio_receipt_with_context(&old.id, &context)
        .unwrap();
    assert_eq!(
        loaded.as_ref().map(|r| &r.id),
        Some(&old.id),
        "point reads must return the same archived evidence as paginated reads"
    );
    let other = chio_kernel::ReceiptReadContext::authenticated_tenant("b");
    assert!(store
        .load_chio_receipt_with_context(&old.id, &other)
        .unwrap()
        .is_none());
}

#[test]
fn retained_native_point_read_rejects_an_uncommitted_archive_only_receipt() {
    let (directory, store, archive) = retained_fixture();
    let extra_path = directory.path().join("extra.db");
    let extra = SqliteReceiptStore::open(&extra_path).unwrap();
    let mut phantom = receipt_with_ts("extra", "foreign-cap", 104);
    for n in 1..=5 {
        phantom = receipt_with_ts(&format!("extra-{n}"), "foreign-cap", 104);
        extra.append_chio_receipt_returning_seq(&phantom).unwrap();
    }
    let connection = Connection::open(&archive).unwrap();
    connection
        .execute(
            "ATTACH DATABASE ?1 AS extra",
            [extra_path.to_str().unwrap()],
        )
        .unwrap();
    copy_archive_tail(&connection, "extra", 5, 5);
    assert!(
        store
            .load_retained_chio_receipt(&phantom.id)
            .unwrap()
            .is_none(),
        "an archive tail cannot supply authority absent from the committed live watermark"
    );
}

fn corrupt_archive_source(sql: &str) -> (tempfile::TempDir, SqliteReceiptStore, String) {
    let (directory, store, archive) = retained_fixture();
    let receipt = store
        .query_receipts(&ReceiptQuery::default().authenticated_tenant("a"))
        .unwrap()
        .receipts
        .remove(0)
        .receipt;
    let connection = Connection::open(archive).unwrap();
    connection
        .execute_batch(
            "DROP TRIGGER IF EXISTS chio_tool_receipts_reject_update;
        DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete;
        DROP TRIGGER IF EXISTS chio_child_receipts_reject_update;
        DROP TRIGGER IF EXISTS chio_child_receipts_reject_delete;",
        )
        .unwrap();
    connection.execute_batch(sql).unwrap();
    (directory, store, receipt.id)
}

#[test]
fn retained_projection_tool_deletion_cannot_silently_shorten_queries_or_exports() {
    let (_directory, store, id) =
        corrupt_archive_source("DELETE FROM chio_tool_receipts WHERE seq = 1");
    assert!(matches!(
        store.query_receipts(&ReceiptQuery::default().local_operator_admin()),
        Err(ReceiptStoreError::Conflict(_))
    ));
    assert!(matches!(
        store.load_chio_receipt_with_context(
            &id,
            &chio_kernel::ReceiptReadContext::authenticated_tenant("a")
        ),
        Err(ReceiptStoreError::Conflict(_))
    ));
    assert!(matches!(
        store.load_retained_chio_receipt(&id),
        Err(ReceiptStoreError::Conflict(_))
    ));
    assert!(matches!(
        store.build_evidence_export_bundle(&EvidenceExportQuery::admin_all()),
        Err(EvidenceExportError::ReceiptStore(
            ReceiptStoreError::Conflict(_)
        ))
    ));
}

#[test]
fn retained_projection_child_deletion_cannot_silently_shorten_export() {
    let (_directory, store, _) =
        corrupt_archive_source("DELETE FROM chio_child_receipts WHERE seq = 1");
    assert!(matches!(
        store.build_evidence_export_bundle(&EvidenceExportQuery::admin_all()),
        Err(EvidenceExportError::ReceiptStore(
            ReceiptStoreError::Conflict(_)
        ))
    ));
}

#[test]
fn retained_projection_filter_drift_rejects_before_filtering_or_counting() {
    for assignment in [
        "tenant_id = 'foreign'",
        "timestamp = 9999",
        "capability_id = 'foreign'",
        "tool_name = 'foreign'",
        "tool_server = 'foreign'",
        "decision_kind = 'deny'",
        "cost_currency = 'USD', cost_charged_be = zeroblob(8)",
        "subject_key = 'foreign'",
    ] {
        let (_directory, store, id) = corrupt_archive_source(&format!(
            "UPDATE chio_tool_receipts SET {assignment} WHERE seq = 1"
        ));
        assert!(
            matches!(
                store.query_receipts(&ReceiptQuery::default().authenticated_tenant("a")),
                Err(ReceiptStoreError::Conflict(_))
            ),
            "untrusted filter projection accepted: {assignment}"
        );
        assert!(
            matches!(
                store.load_retained_chio_receipt(&id),
                Err(ReceiptStoreError::Conflict(_))
            ),
            "untrusted point projection accepted: {assignment}"
        );
    }
}

#[test]
fn retained_projection_signed_payload_substitution_cannot_bypass_claim_commitment() {
    let (_directory, store, _) = corrupt_archive_source("UPDATE chio_tool_receipts SET raw_json = (SELECT raw_json FROM chio_tool_receipts WHERE seq = 2) WHERE seq = 1");
    assert!(matches!(
        store.query_receipts(&ReceiptQuery::default().local_operator_admin()),
        Err(ReceiptStoreError::Conflict(_))
    ));
    assert!(matches!(
        store.build_evidence_export_bundle(&EvidenceExportQuery::admin_all()),
        Err(EvidenceExportError::ReceiptStore(
            ReceiptStoreError::Conflict(_)
        ))
    ));
}
