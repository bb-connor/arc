//! Unsigned archive cursor projections must remain unique and complete.
use super::*;

#[test]
fn p0p1_retained_filter_rejects_extra_unconstrained_source_or_lineage_rows() {
    for lineage in [false, true] {
        let (_directory, store, archive) = retained_fixture();
        let connection = Connection::open(&archive).unwrap();
        if lineage {
            connection
                .execute_batch(
                    "CREATE TABLE extra_lineage AS SELECT * FROM capability_lineage;
                 DROP TABLE capability_lineage;
                 ALTER TABLE extra_lineage RENAME TO capability_lineage;
                 INSERT INTO capability_lineage (capability_id, subject_key, issuer_key)
                 VALUES ('cap', NULL, NULL), ('cap', 'forged-subject', NULL);",
                )
                .unwrap();
        } else {
            connection.execute_batch(
                "CREATE TABLE extra_receipts AS SELECT * FROM chio_tool_receipts;
                 DROP TABLE chio_tool_receipts;
                 ALTER TABLE extra_receipts RENAME TO chio_tool_receipts;
                 INSERT INTO chio_tool_receipts SELECT * FROM chio_tool_receipts WHERE seq = 1;
                 UPDATE chio_tool_receipts SET tool_name = 'forged-filter' WHERE rowid = (SELECT MAX(rowid) FROM chio_tool_receipts);",
            ).unwrap();
        }
        let error = store
            .query_receipts(&ReceiptQuery {
                tool_name: (!lineage).then(|| "forged-filter".into()),
                ..ReceiptQuery::default().local_operator_admin()
            })
            .unwrap_err();
        assert!(matches!(error, ReceiptStoreError::Conflict(_)), "{error}");
    }
}

#[test]
fn p0p1_retained_pages_reject_archive_source_sequence_collision() {
    let (_directory, store, archive) = retained_fixture();
    let connection = Connection::open(&archive).unwrap();
    connection
        .execute_batch(
            "UPDATE chio_tool_receipts SET seq = 3 WHERE seq = 1;
         UPDATE claim_receipt_log_entries SET source_seq = 3 WHERE entry_seq = 1;",
        )
        .unwrap();
    let error = store
        .query_receipts(&ReceiptQuery {
            limit: 1,
            ..ReceiptQuery::default().local_operator_admin()
        })
        .unwrap_err();
    assert!(matches!(error, ReceiptStoreError::Conflict(_)), "{error}");
}

#[test]
fn p0p1_retained_pages_reject_duplicate_archive_sequences_without_schema_trust() {
    let (_directory, store, archive) = retained_fixture();
    let connection = Connection::open(&archive).unwrap();
    // Payload authentication does not authenticate the archive DDL.
    connection
        .execute_batch(
            "CREATE TABLE unconstrained_receipts AS SELECT * FROM chio_tool_receipts;
         DROP TABLE chio_tool_receipts;
         ALTER TABLE unconstrained_receipts RENAME TO chio_tool_receipts;
         UPDATE chio_tool_receipts SET seq = 1;
         UPDATE claim_receipt_log_entries SET source_seq = 1 WHERE receipt_kind = 'tool_receipt';",
        )
        .unwrap();
    let error = store
        .query_receipts(&ReceiptQuery {
            limit: 1,
            ..ReceiptQuery::default().local_operator_admin()
        })
        .unwrap_err();
    assert!(matches!(error, ReceiptStoreError::Conflict(_)), "{error}");
}

#[test]
fn p0p1_retained_export_rejects_source_sequences_beyond_live_allocator() {
    for (table, entry) in [("chio_tool_receipts", 1), ("chio_child_receipts", 3)] {
        let (_directory, store, archive) = retained_fixture();
        let connection = Connection::open(&archive).unwrap();
        connection
            .execute(&format!("UPDATE {table} SET seq = 1000 WHERE seq = 1"), [])
            .unwrap();
        connection
            .execute(
                "UPDATE claim_receipt_log_entries SET source_seq = 1000 WHERE entry_seq = ?1",
                [entry],
            )
            .unwrap();
        let error = store
            .build_evidence_export_bundle(&EvidenceExportQuery::admin_all())
            .unwrap_err();
        assert!(
            matches!(
                error,
                EvidenceExportError::ReceiptStore(ReceiptStoreError::Conflict(_))
            ),
            "{table}: {error}"
        );
    }
}

#[test]
fn p0p1_retained_export_rejects_collision_at_native_page_boundary() {
    let (_directory, store, archive) = retained_fixture();
    for index in 4..=201 {
        store
            .append_chio_receipt_returning_seq(&receipt_with_ts_and_tenant(
                &format!("live-{index}"),
                "cap",
                102,
                Some("a"),
            ))
            .unwrap();
    }
    let connection = Connection::open(&archive).unwrap();
    connection
        .execute_batch(
            "UPDATE chio_tool_receipts SET seq = 201 WHERE seq = 1;
         UPDATE claim_receipt_log_entries SET source_seq = 201 WHERE entry_seq = 1;",
        )
        .unwrap();
    let error = store
        .build_evidence_export_bundle(&EvidenceExportQuery::admin_all())
        .unwrap_err();
    assert!(
        matches!(
            error,
            EvidenceExportError::ReceiptStore(ReceiptStoreError::Conflict(_))
        ),
        "{error}"
    );
}
