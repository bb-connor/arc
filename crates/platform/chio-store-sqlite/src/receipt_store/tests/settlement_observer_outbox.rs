use super::super::*;
use super::support::*;

fn claimed_lease(
    outcome: chio_kernel::SettlementObserverOutboxClaimOutcome,
) -> chio_kernel::SettlementObserverOutboxLease {
    match outcome {
        chio_kernel::SettlementObserverOutboxClaimOutcome::Claimed(lease) => lease,
        other => panic!("expected claimed settlement-observer outbox lease, got {other:?}"),
    }
}

#[test]
fn settlement_observer_outbox_public_bindings_enforce_byte_caps() {
    let path = unique_db_path("chio-observer-outbox-public-caps");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let oversized_receipt_id = "r".repeat(513);
    let oversized_claim_token = "t".repeat(513);
    let oversized_status = "s".repeat(65_537);

    assert!(store
        .claim_settlement_observer_outbox(&oversized_receipt_id, "token", 0, 1)
        .is_err());
    assert!(store
        .claim_settlement_observer_outbox("receipt", &oversized_claim_token, 0, 1)
        .is_err());
    assert!(store
        .stage_settlement_observer_outbox_status(&oversized_receipt_id, 0, "token", "{}",)
        .is_err());
    assert!(store
        .stage_settlement_observer_outbox_status("receipt", 0, &oversized_claim_token, "{}",)
        .is_err());
    assert!(store
        .stage_settlement_observer_outbox_status("receipt", 0, "token", &oversized_status,)
        .is_err());
    assert!(store
        .acknowledge_settlement_observer_outbox(&oversized_receipt_id, 0, "token")
        .is_err());
    assert!(store
        .acknowledge_settlement_observer_outbox("receipt", 0, &oversized_claim_token)
        .is_err());
    assert!(store
        .abandon_settlement_observer_outbox(&oversized_receipt_id, 0, "token", "error")
        .is_err());
    assert!(store
        .abandon_settlement_observer_outbox("receipt", 0, &oversized_claim_token, "error",)
        .is_err());

    let _ = fs::remove_file(path);
}

#[test]
fn settlement_observer_outbox_table_rejects_invalid_direct_rows() {
    let path = unique_db_path("chio-observer-outbox-direct-caps");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let connection = rusqlite::Connection::open(&path).test_unwrap();

    let oversized_receipt_id = "r".repeat(513);
    assert!(connection
        .execute(
            "INSERT INTO chio_settlement_observer_outbox (receipt_id, finalized_at) VALUES (?1, 0)",
            rusqlite::params![oversized_receipt_id],
        )
        .is_err());
    let oversized_claim_token = "t".repeat(513);
    assert!(connection
        .execute(
            "INSERT INTO chio_settlement_observer_outbox (receipt_id, finalized_at, state, claim_token, claim_deadline_unix_ms) VALUES ('bad-token', 0, 'claimed', ?1, 1)",
            rusqlite::params![oversized_claim_token],
        )
        .is_err());
    assert!(connection
        .execute(
            "INSERT INTO chio_settlement_observer_outbox (receipt_id, finalized_at, state, claim_token, claim_deadline_unix_ms) VALUES ('negative-deadline', 0, 'claimed', 'token', -1)",
            [],
        )
        .is_err());
    let oversized_status = "s".repeat(65_537);
    assert!(connection
        .execute(
            "INSERT INTO chio_settlement_observer_outbox (receipt_id, finalized_at, state, claim_token, claim_deadline_unix_ms, staged_status_json) VALUES ('bad-status', 0, 'routing', 'token', 1, ?1)",
            rusqlite::params![oversized_status],
        )
        .is_err());
    let oversized_error = "e".repeat(2_049);
    assert!(connection
        .execute(
            "INSERT INTO chio_settlement_observer_outbox (receipt_id, finalized_at, last_error) VALUES ('bad-error', 0, ?1)",
            rusqlite::params![oversized_error],
        )
        .is_err());

    drop(connection);
    drop(store);
    let _ = fs::remove_file(path);
}

#[test]
fn settlement_observer_outbox_open_rejects_tampered_schema_and_rows() {
    let schema_path = unique_db_path("chio-observer-outbox-schema-tamper");
    drop(SqliteReceiptStore::open(&schema_path).test_unwrap());
    {
        let connection = rusqlite::Connection::open(&schema_path).test_unwrap();
        connection
            .execute_batch(
                r#"
                DROP TRIGGER chio_settlement_observer_outbox_validate_update;
                CREATE TRIGGER chio_settlement_observer_outbox_validate_update
                BEFORE UPDATE ON chio_settlement_observer_outbox
                BEGIN
                    SELECT 1;
                END;
                "#,
            )
            .test_unwrap();
    }
    let schema_error = SqliteReceiptStore::open_existing(&schema_path).test_unwrap_err();
    assert!(
        schema_error
            .to_string()
            .contains("outbox integrity triggers are missing or invalid"),
        "unexpected schema error: {schema_error}"
    );

    let row_path = unique_db_path("chio-observer-outbox-row-tamper");
    drop(SqliteReceiptStore::open(&row_path).test_unwrap());
    {
        let connection = rusqlite::Connection::open(&row_path).test_unwrap();
        connection
            .execute_batch("PRAGMA ignore_check_constraints = ON;")
            .test_unwrap();
        connection
            .execute(
                "INSERT INTO chio_settlement_observer_outbox (receipt_id, finalized_at, state, claim_token, claim_deadline_unix_ms) VALUES ('invalid-row', 0, 'claimed', 'token', -1)",
                [],
            )
            .test_unwrap();
    }
    let row_error = SqliteReceiptStore::open_existing(&row_path).test_unwrap_err();
    assert!(
        row_error
            .to_string()
            .contains("outbox contains an invalid persisted row"),
        "unexpected row error: {row_error}"
    );

    let _ = fs::remove_file(schema_path);
    let _ = fs::remove_file(row_path);
}

#[test]
fn routing_abandon_preserves_staged_bytes_and_is_immediately_reclaimable() {
    let path = unique_db_path("chio-observer-outbox-routing-abandon");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let receipt = sample_receipt_with_id("observer-routing-abandon");
    store
        .append_chio_receipt_with_settlement_observer_outbox_with_timeout(
            &receipt,
            Duration::from_secs(1),
        )
        .test_unwrap();

    let claimed = claimed_lease(
        store
            .claim_settlement_observer_outbox(&receipt.id, "first-token", 10, 20)
            .test_unwrap(),
    );
    let staged_status = r#"{"outcome":"retry","reason":"transient"}"#;
    let routing = store
        .stage_settlement_observer_outbox_status(
            &receipt.id,
            claimed.version,
            &claimed.claim_token,
            staged_status,
        )
        .test_unwrap()
        .test_expect("claimed lease must stage");
    let long_error = "é".repeat(2_000);
    assert!(store
        .abandon_settlement_observer_outbox(
            &receipt.id,
            routing.version,
            &routing.claim_token,
            &long_error,
        )
        .test_unwrap());

    let connection = store.connection().test_unwrap();
    let (state, deadline, staged, error_bytes): (String, i64, String, i64) = connection
        .query_row(
            "SELECT state, claim_deadline_unix_ms, staged_status_json, length(CAST(last_error AS BLOB)) FROM chio_settlement_observer_outbox WHERE receipt_id = ?1",
            rusqlite::params![receipt.id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .test_unwrap();
    assert_eq!(state, "routing");
    assert_eq!(deadline, 0);
    assert_eq!(staged.as_bytes(), staged_status.as_bytes());
    assert_eq!(error_bytes, 2_048);
    drop(connection);

    assert_eq!(
        store
            .list_settlement_observer_outbox_receipt_ids(0, 1)
            .test_unwrap(),
        vec![receipt.id.clone()]
    );
    let reclaimed = claimed_lease(
        store
            .claim_settlement_observer_outbox(&receipt.id, "second-token", 0, 1)
            .test_unwrap(),
    );
    assert_eq!(reclaimed.staged_status_json.as_deref(), Some(staged_status));
    assert!(store
        .acknowledge_settlement_observer_outbox(
            &receipt.id,
            reclaimed.version,
            &reclaimed.claim_token,
        )
        .test_unwrap());

    let _ = fs::remove_file(path);
}
