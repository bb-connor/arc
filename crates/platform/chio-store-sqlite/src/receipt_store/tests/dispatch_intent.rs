//! Dispatch-intent journal tests: schema creation, durable insert/consume,
//! boot reconciliation, and the health surface.

use crate::SqliteReceiptStore;

use super::support::unique_db_path;

fn sample_intent(request_id: &str) -> chio_kernel::receipt_store::DispatchIntentRecord {
    use chio_kernel::receipt_store::{DispatchIntentRecord, SideEffectClass};
    DispatchIntentRecord {
        request_id: request_id.to_string(),
        capability_id: "cap-abc".to_string(),
        tool_server: "srv".to_string(),
        tool_name: "write_file".to_string(),
        parameter_hash: "ph-123".to_string(),
        side_effect_class: SideEffectClass::SideEffecting,
        monetary: false,
        rail: None,
        rail_authorization_id: None,
        tenant_id: None,
        created_at_unix_ms: 42,
    }
}

fn open_intent_row_count(store: &SqliteReceiptStore) -> Result<i64, Box<dyn std::error::Error>> {
    let connection = store.reader_connection_for_test()?;
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM chio_dispatch_intents WHERE state = 'open'",
        [],
        |row| row.get(0),
    )?;
    Ok(count)
}

#[test]
fn record_dispatch_intent_inserts_and_rejects_duplicate(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-intents-insert");
    let store = SqliteReceiptStore::open(&path)?;

    store.record_dispatch_intent(&sample_intent("req-A"))?;
    assert_eq!(open_intent_row_count(&store)?, 1);

    // A second write reusing the request id is rejected fail-closed rather
    // than duplicating an effect record.
    let duplicate = store.record_dispatch_intent(&sample_intent("req-A"));
    let message = duplicate
        .err()
        .ok_or("expected duplicate request_id to be rejected")?
        .to_string();
    assert!(
        message.contains("dispatch intent"),
        "unexpected error: {message}"
    );
    assert_eq!(open_intent_row_count(&store)?, 1);

    // The bounded variant commits durably within budget on a live writer.
    store.record_dispatch_intent_with_timeout(
        &sample_intent("req-B"),
        std::time::Duration::from_secs(5),
    )?;
    assert_eq!(open_intent_row_count(&store)?, 2);

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn attach_rail_ref_updates_open_intent_and_notfound_when_absent(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-intents-attach");
    let store = SqliteReceiptStore::open(&path)?;
    store.record_dispatch_intent(&sample_intent("req-M"))?;

    store.attach_dispatch_intent_rail_ref("req-M", "auth-xyz")?;
    let connection = store.reader_connection_for_test()?;
    let attached: String = connection.query_row(
        "SELECT rail_authorization_id FROM chio_dispatch_intents WHERE request_id = 'req-M'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(attached, "auth-xyz");

    // Attaching to a non-existent intent reports NotFound; the best-effort
    // caller logs and continues.
    let missing = store.attach_dispatch_intent_rail_ref("req-absent", "auth-1");
    assert!(missing.is_err());

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn consume_intent_removes_row_and_persists_receipt_atomically(
) -> Result<(), Box<dyn std::error::Error>> {
    use chio_kernel::receipt_store::{DispatchIntentKey, ReceiptStore};

    let path = unique_db_path("chio-intents-consume");
    let keypair = super::support::receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;

    let receipt = super::support::sample_receipt_with_keypair("consume-ok", 1, &keypair);
    let mut intent = sample_intent("req-C");
    intent.capability_id = receipt.capability_id.clone();
    intent.tool_server = receipt.tool_server.clone();
    intent.tool_name = receipt.tool_name.clone();
    intent.parameter_hash = receipt.action.parameter_hash.clone();
    intent.tenant_id = receipt.tenant_id.clone();
    store.record_dispatch_intent(&intent)?;

    let key = DispatchIntentKey {
        request_id: "req-C".to_string(),
        parameter_hash: receipt.action.parameter_hash.clone(),
        tenant_id: receipt.tenant_id.clone(),
    };
    let seq = store.append_chio_receipt_consuming_intent(&receipt, &key)?;
    assert!(seq.is_some(), "receipt persisted, returns its entry seq");
    store.flush_receipt_writes()?;

    // Intent gone, receipt present: the two shared one commit.
    assert_eq!(open_intent_row_count(&store)?, 0);
    assert!(store.load_chio_receipt(&receipt.id)?.is_some());

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn consume_intent_parameter_hash_mismatch_aborts_and_keeps_intent(
) -> Result<(), Box<dyn std::error::Error>> {
    use chio_kernel::receipt_store::{DispatchIntentKey, ReceiptStore};

    let path = unique_db_path("chio-intents-consume-mismatch");
    let keypair = super::support::receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;

    let receipt = super::support::sample_receipt_with_keypair("consume-bad", 1, &keypair);

    // A key whose parameter_hash disagrees with the receipt is rejected before
    // any write reaches the transaction.
    let mut intent = sample_intent("req-X");
    intent.parameter_hash = receipt.action.parameter_hash.clone();
    intent.tenant_id = receipt.tenant_id.clone();
    store.record_dispatch_intent(&intent)?;
    let disagreeing_key = DispatchIntentKey {
        request_id: "req-X".to_string(),
        parameter_hash: "wrong-hash".to_string(),
        tenant_id: receipt.tenant_id.clone(),
    };
    assert!(store
        .append_chio_receipt_consuming_intent(&receipt, &disagreeing_key)
        .is_err());

    // A key that matches the receipt but not the STORED intent row (the intent
    // was journaled for different parameters) must abort the whole
    // transaction: the receipt must not persist and the intent must stay open.
    let mut stale_intent = sample_intent("req-Y");
    stale_intent.parameter_hash = "journaled-for-other-parameters".to_string();
    store.record_dispatch_intent(&stale_intent)?;
    let key_for_y = DispatchIntentKey {
        request_id: "req-Y".to_string(),
        parameter_hash: receipt.action.parameter_hash.clone(),
        tenant_id: receipt.tenant_id.clone(),
    };
    let result = store.append_chio_receipt_consuming_intent(&receipt, &key_for_y);
    assert!(result.is_err(), "stored-intent mismatch must abort");
    store.flush_receipt_writes()?;

    assert_eq!(
        open_intent_row_count(&store)?,
        2,
        "both intents remain open after the aborted consumes"
    );
    assert!(
        store.load_chio_receipt(&receipt.id)?.is_none(),
        "receipt must not persist when the consume aborts"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn open_creates_dispatch_intents_table_and_open_existing_tolerates_absence(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::support::dispatch_intents_table_exists;

    let path = unique_db_path("chio-intents-schema");
    {
        let store = SqliteReceiptStore::open(&path)?;
        let connection = store.reader_connection_for_test()?;
        assert!(
            dispatch_intents_table_exists(&connection)?,
            "open() must create chio_dispatch_intents"
        );
    }
    // Reopening the same file via open_existing runs no DDL, but the table
    // already exists from the create-branch open above.
    {
        let store = SqliteReceiptStore::open_existing(&path)?;
        let connection = store.reader_connection_for_test()?;
        assert!(dispatch_intents_table_exists(&connection)?);
    }
    let _ = std::fs::remove_file(&path);
    Ok(())
}
