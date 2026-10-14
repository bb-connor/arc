//! A native receipt sink opens with its authority's bank attached before its
//! first write, and an unopened bank owes the sink nothing only once its
//! absence is authenticated.
use super::*;
use crate::SqliteReceiptStore;
use std::sync::Arc;

/// A signed ordinary tool receipt for the real serving append path.
fn ordinary_receipt(id: &str) -> chio_core::error::Result<chio_core::receipt::body::ChioReceipt> {
    let keypair = chio_core::crypto::Keypair::generate();
    chio_core::receipt::body::ChioReceipt::sign(
        chio_core::receipt::body::ChioReceiptBody {
            id: id.to_string(),
            timestamp: 1,
            capability_id: "cap-native-open-1".to_string(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action: chio_core::receipt::decision::ToolCallAction::from_parameters(
                serde_json::json!({ "receipt": id }),
            )?,
            decision: Some(chio_core::receipt::decision::Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: format!("content-{id}"),
            policy_hash: "policy-native-open-1".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        &keypair,
    )
}

/// The receipt's canonical bytes, exactly as the serving append path takes
/// them.
fn canonical_bytes(
    receipt: &chio_core::receipt::body::ChioReceipt,
) -> Result<chio_core::canonical::CanonicalBytes, Box<dyn std::error::Error>> {
    let value = serde_json::to_value(receipt)?;
    Ok(chio_core::canonical::CanonicalBytes::from_value(&value)?)
}

#[test]
fn a_fresh_receipt_sink_switches_to_wal_under_its_attached_bank(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture();
    let bank = fixture.operations.native_receipt_bank_attachment()?;
    let path = fixture.database.with_file_name("native-receipts.sqlite3");
    // The fresh file commits its switch to WAL in rollback journal mode while
    // the debt hook already checks every COMMIT.
    drop(SqliteReceiptStore::open_with_native_bank(&path, &bank)?);
    let mode: String =
        Connection::open(&path)?.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    assert_eq!(mode, "wal");
    drop(SqliteReceiptStore::open_with_native_bank(&path, &bank)?);
    Ok(())
}

/// Ordinary append and same-format reopen on an attached empty bank. This
/// regression does not establish preservation of an outstanding native loan.
#[test]
fn ordinary_appends_on_a_banked_sink_commit_and_grow_the_wal(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture();
    let bank = fixture.operations.native_receipt_bank_attachment()?;
    let path = fixture
        .database
        .with_file_name("native-receipts-priced.sqlite3");
    let store = SqliteReceiptStore::open_with_native_bank(&path, &bank)?;
    // Ordinary appends must remain usable when the actual write fits: each
    // is priced through the receipt write schema at Intake and commits.
    let wal_len = || {
        std::fs::metadata(format!("{}-wal", path.display()))
            .map(|data| data.len())
            .unwrap_or(0)
    };
    let before = wal_len();
    let mut receipts = Vec::new();
    for index in 0..4 {
        let receipt = ordinary_receipt(&format!("rcpt-priced-{index}"))?;
        store.append_chio_receipt_canonical(Arc::new(canonical_bytes(&receipt)?))?;
        receipts.push(receipt);
    }
    let after = wal_len();
    assert!(
        after > before,
        "ordinary priced appends must grow the WAL: {before} -> {after}"
    );
    for receipt in &receipts {
        assert!(store.native_receipt_retained(receipt)?);
    }
    drop(store);
    // Same-format reopen under the same bank keeps the retained history.
    let reopened = SqliteReceiptStore::open_with_native_bank(&path, &bank)?;
    for receipt in &receipts {
        assert!(reopened.native_receipt_retained(receipt)?);
    }
    Ok(())
}

#[test]
fn an_unopened_bank_owes_a_receipt_sink_nothing_only_when_authenticated(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture();
    let reader = Connection::open_with_flags(
        &fixture.database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let debt = crate::admission_operation_store::native_registered_file_debt(
        &reader,
        &fixture.fence.store_uuid,
        1,
        1,
    )?;
    assert!(
        debt.is_none(),
        "a current authority with an empty namespace"
    );
    assert!(
        crate::admission_operation_store::native_registered_file_debt(
            &reader,
            "another-serving-owner",
            1,
            1,
        )
        .is_err(),
        "another owner's view never reads as zero debt"
    );
    drop(reader);
    // An unsupported admission schema refuses instead of owing nothing.
    let writer = Connection::open(&fixture.database)?;
    writer.execute(
        "UPDATE main.chio_store_schema_versions SET version = version + 1
         WHERE store_key = 'admission_operation'",
        [],
    )?;
    assert!(
        crate::admission_operation_store::native_registered_file_debt(
            &writer,
            &fixture.fence.store_uuid,
            1,
            1,
        )
        .is_err()
    );
    Ok(())
}
