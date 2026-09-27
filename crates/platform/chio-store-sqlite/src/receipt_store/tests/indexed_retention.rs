//! Logical security identity must survive payload retention without trusting a path.
use super::support::*;
use chio_core::receipt::security::{
    ActiveDefensePolicyBinding, ActiveDefenseReceiptBody, ActiveDefenseReceiptHeader,
    FlowDenialReceiptBody,
};
use chio_security_types::ports::{
    Digest32, ErrorCode, EventId, OpaqueReceiptRef, RecordId, TenantId,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn indexed_receipt() -> TestResult<(OpaqueReceiptRef, ChioReceipt)> {
    let active = ActiveDefenseReceiptBody::FlowDenial(FlowDenialReceiptBody {
        header: ActiveDefenseReceiptHeader::new(
            100_000,
            TenantId::new("indexed-tenant")?,
            RecordId::new("flow-transition")?,
            vec![],
        )?,
        policy: ActiveDefensePolicyBinding {
            policy_version: RecordId::new("policy-v1")?,
            policy_hash: Digest32::new([1; 32]),
        },
        request_hash: Digest32::new([2; 32]),
        source_label_hash: Digest32::new([3; 32]),
        destination_label_hash: Digest32::new([4; 32]),
        guard_evidence_hash: Digest32::new([5; 32]),
        denial_code: ErrorCode::new("flow_denied")?,
        event_id: EventId::new("flow-event")?,
    });
    let evidence_id = active.evidence_id()?;
    let keypair = receipt_test_keypair();
    let mut body = sample_receipt_with_keypair_and_timestamp("indexed", 1, 100, &keypair).body();
    body.tool_origin = chio_core::receipt::kinds::ToolOrigin::ChioInternal;
    body.tool_server = "chio.kernel".to_owned();
    body.tool_name = active.kind().as_str().to_owned();
    body.tenant_id = Some(active.header().tenant_id.as_str().to_owned());
    body.content_hash = hex::encode(active.body_digest()?.as_bytes());
    body.metadata = Some(serde_json::json!({
        "active_defense_evidence_id": evidence_id.as_str(), "active_defense_body": active,
    }));
    Ok((evidence_id, ChioReceipt::sign(body, &keypair)?))
}

fn archive_indexed_receipt(
    store: &SqliteReceiptStore,
    archive: &std::path::Path,
) -> TestResult<(OpaqueReceiptRef, ChioReceipt)> {
    let (id, receipt) = indexed_receipt()?;
    store.append_indexed_security_evidence(&id, &receipt)?;
    store.create_next_receipt_checkpoint(1, &receipt_test_keypair())?;
    assert_eq!(
        store.archive_receipts_before(3_000, archive.to_str().ok_or("invalid archive path")?)?,
        1
    );
    Ok((id, receipt))
}

fn assert_exact(
    store: &SqliteReceiptStore,
    id: &OpaqueReceiptRef,
    expected: &ChioReceipt,
) -> TestResult {
    let loaded = store
        .load_indexed_security_evidence(id)?
        .ok_or("indexed evidence missing")?;
    assert_eq!(
        serde_json::to_value(&loaded)?,
        serde_json::to_value(expected)?
    );
    let replayed = store.append_indexed_security_evidence(id, expected)?;
    assert_eq!(
        serde_json::to_value(&replayed)?,
        serde_json::to_value(expected)?
    );
    Ok(())
}

#[test]
fn logical_identity_survives_retention_restart_and_exact_retry() -> TestResult {
    for incremental_verification in [false, true] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("live.db");
        let archive = directory.path().join("archive.db");
        let store = SqliteReceiptStore::open_with_options(
            &path,
            crate::SqliteStoreOptions {
                incremental_verification,
                ..crate::SqliteStoreOptions::default()
            },
        )?;
        let (id, receipt) = indexed_receipt()?;
        store.append_indexed_security_evidence(&id, &receipt)?;
        assert_exact(&store, &id, &receipt)?;
        archive_indexed_receipt(&store, &archive)?;
        assert_eq!(store.tool_receipt_count()?, 0);
        assert_exact(&store, &id, &receipt)?;
        store.ensure_indexed_security_evidence_ready()?;
        drop(store);

        let reopened = SqliteReceiptStore::open_existing_with_options(
            &path,
            crate::SqliteStoreOptions {
                incremental_verification,
                ..crate::SqliteStoreOptions::default()
            },
        )?;
        reopened.ensure_indexed_security_evidence_ready()?;
        assert_exact(&reopened, &id, &receipt)?;
        assert_eq!(
            reopened.tool_receipt_count()?,
            0,
            "retry must not restore the live payload"
        );
        // Same logical body with a different signed envelope cannot remap identity.
        let mut body = receipt.body();
        body.timestamp += 1;
        let conflicting = ChioReceipt::sign(body, &receipt_test_keypair())?;
        assert!(
            matches!(reopened.append_indexed_security_evidence(&id, &conflicting),
            Err(ReceiptStoreError::Conflict(message)) if message.contains("already mapped to a different receipt"))
        );
        assert_exact(&reopened, &id, &receipt)?;

        let archived = rusqlite::Connection::open(&archive)?;
        let mapped: String = archived.query_row(
            "SELECT receipt_id FROM chio_security_evidence_index WHERE evidence_id = ?1",
            [id.as_str()],
            |row| row.get(0),
        )?;
        assert_eq!(mapped, receipt.id);
        for statement in [
            "UPDATE chio_security_evidence_index SET receipt_id = 'forged'",
            "DELETE FROM chio_security_evidence_index",
        ] {
            assert!(
                matches!(archived.execute(statement, []), Err(rusqlite::Error::SqliteFailure(error, Some(message)))
                if error.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_TRIGGER && message == "security evidence index entries are immutable")
            );
        }
        drop(archived);
        // Writable open rebuilds the archive's checkpoint projections before
        // the normal indexed read API verifies the archived signed evidence.
        let archived_store = SqliteReceiptStore::open(&archive)?;
        let loaded = archived_store
            .load_indexed_security_evidence(&id)?
            .ok_or("archive lost logical identity")?;
        assert_eq!(
            serde_json::to_value(loaded)?,
            serde_json::to_value(&receipt)?
        );
    }
    Ok(())
}

#[test]
fn logical_identity_survives_version_five_migration_after_retention() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("live.db");
    let archive = directory.path().join("archive.db");
    let store = SqliteReceiptStore::open(&path)?;
    let (id, receipt) = archive_indexed_receipt(&store, &archive)?;
    drop(store);
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute_batch("ALTER TABLE chio_tool_receipts DROP COLUMN attempted_cost_be")?;
    crate::stamp_schema_version(&connection, "receipt", 5)?;
    drop(connection);
    let migrated = SqliteReceiptStore::open(&path)?;
    migrated.ensure_indexed_security_evidence_ready()?;
    assert_exact(&migrated, &id, &receipt)?;
    assert_eq!(migrated.tool_receipt_count()?, 0);
    drop(migrated);
    assert_exact(&SqliteReceiptStore::open_existing(&path)?, &id, &receipt)?;
    Ok(())
}

#[test]
fn indexed_retention_rejects_missing_corrupt_and_replaced_archive_payloads() -> TestResult {
    for fault in ["missing", "corrupt", "replacement"] {
        let directory = tempfile::tempdir()?;
        let archive = directory.path().join("archive.db");
        let store = SqliteReceiptStore::open(directory.path().join("live.db"))?;
        let (id, receipt) = archive_indexed_receipt(&store, &archive)?;
        // Warm the trust path before mutation, catching stale cached validation.
        assert_exact(&store, &id, &receipt)?;
        if fault == "replacement" {
            let replacement = directory.path().join("replacement.db");
            // A valid unrelated Chio database is still the wrong archive.
            drop(SqliteReceiptStore::open(&replacement)?);
            std::fs::rename(&replacement, &archive)?;
        } else {
            #[cfg(unix)]
            let inode = {
                use std::os::unix::fs::MetadataExt;
                std::fs::metadata(&archive)?.ino()
            };
            let connection = rusqlite::Connection::open(&archive)?;
            connection.execute(
                if fault == "missing" {
                    "DELETE FROM chio_tool_receipts"
                } else {
                    "UPDATE chio_tool_receipts SET raw_json = '{}'"
                },
                [],
            )?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                assert_eq!(std::fs::metadata(&archive)?.ino(), inode);
            }
        }
        let read = store.load_indexed_security_evidence(&id);
        let retry = store.append_indexed_security_evidence(&id, &receipt);
        // The claim log retains signed canonical bytes separately from the
        // payload table. A missing/corrupt payload fails at point read; replacing
        // the whole archive also invalidates the checkpoint prefix proof.
        let expected_error = |error: &ReceiptStoreError, reading: bool| match (fault, error) {
            ("missing", ReceiptStoreError::ReadBoundary(message)) => {
                message == "indexed security receipt is absent from its authenticated archive"
            }
            ("corrupt", ReceiptStoreError::Conflict(message)) => {
                message.contains("indexed archived security receipt")
                    && message.contains("failed to decode")
            }
            ("replacement", ReceiptStoreError::Conflict(message)) if reading => {
                message == "claim receipt log has a gap in checkpoint signer binding 1..=1"
            }
            ("replacement", ReceiptStoreError::ReadBoundary(message)) if !reading => {
                message == "configured retention archive does not authenticate the recorded prefix"
            }
            _ => false,
        };
        assert!(
            matches!(&read, Err(error) if expected_error(error, true)),
            "fault {fault}: {read:?}"
        );
        assert!(
            matches!(&retry, Err(error) if expected_error(error, false)),
            "fault {fault}: {retry:?}"
        );
        assert_eq!(store.tool_receipt_count()?, 0);
    }
    Ok(())
}
