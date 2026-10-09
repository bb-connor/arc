//! Schema-version behavior across the stores that share a database file.

use crate::CHIO_SQLITE_APPLICATION_ID;
use rusqlite::Connection;

#[test]
fn every_own_file_store_stamps_application_id() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    crate::test_authority::secure_directory(dir.path());
    let stamped = |name: &str| -> Result<i32, Box<dyn std::error::Error>> {
        let conn = Connection::open(dir.path().join(name))?;
        Ok(conn.query_row("PRAGMA application_id", [], |r| r.get(0))?)
    };

    crate::SqliteRevocationStore::open(dir.path().join("revocation.db"))?;
    crate::SqliteBudgetStore::open(dir.path().join("budget.db"))?;
    crate::SqliteApprovalStore::open(dir.path().join("approval.db"))?;
    crate::SqliteExecutionNonceStore::open(
        dir.path().join("nonce.db"),
        chio_test_support::clock::clock(),
    )?;
    crate::SqliteMemoryProvenanceStore::open(dir.path().join("provenance.db"))?;
    crate::SqliteEncryptedBlobStore::open(dir.path().join("blob.db"))?;
    crate::SqliteCapabilityAuthority::open(dir.path().join("authority.db"))?;

    for name in [
        "revocation.db",
        "budget.db",
        "approval.db",
        "nonce.db",
        "provenance.db",
        "blob.db",
        "authority.db",
    ] {
        assert_eq!(
            stamped(name)?,
            CHIO_SQLITE_APPLICATION_ID,
            "{name} not stamped"
        );
    }
    Ok(())
}

#[test]
fn approval_store_adopts_a_receipt_first_sidecar_file() -> Result<(), Box<dyn std::error::Error>> {
    // `chio api protect` opens the receipt store first on one shared sidecar
    // file, then co-locates the approval store onto it. The approval store's
    // co-located open must adopt the receipt-anchored file rather than reject
    // it as another store's database.
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("sidecar.db");
    crate::SqliteReceiptStore::open(&path)?;
    crate::SqliteApprovalStore::open_colocated_with_receipt_store(&path)?;
    Ok(())
}

#[test]
fn receipt_store_refuses_a_standalone_approval_database() -> Result<(), Box<dyn std::error::Error>>
{
    // A `--receipt-db` mistargeted at a standalone approval database must
    // fail closed. The receipt store carries no approval table among its
    // anchors, so it refuses the file rather than adopting it and commingling
    // receipt tables into an approval store's database.
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("approval.db");
    crate::SqliteApprovalStore::open(&path)?;
    assert!(crate::SqliteReceiptStore::open(&path).is_err());
    Ok(())
}

#[test]
fn receipt_store_refuses_a_stamped_budget_database() -> Result<(), Box<dyn std::error::Error>> {
    // A path mistargeted at a budget database must fail closed instead of
    // writing receipt tables into another store's file.
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("budget.db");
    crate::SqliteBudgetStore::open(&path)?;
    assert!(crate::SqliteReceiptStore::open(&path).is_err());
    Ok(())
}

#[test]
fn approval_store_refuses_a_standalone_revocation_database(
) -> Result<(), Box<dyn std::error::Error>> {
    // The revocation store lives in its own file alongside the sidecar
    // database. A `--receipt-store` mistargeted at that revocation file must
    // fail closed: `chio api protect` opens the approval store first, so if a
    // lone `revoked_capabilities` table let it adopt the file, it would write
    // approval tables into the revocation database and the receipt store would
    // then accept the commingled file too.
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("sidecar.db.revocations");
    crate::SqliteRevocationStore::open(&path)?;
    assert!(crate::SqliteApprovalStore::open(&path).is_err());
    assert!(crate::SqliteReceiptStore::open(&path).is_err());
    Ok(())
}
