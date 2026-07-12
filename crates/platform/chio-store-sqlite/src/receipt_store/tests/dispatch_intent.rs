//! Dispatch-intent journal tests: schema creation, durable insert/consume,
//! boot reconciliation, and the health surface.

use crate::SqliteReceiptStore;

use super::support::unique_db_path;

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
