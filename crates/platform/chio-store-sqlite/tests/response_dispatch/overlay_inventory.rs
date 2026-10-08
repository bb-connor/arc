use super::*;

#[test]
fn overlay_inventory_rejects_unreadable_scheduler_retry_schema() {
    for damage in [
        "DROP TABLE security_scheduler_retries",
        "ALTER TABLE security_scheduler_retries RENAME COLUMN action_id TO damaged_action_id",
    ] {
        let directory = chio_test_support::private_tempdir()
            .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
        let path = directory.path().join("inventory-retry-schema.db");
        let store = SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("security store open failed: {error}"));
        let inventory = store
            .active_defense_overlay_inventory()
            .unwrap_or_else(|error| panic!("healthy inventory failed: {error}"));
        assert!(!inventory.has_active_contributions());
        let connection = rusqlite::Connection::open(&path)
            .unwrap_or_else(|error| panic!("inventory fault connection failed: {error}"));
        connection
            .execute_batch(damage)
            .unwrap_or_else(|error| panic!("damage retry schema failed: {error}"));

        let error = rejected(
            store.active_defense_overlay_inventory(),
            "inventory silently accepted unreadable scheduler retry state",
        );
        assert_eq!(error.kind(), PortErrorKind::Unavailable);
    }
}
