//! Preserve v1 commit hashes and rollback anchors while introducing a separate
//! authority-observed clock. Historical rows deliberately retain NULL here.

use super::*;

/// Rebuilding a referenced parent must not redirect child foreign keys to the
/// temporary table name. This is an offline upgrade under the serving lock;
/// the migration verifies all foreign keys before committing, and restores
/// both connection settings on success and failure before any serving use.
pub(super) fn preserving_parent_names(
    connection: &mut Connection,
    migrate: impl FnOnce(&mut Connection) -> Result<(), AdmissionOperationStoreError>,
) -> Result<(), AdmissionOperationStoreError> {
    if !connection.is_autocommit() {
        return Err(invariant(
            "admission schema upgrade requires its own transaction",
        ));
    }
    let foreign_keys: bool = connection
        .pragma_query_value(None, "foreign_keys", |row| row.get(0))
        .map_err(sqlite_error)?;
    let legacy_alter: bool = connection
        .pragma_query_value(None, "legacy_alter_table", |row| row.get(0))
        .map_err(sqlite_error)?;
    let result = (|| {
        connection
            .pragma_update(None, "foreign_keys", false)
            .map_err(sqlite_error)?;
        connection
            .pragma_update(None, "legacy_alter_table", true)
            .map_err(sqlite_error)?;
        migrate(connection)
    })();
    let restore_foreign = connection.pragma_update(None, "foreign_keys", foreign_keys);
    let restore_legacy = connection.pragma_update(None, "legacy_alter_table", legacy_alter);
    restore_foreign.map_err(sqlite_error)?;
    restore_legacy.map_err(sqlite_error)?;
    result
}

pub(super) fn migrate_commit_observation_clock(
    transaction: &Transaction<'_>,
) -> Result<(), AdmissionOperationStoreError> {
    if !table_exists(transaction, "admission_operation_commits")? {
        return Ok(());
    }
    let has_observation: bool = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('admission_operation_commits') WHERE name = 'observed_at_unix_ms')",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    // Earlier schema migrations may already have rebuilt this table using the
    // current canonical definition. Its full catalog is checked before commit.
    if has_observation {
        return Ok(());
    }
    transaction
        .execute_batch(
            r#"
            DROP TRIGGER admission_operation_commits_exact_lease;
            DROP TRIGGER admission_operation_commits_immutable;
            DROP TRIGGER admission_operation_commits_no_delete;
            DROP INDEX admission_operation_commits_operation;
            ALTER TABLE admission_operation_commits RENAME TO admission_operation_commits_v16;
            "#,
        )
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(ADMISSION_OPERATION_SCHEMA)
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(
            r#"
            DROP TRIGGER admission_operation_commits_exact_lease;
            INSERT INTO admission_operation_commits (
                commit_sequence, operation_id, operation_version, mutation_kind,
                operation_digest, recovery_claim_digest, participant_digest,
                previous_chain_digest, chain_digest, store_uuid, store_lease_id,
                store_owner_epoch, recorded_at_unix_ms
            )
            SELECT commit_sequence, operation_id, operation_version, mutation_kind,
                   operation_digest, recovery_claim_digest, participant_digest,
                   previous_chain_digest, chain_digest, store_uuid, store_lease_id,
                   store_owner_epoch, recorded_at_unix_ms
            FROM admission_operation_commits_v16 ORDER BY commit_sequence;
            DROP TABLE admission_operation_commits_v16;
            "#,
        )
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(ADMISSION_OPERATION_SCHEMA)
        .map_err(sqlite_error)
}
