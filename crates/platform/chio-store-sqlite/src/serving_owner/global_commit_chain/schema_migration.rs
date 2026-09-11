//! Upgrade only exact supported global-commit catalogs, preserving every
//! historical row and its existing chain digest.

use super::{
    global_schema_catalog, invalid, Connection, SqliteServingOwnerError, GLOBAL_COMMIT_SCHEMA,
};

pub(super) fn migrate_previous_global_commit_schema(
    connection: &Connection,
) -> Result<(), SqliteServingOwnerError> {
    let actual = global_schema_catalog(connection)?;
    let mut previous_schema = GLOBAL_COMMIT_SCHEMA.to_owned();
    let mut unsupported = Vec::new();
    let mut matched = false;
    for kind in [
        "security_participant_output",
        "native_dispatch_ledger",
        "security_participant_egress",
        "security_participant_state",
        "security_participant_migration",
        "dpop_replay_migration",
        "governed_approval_replay_migration",
        "runtime_replay_migration",
        "finding_status",
        "finding_challenge",
    ] {
        previous_schema = previous_schema.replace(&format!(", '{kind}'"), "");
        unsupported.push(kind);
        let expected = Connection::open_in_memory()?;
        expected.execute_batch(&previous_schema)?;
        if actual != global_schema_catalog(&expected)? {
            continue;
        }
        // A disabled CHECK must not smuggle a future projection into otherwise
        // canonical legacy DDL. Validate before any schema mutation.
        for kind in &unsupported {
            let exists: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM authority_global_commits WHERE projection_kind = ?1)",
                [kind],
                |row| row.get(0),
            )?;
            if exists {
                return Err(invalid(
                    "legacy global catalog contains an unqualified projection kind",
                ));
            }
        }
        matched = true;
        break;
    }
    if !matched {
        return Err(invalid("global authority commit schema is not canonical"));
    }
    let transaction = connection.unchecked_transaction()?;
    transaction.execute_batch(
        r#"
        DROP TRIGGER authority_global_commits_immutable;
        DROP TRIGGER authority_global_commits_no_delete;
        DROP INDEX authority_global_commits_projection;
        ALTER TABLE authority_global_commits
            RENAME TO authority_global_commits_previous;
        "#,
    )?;
    transaction.execute_batch(GLOBAL_COMMIT_SCHEMA)?;
    transaction.execute_batch(
        r#"
        INSERT INTO authority_global_commits
        SELECT * FROM authority_global_commits_previous;
        DROP TABLE authority_global_commits_previous;
        "#,
    )?;
    transaction.commit()?;
    Ok(())
}
