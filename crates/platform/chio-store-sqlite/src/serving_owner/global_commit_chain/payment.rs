//! Payment journal and resolution coverage in the global authority chain.
use super::*;

pub(super) fn payment_resolution_reference_digest(
    connection: &Connection,
    operation_id: &str,
    sequence: u64,
) -> Result<String, SqliteServingOwnerError> {
    let (table, operation_id) = operation_id
        .strip_prefix("capture-waiver:")
        .map_or(("unknown_payment_release_records", operation_id), |id| {
            ("capture_waiver_records", id)
        });
    let (bytes, stored): (Vec<u8>, String) = connection.query_row(
        &format!("SELECT record_json,record_digest FROM {table} WHERE operation_id=?1 AND sequence=?2"),
        params![operation_id, sqlite_u64(sequence, "payment resolution sequence")?],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).optional()?.ok_or_else(|| invalid("payment resolution projection is absent"))?;
    if bytes.is_empty() || bytes.len() > 1024 * 1024 || sha256_hex(&bytes) != stored {
        return Err(invalid("payment resolution projection digest is invalid"));
    }
    Ok(stored)
}

pub(super) fn verify_payment_resolution_coverage(
    connection: &Connection,
) -> Result<(), SqliteServingOwnerError> {
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='unknown_payment_release_records')", [], |row| row.get(0))?;
    if !exists {
        let orphaned: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM authority_global_commits WHERE projection_kind='payment_resolution')", [], |row| row.get(0))?;
        return if orphaned {
            Err(invalid("payment resolution table is absent"))
        } else {
            Ok(())
        };
    }
    let invalid_coverage: bool = connection.query_row(
        r#"
        SELECT EXISTS(SELECT 1 FROM unknown_payment_release_records AS local
            WHERE (SELECT COUNT(*) FROM authority_global_commits AS global
                WHERE global.projection_kind='payment_resolution'
                AND global.mutation_kind='unknown_payment_release'
                AND global.projection_key=local.operation_id
                AND global.projection_sequence=local.sequence
                AND global.projection_reference_digest=local.record_digest) <> 1)
        OR EXISTS(SELECT 1 FROM authority_global_commits AS global
            WHERE global.projection_kind='payment_resolution' AND global.mutation_kind <> 'capture_waiver' AND
            (global.mutation_kind <> 'unknown_payment_release' OR NOT EXISTS(
                SELECT 1 FROM unknown_payment_release_records AS local
                WHERE local.operation_id=global.projection_key
                AND local.sequence=global.projection_sequence)))
        "#,
        [],
        |row| row.get(0),
    )?;
    if invalid_coverage {
        return Err(invalid("payment resolution global coverage is not exact"));
    }
    verify_capture_waiver_coverage(connection)?;

    Ok(())
}

fn verify_capture_waiver_coverage(connection: &Connection) -> Result<(), SqliteServingOwnerError> {
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='capture_waiver_records')",
        [], |row| row.get(0),
    )?;
    if !exists {
        let orphan: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM authority_global_commits WHERE mutation_kind='capture_waiver')",
            [], |row| row.get(0),
        )?;
        return if orphan {
            Err(invalid("capture waiver table absent"))
        } else {
            Ok(())
        };
    }
    let invalid_coverage: bool = connection.query_row(
        r#"
        SELECT EXISTS(SELECT 1 FROM capture_waiver_records AS local
            WHERE (SELECT COUNT(*) FROM authority_global_commits AS global
                WHERE global.projection_kind='payment_resolution'
                AND global.mutation_kind='capture_waiver'
                AND global.projection_key='capture-waiver:'||local.operation_id
                AND global.projection_sequence=local.sequence
                AND global.projection_reference_digest=local.record_digest) <> 1)
        OR EXISTS(SELECT 1 FROM authority_global_commits AS global
            WHERE global.projection_kind='payment_resolution'
            AND global.mutation_kind='capture_waiver'
            AND NOT EXISTS(SELECT 1 FROM capture_waiver_records AS local
                WHERE global.projection_key='capture-waiver:'||local.operation_id
                AND global.projection_sequence=local.sequence))
        "#,
        [],
        |row| row.get(0),
    )?;
    if invalid_coverage {
        return Err(invalid("capture waiver coverage is not exact"));
    }
    Ok(())
}

pub(super) fn payment_journal_reference_digest(
    connection: &Connection,
    operation_id: &str,
    journal_version: u64,
) -> Result<String, SqliteServingOwnerError> {
    let stored_version = connection
        .query_row(
            "SELECT journal_version FROM payment_journal WHERE operation_id = ?1",
            [operation_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .ok_or_else(|| invalid("payment journal projection reference is absent"))?;
    if read_u64(stored_version, "payment journal version")? != journal_version {
        return Err(invalid(
            "payment journal projection sequence does not match its record",
        ));
    }
    let tables = ["payment_journal", "payment_release_evidence"];
    let mut snapshots = Vec::with_capacity(tables.len());
    for table in tables {
        snapshots.push(table_snapshot(
            connection,
            table,
            Some(("operation_id", operation_id)),
        )?);
    }
    digest(&AuthoritySnapshot {
        format: "chio.sqlite-authority-payment-journal-reference.v1",
        tables: snapshots,
    })
}
