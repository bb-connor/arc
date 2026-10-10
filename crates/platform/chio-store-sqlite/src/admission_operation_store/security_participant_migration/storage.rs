//! Bounded physical inventory storage. Canonical row bytes are rehashed on reads;
//! a retained fingerprint is not a substitute for retaining its actual rows.
use crate::security_state::{
    decode_retained_security_row, RetainedSecuritySourceRows, TableHasher,
};

use super::*;

#[cfg(all(test, unix))]
mod tests;

type CatalogEntry = (String, String, String, Option<String>);
const NAMESPACE: &str = "lower(name) GLOB 'security_participant_migration*' OR lower(tbl_name) GLOB 'security_participant_migration*'";

fn expected_catalog() -> Result<&'static [CatalogEntry], AdmissionOperationStoreError> {
    // Only the compiled canonical definition is cached, never observed database
    // state or row verification. Every read still inspects the live catalog.
    static EXPECTED: std::sync::OnceLock<Result<Vec<CatalogEntry>, String>> =
        std::sync::OnceLock::new();
    match EXPECTED.get_or_init(|| {
        let connection = Connection::open_in_memory().map_err(|error| error.to_string())?;
        connection
            .execute_batch(SECURITY_PARTICIPANT_MIGRATION_SCHEMA)
            .map_err(|error| error.to_string())?;
        catalog(&connection).map_err(|error| error.to_string())
    }) {
        Ok(catalog) => Ok(catalog),
        Err(error) => Err(invalid(error)),
    }
}

fn catalog(connection: &Connection) -> Result<Vec<CatalogEntry>, AdmissionOperationStoreError> {
    let (count, bytes): (i64, i64) = connection.query_row(
        &format!("SELECT COUNT(*), COALESCE(SUM(length(CAST(name AS BLOB)) + length(CAST(tbl_name AS BLOB)) + COALESCE(length(CAST(sql AS BLOB)), 0)), 0) FROM sqlite_schema WHERE {NAMESPACE}"),
        [], |row| Ok((row.get(0)?, row.get(1)?)),
    ).map_err(sqlite_error)?;
    if !(0..=32).contains(&count) || !(0..=131_072).contains(&bytes) {
        return Err(invalid("migration catalog exceeds bounds"));
    }
    let mut statement = connection.prepare(&format!(
        "SELECT type, name, tbl_name, sql FROM sqlite_schema WHERE {NAMESPACE} ORDER BY type, name, tbl_name"
    )).map_err(sqlite_error)?;
    let entries = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    Ok(entries)
}

/// Absence is allowed only for historical, entirely absent migration schemas.
/// Global coverage and the versioned admission catalog separately enforce that
/// absence is not a way to erase an already anchored migration.
pub(super) fn validate_bounds(
    connection: &Connection,
) -> Result<bool, AdmissionOperationStoreError> {
    let actual = catalog(connection)?;
    if actual.is_empty() {
        return Ok(false);
    }
    if actual != expected_catalog()? {
        return Err(invalid("migration catalog is not canonical"));
    }
    for (table, columns, predicate, count_limit) in [
        ("security_participant_migration_expectations", vec![
            ("security_authority_id", 512), ("source_id", 512), ("expectation_id", 64),
            ("destination_store_uuid", 512), ("source_device", 20), ("source_inode", 20),
            ("fingerprint_digest", 64),
        ], "typeof(canonical_source) <> 'blob' OR length(canonical_source) NOT BETWEEN 1 AND 65536", MAX_MIGRATIONS),
        ("security_participant_migration_events", vec![
            ("security_authority_id", 512), ("mutation_kind", 64), ("event_digest", 64),
            ("store_uuid", 512), ("store_lease_id", 512),
        ], "typeof(sequence) <> 'integer' OR sequence NOT BETWEEN 1 AND 2
          OR typeof(observed_at_unix_ms) <> 'integer' OR observed_at_unix_ms NOT BETWEEN 1 AND 9007199254740991
          OR typeof(store_owner_epoch) <> 'integer' OR store_owner_epoch < 1", MAX_MIGRATIONS * 2),
        ("security_participant_migration_rows", vec![
            ("security_authority_id", 512), ("table_name", 128),
        ], "typeof(row_index) <> 'integer' OR row_index NOT BETWEEN 0 AND 16383
          OR typeof(canonical_row) <> 'blob' OR length(canonical_row) NOT BETWEEN 1 AND 16777216", MAX_TOTAL_ROWS),
    ] {
        let count: i64 = connection.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get(0)).map_err(sqlite_error)?;
        if u64::try_from(count).map_err(invalid)? > count_limit { return Err(invalid("migration row count exceeds bounds")); }
        let mut predicates = vec![predicate.to_owned()];
        predicates.extend(columns.into_iter().map(|(column, bound)| format!(
            "typeof({column}) <> 'text' OR length(CAST({column} AS BLOB)) NOT BETWEEN 1 AND {bound}"
        )));
        let malformed: bool = connection.query_row(&format!(
            "SELECT EXISTS(SELECT 1 FROM {table} WHERE {})", predicates.join(" OR ")
        ), [], |row| row.get(0)).map_err(sqlite_error)?;
        if malformed { return Err(invalid("migration row type or byte bounds invalid")); }
    }
    let bytes: i64 = connection.query_row(
        "SELECT COALESCE(SUM(length(canonical_row)), 0) FROM security_participant_migration_rows",
        [], |row| row.get(0),
    ).map_err(sqlite_error)?;
    if u64::try_from(bytes).map_err(invalid)? > MAX_TOTAL_BYTES {
        return Err(invalid("migration retained bytes exceed bounds"));
    }
    for table in [
        "security_participant_migration_events",
        "security_participant_migration_rows",
    ] {
        let orphan: bool = connection.query_row(&format!(
            "SELECT EXISTS(SELECT 1 FROM {table} AS child LEFT JOIN security_participant_migration_expectations AS parent
             ON child.security_authority_id = parent.security_authority_id WHERE parent.security_authority_id IS NULL)"
        ), [], |row| row.get(0)).map_err(sqlite_error)?;
        if orphan {
            return Err(invalid("orphan migration row"));
        }
    }
    Ok(true)
}

pub(super) fn insert_rows(
    tx: &Transaction<'_>,
    record: &SecurityParticipantMigrationRecord,
    retained: RetainedSecuritySourceRows,
) -> Result<(), AdmissionOperationStoreError> {
    if retained.tables.len() != record.snapshot.tables().len() {
        return Err(invalid("retained table count mismatch"));
    }
    let mut statement = tx
        .prepare(
            "INSERT INTO security_participant_migration_rows
        (security_authority_id, table_name, row_index, canonical_row) VALUES (?1, ?2, ?3, ?4)",
        )
        .map_err(sqlite_error)?;
    for ((table, rows), fingerprint) in retained.tables.into_iter().zip(record.snapshot.tables()) {
        if table != fingerprint.table {
            return Err(invalid("retained table order mismatch"));
        }
        let mut hasher = TableHasher::new(table);
        for (index, row) in rows.into_iter().enumerate() {
            decode_retained_security_row(table, &row).map_err(invalid)?;
            hasher.push(&row).map_err(invalid)?;
            statement
                .execute(params![
                    record.authority(),
                    table,
                    i64::try_from(index).map_err(invalid)?,
                    row
                ])
                .map_err(sqlite_error)?;
        }
        if hasher.finish() != *fingerprint {
            return Err(invalid("retained source rows differ from pin"));
        }
    }
    Ok(())
}

pub(super) fn verify_rows(
    connection: &Connection,
    record: &SecurityParticipantMigrationRecord,
) -> Result<(), AdmissionOperationStoreError> {
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM security_participant_migration_rows
        WHERE security_authority_id = ?1",
            [record.authority()],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if record.phase() == SecurityParticipantMigrationPhase::Expected {
        if count != 0 {
            return Err(invalid(
                "pending migration contains premature retained rows",
            ));
        }
        return Ok(());
    }
    let mut verified = 0_u64;
    let mut statement = connection
        .prepare(
            "SELECT row_index, canonical_row FROM security_participant_migration_rows
        WHERE security_authority_id = ?1 AND table_name = ?2 ORDER BY row_index",
        )
        .map_err(sqlite_error)?;
    for expected in record.snapshot.tables() {
        let mut rows = statement
            .query(params![record.authority(), expected.table])
            .map_err(sqlite_error)?;
        let mut hasher = TableHasher::new(&expected.table);
        let mut next_index = 0_i64;
        while let Some(row) = rows.next().map_err(sqlite_error)? {
            let index: i64 = row.get(0).map_err(sqlite_error)?;
            if index != next_index {
                return Err(invalid("retained row index is not contiguous"));
            }
            let bytes = row
                .get_ref(1)
                .map_err(sqlite_error)?
                .as_blob()
                .map_err(invalid)?;
            decode_retained_security_row(&expected.table, bytes).map_err(invalid)?;
            hasher.push(bytes).map_err(invalid)?;
            next_index += 1;
        }
        if hasher.finish() != *expected {
            return Err(invalid("retained row bytes differ from pinned inventory"));
        }
        verified = verified
            .checked_add(expected.row_count)
            .ok_or_else(|| invalid("verified row count overflow"))?;
    }
    if verified != u64::try_from(count).map_err(invalid)? {
        return Err(invalid("extra retained source table rows"));
    }
    Ok(())
}
