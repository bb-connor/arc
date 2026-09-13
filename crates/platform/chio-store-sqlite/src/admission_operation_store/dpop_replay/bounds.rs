//! Check storage representation and aggregate bounds before loading blobs.
use super::records::TABLES;
use super::*;

pub(super) fn invalid_row_exists(
    connection: &Connection,
    table: &str,
    predicate: &str,
) -> Result<bool, String> {
    connection
        .query_row(
            &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE {predicate})"),
            [],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())
}

pub(super) fn validate_storage_bounds(connection: &Connection) -> Result<bool, String> {
    let namespace: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE lower(name) GLOB 'dpop_replay_*' OR lower(tbl_name) GLOB 'dpop_replay_*'",
        [], |row| row.get(0),
    ).map_err(|error| error.to_string())?;
    if namespace == 0 {
        return Ok(false);
    }
    let tables: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' AND name IN
         ('dpop_replay_migration_expectations','dpop_replay_migration_events','dpop_replay_legacy_tombstones')",
        [], |row| row.get(0),
    ).map_err(|error| error.to_string())?;
    if tables != 3 {
        return Err("partial or substituted DPoP migration schema".into());
    }
    let (expectations, bytes): (i64, i64) = connection.query_row(
        "SELECT COUNT(*), COALESCE(SUM(length(CAST(canonical_source AS BLOB))), 0) FROM dpop_replay_migration_expectations",
        [], |row| Ok((row.get(0)?,row.get(1)?)),
    ).map_err(|error| error.to_string())?;
    if !(0..=MAX_MIGRATIONS as i64).contains(&expectations)
        || !(0..=MAX_TOTAL_SOURCE_BYTES as i64).contains(&bytes)
    {
        return Err("DPoP expectation aggregate limit exceeded".into());
    }
    for (table, text_columns, extra, limit) in [
        (TABLES[0], vec![("dpop_authority_id",1,512),("source_instance_id",1,512),
          ("expectation_id",1,512),("destination_store_uuid",1,512),
          ("inventory_sha256",64,64),("expectation_digest",64,64)],
          "typeof(canonical_source) <> 'blob' OR length(canonical_source) NOT BETWEEN 1 AND 16777216", MAX_MIGRATIONS),
        (TABLES[1], vec![("dpop_authority_id",1,512),("mutation_kind",1,64),
          ("expectation_digest",64,64),("inventory_sha256",64,64),("event_digest",64,64),
          ("store_uuid",1,512),("store_lease_id",1,512)],
          "typeof(sequence) <> 'integer' OR sequence NOT BETWEEN 1 AND 3
           OR typeof(observed_at_unix_ms) <> 'integer' OR observed_at_unix_ms NOT BETWEEN 0 AND 9007199254740991
           OR typeof(store_owner_epoch) <> 'integer' OR store_owner_epoch < 1", MAX_MIGRATIONS * 3),
        (TABLES[2], vec![("dpop_authority_id",1,512),("capability_id",0,4096),
          ("nonce",0,4096),("source_instance_id",1,512),("expectation_id",1,512)],
          "typeof(canonical_marker) <> 'blob' OR length(canonical_marker) NOT BETWEEN 1 AND 131072", MAX_TOTAL_MARKERS),
    ] {
        let rows: i64 = connection.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get(0))
            .map_err(|error| error.to_string())?;
        if !(0..=limit as i64).contains(&rows) { return Err(format!("{table} row limit exceeded")); }
        let predicate = text_columns.into_iter().map(|(column, min, max)| format!(
            "typeof({column}) <> 'text' OR length(CAST({column} AS BLOB)) NOT BETWEEN {min} AND {max}"
        )).chain([extra.to_owned()]).collect::<Vec<_>>().join(" OR ");
        if invalid_row_exists(connection, table, &predicate)? {
            return Err(format!("{table} has invalid storage types or sizes"));
        }
    }
    let marker_bytes: i64 = connection.query_row(
        "SELECT COALESCE(SUM(length(CAST(canonical_marker AS BLOB))), 0) FROM dpop_replay_legacy_tombstones",
        [], |row| row.get(0),
    ).map_err(|error| error.to_string())?;
    if !(0..=MAX_TOTAL_SOURCE_BYTES as i64).contains(&marker_bytes) {
        return Err("DPoP tombstone byte limit exceeded".into());
    }
    super::activation::validate_storage_bounds(connection)?;
    Ok(true)
}
