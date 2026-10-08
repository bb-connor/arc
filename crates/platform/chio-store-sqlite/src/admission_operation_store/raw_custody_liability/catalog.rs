//! Exact current producer SQL and physical geometry are cost DATA, not credit.
use super::*;
use std::sync::OnceLock;

const SQLITE_SOURCE: &str =
    "2026-03-13 10:38:09 737ae4a34738ffa0c3ff7f9bb18df914dd1cad163f28fd6b6e114a344fe6d618";
const TABLES: [&str; 7] = [
    "tool_outcome_blobs",
    "tool_outcomes",
    "admission_operations",
    "admission_operation_commits",
    "admission_operation_commit_meta",
    "authority_global_commits",
    "authority_global_commit_meta",
];
type CatalogEntry = (String, String, String, Option<String>);

pub(in crate::admission_operation_store) struct RawWriteProfileData {
    page_size: u64,
    fingerprint: String,
}

impl RawWriteProfileData {
    pub(in crate::admission_operation_store) fn page_size(&self) -> u64 {
        self.page_size
    }

    pub(in crate::admission_operation_store) fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

/// The full ToolOutcome producing family adds its actual evaluation table,
/// primary and unique indexes, lease guards and versioned-body guards. This
/// distinct DATA type cannot substitute the smaller Raw catalogue for them.
pub(in crate::admission_operation_store) struct ToolOutcomeWriteProfileData {
    raw: RawWriteProfileData,
    fingerprint: String,
}

impl ToolOutcomeWriteProfileData {
    pub(in crate::admission_operation_store) fn page_size(&self) -> u64 {
        self.raw.page_size()
    }

    pub(in crate::admission_operation_store) fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

pub(in crate::admission_operation_store) fn tool_outcome_write_profile(
    tx: &Connection,
) -> Result<ToolOutcomeWriteProfileData, AdmissionOperationStoreError> {
    // The existing seven-table verifier first fences the namespace, whole
    // geometry, exact source version and its unmodified compiled catalogue.
    let raw = raw_write_profile(tx)?;
    let evaluation = evaluation_catalog(tx)?;
    if evaluation.as_slice() != expected_evaluation_catalog()? {
        return Err(invariant(
            "ToolOutcome evaluation catalog differs from its compiled definition",
        ));
    }
    let bytes = canonical_json_bytes(&(
        "chio.sqlite.tool-outcome-write-profile.v1",
        raw.fingerprint(),
        evaluation,
        recovery::resources::tool_outcome_price_algorithm_fingerprint()?,
        "eight actual producer tables; current admission40 and tool outcome3",
    ))
    .map_err(|error| invariant(error.to_string()))?;
    Ok(ToolOutcomeWriteProfileData {
        raw,
        fingerprint: sha256_hex(&bytes),
    })
}

fn evaluation_catalog(tx: &Connection) -> Result<Vec<CatalogEntry>, AdmissionOperationStoreError> {
    let (count, bytes): (i64, i64) = tx
        .query_row(
            "SELECT COUNT(*),COALESCE(SUM(length(CAST(type AS BLOB))
                +length(CAST(name AS BLOB))+length(CAST(tbl_name AS BLOB))
                +COALESCE(length(CAST(sql AS BLOB)),0)),0)
             FROM main.sqlite_schema WHERE tbl_name='post_return_evaluations' COLLATE NOCASE",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(sqlite_error)?;
    if !(1..=32).contains(&count) || !(1..=524_288).contains(&bytes) {
        return Err(invariant(
            "evaluation catalog exceeds its bounded inventory",
        ));
    }
    let mut statement = tx
        .prepare(
            "SELECT type,name,tbl_name,sql FROM main.sqlite_schema
             WHERE tbl_name='post_return_evaluations' COLLATE NOCASE
             ORDER BY type COLLATE BINARY,name COLLATE BINARY,tbl_name COLLATE BINARY",
        )
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .map_err(sqlite_error)?;
    rows.map(|row| row.map_err(sqlite_error)).collect()
}

fn expected_evaluation_catalog() -> Result<&'static [CatalogEntry], AdmissionOperationStoreError> {
    static EXPECTED: OnceLock<Result<Vec<CatalogEntry>, String>> = OnceLock::new();
    EXPECTED
        .get_or_init(|| {
            let model = Connection::open_in_memory().map_err(|error| error.to_string())?;
            model
                .execute_batch(crate::tool_outcome_store::compiled_tool_outcome_schema())
                .map_err(|error| error.to_string())?;
            evaluation_catalog(&model).map_err(|error| error.to_string())
        })
        .as_ref()
        .map(|entries| entries.as_slice())
        .map_err(|error| invariant(error.to_string()))
}

pub(in crate::admission_operation_store) fn raw_write_profile(
    tx: &Connection,
) -> Result<RawWriteProfileData, AdmissionOperationStoreError> {
    require_namespace(tx)?;
    let source: String = tx
        .query_row("SELECT sqlite_source_id()", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    let encoding: String = tx
        .query_row("PRAGMA main.encoding", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    let journal: String = tx
        .query_row("PRAGMA main.journal_mode", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    let page_size: i64 = tx
        .query_row("PRAGMA main.page_size", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    let vacuum: i64 = tx
        .query_row("PRAGMA main.auto_vacuum", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    let synchronous: i64 = tx
        .query_row("PRAGMA main.synchronous", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    let spill: i64 = tx
        .query_row("PRAGMA main.cache_spill", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    let page_size = stored_u64(page_size, "Raw page size")?;
    let geometry =
        chio_sqlite_file_identity::main_database_write_geometry(tx).map_err(invariant)?;
    // The closed row codec uses UTF-8 bytes. A pending reserve-byte request
    // is rejected too; reading only the old database header would miss it.
    if source != SQLITE_SOURCE
        || encoding != "UTF-8"
        || journal != "wal"
        || !(512..=65_536).contains(&page_size)
        || !page_size.is_power_of_two()
        || vacuum != 0
        || synchronous != 2
        || spill < 0
        || geometry.reserved_bytes() != 0
    {
        return Err(invariant("Raw physical write profile is unsupported"));
    }
    let actual = catalog(tx)?;
    if actual.as_slice() != expected()? {
        return Err(invariant(
            "Raw physical catalog differs from its compiled definition",
        ));
    }
    let bytes = canonical_json_bytes(&(
        "chio.sqlite.raw-custody-write-profile.v1",
        SQLITE_SOURCE,
        &actual,
        recovery::resources::raw_custody_price_algorithm_fingerprint()?,
        (
            page_size,
            "UTF-8",
            "wal",
            0_u8,
            2_u8,
            geometry.reserved_bytes(),
            geometry.sector_bytes(),
            geometry.device_characteristics(),
            geometry.vfs_name(),
        ),
        (
            "spill supported by per-mutation and allocation frame bounds",
            "every FULL commit includes the bundled65536 sector ceiling",
            "no attached database or temporary main source or callback",
            "fixed current admission40 and tool outcome3 catalog",
        ),
    ))
    .map_err(|error| invariant(error.to_string()))?;
    Ok(RawWriteProfileData {
        page_size,
        fingerprint: sha256_hex(&bytes),
    })
}

fn require_namespace(tx: &Connection) -> Result<(), AdmissionOperationStoreError> {
    let mut databases = tx.prepare("PRAGMA database_list").map_err(sqlite_error)?;
    let rows = databases
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(sqlite_error)?;
    let mut main = false;
    for row in rows {
        match row.map_err(sqlite_error)?.as_str() {
            "main" => main = true,
            "temp" => (),
            _ => return Err(invariant("Raw profile contains an attached database")),
        }
    }
    if !main {
        return Err(invariant("Raw profile has no main database"));
    }
    // Source helpers also read serving, stamp, lease, clock and reserved-stage
    // tables. Refuse any TEMP table/view shadowing an actual main source.
    // Unrelated TEMP census tables are permitted. No TEMP trigger grants a
    // priced producer an ambient write to another family or database.
    let unsafe_temporary: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM temp.sqlite_schema t
             WHERE t.type='trigger'
                OR (t.type IN ('table','view') AND (
                    lower(t.name) IN ('sqlite_schema','sqlite_master','dbstat')
                    OR lower(t.name) GLOB 'pragma_*'
                    OR EXISTS(SELECT 1 FROM main.sqlite_schema m
                              WHERE m.type IN ('table','view')
                                AND t.name=m.name COLLATE NOCASE))))",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if unsafe_temporary {
        return Err(invariant(
            "Raw profile contains an unpriced temporary source or trigger",
        ));
    }
    Ok(())
}

fn catalog(tx: &Connection) -> Result<Vec<CatalogEntry>, AdmissionOperationStoreError> {
    let tables = TABLES.map(|table| format!("'{table}'")).join(",");
    let predicate = format!("lower(tbl_name) IN ({tables})");
    let (count, bytes): (i64, i64) = tx
        .query_row(
            &format!(
                "SELECT COUNT(*),COALESCE(SUM(length(CAST(type AS BLOB))
                    +length(CAST(name AS BLOB))+length(CAST(tbl_name AS BLOB))
                    +COALESCE(length(CAST(sql AS BLOB)),0)),0)
                 FROM main.sqlite_schema WHERE {predicate}",
            ),
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(sqlite_error)?;
    if !(0..=256).contains(&count) || !(0..=2_097_152).contains(&bytes) {
        return Err(invariant("Raw catalog exceeds its bounded inventory"));
    }
    let mut statement = tx
        .prepare(&format!(
            "SELECT type,name,tbl_name,sql FROM main.sqlite_schema WHERE {predicate}
             ORDER BY type COLLATE BINARY,name COLLATE BINARY,tbl_name COLLATE BINARY",
        ))
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .map_err(sqlite_error)?;
    rows.map(|row| row.map_err(sqlite_error)).collect()
}

fn expected() -> Result<&'static [CatalogEntry], AdmissionOperationStoreError> {
    static EXPECTED: OnceLock<Result<Vec<CatalogEntry>, String>> = OnceLock::new();
    EXPECTED
        .get_or_init(|| {
            let model = schema::current_admission_write_catalog_model()
                .map_err(|error| error.to_string())?;
            model
                .execute_batch(crate::tool_outcome_store::compiled_tool_outcome_schema())
                .map_err(|error| error.to_string())?;
            model
                .execute_batch(crate::serving_owner::compiled_global_commit_schema())
                .map_err(|error| error.to_string())?;
            catalog(&model).map_err(|error| error.to_string())
        })
        .as_ref()
        .map(|entries| entries.as_slice())
        .map_err(|error| invariant(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // These are actual SQLite layout controls. They create no serving owner,
    // original operation, Raw source role or bank allowance.
    fn physical_catalog_database(
        encoding: &str,
    ) -> Result<(tempfile::TempDir, Connection), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let tx = Connection::open(directory.path().join("raw-profile.sqlite3"))?;
        tx.pragma_update(Some("main"), "encoding", encoding)?;
        tx.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")?;
        for kind in ["table", "index", "trigger"] {
            for (actual_kind, _, _, sql) in expected()? {
                if actual_kind == kind {
                    if let Some(sql) = sql {
                        tx.execute_batch(sql)?;
                    }
                }
            }
        }
        Ok((directory, tx))
    }

    #[test]
    fn raw_layout_rejects_utf16_before_using_utf8_row_sizes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (_ordinary_directory, ordinary) = physical_catalog_database("UTF-8")?;
        assert!(!raw_write_profile(&ordinary)?.fingerprint().is_empty());
        let (_utf16_directory, utf16) = physical_catalog_database("UTF-16le")?;
        let encoding: String = utf16.query_row("PRAGMA main.encoding", [], |row| row.get(0))?;
        assert_eq!(encoding, "UTF-16le");
        assert!(matches!(
            raw_write_profile(&utf16),
            Err(AdmissionOperationStoreError::Invariant(reason))
                if reason == "Raw physical write profile is unsupported"
        ));
        Ok(())
    }

    #[test]
    fn raw_layout_accepts_enabled_spill_without_changing_the_writer(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (_directory, connection) = physical_catalog_database("UTF-8")?;
        let before: i64 = connection.query_row("PRAGMA main.cache_spill", [], |row| row.get(0))?;
        assert!(before > 0);
        assert!(!raw_write_profile(&connection)?.fingerprint().is_empty());
        assert_eq!(
            connection.query_row("PRAGMA main.cache_spill", [], |row| row.get::<_, i64>(0))?,
            before
        );
        connection.pragma_update(Some("main"), "synchronous", 1)?;
        assert!(raw_write_profile(&connection).is_err());
        Ok(())
    }

    #[test]
    fn full_custody_profile_requires_the_actual_evaluation_table_and_guards(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (_directory, connection) = physical_catalog_database("UTF-8")?;
        assert!(!raw_write_profile(&connection)?.fingerprint().is_empty());
        assert!(tool_outcome_write_profile(&connection).is_err());
        connection.execute_batch(crate::tool_outcome_store::compiled_tool_outcome_schema())?;
        let full = tool_outcome_write_profile(&connection)?;
        assert_ne!(
            full.fingerprint(),
            raw_write_profile(&connection)?.fingerprint()
        );
        assert_eq!(
            full.page_size(),
            raw_write_profile(&connection)?.page_size()
        );
        connection.execute_batch("DROP TRIGGER post_return_evaluations_versioned_body")?;
        assert!(!raw_write_profile(&connection)?.fingerprint().is_empty());
        assert!(tool_outcome_write_profile(&connection).is_err());
        Ok(())
    }

    #[test]
    fn full_custody_profile_refuses_extra_evaluation_indexes_and_temporary_callbacks(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (_directory, connection) = physical_catalog_database("UTF-8")?;
        connection.execute_batch(crate::tool_outcome_store::compiled_tool_outcome_schema())?;
        assert!(!tool_outcome_write_profile(&connection)?
            .fingerprint()
            .is_empty());
        connection.execute_batch(
            "CREATE INDEX unpriced_evaluation_body ON post_return_evaluations(evaluation_json)",
        )?;
        assert!(!raw_write_profile(&connection)?.fingerprint().is_empty());
        assert!(tool_outcome_write_profile(&connection).is_err());
        connection.execute_batch("DROP INDEX unpriced_evaluation_body")?;
        assert!(!tool_outcome_write_profile(&connection)?
            .fingerprint()
            .is_empty());
        connection.execute_batch(
            "CREATE TEMP TRIGGER unpriced_evaluation_callback
             AFTER INSERT ON main.post_return_evaluations BEGIN SELECT 1; END",
        )?;
        assert!(tool_outcome_write_profile(&connection).is_err());
        Ok(())
    }
}
