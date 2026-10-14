//! Compiled native catalog and inactive-state mutation barriers.
use super::*;
use std::sync::OnceLock;
mod mutations;
mod write_catalog;
pub(in crate::admission_operation_store) use write_catalog::native_flow_write_catalog;

/// The native catalog the current hydration writer commits: the v29 catalog
/// plus only the immutable imported scope index.
pub(in crate::admission_operation_store) const CURRENT_VERSION: i32 = 30;

pub(in crate::admission_operation_store) struct Table {
    pub source: &'static str,
    pub native: &'static str,
}

pub(in crate::admission_operation_store) const TABLES: &[Table] = &[
    Table {
        source: "security_declassification_evidence_identity",
        native: "security_participant_state_declassification_evidence_identity",
    },
    Table {
        source: "security_declassification_lifecycle",
        native: "security_participant_state_declassification_lifecycle",
    },
    Table {
        source: "security_declassification_receipt_outbox",
        native: "security_participant_state_declassification_receipt_outbox",
    },
    Table {
        source: "security_declassification_tombstones",
        native: "security_participant_state_declassification_tombstones",
    },
    Table {
        source: "security_declassification_uses",
        native: "security_participant_state_declassification_uses",
    },
    Table {
        source: "security_egress_fences",
        native: "security_participant_state_egress_fences",
    },
    Table {
        source: "security_flow_contexts",
        native: "security_participant_state_flow_contexts",
    },
    Table {
        source: "security_flow_sequences",
        native: "security_participant_state_flow_sequences",
    },
    Table {
        source: "security_isolation_epochs",
        native: "security_participant_state_isolation_epochs",
    },
    Table {
        source: "security_lineage_flow_state",
        native: "security_participant_state_lineage_flow_state",
    },
    Table {
        source: "security_principal_flow_state",
        native: "security_participant_state_principal_flow_state",
    },
    Table {
        source: "security_session_flow_state",
        native: "security_participant_state_session_flow_state",
    },
    Table {
        source: "security_session_memberships",
        native: "security_participant_state_session_memberships",
    },
    Table {
        source: "security_transitions",
        native: "security_participant_state_transitions",
    },
];
const NAMESPACE: &str = "lower(name) GLOB 'security_participant_state*' OR lower(tbl_name) GLOB 'security_participant_state*'";
type CatalogEntry = (String, String, String, Option<String>);

pub(in crate::admission_operation_store) fn predecessor_sql() -> String {
    let mut sql =
        include_str!("../../admission_operation_security_participant_state.sql").to_owned();
    for (index, table) in TABLES.iter().enumerate() {
        for (suffix, operation, predicate) in [
            ("insert", "INSERT", "security_authority_id = NEW.security_authority_id"),
            ("update", "UPDATE", "security_authority_id = OLD.security_authority_id OR security_authority_id = NEW.security_authority_id"),
            ("delete", "DELETE", "security_authority_id = OLD.security_authority_id"),
        ] {
            sql.push_str(&format!("\nCREATE TRIGGER IF NOT EXISTS security_participant_state_{index}_inactive_{suffix}\nBEFORE {operation} ON {} WHEN EXISTS (SELECT 1 FROM security_participant_state_initializations WHERE {predicate})\nBEGIN SELECT RAISE(ABORT, 'native security state is inactive'); END;\n", table.native));
        }
    }
    for (suffix, operation, predicate) in [
        ("insert", "INSERT", "WHEN EXISTS (SELECT 1 FROM security_participant_state_initializations WHERE security_authority_id = NEW.security_authority_id)"),
        ("update", "UPDATE", ""), ("delete", "DELETE", ""),
    ] {
        sql.push_str(&format!("\nCREATE TRIGGER IF NOT EXISTS security_participant_state_initialization_no_{suffix}\nBEFORE {operation} ON security_participant_state_initializations {predicate}\nBEGIN SELECT RAISE(ABORT, 'native initialization history is immutable'); END;\n"));
    }
    sql
}

/// Compiled catalog of one supported native version.
pub(in crate::admission_operation_store) fn sql_version(
    version: i32,
) -> Result<String, AdmissionOperationStoreError> {
    match version {
        28 => Ok(predecessor_sql()),
        29 => mutations::extend(predecessor_sql()),
        CURRENT_VERSION => {
            let mut sql = sql_version(29)?;
            sql.push('\n');
            sql.push_str(include_str!(
                "../../admission_operation_security_participant_imported_scope_index.sql"
            ));
            Ok(sql)
        }
        _ => Err(invalid("native security catalog version is unsupported")),
    }
}

pub(in crate::admission_operation_store) fn sql() -> Result<String, AdmissionOperationStoreError> {
    sql_version(CURRENT_VERSION)
}

fn catalog(connection: &Connection) -> Result<Vec<CatalogEntry>, AdmissionOperationStoreError> {
    let (count, bytes): (i64, i64) = connection.query_row(&format!("SELECT COUNT(*), COALESCE(SUM(length(CAST(name AS BLOB)) + length(CAST(tbl_name AS BLOB)) + COALESCE(length(CAST(sql AS BLOB)), 0)), 0) FROM main.sqlite_schema WHERE {NAMESPACE}"), [], |row| Ok((row.get(0)?, row.get(1)?))).map_err(sqlite_error)?;
    if !(0..=256).contains(&count) || !(0..=1_048_576).contains(&bytes) {
        return Err(invalid("native security catalog exceeds bounds"));
    }
    let mut statement = connection.prepare(&format!("SELECT type, name, tbl_name, sql FROM main.sqlite_schema WHERE {NAMESPACE} ORDER BY type, name, tbl_name")).map_err(sqlite_error)?;
    let entries = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    Ok(entries)
}

fn expected(version: i32) -> Result<&'static [CatalogEntry], AdmissionOperationStoreError> {
    static PREDECESSOR: OnceLock<Result<Vec<CatalogEntry>, String>> = OnceLock::new();
    static MUTATIONS: OnceLock<Result<Vec<CatalogEntry>, String>> = OnceLock::new();
    static CURRENT: OnceLock<Result<Vec<CatalogEntry>, String>> = OnceLock::new();
    let cache = match version {
        28 => &PREDECESSOR,
        29 => &MUTATIONS,
        CURRENT_VERSION => &CURRENT,
        _ => return Err(invalid("native security catalog version is unsupported")),
    };
    match cache.get_or_init(|| {
        let connection = Connection::open_in_memory().map_err(|error| error.to_string())?;
        connection
            .execute_batch(&sql_version(version).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
        catalog(&connection).map_err(|error| error.to_string())
    }) {
        Ok(catalog) => Ok(catalog),
        Err(error) => Err(invalid(error)),
    }
}

/// Verify the live catalog against the native version its admission stamp
/// selects. An absent catalog is reported as absent, never inferred.
pub(super) fn verify(connection: &Connection) -> Result<bool, AdmissionOperationStoreError> {
    if catalog(connection)?.is_empty() {
        return Ok(false);
    }
    verify_version(connection, recorded_version(connection)?)
}

pub(in crate::admission_operation_store) fn verify_version(
    connection: &Connection,
    version: i32,
) -> Result<bool, AdmissionOperationStoreError> {
    let actual = catalog(connection)?;
    if actual.is_empty() {
        return Ok(false);
    }
    if actual != expected(version)? {
        return Err(invalid("native security catalog is not canonical"));
    }
    Ok(true)
}

pub(in crate::admission_operation_store) fn require_absent(
    connection: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    if !catalog(connection)?.is_empty() {
        return Err(invalid("pre-v28 native security state is unqualified"));
    }
    Ok(())
}

/// Verify the genuine native catalog of a supported predecessor admission
/// format before any successor DDL runs. Formats before v28 carry none.
pub(in crate::admission_operation_store) fn verify_predecessor_catalog(
    connection: &Connection,
    admission_version: i32,
) -> Result<(), AdmissionOperationStoreError> {
    if admission_version < 28 {
        return require_absent(connection);
    }
    let version = native_catalog_version(admission_version)?;
    if version == CURRENT_VERSION {
        return Err(invalid("native security predecessor is already current"));
    }
    verify_version(connection, version).map(|_| ())
}

pub(super) fn digest() -> Result<String, AdmissionOperationStoreError> {
    digest_version(CURRENT_VERSION)
}

/// Native catalog carried by each supported admission format.
pub(in crate::admission_operation_store) fn native_catalog_version(
    admission_version: i32,
) -> Result<i32, AdmissionOperationStoreError> {
    match admission_version {
        28 => Ok(28),
        // Admission v30 through v34 add independent journals and the caller
        // wait state over the unchanged v29 native catalog.
        29..=34 => Ok(29),
        ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION => Ok(CURRENT_VERSION),
        _ => Err(invalid("native security schema version is unsupported")),
    }
}

pub(super) fn recorded_version(
    connection: &Connection,
) -> Result<i32, AdmissionOperationStoreError> {
    let version: i32 = connection.query_row(
        "SELECT version FROM main.chio_store_schema_versions WHERE store_key = 'admission_operation'",
        [], |row| row.get(0),
    ).map_err(sqlite_error)?;
    native_catalog_version(version)
}

pub(super) fn digest_version(version: i32) -> Result<String, AdmissionOperationStoreError> {
    // Only compiled catalog bytes are memoized. Live SQLite catalogs, rows,
    // authority bindings and their verification results are never cached here.
    static PREDECESSOR: OnceLock<Result<String, String>> = OnceLock::new();
    static MUTATIONS: OnceLock<Result<String, String>> = OnceLock::new();
    static CURRENT: OnceLock<Result<String, String>> = OnceLock::new();
    let cache = match version {
        28 => &PREDECESSOR,
        29 => &MUTATIONS,
        CURRENT_VERSION => &CURRENT,
        _ => return Err(invalid("native security catalog version is unsupported")),
    };
    cache
        .get_or_init(|| {
            let catalog = expected(version).map_err(|error| error.to_string())?;
            let mut bytes = b"chio.security-participant-state.catalog.v1\0".to_vec();
            bytes.extend(canonical_json_bytes(&catalog).map_err(|error| error.to_string())?);
            Ok(sha256_hex(&bytes))
        })
        .as_ref()
        .cloned()
        .map_err(invalid)
}

#[cfg(test)]
mod tests;
