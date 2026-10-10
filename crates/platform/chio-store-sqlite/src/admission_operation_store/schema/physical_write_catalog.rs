//! Physical pricing binds the compiled catalog, never a historical fixture.
use super::*;
use std::sync::OnceLock;

const TABLES: [&str; 4] = [
    "admission_operation_recovery_records",
    "admission_operation_recovery_events",
    "authority_global_commits",
    "authority_global_commit_meta",
];
/// Indexes of the never-released successor-ownership prototype. No supported
/// store installs them, and their retained presence refuses pricing.
const UNSUPPORTED_OWNERSHIP_INDEXES: [&str; 4] = [
    "admission_operation_recovery_original_owner",
    "admission_operation_recovery_original_transfer",
    "admission_operation_recovery_original_tombstone",
    "admission_operation_recovery_unused_setup_generation",
];
type Entry = (String, String, String, Option<String>);

/// This fingerprint describes a priced layout. It grants no source readiness,
/// phase allocation, writer authority or physical allowance.
pub(in crate::admission_operation_store) struct PhysicalCommandCatalogData {
    fingerprint: String,
}
impl PhysicalCommandCatalogData {
    pub(in crate::admission_operation_store) fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

pub(in crate::admission_operation_store) fn verify_physical_command_catalog(
    connection: &Connection,
) -> Result<PhysicalCommandCatalogData, AdmissionOperationStoreError> {
    refuse_unsupported_ownership_indexes(connection)?;
    let actual = catalog(connection)?;
    if actual.as_slice() != expected()? {
        return Err(invariant(
            "physical command catalog differs from its compiled definition",
        ));
    }
    let bytes = canonical_json_bytes(&("chio.sqlite-native-physical-command-catalog.v1", &actual))
        .map_err(|error| invariant(error.to_string()))?;
    Ok(PhysicalCommandCatalogData {
        fingerprint: sha256_hex(&bytes),
    })
}

fn refuse_unsupported_ownership_indexes(
    connection: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    for name in UNSUPPORTED_OWNERSHIP_INDEXES {
        let found: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM main.sqlite_schema WHERE name=?1)",
                [name],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if found {
            return Err(invariant(
                "physical command catalog contains the unsupported successor-ownership prototype",
            ));
        }
    }
    Ok(())
}

fn catalog(connection: &Connection) -> Result<Vec<Entry>, AdmissionOperationStoreError> {
    let tables = TABLES.map(|table| format!("'{table}'")).join(",");
    let predicate = format!("lower(tbl_name) IN ({tables})");
    let (count, bytes): (i64, i64) = connection
        .query_row(
            &format!(
        "SELECT COUNT(*), COALESCE(SUM(length(CAST(type AS BLOB)) + length(CAST(name AS BLOB))
         + length(CAST(tbl_name AS BLOB)) + COALESCE(length(CAST(sql AS BLOB)),0)),0)
         FROM main.sqlite_schema WHERE {predicate}"
    ),
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(sqlite_error)?;
    if !(0..=256).contains(&count) || !(0..=2_097_152).contains(&bytes) {
        return Err(invariant(
            "physical command catalog exceeds its bounded inventory",
        ));
    }
    let mut statement = connection
        .prepare(&format!(
            "SELECT type,name,tbl_name,sql FROM main.sqlite_schema WHERE {predicate}
         ORDER BY type COLLATE BINARY,name COLLATE BINARY,tbl_name COLLATE BINARY"
        ))
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })
        .map_err(sqlite_error)?;
    // SQLite already emits its stored CREATE statement. Compare those exact
    // compiled bytes: whitespace inside quoted guards and identifiers is data.
    rows.map(|row| row.map_err(sqlite_error)).collect()
}

fn expected() -> Result<&'static [Entry], AdmissionOperationStoreError> {
    static BASE: OnceLock<Result<Vec<Entry>, String>> = OnceLock::new();
    BASE.get_or_init(|| {
        // Reuse the complete supported catalog, including each immutable
        // guard and expression/partial index. An incomplete
        // recovery-only model cannot price a real current authority.
        let model = current_command_catalog_model().map_err(|error| error.to_string())?;
        catalog(&model).map_err(|error| error.to_string())
    })
    .as_ref()
    .map(|entries| entries.as_slice())
    .map_err(|error| invariant(error.to_string()))
}

fn current_command_catalog_model() -> Result<Connection, AdmissionOperationStoreError> {
    let model =
        super::expected_admission_operation_schema(ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION)?;
    model
        .execute_batch(crate::serving_owner::compiled_global_commit_schema())
        .map_err(sqlite_error)?;
    Ok(model)
}

#[cfg(test)]
pub(in crate::admission_operation_store) fn current_command_catalog_model_for_test(
) -> Result<Connection, AdmissionOperationStoreError> {
    current_command_catalog_model()
}

#[cfg(test)]
pub(in crate::admission_operation_store) type CommandCatalogDifferenceForTest =
    (String, String, String, Option<String>, Option<String>);

/// Compare only static catalog identity and raw SQL digests. This observer
/// neither changes the catalog nor reads retained authority or provider data.
#[cfg(test)]
pub(in crate::admission_operation_store) fn command_catalog_difference_for_test(
    connection: &Connection,
) -> Result<Vec<CommandCatalogDifferenceForTest>, AdmissionOperationStoreError> {
    use std::collections::{BTreeMap, BTreeSet};
    let actual = catalog(connection)?;
    let expected = expected()?;
    let keyed = |entries: &[Entry]| {
        entries
            .iter()
            .map(|entry| {
                (
                    (entry.0.clone(), entry.1.clone(), entry.2.clone()),
                    entry.3.clone(),
                )
            })
            .collect::<BTreeMap<_, _>>()
    };
    let actual = keyed(&actual);
    let expected = keyed(expected);
    let keys = actual
        .keys()
        .chain(expected.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let digest = |entry: Option<&Option<String>>| {
        entry.map(|sql| sha256_hex(sql.as_ref().map_or(&[][..], |sql| sql.as_bytes())))
    };
    Ok(keys
        .into_iter()
        .filter_map(|(kind, name, table)| {
            let key = (kind.clone(), name.clone(), table.clone());
            let stored = actual.get(&key);
            let compiled = expected.get(&key);
            (stored != compiled).then(|| (kind, name, table, digest(compiled), digest(stored)))
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model() -> Result<Connection, Box<dyn std::error::Error>> {
        let connection = super::super::expected_admission_operation_schema(
            ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION,
        )?;
        connection.execute_batch(crate::serving_owner::compiled_global_commit_schema())?;
        Ok(connection)
    }

    #[test]
    fn compiled_physical_catalog_has_a_stable_fingerprint() -> Result<(), Box<dyn std::error::Error>>
    {
        let first = verify_physical_command_catalog(&model()?)?;
        let second = verify_physical_command_catalog(&model()?)?;
        assert_eq!(first.fingerprint(), second.fingerprint());
        assert_eq!(first.fingerprint().len(), 64);
        Ok(())
    }

    #[test]
    fn predecessor_recovery_only_catalog_cannot_use_the_current_command_price_profile(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let predecessor = Connection::open_in_memory()?;
        predecessor.execute_batch(crate::admission_operation_store::recovery::SQL)?;
        predecessor.execute_batch(crate::serving_owner::compiled_global_commit_schema())?;
        assert!(verify_physical_command_catalog(&predecessor).is_err());
        assert!(command_catalog_difference_for_test(&model()?)?.is_empty());
        Ok(())
    }

    #[test]
    fn changed_quoted_trigger_bytes_refuse_the_priced_catalog(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = model()?;
        verify_physical_command_catalog(&connection)?;
        let original: String = connection.query_row(
            "SELECT sql FROM sqlite_schema WHERE name='admission_operation_recovery_event_no_update'",
            [],
            |row| row.get(0),
        )?;
        let changed = original.replace(
            "'recovery history is immutable'",
            "'recovery  history is immutable'",
        );
        assert_ne!(changed, original);
        connection.execute_batch("DROP TRIGGER admission_operation_recovery_event_no_update")?;
        connection.execute_batch(&changed)?;
        assert!(verify_physical_command_catalog(&connection).is_err());
        Ok(())
    }

    #[test]
    fn unknown_write_trigger_refuses_the_priced_catalog() -> Result<(), Box<dyn std::error::Error>>
    {
        let connection = model()?;
        verify_physical_command_catalog(&connection)?;
        connection.execute_batch(
            "CREATE TRIGGER extra_recovery_write AFTER INSERT ON admission_operation_recovery_records
             BEGIN UPDATE authority_global_commit_meta SET head_sequence=head_sequence+1; END;",
        )?;
        assert!(verify_physical_command_catalog(&connection).is_err());
        Ok(())
    }

    #[test]
    fn unsupported_ownership_indexes_refuse_pricing(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = model()?;
        verify_physical_command_catalog(&connection)?;
        for index in UNSUPPORTED_OWNERSHIP_INDEXES {
            connection.execute_batch(&format!(
                "CREATE INDEX {index} ON admission_operation_recovery_records(record_key);"
            ))?;
            assert!(
                verify_physical_command_catalog(&connection).is_err(),
                "the successor-ownership prototype index {index} remained priceable"
            );
        }
        Ok(())
    }
}
