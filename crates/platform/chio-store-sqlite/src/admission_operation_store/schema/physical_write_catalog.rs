//! Physical pricing binds the compiled catalog, never a historical fixture.
use super::*;
use std::sync::OnceLock;

const TABLES: [&str; 4] = [
    "admission_operation_recovery_records",
    "admission_operation_recovery_events",
    "authority_global_commits",
    "authority_global_commit_meta",
];
const ORIGINAL_INDEXES: [&str; 4] = [
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
    let original = original_index_inventory(connection)?;
    let actual = catalog(connection)?;
    if actual.as_slice() != expected(original)? {
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

fn original_index_inventory(connection: &Connection) -> Result<bool, AdmissionOperationStoreError> {
    let mut present = 0_usize;
    for name in ORIGINAL_INDEXES {
        let found: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM main.sqlite_schema WHERE name=?1)",
                [name],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        present += usize::from(found);
    }
    match present {
        0 => Ok(false),
        4 => Ok(true),
        _ => Err(invariant(
            "physical command catalog contains a partial original-owner cohort",
        )),
    }
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

fn expected(original: bool) -> Result<&'static [Entry], AdmissionOperationStoreError> {
    static BASE: OnceLock<Result<Vec<Entry>, String>> = OnceLock::new();
    static ORIGINAL: OnceLock<Result<Vec<Entry>, String>> = OnceLock::new();
    let cached = if original { &ORIGINAL } else { &BASE };
    cached
        .get_or_init(|| {
            // Reuse the complete trusted current40 birth catalog, including
            // every36-40 immutable guard and expression/partial index. A35
            // recovery-only model cannot price a real current authority.
            let model = current_command_catalog_model().map_err(|error| error.to_string())?;
            if original {
                model
                    .execute_batch(super::super::recovery::storage::ORIGINAL_OWNER_SQL)
                    .map_err(|error| error.to_string())?;
                model
                    .execute_batch(super::super::recovery::storage::UNUSED_SETUP_GENERATION_SQL)
                    .map_err(|error| error.to_string())?;
            }
            catalog(&model).map_err(|error| error.to_string())
        })
        .as_ref()
        .map(|entries| entries.as_slice())
        .map_err(|error| invariant(error.to_string()))
}

fn current_command_catalog_model() -> Result<Connection, AdmissionOperationStoreError> {
    let model = super::expected_admission_operation_schema(40)?;
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
    let expected = expected(original_index_inventory(connection)?)?;
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
        let connection = super::super::expected_admission_operation_schema(40)?;
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
    fn partial_original_owner_index_cohort_refuses_the_priced_catalog(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = model()?;
        connection.execute_batch(
            crate::admission_operation_store::recovery::storage::ORIGINAL_OWNER_SQL,
        )?;
        connection.execute_batch(
            crate::admission_operation_store::recovery::storage::UNUSED_SETUP_GENERATION_SQL,
        )?;
        verify_physical_command_catalog(&connection)?;
        connection.execute_batch("DROP INDEX admission_operation_recovery_original_tombstone")?;
        assert!(verify_physical_command_catalog(&connection).is_err());
        Ok(())
    }
}
