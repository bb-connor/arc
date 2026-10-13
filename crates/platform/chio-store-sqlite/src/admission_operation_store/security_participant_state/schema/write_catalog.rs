//! Exact compiled native flow layout is data, never a phase or source grant.
use super::*;
mod connection_namespace;

pub(in crate::admission_operation_store) struct NativeFlowWriteCatalogData {
    fingerprint: String,
}

impl NativeFlowWriteCatalogData {
    pub(in crate::admission_operation_store) fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

/// This closes the native row tables and their real affine SQL callbacks.
/// Protected Knowledge roots/chunks, events and global rows have a separate
/// catalog. Native Output, outcome and other participants are not priced here.
pub(in crate::admission_operation_store) fn native_flow_write_catalog(
    connection: &Connection,
) -> Result<NativeFlowWriteCatalogData, AdmissionOperationStoreError> {
    connection_namespace::require_native_source_namespace(connection)?;
    let version = recorded_version(connection)?;
    if version != 29 || !verify_version(connection, version)? {
        return Err(invalid(
            "native flow write catalog is not the active compiled layout",
        ));
    }
    Ok(NativeFlowWriteCatalogData {
        fingerprint: digest_version(version)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model() -> Result<Connection, Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(&sql()?)?;
        connection.execute_batch(
            "CREATE TABLE chio_store_schema_versions(store_key TEXT PRIMARY KEY,version INTEGER);
             INSERT INTO chio_store_schema_versions VALUES('admission_operation',40);",
        )?;
        Ok(connection)
    }

    #[test]
    fn native_flow_layout_fingerprint_binds_the_full_compiled_callback_catalog(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let first = native_flow_write_catalog(&model()?)?;
        let second = native_flow_write_catalog(&model()?)?;
        assert_eq!(first.fingerprint(), second.fingerprint());
        assert_eq!(first.fingerprint().len(), 64);
        Ok(())
    }

    #[test]
    fn changed_quoted_native_guard_refuses_the_native_write_profile(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = model()?;
        native_flow_write_catalog(&connection)?;
        let name = "security_participant_state_6_inactive_update";
        let original: String = connection.query_row(
            "SELECT sql FROM sqlite_schema WHERE name=?1",
            [name],
            |row| row.get(0),
        )?;
        let changed = original.replace(
            "'native security state lacks operation custody'",
            "'native security state  lacks operation custody'",
        );
        assert_ne!(changed, original);
        connection.execute_batch(&format!("DROP TRIGGER {name}"))?;
        connection.execute_batch(&changed)?;
        assert!(native_flow_write_catalog(&connection).is_err());
        Ok(())
    }

    #[test]
    fn unknown_native_write_trigger_refuses_the_native_write_profile(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = model()?;
        native_flow_write_catalog(&connection)?;
        connection.execute_batch(
            "CREATE TRIGGER extra_native_write AFTER UPDATE ON security_participant_state_flow_contexts
             BEGIN UPDATE security_participant_state_flow_sequences
             SET last_generation=last_generation+1; END;",
        )?;
        assert!(native_flow_write_catalog(&connection).is_err());
        Ok(())
    }

    #[test]
    fn an_uninstalled_successor_cannot_reuse_a_native_write_profile(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = model()?;
        native_flow_write_catalog(&connection)?;
        connection.execute("UPDATE chio_store_schema_versions SET version=41", [])?;
        assert!(native_flow_write_catalog(&connection).is_err());
        Ok(())
    }

    #[test]
    fn native_write_profile_refuses_an_unpriced_attached_database(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = model()?;
        native_flow_write_catalog(&connection)?;
        connection.execute_batch("ATTACH DATABASE ':memory:' AS unpriced")?;
        assert!(native_flow_write_catalog(&connection).is_err());
        Ok(())
    }

    #[test]
    fn native_write_profile_refuses_a_temporary_source_stamp(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = model()?;
        native_flow_write_catalog(&connection)?;
        connection.execute_batch(
            "CREATE TEMP TABLE chio_store_schema_versions(store_key TEXT,version INTEGER);
             INSERT INTO temp.chio_store_schema_versions VALUES('admission_operation',40);",
        )?;
        assert!(native_flow_write_catalog(&connection).is_err());
        Ok(())
    }

    #[test]
    fn native_write_profile_refuses_a_temporary_native_callback(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = model()?;
        native_flow_write_catalog(&connection)?;
        connection.execute_batch(
            "CREATE TEMP TABLE unpriced_callback_sink(value INTEGER);
             CREATE TEMP TRIGGER unpriced_native_callback
             AFTER UPDATE ON main.security_participant_state_flow_sequences
             BEGIN INSERT INTO unpriced_callback_sink VALUES(NEW.last_generation); END;",
        )?;
        assert!(native_flow_write_catalog(&connection).is_err());
        Ok(())
    }

    #[test]
    fn native_write_profile_allows_an_unrelated_temporary_census(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = model()?;
        let original = native_flow_write_catalog(&connection)?;
        connection.execute_batch("CREATE TEMP TABLE unrelated_census(value INTEGER)")?;
        assert_eq!(
            native_flow_write_catalog(&connection)?.fingerprint(),
            original.fingerprint(),
        );
        Ok(())
    }
}
