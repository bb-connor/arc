use super::{records, INSTALL_MUTATION, PROJECTION_KIND};
use crate::serving_owner::SqliteServingOwnerError;
use rusqlite::{params, Connection};

fn invalid(detail: impl std::fmt::Display) -> SqliteServingOwnerError {
    SqliteServingOwnerError::Invalid(format!("runtime source qualification integrity: {detail}"))
}

pub(crate) fn runtime_source_projection_reference(
    connection: &Connection,
    key: &str,
    sequence: u64,
) -> Result<String, SqliteServingOwnerError> {
    if sequence != 1 {
        return Err(invalid("runtime source projection sequence must be one"));
    }
    let record = records::load_record(connection, key)
        .map_err(invalid)?
        .ok_or_else(|| invalid("global projection names an absent runtime source"))?;
    Ok(record.record_digest)
}

pub(crate) fn verify_runtime_source_projection_coverage(
    connection: &Connection,
) -> Result<(), SqliteServingOwnerError> {
    let records = records::verify_all_records(connection).map_err(invalid)?;
    if global_count(connection)? != i64::try_from(records.len()).map_err(invalid)? {
        return Err(invalid(
            "runtime sources and global references have different counts",
        ));
    }
    for record in records {
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM authority_global_commits
             WHERE projection_kind = ?1 AND projection_key = ?2 AND projection_sequence = 1
               AND mutation_kind = ?3 AND projection_reference_digest = ?4 AND store_uuid = ?5
               AND store_lease_id = ?6 AND store_owner_epoch = ?7",
                params![
                    PROJECTION_KIND,
                    record.qualification.runtime_authority_id(),
                    INSTALL_MUTATION,
                    record.record_digest,
                    record.fence.store_uuid,
                    record.fence.lease_id,
                    i64::try_from(record.fence.owner_epoch).map_err(invalid)?
                ],
                |row| row.get(0),
            )
            .map_err(invalid)?;
        if count != 1 {
            return Err(invalid(
                "runtime source lacks exactly one matching global commit",
            ));
        }
    }
    Ok(())
}

pub(crate) fn verify_runtime_source_pristine(
    connection: &Connection,
) -> Result<(), SqliteServingOwnerError> {
    if records::source_table_exists(connection).map_err(invalid)?
        && !records::verify_all_records(connection)
            .map_err(invalid)?
            .is_empty()
    {
        return Err(invalid(
            "runtime source qualification state is not pristine",
        ));
    }
    let global_exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'authority_global_commits')",
        [], |row| row.get(0),
    ).map_err(invalid)?;
    if global_exists && global_count(connection)? != 0 {
        return Err(invalid(
            "pristine runtime source state has global references",
        ));
    }
    Ok(())
}

fn global_count(connection: &Connection) -> Result<i64, SqliteServingOwnerError> {
    connection
        .query_row(
            "SELECT COUNT(*) FROM authority_global_commits WHERE projection_kind = ?1",
            [PROJECTION_KIND],
            |row| row.get(0),
        )
        .map_err(invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_source_table_is_only_allowed_before_provisioning(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        verify_runtime_source_pristine(&connection)?;
        assert_eq!(
            records::verify_all_records(&connection).err().as_deref(),
            Some("runtime source qualification table is absent"),
        );
        let error = verify_runtime_source_projection_coverage(&connection).err();
        assert!(
            matches!(error, Some(SqliteServingOwnerError::Invalid(detail))
            if detail == "runtime source qualification integrity: runtime source qualification table is absent")
        );
        Ok(())
    }
}
