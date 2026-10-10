//! Select physical geometry before the first authority schema write.
use super::*;

pub(super) fn require_small_pages_before_schema(
    connection: &Connection,
) -> Result<(), SqliteServingOwnerError> {
    let pages: i64 = connection.query_row("PRAGMA main.page_count", [], |row| row.get(0))?;
    if pages == 0 {
        let objects: i64 =
            connection.query_row("SELECT count(*) FROM main.sqlite_schema", [], |row| {
                row.get(0)
            })?;
        if objects != 0 {
            return Err(SqliteServingOwnerError::Invalid(
                "empty Native file has an occupied schema".into(),
            ));
        }
        connection.execute_batch("PRAGMA main.page_size=512;")?;
    }
    let page_bytes: i64 = connection.query_row("PRAGMA main.page_size", [], |row| row.get(0))?;
    if page_bytes != 512 {
        return Err(SqliteServingOwnerError::Invalid(
            "Native financing provisioning requires an empty file or existing 512-byte pages"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_profile_persists_geometry_across_reopen() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("small-page-authority.db");
        {
            let connection = Connection::open(&path)?;
            require_small_pages_before_schema(&connection)?;
            connection.execute_batch(
                "CREATE TABLE retained(value INTEGER); INSERT INTO retained VALUES(7);",
            )?;
        }
        let connection = Connection::open(&path)?;
        require_small_pages_before_schema(&connection)?;
        let page: i64 = connection.query_row("PRAGMA main.page_size", [], |row| row.get(0))?;
        let page = u64::try_from(page)?;
        let value: i64 =
            connection.query_row("SELECT value FROM retained", [], |row| row.get(0))?;
        let value = u64::try_from(value)?;
        assert_eq!((page, value), (512, 7));
        Ok(())
    }

    #[test]
    fn populated_large_page_file_is_not_converted_or_truncated(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("retained-authority.db");
        let connection = Connection::open(&path)?;
        connection.execute_batch("PRAGMA main.page_size=4096; CREATE TABLE retained(value INTEGER); INSERT INTO retained VALUES(9);")?;
        assert!(require_small_pages_before_schema(&connection).is_err());
        let page: i64 = connection.query_row("PRAGMA main.page_size", [], |row| row.get(0))?;
        let page = u64::try_from(page)?;
        let value: i64 =
            connection.query_row("SELECT value FROM retained", [], |row| row.get(0))?;
        let value = u64::try_from(value)?;
        assert_eq!((page, value), (4096, 9));
        Ok(())
    }

    #[cfg(unix)]
    #[derive(Debug, PartialEq)]
    struct RetainedAuthoritySnapshot {
        file_identity: (u64, u64),
        file_length: u64,
        page_bytes: i64,
        page_count: i64,
        geometry: chio_sqlite_file_identity::SqliteWriteGeometryData,
        store_uuid: String,
        owner_row: Vec<rusqlite::types::Value>,
        global_head: (u64, String),
        revocations: Vec<(String, i64, Option<i64>, Option<i64>)>,
    }

    #[cfg(unix)]
    fn retained_authority_snapshot(
        database: &Path,
    ) -> Result<RetainedAuthoritySnapshot, Box<dyn std::error::Error>> {
        use std::os::unix::fs::MetadataExt;

        let database = fs::canonicalize(database)?;
        let metadata = fs::metadata(&database)?;
        let connection = Connection::open_with_flags(
            database,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        let owner_row = connection.query_row(
            "SELECT * FROM main.chio_serving_owner WHERE singleton=1",
            [],
            |row| {
                (0..row.as_ref().column_count())
                    .map(|column| row.get(column))
                    .collect::<Result<Vec<_>, _>>()
            },
        )?;
        let revocations = {
            let mut statement = connection.prepare(
                "SELECT capability_id,revoked_at,revocation_index,admission_authority_commit_index
                 FROM main.revoked_capabilities ORDER BY capability_id",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        Ok(RetainedAuthoritySnapshot {
            file_identity: (metadata.dev(), metadata.ino()),
            file_length: metadata.len(),
            page_bytes: connection.query_row("PRAGMA main.page_size", [], |row| row.get(0))?,
            page_count: connection.query_row("PRAGMA main.page_count", [], |row| row.get(0))?,
            geometry: chio_sqlite_file_identity::main_database_write_geometry(&connection)?,
            store_uuid: connection.query_row(
                "SELECT store_uuid FROM main.chio_serving_owner WHERE singleton=1",
                [],
                |row| row.get(0),
            )?,
            owner_row,
            global_head: native_finishing_global_head(&connection)?,
            revocations,
        })
    }

    #[cfg(unix)]
    #[test]
    fn explicit_small_page_authority_retains_identity_and_data_across_serving_reopen(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use super::super::tests::{create_lock_root, secure_directory};
        use chio_kernel::RevocationStore;

        let directory = tempfile::tempdir()?;
        secure_directory(directory.path());
        let database = directory.path().join("authority.db");
        let lock_root = directory.path().join("locks");
        create_lock_root(&lock_root);
        SqliteAuthorityStore::provision_small_page_native_authority(&database, &lock_root)?;
        let provisioned = retained_authority_snapshot(&database)?;
        assert_eq!(provisioned.page_bytes, 512);
        assert!(provisioned.page_count > 0);
        assert!(provisioned.global_head.0 > 0);
        assert!(provisioned.revocations.is_empty());

        let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
        assert_eq!(
            authority.mutation_fence().store_uuid,
            provisioned.store_uuid
        );
        let revocation = authority.revocation_store();
        assert!(revocation.revoke("retained-small-page")?);
        drop(revocation);
        drop(authority);
        let before_reopen = retained_authority_snapshot(&database)?;
        assert_eq!(before_reopen.page_bytes, 512);
        assert_eq!(before_reopen.file_identity, provisioned.file_identity);
        assert_eq!(before_reopen.geometry, provisioned.geometry);
        assert_eq!(before_reopen.store_uuid, provisioned.store_uuid);
        assert_eq!(before_reopen.revocations.len(), 1);

        let reopened = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
        assert_eq!(reopened.mutation_fence().store_uuid, provisioned.store_uuid);
        let revocation = reopened.revocation_store();
        assert!(revocation.is_revoked("retained-small-page")?);
        drop(revocation);
        drop(reopened);
        let after_reopen = retained_authority_snapshot(&database)?;
        assert_eq!(after_reopen.page_bytes, 512);
        assert_eq!(after_reopen.file_identity, provisioned.file_identity);
        assert_eq!(after_reopen.geometry, provisioned.geometry);
        assert_eq!(after_reopen.store_uuid, provisioned.store_uuid);
        assert_eq!(after_reopen.revocations, before_reopen.revocations);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn explicit_small_page_provision_refuses_existing_large_page_authority_without_mutation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use super::super::tests::{create_lock_root, secure_directory};
        use chio_kernel::RevocationStore;

        let directory = tempfile::tempdir()?;
        secure_directory(directory.path());
        let database = directory.path().join("authority.db");
        let lock_root = directory.path().join("locks");
        create_lock_root(&lock_root);
        SqliteAuthorityStore::provision(&database, &lock_root)?;
        let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
        let store_uuid = authority.mutation_fence().store_uuid;
        let revocation = authority.revocation_store();
        assert!(revocation.revoke("retained-large-page")?);
        drop(revocation);
        drop(authority);

        // All serving handles are closed before either offline snapshot. The
        // refusal must preserve even the owner lease row and complete head.
        let before = retained_authority_snapshot(&database)?;
        assert_eq!(before.page_bytes, 4096);
        assert!(before.page_count > 0);
        assert_eq!(before.store_uuid, store_uuid);
        assert_eq!(before.revocations.len(), 1);
        assert!(before.global_head.0 > 0);
        let result =
            SqliteAuthorityStore::provision_small_page_native_authority(&database, &lock_root);
        assert!(
            matches!(
                &result,
                Err(SqliteServingOwnerError::Invalid(message))
                    if message == "Native financing provisioning requires an empty file or existing 512-byte pages"
            ),
            "unexpected provisioning result: {result:?}"
        );
        assert_eq!(retained_authority_snapshot(&database)?, before);

        let reopened = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
        assert_eq!(reopened.mutation_fence().store_uuid, store_uuid);
        let revocation = reopened.revocation_store();
        assert!(revocation.is_revoked("retained-large-page")?);
        drop(revocation);
        drop(reopened);
        let after_reopen = retained_authority_snapshot(&database)?;
        assert_eq!(after_reopen.page_bytes, 4096);
        assert_eq!(after_reopen.file_identity, before.file_identity);
        assert_eq!(after_reopen.geometry, before.geometry);
        assert_eq!(after_reopen.store_uuid, store_uuid);
        assert_eq!(after_reopen.revocations, before.revocations);
        Ok(())
    }
}
