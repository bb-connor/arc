use std::fs;

use chio_kernel::admission_operation::{
    AdmissionIdentifier, AdmissionOperationStoreError, RuntimeSourcePort,
    RuntimeSourceQualificationV1, MAX_RUNTIME_SOURCE_BYTES,
};
use chio_sqlite_file_identity::{main_database_file_identity, SqliteFileIdentity};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};

use super::{sqlite_error, ChioRuntimeError, SqliteRuntimeOrchestrationStore};

fn invalid(detail: impl Into<String>) -> ChioRuntimeError {
    ChioRuntimeError::Rejected {
        code: "runtime_source_qualification_invalid",
        detail: detail.into(),
    }
}

impl SqliteRuntimeOrchestrationStore {
    fn source_file_identity(
        &self,
        connection: &Connection,
    ) -> Result<SqliteFileIdentity, ChioRuntimeError> {
        let identity = main_database_file_identity(connection)
            .map_err(|error| invalid(format!("runtime source file identity: {error}")))?;
        let metadata = fs::symlink_metadata(&self.path)
            .map_err(|error| invalid(format!("runtime source path identity: {error}")))?;
        if !metadata.file_type().is_file() || identity.link_count != 1 {
            return Err(invalid(
                "runtime source requires a regular single-link database file",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.dev() != identity.device
                || metadata.ino() != identity.inode
                || metadata.nlink() != identity.link_count
            {
                return Err(invalid(
                    "runtime source path no longer identifies its open database",
                ));
            }
        }
        Ok(identity)
    }

    fn load_source_qualification(
        &self,
        connection: &Connection,
    ) -> Result<Option<RuntimeSourceQualificationV1>, ChioRuntimeError> {
        let rows: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM runtime_source_qualification",
                [],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if rows > 1 {
            return Err(invalid("runtime source has multiple qualification records"));
        }
        let size: Option<(i64, String)> = connection
            .query_row(
                "SELECT length(canonical_bytes), typeof(canonical_bytes)
             FROM runtime_source_qualification WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(sqlite_error)?;
        let Some((size, storage)) = size else {
            if rows != 0 {
                return Err(invalid("runtime source qualification singleton is invalid"));
            }
            return Ok(None);
        };
        if storage != "blob"
            || size <= 0
            || usize::try_from(size)
                .ok()
                .is_none_or(|size| size > MAX_RUNTIME_SOURCE_BYTES)
        {
            return Err(invalid("runtime source qualification storage is invalid"));
        }
        let bytes: Vec<u8> = connection
            .query_row(
                "SELECT canonical_bytes FROM runtime_source_qualification WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        let qualification = RuntimeSourceQualificationV1::from_canonical_bytes(&bytes)
            .map_err(|error| invalid(error.to_string()))?;
        let identity = self.source_file_identity(connection)?;
        if qualification.device() != identity.device
            || qualification.inode() != identity.inode
            || qualification.link_count() != identity.link_count
        {
            return Err(invalid(
                "runtime source qualification belongs to a different physical file",
            ));
        }
        Ok(Some(qualification))
    }

    pub(in crate::store::sqlite) fn verify_runtime_source(
        &self,
        expected: &RuntimeSourceQualificationV1,
    ) -> Result<(), ChioRuntimeError> {
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_error)?;
        let actual = self
            .load_source_qualification(&transaction)?
            .ok_or_else(|| invalid("runtime source qualification is missing"))?;
        if actual != *expected {
            return Err(invalid("runtime source qualification binding mismatch"));
        }
        transaction.commit().map_err(sqlite_error)
    }

    pub(super) fn verify_source_qualification_on_open(&self) -> Result<(), ChioRuntimeError> {
        let connection = self.lock_connection()?;
        self.load_source_qualification(&connection)?;
        Ok(())
    }
}

impl RuntimeSourcePort for SqliteRuntimeOrchestrationStore {
    fn qualify(
        &self,
        source_id: &AdmissionIdentifier,
        runtime_authority_id: &AdmissionIdentifier,
        destination_authority_id: &AdmissionIdentifier,
    ) -> Result<RuntimeSourceQualificationV1, AdmissionOperationStoreError> {
        let mut connection = self.lock_connection().map_err(port_error)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)
            .map_err(port_error)?;
        let identity = self
            .source_file_identity(&transaction)
            .map_err(port_error)?;
        let candidate = RuntimeSourceQualificationV1::new(
            source_id.clone(),
            runtime_authority_id.clone(),
            destination_authority_id.clone(),
            identity.device,
            identity.inode,
            identity.link_count,
        )?;
        if let Some(actual) = self
            .load_source_qualification(&transaction)
            .map_err(port_error)?
        {
            if actual != candidate {
                return Err(port_error(invalid(
                    "runtime source is bound to another qualification",
                )));
            }
        } else {
            transaction.execute(
                "INSERT INTO runtime_source_qualification (singleton, canonical_bytes) VALUES (1, ?1)",
                [candidate.canonical_bytes()],
            ).map_err(sqlite_error).map_err(port_error)?;
        }
        let actual = self
            .load_source_qualification(&transaction)
            .map_err(port_error)?
            .ok_or_else(|| {
                port_error(invalid("runtime source qualification readback is missing"))
            })?;
        if actual != candidate {
            return Err(port_error(invalid(
                "runtime source qualification readback mismatch",
            )));
        }
        transaction
            .commit()
            .map_err(sqlite_error)
            .map_err(port_error)?;
        Ok(actual)
    }

    fn verify_exact(
        &self,
        expected: &RuntimeSourceQualificationV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.verify_runtime_source(expected).map_err(port_error)
    }
}

fn port_error(error: ChioRuntimeError) -> AdmissionOperationStoreError {
    match error {
        ChioRuntimeError::Rejected { .. } | ChioRuntimeError::DuplicateAdmissionBundle => {
            AdmissionOperationStoreError::Invariant(error.to_string())
        }
        _ => AdmissionOperationStoreError::Unavailable(error.to_string()),
    }
}
