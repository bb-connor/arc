//! Immutable final-release checkpoints share the admission commit chain.

use super::*;
#[cfg(test)]
#[path = "tool_outcome_security_release_tests.rs"]
mod tests;

fn has_release_namespace(connection: &Connection) -> Result<bool, ToolOutcomeStoreError> {
    connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE lower(name) GLOB 'tool_outcome_security_release*' OR lower(tbl_name) GLOB 'tool_outcome_security_release*')",
        [], |row| row.get(0),
    ).map_err(sqlite_error)
}

pub(super) fn verify_unstamped_source(
    connection: &Connection,
) -> Result<(), ToolOutcomeStoreError> {
    let app_id: i32 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(sqlite_error)?;
    if app_id == 0 && has_release_namespace(connection)? {
        return Err(invariant(
            "unstamped security release source cannot be adopted",
        ));
    }
    let version_namespace: Option<(String, String)> = connection
        .query_row(
            "SELECT type, name FROM sqlite_schema WHERE lower(name) = 'chio_store_schema_versions'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    if let Some((kind, name)) = version_namespace {
        if kind != "table" || name != "chio_store_schema_versions" {
            return Err(invariant(
                "outcome schema-version namespace is not canonical",
            ));
        }
        if app_id == 0 {
            return Err(invariant(
                "versioned outcome source has a damaged application identity",
            ));
        }
    }
    Ok(())
}

fn predecessor_schema(version: i32) -> String {
    if version == 1 {
        // Exact v1 trigger predicate from 1ba3d031ff^, before qualified payload
        // rehydration was introduced. No other predecessor shape is accepted.
        TOOL_OUTCOME_SCHEMA.replace(
            "  OR (OLD.canonical_bytes IS NULL AND NEW.canonical_bytes IS NULL)\n  OR (OLD.canonical_bytes IS NOT NULL AND NEW.canonical_bytes IS NOT NULL)",
            "  OR OLD.canonical_bytes IS NULL\n  OR NEW.canonical_bytes IS NOT NULL",
        )
    } else {
        TOOL_OUTCOME_SCHEMA.to_owned()
    }
}

pub(super) fn verify_pre_migration(
    connection: &Connection,
    on_disk: i32,
) -> Result<(), ToolOutcomeStoreError> {
    if has_release_namespace(connection)? {
        return Err(invariant(
            "pre-v3 outcome source contains unqualified security release records",
        ));
    }
    let actual = tool_outcome_schema_catalog(connection)?;
    if on_disk != 0 || !actual.is_empty() {
        let mut matched = false;
        for version in [1, 2] {
            if on_disk != 0 && on_disk != version {
                continue;
            }
            let expected = Connection::open_in_memory().map_err(sqlite_error)?;
            expected
                .execute_batch(&predecessor_schema(version))
                .map_err(sqlite_error)?;
            matched |= actual == tool_outcome_schema_catalog(&expected)?;
        }
        if !matched {
            return Err(invariant(
                "pre-v3 outcome schema is not the exact qualified predecessor",
            ));
        }
        let future: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM tool_outcome_blobs WHERE canonical_bytes IS NOT NULL AND (json_extract(canonical_bytes, '$.schema') = 'chio.raw-invocation-outcome-with-security-release.v1' OR json_type(canonical_bytes, '$.security_release_required') IS NOT NULL))",
            [], |row| row.get(0),
        ).map_err(sqlite_error)?;
        if future {
            return Err(invariant(
                "pre-v3 outcome source carries unqualified release requirements",
            ));
        }
    }
    Ok(())
}

fn participant_digest(record: &SecurityReleaseRecordV1) -> Result<String, ToolOutcomeStoreError> {
    #[derive(Serialize)]
    struct Commitment<'a> {
        schema: &'static str,
        record: &'a SecurityReleaseRecordV1,
    }
    canonical_json_bytes(&Commitment {
        schema: "chio.security-release-participant.v1",
        record,
    })
    .map(|bytes| sha256_hex(&bytes))
    .map_err(|error| invariant(error.to_string()))
}

pub(super) fn load(
    connection: &Connection,
    operation_id: &str,
) -> Result<Option<SecurityReleaseRecordV1>, ToolOutcomeStoreError> {
    type Row = (Vec<u8>, String, i64, String, String, i64);
    let row: Option<Row> = connection.query_row(
        "SELECT canonical_record, participant_digest, acknowledged_at_unix_ms, store_uuid, store_lease_id, store_owner_epoch FROM tool_outcome_security_releases WHERE operation_id = ?1",
        [operation_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
    ).optional().map_err(sqlite_error)?;
    row.map(|(bytes, digest, at, store_uuid, lease_id, epoch)| {
        let record = SecurityReleaseRecordV1::from_canonical_bytes(&bytes).map_err(|error| invariant(error.to_string()))?;
        if record.operation_id().as_str() != operation_id
            || digest != participant_digest(&record)?
            || sqlite_u64(record.acknowledged_at_unix_ms(), "release time")? != at
            || record.store_fence().store_uuid != store_uuid
            || record.store_fence().lease_id != lease_id
            || sqlite_u64(record.store_fence().owner_epoch, "release owner epoch")? != epoch {
            return Err(invariant("security release row differs from its canonical record"));
        }
        let exact_lease: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM chio_serving_leases WHERE store_uuid = ?1 AND lease_id = ?2 AND owner_epoch = ?3)",
            params![store_uuid, lease_id, epoch], |row| row.get(0),
        ).map_err(sqlite_error)?;
        if !exact_lease { return Err(invariant("security release has no exact historical serving lease")); }
        Ok(record)
    }).transpose()
}

pub(super) fn verify_projection(
    connection: &Connection,
    operation: &AdmissionOperationV1,
    outcome: &ToolOutcomeRecordV1,
    evaluation: Option<&PostReturnEvaluationRecordV1>,
) -> Result<Option<String>, ToolOutcomeStoreError> {
    let record = load(connection, operation.binding().operation_id().as_str())?;
    let raw = match load_blob_state_connection(connection, outcome.raw_output_digest())? {
        Some(StoredInvocationBlob::Present(blob)) => Some(
            RawInvocationOutcomeV1::from_canonical_bytes(blob.bytes())
                .map_err(|error| invariant(error.to_string()))?,
        ),
        Some(StoredInvocationBlob::Compacted) => None,
        None => return Err(invariant("security release lost its raw-outcome identity")),
    };
    if let Some(record) = record {
        let evaluation =
            evaluation.ok_or_else(|| invariant("release checkpoint has no terminal evaluation"))?;
        match raw.as_ref() {
            Some(raw) => record.validate_against(operation, raw, outcome, evaluation),
            None => record.validate_retained_against(operation, outcome, evaluation),
        }
        .map_err(|error| invariant(error.to_string()))?;
        return participant_digest(&record).map(Some);
    }
    // Historical records retain their bytes; runtime recovery rejects an
    // unknown legacy requirement instead of inventing a successful release.
    if operation.state().is_terminal()
        && raw
            .as_ref()
            .is_some_and(|raw| raw.requires_security_release() == Ok(true))
    {
        return Err(invariant(
            "terminal operation is missing its required security release",
        ));
    }
    Ok(None)
}

/// Enforce release independently at the store's terminal projection boundary.
/// This does not perform a callback or turn a missing checkpoint into success.
pub(crate) fn require_terminal_release(
    connection: &Connection,
    operation: &AdmissionOperationV1,
) -> Result<(), AdmissionOperationStoreError> {
    let verify = || -> Result<(), ToolOutcomeStoreError> {
        let Some(outcome) =
            load_outcome_connection(connection, operation.binding().operation_id().as_str())?
        else {
            return Ok(());
        };
        let Some(StoredInvocationBlob::Present(blob)) =
            load_blob_state_connection(connection, outcome.raw_output_digest())?
        else {
            // Existing terminal replay may outlive payload retention. Exact
            // checkpoint and admission-chain coverage remain mandatory.
            return verify_outcome_projection(
                connection,
                operation.binding().operation_id().as_str(),
            );
        };
        let raw = RawInvocationOutcomeV1::from_canonical_bytes(blob.bytes())
            .map_err(|error| invariant(error.to_string()))?;
        if raw
            .requires_security_release()
            .map_err(|error| invariant(error.to_string()))?
            && load(connection, operation.binding().operation_id().as_str())?.is_none()
        {
            return Err(invariant(
                "terminal projection requires a security release checkpoint",
            ));
        }
        verify_outcome_projection(connection, operation.binding().operation_id().as_str())
    };
    verify().map_err(|error| AdmissionOperationStoreError::Invariant(error.to_string()))
}

impl SqliteToolOutcomeStore {
    pub(super) fn persist_security_release(
        &self,
        acknowledged: &AcknowledgedSecurityReleaseV1,
        lease: &AdmissionRecoveryLease,
    ) -> Result<SecurityReleaseRecordV1, ToolOutcomeStoreError> {
        let record = acknowledged.record();
        let now = record.acknowledged_at_unix_ms();
        let fence = record.store_fence();
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, fence, now)?;
        let operation = load_operation_for_participant_tx(&transaction, record.operation_id())
            .map_err(admission_error)?
            .ok_or(ToolOutcomeStoreError::NotFound)?;
        crate::admission_operation_store::verify_participant_recovery_lease_tx(
            &transaction,
            &self.serving_owner,
            &operation,
            lease,
            now,
        )
        .map_err(admission_error)?;
        let outcome = load_outcome_tx(&transaction, record.operation_id())?
            .ok_or(ToolOutcomeStoreError::NotFound)?;
        require_finalizing_operation(&operation, &outcome)?;
        let evaluation = load_evaluation_tx(&transaction, record.operation_id())?
            .ok_or(ToolOutcomeStoreError::NotFound)?;
        let blob = load_blob_tx(&transaction, outcome.raw_output_digest())?
            .ok_or(ToolOutcomeStoreError::NotFound)?;
        let raw = RawInvocationOutcomeV1::from_canonical_bytes(blob.bytes())
            .map_err(|error| invariant(error.to_string()))?;
        record
            .validate_against(&operation, &raw, &outcome, &evaluation)
            .map_err(|error| invariant(error.to_string()))?;
        verify_outcome_projection(&transaction, record.operation_id().as_str())?;
        if let Some(existing) = load(&transaction, record.operation_id().as_str())? {
            if &existing != record {
                return Err(ToolOutcomeStoreError::Conflict);
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(existing);
        }
        let bytes = record
            .canonical_bytes()
            .map_err(|error| invariant(error.to_string()))?;
        let digest = participant_digest(record)?;
        transaction.execute(
            "INSERT INTO tool_outcome_security_releases(operation_id, canonical_record, participant_digest, acknowledged_at_unix_ms, store_uuid, store_lease_id, store_owner_epoch) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![record.operation_id().as_str(), bytes, digest, sqlite_u64(now, "release time")?, fence.store_uuid, fence.lease_id, sqlite_u64(fence.owner_epoch, "release epoch")?],
        ).map_err(sqlite_error)?;
        append_participant_update_tx(
            &transaction,
            &self.serving_owner,
            &operation,
            lease,
            &digest,
            now,
        )
        .map_err(admission_error)?;
        verify_outcome_projection(&transaction, record.operation_id().as_str())?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(record.clone())
    }
}
