//! An immutable v2 proof domain retires v1 acceptance; it never restores lost
//! history or translates legacy monotonic clocks into portable expiry.
use super::*;

const TABLE: &str = "dpop_replay_authority_activations";

impl SqliteAdmissionOperationStore {
    /// Activate only the explicit v2 proof domain for this exact imported source.
    /// This is trusted operator configuration, not a caller-supplied opt-in.
    /// A first activation verifies the actual retired source. Once committed,
    /// exact readback/retry depends only on durable authority, so process-local
    /// source loss cannot erase or recreate the activated generation.
    ///
    /// Legacy v1 proofs are never admitted by this domain. Activation does not
    /// grant an operation claim, enable the legacy verifier, or permit dispatch.
    pub fn activate_dpop_replay_source(
        &self,
        authority: &DpopReplayAuthorityV1,
        source: &dyn DpopReplaySourcePort,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<DpopReplayMigrationRecordV1, AdmissionOperationStoreError> {
        let _migration = self
            .serving_owner
            .begin_replay_source_migration()
            .map_err(map_owner_error)?;
        let expected = self
            .load_dpop_replay_migration(authority.dpop_authority_id(), fence, trusted_now_unix_ms)?
            .ok_or_else(|| invariant("DPoP activation requires a pinned source"))?;
        require_binding(&expected, authority).map_err(integrity_error)?;
        if expected.is_active() {
            if expected.authority() != Some(authority) {
                return Err(invariant("DPoP activation policy is immutable"));
            }
            return Ok(expected);
        }
        if !expected.imported_inactive() {
            return Err(invariant(
                "DPoP activation requires complete inactive import",
            ));
        }
        source_io(|| source.verify_exact(expected.snapshot()))?;
        {
            let mut connection = self.connection()?;
            let transaction = self.begin_write(&mut connection, Some(fence))?;
            let observed = migration_time(&transaction, trusted_now_unix_ms)?;
            expected
                .snapshot
                .validate_transition_time(observed)
                .map_err(integrity_error)?;
            verify_all_records(&transaction).map_err(integrity_error)?;
            let mut current =
                records::load_record(&transaction, authority.dpop_authority_id().as_str())
                    .map_err(integrity_error)?
                    .ok_or_else(|| invariant("DPoP activation expectation disappeared"))?;
            require_same_expectation(&current, &expected)?;
            if !current.imported_inactive() {
                return Err(invariant("DPoP activation source state changed"));
            }
            let canonical = canonical_json_bytes(authority).map_err(integrity_error)?;
            transaction.execute("INSERT INTO dpop_replay_authority_activations (dpop_authority_id, canonical_authority) VALUES (?1, ?2)",
                params![authority.dpop_authority_id().as_str(), canonical]).map_err(sqlite_error)?;
            current.authority = Some(authority.clone());
            records::insert_event(&transaction, &current, 3, observed, fence)?;
            verify_all_records(&transaction).map_err(integrity_error)?;
            append_migration_commit(
                &self.serving_owner,
                &transaction,
                authority.dpop_authority_id().as_str(),
                3,
            )?;
            self.commit_write(transaction)?;
            self.sync_after_write(&connection)?;
        }
        let active = self
            .load_dpop_replay_migration(authority.dpop_authority_id(), fence, trusted_now_unix_ms)?
            .ok_or_else(|| invariant("DPoP activation readback missing"))?;
        require_same_expectation(&active, &expected)?;
        if !active.is_active() || active.authority() != Some(authority) {
            return Err(invariant("DPoP activation readback mismatch"));
        }
        Ok(active)
    }

    /// Read the exact configured domain through the fenced authority port.
    /// A serialized descriptor alone is not proof of this activation.
    pub fn load_dpop_replay_activation(
        &self,
        authority: &DpopReplayAuthorityV1,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<DpopReplayAuthorityV1, AdmissionOperationStoreError> {
        let record = self
            .load_dpop_replay_migration(authority.dpop_authority_id(), fence, trusted_now_unix_ms)?
            .ok_or_else(|| invariant("DPoP authority is not registered"))?;
        if !record.is_active() || record.authority() != Some(authority) {
            return Err(invariant(
                "DPoP authority is not activated with the exact configured policy",
            ));
        }
        Ok(authority.clone())
    }
}

fn require_binding(
    record: &DpopReplayMigrationRecordV1,
    authority: &DpopReplayAuthorityV1,
) -> Result<(), String> {
    if authority.dpop_authority_id().as_str() != record.snapshot.dpop_authority_id()
        || authority.destination_store_uuid().as_str() != record.snapshot.destination_authority_id()
        || authority.expectation_id().as_str() != record.expectation_id.as_str()
    {
        return Err(
            "DPoP activation does not name the exact destination and source generation".into(),
        );
    }
    Ok(())
}

fn table_exists(connection: &Connection) -> Result<bool, String> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
            [TABLE],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())
}

pub(super) fn load_authority(
    connection: &Connection,
    record: &DpopReplayMigrationRecordV1,
) -> Result<Option<DpopReplayAuthorityV1>, String> {
    if !table_exists(connection)? {
        return Ok(None);
    }
    let bytes: Option<Vec<u8>> = connection.query_row(
        "SELECT canonical_authority FROM dpop_replay_authority_activations WHERE dpop_authority_id = ?1",
        [record.snapshot.dpop_authority_id()], |row| row.get(0)).optional().map_err(|error| error.to_string())?;
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    let authority: DpopReplayAuthorityV1 =
        serde_json::from_slice(&bytes).map_err(|_| "DPoP activation decode failed")?;
    if canonical_json_bytes(&authority).map_err(|error| error.to_string())? != bytes {
        return Err("DPoP activation is not canonical".into());
    }
    require_binding(record, &authority)?;
    Ok(Some(authority))
}

pub(super) fn validate_storage_bounds(connection: &Connection) -> Result<(), String> {
    let namespace: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE lower(name) GLOB 'dpop_replay_authority_*' OR lower(tbl_name) GLOB 'dpop_replay_authority_*')", [], |row| row.get(0)).map_err(|error| error.to_string())?;
    if !namespace {
        return Ok(());
    }
    if !table_exists(connection)? {
        return Err("partial or substituted DPoP activation schema".into());
    }
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM dpop_replay_authority_activations",
            [],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    if !(0..=MAX_MIGRATIONS as i64).contains(&count) {
        return Err("DPoP activation count exceeds bound".into());
    }
    if super::bounds::invalid_row_exists(connection, TABLE,
        "typeof(dpop_authority_id) <> 'text' OR length(CAST(dpop_authority_id AS BLOB)) NOT BETWEEN 1 AND 512
         OR typeof(canonical_authority) <> 'blob' OR length(canonical_authority) NOT BETWEEN 1 AND 4096
         OR NOT EXISTS(SELECT 1 FROM dpop_replay_migration_expectations AS expected WHERE expected.dpop_authority_id = dpop_replay_authority_activations.dpop_authority_id)")? {
        return Err("DPoP activation has invalid storage or no source expectation".into());
    }
    Ok(())
}
